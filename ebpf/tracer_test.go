// +build linux_bpf

package ebpf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"os"

	"github.com/stretchr/testify/assert"
)

var (
	clientMessageSize = 2 << 8
	serverMessageSize = 2 << 14
	payloadSizesTCP   = []int{2 << 5, 2 << 8, 2 << 10, 2 << 12, 2 << 14, 2 << 15}
	payloadSizesUDP   = []int{2 << 5, 2 << 8, 2 << 12, 2 << 14}
)

func TestRemoveDuplicates(t *testing.T) {
	conn1 := ConnectionStats{
		Pid:         123,
		Type:        TCP,
		Family:      AFINET,
		Source:      "localhost",
		Dest:        "localhost",
		SPort:       31890,
		DPort:       80,
		SendBytes:   12345,
		RecvBytes:   6789,
		Retransmits: 2,
	}

	// Different family
	conn2 := ConnectionStats{
		Pid:         123,
		Type:        TCP,
		Family:      AFINET6,
		Source:      "localhost",
		Dest:        "localhost",
		SPort:       31890,
		DPort:       80,
		SendBytes:   12345,
		RecvBytes:   6789,
		Retransmits: 2,
	}

	// Same as conn1 but with different stats
	conn3 := ConnectionStats{
		Pid:         123,
		Type:        TCP,
		Family:      AFINET6,
		Source:      "localhost",
		Dest:        "localhost",
		SPort:       31890,
		DPort:       80,
		SendBytes:   0,
		RecvBytes:   123,
		Retransmits: 1,
	}

	conns := []ConnectionStats{conn1, conn1}
	assert.Equal(t, 1, len(removeDuplicates(conns)))

	// conn1 and conn3 are duplicates
	conns = []ConnectionStats{conn1, conn2, conn3}
	assert.Equal(t, 2, len(removeDuplicates(conns)))

	conns = []ConnectionStats{conn1, conn1, conn1, conn2, conn2, conn2, conn3, conn3, conn3}
	assert.Equal(t, 2, len(removeDuplicates(conns)))
}

func TestTCPSendAndReceive(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(NewDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	assert.Equal(t, 0, int(conn.Retransmits))
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, addrPort(server.address), int(conn.DPort))

	doneChan <- struct{}{}
}

func TestTCPRemoveEntries(t *testing.T) {
	tr, err := NewTracer(&Config{
		CollectTCPConns: true,
		TCPConnTimeout:  100 * time.Millisecond,
	})

	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create a dummy TCP Server
	server := NewTCPServer(func(c net.Conn) {
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Write a message
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write a bunch of messages with blocking iptable rule to create retransmits
	iptablesWrapper(t, func() {
		for i := 0; i < 99; i++ {
			// Send a bunch of messages
			c.Write(genPayload(clientMessageSize))
		}
		time.Sleep(time.Second)
	})

	// Wait a bit for the first connection to be considered as timeouting
	time.Sleep(1 * time.Second)

	// Create a new client
	c2, err := net.DialTimeout("tcp", server.address, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Send a messages
	if _, err = c2.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	// Retrieve the list of connections
	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Make sure the first connection got cleaned up
	_, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	// Assert the TCP map is empty because of the clean up
	key, nextKey, stats := &ConnTuple{}, &ConnTuple{}, &ConnStatsWithTimestamp{}
	tcpMp, err := tr.getMap(tcpStatsMap)
	assert.Nil(t, err)
	// This should return false and an error
	hasNext, err := tr.m.LookupNextElement(tcpMp, unsafe.Pointer(key), unsafe.Pointer(nextKey), unsafe.Pointer(stats))
	assert.False(t, hasNext)
	assert.NotNil(t, err)

	conn, ok := findConnection(c2.LocalAddr(), c2.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.SendBytes))
	assert.Equal(t, 0, int(conn.RecvBytes))
	assert.Equal(t, 0, int(conn.Retransmits))
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, addrPort(server.address), int(conn.DPort))

	doneChan <- struct{}{}
}

func TestTCPRetransmit(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(NewDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	iptablesWrapper(t, func() {
		for i := 0; i < 99; i++ {
			// Send a bunch of messages
			c.Write(genPayload(clientMessageSize))
		}
		time.Sleep(time.Second)
	})

	// Iterate through active connections until we find connection created above, and confirm send + recv counts and there was at least 1 retransmission
	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, 100*clientMessageSize, int(conn.SendBytes))
	assert.True(t, int(conn.Retransmits) > 0)
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, addrPort(server.address), int(conn.DPort))

	doneChan <- struct{}{}
}

func TestTCPShortlived(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(NewDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	// Explicitly close this TCP connection
	c.Close()

	// Wait for the message to be sent from the perf buffer
	time.Sleep(10 * time.Millisecond)

	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we can retrieve the shortlived connection
	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	assert.Equal(t, 0, int(conn.Retransmits))
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, addrPort(server.address), int(conn.DPort))

	// Confirm that the connection has been cleaned up since the last get
	connections, err = tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok = findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
}

func TestTCPOverIPv6(t *testing.T) {
	config := NewDefaultConfig()
	config.CollectIPv6Conns = true

	tr, err := NewTracer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	ln, err := net.Listen("tcp6", net.IPv6loopback.String())
	if err != nil {
		fmt.Println(err)
		return
	}

	doneChan := make(chan struct{})
	go func(done chan struct{}) {
		<-done
		ln.Close()
	}(doneChan)

	// Create TCP Server which sends back serverMessageSize bytes
	go func() {
		for {
			if c, err := ln.Accept(); err != nil {
				return
			} else {
				r := bufio.NewReader(c)
				r.ReadBytes(byte('\n'))
				c.Write(genPayload(serverMessageSize))
				c.Close()
			}
		}
	}()

	// Connect to server
	c, err := net.DialTimeout("tcp6", net.IPv6loopback.String(), 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	assert.Equal(t, 0, int(conn.Retransmits))
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, ln.Addr().(*net.TCPAddr).Port, int(conn.DPort))

	doneChan <- struct{}{}

}

func TestTCPCollectionDisabled(t *testing.T) {
	// Enable BPF-based network tracer with TCP disabled
	config := NewDefaultConfig()
	config.CollectTCPConns = false

	tr, err := NewTracer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create TCP Server which sends back serverMessageSize bytes
	server := NewTCPServer(func(c net.Conn) {
		r := bufio.NewReader(c)
		r.ReadBytes(byte('\n'))
		c.Write(genPayload(serverMessageSize))
		c.Close()
	})
	doneChan := make(chan struct{})
	server.Run(doneChan)

	// Connect to server
	c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	r.ReadBytes(byte('\n'))

	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	// Confirm that we could not find connection created above
	_, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
}

func TestUDPSendAndReceive(t *testing.T) {
	// Enable BPF-based network tracer
	tr, err := NewTracer(NewDefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create UDP Server which sends back serverMessageSize bytes
	server := NewUDPServer(func(b []byte, n int) []byte {
		return genPayload(serverMessageSize)
	})

	doneChan := make(chan struct{})
	server.Run(doneChan, clientMessageSize)

	// Connect to server
	c, err := net.DialTimeout("udp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}

	c.Read(make([]byte, serverMessageSize))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	conn, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.True(t, ok)
	assert.Equal(t, clientMessageSize, int(conn.SendBytes))
	assert.Equal(t, serverMessageSize, int(conn.RecvBytes))
	assert.Equal(t, os.Getpid(), int(conn.Pid))
	assert.Equal(t, addrPort(server.address), int(conn.DPort))

	doneChan <- struct{}{}
}

func TestUDPDisabled(t *testing.T) {
	// Enable BPF-based network tracer with UDP disabled
	config := NewDefaultConfig()
	config.CollectUDPConns = false

	tr, err := NewTracer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	// Create UDP Server which sends back serverMessageSize bytes
	server := NewUDPServer(func(b []byte, n int) []byte {
		return genPayload(serverMessageSize)
	})

	doneChan := make(chan struct{})
	server.Run(doneChan, clientMessageSize)

	// Connect to server
	c, err := net.DialTimeout("udp", server.address, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write clientMessageSize to server, and read response
	if _, err = c.Write(genPayload(clientMessageSize)); err != nil {
		t.Fatal(err)
	}

	c.Read(make([]byte, serverMessageSize))

	// Iterate through active connections until we find connection created above, and confirm send + recv counts
	connections, err := tr.GetActiveConnections()
	if err != nil {
		t.Fatal(err)
	}

	_, ok := findConnection(c.LocalAddr(), c.RemoteAddr(), connections)
	assert.False(t, ok)

	doneChan <- struct{}{}
}

func findConnection(l, r net.Addr, c *Connections) (*ConnectionStats, bool) {
	for _, conn := range c.Conns {
		localAddr := fmt.Sprintf("%s:%d", conn.Source, conn.SPort)
		remoteAddr := fmt.Sprintf("%s:%d", conn.Dest, conn.DPort)
		if localAddr == l.String() && remoteAddr == r.String() {
			return &conn, true
		}
	}
	return nil, false
}

func runBenchtests(b *testing.B, payloads []int, prefix string, f func(p int) func(*testing.B)) {
	for _, p := range payloads {
		name := strings.TrimSpace(strings.Join([]string{prefix, strconv.Itoa(p), "bytes"}, " "))
		b.Run(name, f(p))
	}
}

func BenchmarkUDPEcho(b *testing.B) {
	runBenchtests(b, payloadSizesUDP, "", benchEchoUDP)

	// Enable BPF-based network tracer
	t, err := NewTracer(NewDefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer t.Stop()

	runBenchtests(b, payloadSizesUDP, "eBPF", benchEchoUDP)
}

func benchEchoUDP(size int) func(b *testing.B) {
	payload := genPayload(size)
	echoOnMessage := func(b []byte, n int) []byte {
		resp := make([]byte, len(b))
		copy(resp, b)
		return resp
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := NewUDPServer(echoOnMessage)
		server.Run(end, size)

		c, err := net.DialTimeout("udp", server.address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Write(payload)
			buf := make([]byte, size)
			n, err := r.Read(buf)

			if err != nil || n != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func BenchmarkTCPEcho(b *testing.B) {
	runBenchtests(b, payloadSizesTCP, "", benchEchoTCP)

	// Enable BPF-based network tracer
	t, err := NewTracer(NewDefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer t.Stop()

	runBenchtests(b, payloadSizesTCP, "eBPF", benchEchoTCP)
}

func BenchmarkTCPSend(b *testing.B) {
	runBenchtests(b, payloadSizesTCP, "", benchSendTCP)

	// Enable BPF-based network tracer
	t, err := NewTracer(NewDefaultConfig())
	if err != nil {
		b.Fatal(err)
	}
	defer t.Stop()

	runBenchtests(b, payloadSizesTCP, "eBPF", benchSendTCP)
}

func benchEchoTCP(size int) func(b *testing.B) {
	payload := genPayload(size)
	echoOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for {
			buf, err := r.ReadBytes(byte('\n'))
			if err == io.EOF {
				c.Close()
				return
			}
			c.Write(buf)
		}
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := NewTCPServer(echoOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		r := bufio.NewReader(c)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Write(payload)
			buf, err := r.ReadBytes(byte('\n'))

			if err != nil || len(buf) != len(payload) || !bytes.Equal(payload, buf) {
				b.Fatalf("Sizes: %d, %d. Equal: %v. Error: %s", len(buf), len(payload), bytes.Equal(payload, buf), err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

func benchSendTCP(size int) func(b *testing.B) {
	payload := genPayload(size)
	dropOnMessage := func(c net.Conn) {
		r := bufio.NewReader(c)
		for { // Drop all payloads received
			_, err := r.Discard(r.Buffered() + 1)
			if err == io.EOF {
				c.Close()
				return
			}
		}
	}

	return func(b *testing.B) {
		end := make(chan struct{})
		server := NewTCPServer(dropOnMessage)
		server.Run(end)

		c, err := net.DialTimeout("tcp", server.address, 50*time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ { // Send-heavy workload
			_, err := c.Write(payload)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()

		end <- struct{}{}
	}
}

type TCPServer struct {
	address   string
	onMessage func(c net.Conn)
}

func NewTCPServer(onMessage func(c net.Conn)) *TCPServer {
	return &TCPServer{
		address:   "127.0.0.1:0",
		onMessage: onMessage,
	}
}

func (s *TCPServer) Run(done chan struct{}) {
	ln, err := net.Listen("tcp", s.address)
	if err != nil {
		fmt.Println(err)
		return
	}
	s.address = ln.Addr().String()

	go func() {
		<-done
		ln.Close()
	}()

	go func() {
		for {
			if conn, err := ln.Accept(); err != nil {
				return
			} else {
				s.onMessage(conn)
			}
		}
	}()
}

type UDPServer struct {
	address   string
	onMessage func(b []byte, n int) []byte
}

func NewUDPServer(onMessage func(b []byte, n int) []byte) *UDPServer {
	return &UDPServer{
		address:   "127.0.0.1:0",
		onMessage: onMessage,
	}
}

func (s *UDPServer) Run(done chan struct{}, payloadSize int) {
	ln, err := net.ListenPacket("udp", s.address)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s.address = ln.LocalAddr().String()

	go func() {
		buf := make([]byte, payloadSize)
		for {
			select {
			case <-done:
				break
			default:
				ln.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				n, addr, err := ln.ReadFrom(buf)
				if err != nil {
					break
				}
				_, err = ln.WriteTo(s.onMessage(buf, n), addr)
				if err != nil {
					fmt.Println(err)
					break
				}
			}
		}

		ln.Close()
	}()
}

var letterBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func genPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if i == n-1 {
			b[i] = '\n'
		} else {
			b[i] = letterBytes[rand.Intn(len(letterBytes))]
		}
	}
	return b
}

func iptablesWrapper(t *testing.T, f func()) {
	iptables, err := exec.LookPath("iptables")
	assert.Nil(t, err)

	// Init iptables rule to simulate packet loss
	rule := "INPUT --source 127.0.0.1 -j DROP"
	create := strings.Fields(fmt.Sprintf("-A %s", rule))
	remove := strings.Fields(fmt.Sprintf("-D %s", rule))

	createCmd := exec.Command(iptables, create...)
	err = createCmd.Start()
	assert.Nil(t, err)
	err = createCmd.Wait()
	assert.Nil(t, err)

	f()

	// Remove the iptable rule
	removeCmd := exec.Command(iptables, remove...)
	err = removeCmd.Start()
	assert.Nil(t, err)
	err = removeCmd.Wait()
	assert.Nil(t, err)
}

func addrPort(addr string) int {
	p, _ := strconv.Atoi(strings.Split(addr, ":")[1])
	return p
}
