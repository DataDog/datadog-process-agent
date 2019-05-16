package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testConn = ConnectionStats{
		Pid:                123,
		Type:               1,
		Family:             0,
		Source:             V4AddressFromString("192.168.0.1"),
		Dest:               V4AddressFromString("192.168.0.103"),
		SPort:              123,
		DPort:              35000,
		MonotonicSentBytes: 123123,
		MonotonicRecvBytes: 312312,
	}
)

func TestBeautifyKey(t *testing.T) {
	buf := &bytes.Buffer{}
	for _, c := range []ConnectionStats{
		testConn,
		{
			Pid:    345,
			Type:   0,
			Family: 1,
			Source: V4AddressFromString("127.0.0.1"),
			Dest:   V4AddressFromString("192.168.0.103"),
			SPort:  4444,
			DPort:  8888,
		},
	} {
		bk, err := c.ByteKey(buf)
		require.NoError(t, err)
		expected := fmt.Sprintf(keyFmt, c.Pid, c.SourceAddr().String(), c.SPort, c.DestAddr().String(), c.DPort, c.Family, c.Type)
		assert.Equal(t, expected, BeautifyKey(string(bk)))
	}
}

var sink string

func BenchmarkUniqueConnKeyString(b *testing.B) {
	c := testConn
	for n := 0; n < b.N; n++ {
		sink = fmt.Sprintf("%d-%d-%d-%s-%d-%s-%d", c.Pid, c.Type, c.Family, c.Source, c.SPort, c.Dest, c.DPort)
	}
	sink += ""
}

func BenchmarkUniqueConnKeyByteBuffer(b *testing.B) {
	c := testConn
	buf := new(bytes.Buffer)
	for n := 0; n < b.N; n++ {
		buf.Reset()
		buf.WriteString(c.SourceAddr().String())
		buf.WriteString(c.DestAddr().String())
		binary.Write(buf, binary.LittleEndian, c.Pid)
		binary.Write(buf, binary.LittleEndian, c.Type)
		binary.Write(buf, binary.LittleEndian, c.Family)
		binary.Write(buf, binary.LittleEndian, c.SPort)
		binary.Write(buf, binary.LittleEndian, c.DPort)
		buf.Bytes()
	}
}

func BenchmarkUniqueConnKeyByteBufferPacked(b *testing.B) {
	c := testConn
	buf := new(bytes.Buffer)
	for n := 0; n < b.N; n++ {
		buf.Reset()
		// PID (32 bits) + SPort (16 bits) + DPort (16 bits) = 64 bits
		p0 := uint64(c.Pid)<<32 | uint64(c.SPort)<<16 | uint64(c.DPort)
		binary.Write(buf, binary.LittleEndian, p0)
		buf.WriteString(c.SourceAddr().String())
		// Family (8 bits) + Type (8 bits) = 16 bits
		p1 := uint16(c.Family)<<8 | uint16(c.Type)
		binary.Write(buf, binary.LittleEndian, p1)
		buf.WriteString(c.DestAddr().String())
		buf.Bytes()
	}
}

func TestConnStatsByteKey(t *testing.T) {
	buf := new(bytes.Buffer)
	addrA := V4AddressFromString("127.0.0.1")
	addrB := V4AddressFromString("127.0.0.2")

	for _, test := range []struct {
		a ConnectionStats
		b ConnectionStats
	}{
		{ // Port is different
			a: ConnectionStats{Source: addrA, Dest: addrB, Pid: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Family is different
			a: ConnectionStats{Source: addrA, Dest: addrB, Family: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Type is different
			a: ConnectionStats{Source: addrA, Dest: addrB, Type: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Source is different
			a: ConnectionStats{Source: V4AddressFromString("123.255.123.0"), Dest: addrB},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Dest is different
			a: ConnectionStats{Source: addrA, Dest: V4AddressFromString("129.0.1.2")},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Source port is different
			a: ConnectionStats{Source: addrA, Dest: addrB, SPort: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Dest port is different
			a: ConnectionStats{Source: addrA, Dest: addrB, DPort: 1},
			b: ConnectionStats{Source: addrA, Dest: addrB},
		},
		{ // Fields set, but sources are different
			a: ConnectionStats{Pid: 1, Family: 0, Type: 1, Source: addrA, Dest: addrB},
			b: ConnectionStats{Pid: 1, Family: 0, Type: 1, Source: addrB, Dest: addrB},
		},
		{ // Both sources and dest are different
			a: ConnectionStats{Pid: 1, Dest: addrB, Family: 0, Type: 1, Source: addrA},
			b: ConnectionStats{Pid: 1, Dest: addrA, Family: 0, Type: 1, Source: addrB},
		},
		{ // Family and Type are different
			a: ConnectionStats{Pid: 1, Source: addrA, Dest: addrB, Family: 1},
			b: ConnectionStats{Pid: 1, Source: addrA, Dest: addrB, Type: 1},
		},
	} {
		var keyA, keyB string
		if b, err := test.a.ByteKey(buf); assert.NoError(t, err) {
			keyA = string(b)
		}
		if b, err := test.b.ByteKey(buf); assert.NoError(t, err) {
			keyB = string(b)
		}
		assert.NotEqual(t, keyA, keyB)
	}
}
