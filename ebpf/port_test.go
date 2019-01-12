package ebpf

import (
	"github.com/stretchr/testify/require"
	"net"
	"net/url"
	"strconv"
	"testing"
)

func TestReadInitialState(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	l6, err := net.Listen("tcp6", ":0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	tcpAddr, tcpPort := getAddress(t, l)
	tcp6Addr, tcp6Port := getAddress(t, l6)

	ports := NewPortMapping("/proc", NewDefaultConfig())

	err = ports.ReadInitialState()
	require.NoError(t, err)

	require.True(t, ports.IsListening(tcpPort, tcpAddr))
	require.True(t, ports.IsListening(tcp6Port, tcp6Addr))

	require.False(t, ports.IsListening(999, tcpAddr))
}

func TestAddRemove(t *testing.T) {
	ports := NewPortMapping("/proc", NewDefaultConfig())

	require.False(t, ports.IsListening(123, "0.0.0.0"))

	ports.AddMapping(123, "0.0.0.0")

	require.True(t, ports.IsListening(123, "0.0.0.0"))

	ports.RemoveMapping(123)

	require.False(t, ports.IsListening(123, "0.0.0.0"))
}

func getAddress(t *testing.T, listener net.Listener) (string, uint16) {
	addr := listener.Addr()
	listenerURL := url.URL{Scheme: addr.Network(), Host: addr.String()}
	port, err := strconv.Atoi(listenerURL.Port())
	require.NoError(t, err)
	return listenerURL.Hostname(), uint16(port)
}
