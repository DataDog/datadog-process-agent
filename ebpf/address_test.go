package ebpf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetIPToAddress(t *testing.T) {
	// V4
	addr := V4Address(889192575)
	addrFromIP := NetIPToAddress(net.ParseIP("127.0.0.1"))

	_, ok := addrFromIP.(v4Address)
	assert.True(t, ok)
	assert.Equal(t, addrFromIP, addr)

	// V6
	addr = V6Address(889192575, 0)
	addrFromIP = NetIPToAddress(net.ParseIP("::7f00:35:0:0"))

	_, ok = addrFromIP.(v6Address)
	assert.True(t, ok)
	assert.Equal(t, addrFromIP, addr)

	// Mismatch tests
	a := NetIPToAddress(net.ParseIP("127.0.0.1"))
	b := NetIPToAddress(net.ParseIP("::7f00:35:0:0"))
	assert.NotEqual(t, a, b)

	a = NetIPToAddress(net.ParseIP("127.0.0.1"))
	b = NetIPToAddress(net.ParseIP("127.0.0.2"))
	assert.NotEqual(t, a, b)

	a = NetIPToAddress(net.ParseIP("::7f00:35:0:1"))
	b = NetIPToAddress(net.ParseIP("::7f00:35:0:0"))
	assert.NotEqual(t, a, b)
}

func TestAddressUsageInMaps(t *testing.T) {
	addrMap := make(map[Address]struct{})

	addrMap[V4Address(889192575)] = struct{}{}
	addrMap[V6Address(889192575, 0)] = struct{}{}

	_, ok := addrMap[V4AddressFromString("127.0.0.1")]
	assert.True(t, ok)

	_, ok = addrMap[V4AddressFromString("127.0.0.1")]
	assert.False(t, ok)

	_, ok = addrMap[V6AddressFromString("::7f00:35:0:0")]
	assert.True(t, ok)

	_, ok = addrMap[V6AddressFromString("::")]
	assert.False(t, ok)
}

func TestAddressV4(t *testing.T) {
	addr := V4Address(889192575)

	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V4AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V4AddressFromString("127.0.0.53"))
	assert.Equal(t, "127.0.0.53", addr.String())

	addr = V4Address(0)
	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V4AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V4AddressFromString("0.0.0.0"))
	assert.Equal(t, "0.0.0.0", addr.String())

	addr = V4Address(16820416)
	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V4AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V4AddressFromString("192.168.0.1"))
	assert.Equal(t, "192.168.0.1", addr.String())
}

func TestAddressV6(t *testing.T) {
	addr := V6Address(889192575, 0)
	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V6AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V6AddressFromString("::7f00:35:0:0"))
	assert.Equal(t, "::7f00:35:0:0", addr.String())

	addr = V6Address(0, 0)
	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V6AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V6AddressFromString("::"))
	assert.Equal(t, "::", addr.String())

	addr = V6Address(72057594037927936, 0)
	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V6AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V6AddressFromString("::1"))
	assert.Equal(t, "::1", addr.String())

	addr = V6Address(72059793061183488, 3087860000)
	// Should be able to recreate addr from bytes alone
	assert.Equal(t, addr, V6AddressFromBytes(addr.Bytes()))
	// Should be able to recreate addr from IP string
	assert.Equal(t, addr, V6AddressFromString("2001:db8::2:1"))
	assert.Equal(t, "2001:db8::2:1", addr.String())
}
