package ebpf

import (
	"encoding/binary"
	"net"

	"github.com/mailru/easyjson/jwriter"
)

type Address interface {
	Bytes() []byte
	String() string
	MarshalEasyJSON(w *jwriter.Writer)
}

type v4Address [4]byte

func V4Address(ip uint32) Address {
	var a v4Address
	a[0] = byte(ip)
	a[1] = byte(ip >> 8)
	a[2] = byte(ip >> 16)
	a[3] = byte(ip >> 24)
	return a
}

func V4AddressFromBytes(buf []byte) Address {
	var a v4Address
	copy(a[:], buf)
	return a
}

func (a v4Address) Bytes() []byte {
	return a[:]
}

func (a v4Address) String() string {
	return net.IPv4(a[0], a[1], a[2], a[3]).String()
}

func (a v4Address) MarshalEasyJSON(w *jwriter.Writer) {
	w.String(a.String())
}

type v6Address [16]byte

func V6Address(low, high uint64) Address {
	var a v6Address
	binary.LittleEndian.PutUint64(a[:8], high)
	binary.LittleEndian.PutUint64(a[8:], low)
	return a
}

func V6AddressFromBytes(buf []byte) Address {
	var a v6Address
	copy(a[:], buf)
	return a
}

func (a v6Address) Bytes() []byte {
	return a[:]
}

func (a v6Address) String() string {
	return net.IP(a[:]).String()
}

func (a v6Address) MarshalEasyJSON(w *jwriter.Writer) {
	w.String(a.String())
}
