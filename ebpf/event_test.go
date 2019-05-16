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
		Source:             V4Address(231201201),
		Dest:               V6Address(123123123, 987654321),
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
			Source: V4Address(889192575),
			Dest:   V4Address(123192319),
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
	for _, test := range []struct {
		a ConnectionStats
		b ConnectionStats
	}{
		{
			a: ConnectionStats{Pid: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Family: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Type: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Source: "hello"},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Dest: "goodbye"},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{SPort: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{DPort: 1},
			b: ConnectionStats{},
		},
		{
			a: ConnectionStats{Pid: 1, Family: 0, Type: 1, Source: "a"},
			b: ConnectionStats{Pid: 1, Family: 0, Type: 1, Source: "b"},
		},
		{
			a: ConnectionStats{Pid: 1, Dest: "b", Family: 0, Type: 1, Source: "a"},
			b: ConnectionStats{Pid: 1, Dest: "a", Family: 0, Type: 1, Source: "b"},
		},
		{
			a: ConnectionStats{Pid: 1, Dest: "", Family: 0, Type: 1, Source: "a"},
			b: ConnectionStats{Pid: 1, Dest: "a", Family: 0, Type: 1, Source: ""},
		},
		{
			a: ConnectionStats{Pid: 1, Dest: "b", Family: 0, Type: 1},
			b: ConnectionStats{Pid: 1, Family: 0, Type: 1, Source: "b"},
		},
		{
			a: ConnectionStats{Pid: 1, Dest: "b", Family: 1},
			b: ConnectionStats{Pid: 1, Dest: "b", Type: 1},
		},
		{
			a: ConnectionStats{Pid: 1, Dest: "b", Type: 0, SPort: 3},
			b: ConnectionStats{Pid: 1, Dest: "b", Type: 0, DPort: 3},
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
