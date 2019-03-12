package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ConnectionType will be either TCP or UDP
type ConnectionType uint8

const (
	// TCP connection type
	TCP ConnectionType = 0

	// UDP connection type
	UDP ConnectionType = 1
)

func (c ConnectionType) String() string {
	if c == TCP {
		return "TCP"
	}
	return "UDP"
}

// ConnectionFamily will be either v4 or v6
type ConnectionFamily uint8

// ConnectionDirection indicates if the connection is incoming to the host or outbound
type ConnectionDirection uint8

const (
	// INCOMING represents connections inbound to the host
	INCOMING ConnectionDirection = 0

	// OUTGOING represents outbound connections from the host
	OUTGOING ConnectionDirection = 1

	// LOCAL represents connections that don't leave the host
	LOCAL ConnectionDirection = 2
)

func (d ConnectionDirection) String() string {
	switch d {
	case OUTGOING:
		return "outgoing"
	case LOCAL:
		return "local"
	default:
		return "incoming"
	}
}

const (
	// AFINET represents v4 connections
	AFINET ConnectionFamily = 0

	// AFINET6 represents v6 connections
	AFINET6 ConnectionFamily = 1
)

// Connections wraps a collection of ConnectionStats
//easyjson:json
type Connections struct {
	Conns []ConnectionStats `json:"connections"`
}

// ConnectionStats stores statistics for a single connection
//easyjson:json
type ConnectionStats struct {
	Pid    uint32           `json:"pid"`
	Type   ConnectionType   `json:"type"`
	Family ConnectionFamily `json:"family"`
	NetNS  uint32           `json:"net_ns"`

	// Source & Dest represented as a string to handle both IPv4 & IPv6
	Source string `json:"source"`
	Dest   string `json:"dest"`
	SPort  uint16 `json:"sport"`
	DPort  uint16 `json:"dport"`

	Direction ConnectionDirection `json:"direction"`

	MonotonicSentBytes uint64 `json:"monotonic_sent_bytes"`
	LastSentBytes      uint64 `json:"last_sent_bytes"`

	MonotonicRecvBytes uint64 `json:"monotonic_recv_bytes"`
	LastRecvBytes      uint64 `json:"last_recv_bytes"`

	MonotonicRetransmits uint32 `json:"monotonic_retransmits"`
	LastRetransmits      uint32 `json:"last_retransmits"`

	// Last time the stats for this connection were updated
	LastUpdateEpoch uint64 `json:"last_update_epoch"`

	// If this connection is the aggregation of multiple connections, this will be > 0
	RollUpCount uint16 `json:"rollup_count"`
}

func (c ConnectionStats) String() string {
	return fmt.Sprintf(
		"[%s, PID:%d] [%v:%d ⇄ %v:%d] (%s) %dB sent (+%d), %dB received (+%d), %d retransmits (+%d), rollup: %d",
		c.Type,
		c.Pid,
		c.Source,
		c.SPort,
		c.Dest,
		c.DPort,
		c.Direction,
		c.MonotonicSentBytes, c.LastSentBytes,
		c.MonotonicRecvBytes, c.LastRecvBytes,
		c.MonotonicRetransmits, c.LastRetransmits,
		c.RollUpCount,
	)
}

// ByteKey returns a unique key for this connection represented as a byte array
func (c ConnectionStats) ByteKey(buffer *bytes.Buffer) ([]byte, error) {
	buffer.Reset()
	// Byte-packing to improve creation speed
	// PID (32 bits) + SPort (16 bits) + DPort (16 bits) = 64 bits
	p0 := uint64(c.Pid)<<32 | uint64(c.SPort)<<16 | uint64(c.DPort)
	if err := binary.Write(buffer, binary.LittleEndian, p0); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Source); err != nil {
		return nil, err
	}
	// Family (4 bits) + Type (4 bits) = 8 bits
	p1 := uint8(c.Family)<<4 | uint8(c.Type)
	if err := binary.Write(buffer, binary.LittleEndian, p1); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Dest); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func applyFuncOnRange(cs []ConnectionStats, isSame func(a, b *ConnectionStats) bool, f func([]ConnectionStats)) {
	curr := make([]ConnectionStats, 0)

	for i, c := range cs {
		if isSame(&cs[max(i-1, 0)], &c) {
			curr = append(curr, c)
		} else {
			f(curr)
			curr = []ConnectionStats{c}
		}
	}

	if len(curr) > 0 {
		f(curr)
	}
}
