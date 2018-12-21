package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	log "github.com/cihub/seelog"
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

	// Source & Dest represented as a string to handle both IPv4 & IPv6
	Source string `json:"source"`
	Dest   string `json:"dest"`
	SPort  uint16 `json:"sport"`
	DPort  uint16 `json:"dport"`

	SendBytes uint64 `json:"send_bytes"`
	RecvBytes uint64 `json:"recv_bytes"`

	Retransmits uint32 `json:"retransmits"`

	// collected is used internally to know if this connection stats has been collected or not
	collected bool
}

func (c ConnectionStats) String() string {
	return fmt.Sprintf("[%s] [PID: %d] [%v:%d ⇄ %v:%d] %d bytes sent, %d bytes received, %d retransmits",
		c.Type, c.Pid, c.Source, c.SPort, c.Dest, c.DPort, c.SendBytes, c.RecvBytes, c.Retransmits)
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
	// Family (8 bits) + Type (8 bits) = 16 bits
	p1 := uint16(c.Family)<<8 | uint16(c.Type)
	if err := binary.Write(buffer, binary.LittleEndian, p1); err != nil {
		return nil, err
	}
	if _, err := buffer.WriteString(c.Dest); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func removeDuplicates(conns []ConnectionStats) []ConnectionStats {
	connections := make([]ConnectionStats, 0, len(conns))
	seen := map[string]struct{}{}
	buf := &bytes.Buffer{}
	for _, c := range conns {
		key, err := c.ByteKey(buf)
		if err != nil {
			// Skip the connection
			log.Errorf("could not get byte key for connection %v: %s", c, err)
			continue
		}

		// If it's the first time we see this connection add it
		if _, ok := seen[string(key)]; !ok {
			connections = append(connections, c)
			seen[string(key)] = struct{}{}
		}
	}

	return connections
}
