package ebpf

import (
	"bufio"
	"bytes"
	log "github.com/cihub/seelog"
	"io"
	"net"
	"os"
	"strconv"
)

const tcpListen = 10

// readProcNet reads a /proc/net/ file and returns a map of port->address for all listening addresses
func readProcNet(path string) (map[uint16]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	reader := bufio.NewReader(f)

	var addrBuf [16]byte

	ports := make(map[uint16]string)

	// Skip header line
	_, _ = reader.ReadBytes('\n')

	for {
		var rawLocal, rawState []byte

		b, err := reader.ReadBytes('\n')

		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		} else {
			iter := &fieldIterator{data: b}
			iter.nextField() // entry number

			rawLocal = iter.nextField() // local_address

			iter.nextField() // remote_address

			rawState = iter.nextField() // st

			state, err := strconv.ParseInt(string(rawState), 16, 0)
			if err != nil {
				log.Errorf("error parsing tcp state [%s] as hex: %s", rawState, err)
				continue
			}

			if state != tcpListen {
				continue
			}

			idx := bytes.IndexByte(rawLocal, ':')
			if idx == -1 {
				continue
			}

			address := decodeAddress(rawLocal[:idx], &addrBuf)

			port, err := strconv.ParseInt(string(rawLocal[idx+1:]), 16, 0)
			if err != nil {
				log.Errorf("error parsing port [%s] as hex: %s", rawLocal[idx+1:], err)
				continue
			}

			ports[uint16(port)] = address
		}
	}

	return ports, nil
}

// decodeAddress decodes sequences of 32bit big endian bytes. The address is a big endian 32 bit ints, hex encoded
// so we just decode the hex and flip the bytes in every group of 4.
// adapted from weaveworks/scope/probe/endpoint/procspy/procnet.go
func decodeAddress(src []byte, buf *[16]byte) string {
	blocks := len(src) / 8
	for block := 0; block < blocks; block++ {
		for i := 0; i < 4; i++ {
			a := fromHexChar(src[block*8+i*2])
			b := fromHexChar(src[block*8+i*2+1])
			buf[block*4+3-i] = (a << 4) | b
		}
	}
	return net.IP(buf[:blocks*4]).String()
}

// fromHexChar converts a hex character into its value.
// from weaveworks/scope/probe/endpoint/procspy/procnet.go
func fromHexChar(c byte) uint8 {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

type fieldIterator struct {
	data []byte
}

func (iter *fieldIterator) nextField() []byte {
	// Skip any leading whitespace
	for i, b := range iter.data {
		if b != ' ' {
			iter.data = iter.data[i:]
			break
		}
	}

	// Read field up until the first whitespace char
	var result []byte
	for i, b := range iter.data {
		if b == ' ' {
			result = iter.data[:i]
			iter.data = iter.data[i:]
			break
		}
	}

	return result
}
