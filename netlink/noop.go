// +build linux

package netlink

type noOpConntracker struct{}

func NewNoOpConntracker() Conntracker {
	return &noOpConntracker{}
}

func (*noOpConntracker) GetConntrackEntryForConn(ip string, port uint16) *IPTranslation {
	return nil
}

func (*noOpConntracker) Close() {}
