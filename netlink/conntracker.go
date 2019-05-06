// +build linux

package netlink

import (
	"bytes"
	"context"
	golog "log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"

	ct "github.com/florianl/go-conntrack"
)

// Conntracker is a wrapper around go-conntracker that keeps a record of all connections in user space
type Conntracker interface {
	GetConntrackEntryForConn(ip string, port uint16) *IPTranslation
	Close()
}

type connKey struct {
	ip   string
	port uint16
}

type realConntracker struct {
	nfct  *ct.Nfct
	l     *sync.Mutex
	state map[connKey]*IPTranslation

	statsTicker   *time.Ticker
	compactTicker *time.Ticker
	stats         struct {
		gets               int64
		getTimeTotal       int64
		registers          int64
		registersTotalTime int64
	}
}

func NewConntracker() (Conntracker, error) {
	nfct, err := ct.Open(&ct.Config{ReadTimeout: 10 * time.Millisecond, Logger: golog.New(os.Stdout, "go-conntrack", 0)})
	if err != nil {
		return nil, err
	}

	ctr := &realConntracker{
		nfct:          nfct,
		l:             &sync.Mutex{},
		statsTicker:   time.NewTicker(time.Second * 10),
		compactTicker: time.NewTicker(time.Hour),
		state:         make(map[connKey]*IPTranslation),
	}

	// seed the state
	sessions, err := nfct.Dump(ct.Ct, ct.CtIPv4)
	if err != nil {
		return nil, err
	}
	ctr.registerUnlocked(sessions)

	sessions, err = nfct.Dump(ct.Ct, ct.CtIPv6)
	if err != nil {
		// this is not fatal because we've already seeded with IPv4
		log.Errorf("Failed to dump IPv6")
	}
	ctr.registerUnlocked(sessions)

	go ctr.emitStats()
	go ctr.compact()

	nfct.Register(context.Background(), ct.Ct, ct.NetlinkCtNew|ct.NetlinkCtExpectedNew|ct.NetlinkCtUpdate, ctr.register)
	nfct.Register(context.Background(), ct.Ct, ct.NetlinkCtDestroy, ctr.unregister)

	log.Infof("initialized conntrack")

	return ctr, nil
}

func (ctr *realConntracker) GetConntrackEntryForConn(ip string, port uint16) *IPTranslation {
	then := time.Now().UnixNano()

	ctr.l.Lock()
	defer ctr.l.Unlock()

	result := ctr.state[connKey{ip, port}]

	now := time.Now().UnixNano()
	atomic.AddInt64(&ctr.stats.gets, 1)
	atomic.AddInt64(&ctr.stats.getTimeTotal, now-then)
	return result
}

func (ctr *realConntracker) Close() {
	ctr.statsTicker.Stop()
	ctr.compactTicker.Stop()
	ctr.nfct.Close()
}

func (ctr *realConntracker) registerUnlocked(sessions []ct.Conn) {
	for _, c := range sessions {
		if isNAT(c) {
			ctr.state[formatKey(c)] = formatIPTranslation(c)
		}
	}
}

func (ctr *realConntracker) register(c ct.Conn) int {
	// don't both storing if the connection is not NAT
	if !isNAT(c) {
		return 0
	}

	now := time.Now().UnixNano()
	ctr.l.Lock()
	defer ctr.l.Unlock()

	ctr.state[formatKey(c)] = formatIPTranslation(c)

	then := time.Now().UnixNano()
	atomic.AddInt64(&ctr.stats.registers, 1)
	atomic.AddInt64(&ctr.stats.registersTotalTime, then-now)

	return 0
}

func (ctr *realConntracker) unregister(c ct.Conn) int {
	if !isNAT(c) {
		return 0
	}

	ctr.l.Lock()
	defer ctr.l.Unlock()

	delete(ctr.state, formatKey(c))

	return 0
}

func (ctr *realConntracker) compact() {
	for range ctr.compactTicker.C {

		ctr.l.Lock()

		copied := make(map[connKey]*IPTranslation, len(ctr.state))
		for k, v := range ctr.state {
			copied[k] = v
		}
		ctr.state = copied

		ctr.l.Unlock()

	}
}

func (ctr *realConntracker) emitStats() {
	for range ctr.statsTicker.C {

		ctr.l.Lock()
		size := len(ctr.state)
		ctr.l.Unlock()

		log.Debugf("state size %d", size)
		if ctr.stats.gets != 0 {
			log.Debugf("total gets: %d, ns/get: %f", ctr.stats.gets, float64(ctr.stats.getTimeTotal)/float64(ctr.stats.gets))
		}
		if ctr.stats.registers != 0 {
			log.Debugf("total registers: %d, ns/register: %f", ctr.stats.registers, float64(ctr.stats.registersTotalTime)/float64(ctr.stats.registers))
		}
		atomic.StoreInt64(&ctr.stats.gets, 0)
		atomic.StoreInt64(&ctr.stats.getTimeTotal, 0)
		atomic.StoreInt64(&ctr.stats.registers, 0)
		atomic.StoreInt64(&ctr.stats.registersTotalTime, 0)
	}
}

func isNAT(c ct.Conn) bool {
	originSrcIPv4 := c[ct.AttrOrigIPv4Src]
	originDstIPv4 := c[ct.AttrOrigIPv4Dst]
	replSrcIPv4 := c[ct.AttrReplIPv4Src]
	replDstIPv4 := c[ct.AttrReplIPv4Dst]

	originSrcIPv6 := c[ct.AttrOrigIPv6Src]
	originDstIPv6 := c[ct.AttrOrigIPv6Dst]
	replSrcIPv6 := c[ct.AttrReplIPv6Src]
	replDstIPv6 := c[ct.AttrReplIPv6Dst]

	originSrcPort, _ := c.Uint16(ct.AttrOrigPortSrc)
	originDstPort, _ := c.Uint16(ct.AttrOrigPortDst)
	replSrcPort, _ := c.Uint16(ct.AttrReplPortSrc)
	replDstPort, _ := c.Uint16(ct.AttrReplPortDst)

	nat := !bytes.Equal(originSrcIPv4, replDstIPv4) ||
		!bytes.Equal(originSrcIPv6, replDstIPv6) ||
		!bytes.Equal(originDstIPv4, replSrcIPv4) ||
		!bytes.Equal(originDstIPv6, replSrcIPv6) ||
		originSrcPort != replDstPort ||
		originDstPort != replSrcPort

	return nat
}

func ReplSrcIP(c ct.Conn) net.IP {
	ipv4, ok := c[ct.AttrReplIPv4Src]
	if ok {
		return net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
	}

	ipv6, ok := c[ct.AttrReplIPv6Src]
	if ok {
		return net.IP(ipv6)
	}

	return nil
}

func ReplDstIP(c ct.Conn) net.IP {
	ipv4, ok := c[ct.AttrReplIPv4Dst]
	if ok {
		return net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
	}

	ipv6, ok := c[ct.AttrReplIPv6Dst]
	if ok {
		return net.IP(ipv6)
	}

	return nil
}

func formatIPTranslation(c ct.Conn) *IPTranslation {
	replSrcIP := ReplSrcIP(c)
	replDstIP := ReplDstIP(c)

	replSrcPort, err := c.Uint16(ct.AttrReplPortSrc)
	if err != nil {
		return nil
	}

	replDstPort, err := c.Uint16(ct.AttrReplPortDst)
	if err != nil {
		return nil
	}

	return &IPTranslation{
		ReplSrcIP:   replSrcIP.String(),
		ReplDstIP:   replDstIP.String(),
		ReplSrcPort: NtohsU16(replSrcPort),
		ReplDstPort: NtohsU16(replDstPort),
	}
}

func formatKey(c ct.Conn) (k connKey) {
	if ip, err := c.OrigSrcIP(); err == nil {
		k.ip = ip.String()
	}
	if port, err := c.Uint16(ct.AttrOrigPortSrc); err == nil {
		k.port = NtohsU16(port)
	}
	return
}
