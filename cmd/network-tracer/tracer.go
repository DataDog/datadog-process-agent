package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/cihub/seelog"
	"github.com/mailru/easyjson"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/net"
	"github.com/DataDog/datadog-process-agent/util"
	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

// ErrTracerUnsupported is the unsupported error prefix, for error-class matching from callers
var ErrTracerUnsupported = errors.New("tracer unsupported")

// NetworkTracer maintains and starts the underlying network connection collection process as well as
// exposes these connections over HTTP (via UDS)
type NetworkTracer struct {
	cfg *config.AgentConfig

	supported bool
	tracer    *tracer.Tracer
	conn      net.Conn
}

// CreateNetworkTracer creates a NetworkTracer as well as it's UDS socket after confirming that the OS supports BPF-based
// network tracing
func CreateNetworkTracer(cfg *config.AgentConfig) (*NetworkTracer, error) {
	var err error
	nt := &NetworkTracer{}

	// Checking whether the current OS + kernel version is supported by the tracer
	if nt.supported, err = tracer.IsTracerSupportedByOS(); err != nil {
		return nil, fmt.Errorf("%s: %s", ErrTracerUnsupported, err)
	}

	log.Infof("Creating tracer for: %s", filepath.Base(os.Args[0]))
	t, err := tracer.NewTracer(tracer.DefaultConfig)
	if err != nil {
		return nil, err
	}

	// Setting up the unix socket
	uds, err := net.NewUDSListener(cfg)
	if err != nil {
		return nil, err
	}

	nt.tracer = t
	nt.cfg = cfg
	nt.conn = uds
	return nt, nil
}

// Run starts the network tracer annd makes available the HTTP endpoint for network collection
func (nt *NetworkTracer) Run() {
	nt.tracer.Start()

	http.HandleFunc("/status", func(w http.ResponseWriter, req *http.Request) {})

	http.HandleFunc("/connections", func(w http.ResponseWriter, req *http.Request) {
		cs, err := nt.tracer.GetActiveConnections()

		if err != nil {
			log.Errorf("unable to retrieve connections: %s", err)
			w.WriteHeader(500)
			return
		}

		buf, err := easyjson.Marshal(cs)
		if err != nil {
			log.Errorf("unable to marshall connections into JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		filterDeadConnections(cs)
		w.Write(buf)
		log.Debugf("/connections: %d connections, %d bytes", len(cs.Conns), len(buf))
	})

	http.Serve(nt.conn.GetListener(), nil)
}

// Close will stop all network tracing activities
func (nt *NetworkTracer) Close() {
	nt.conn.Stop()
	nt.tracer.Stop()
}

// occasionally the eBPF module will miss tcp_close calls and leave TCP
// connections in an open state. This method filters out TCP connections
// associated with processes that aren't alive
func filterDeadConnections(conns *tracer.Connections) {
	if conns == nil {
		return
	}

	var filteredConnections []tracer.ConnectionStats

	deadProcs := 0
	for _, conn := range conns.Conns {
		if conn.Type == tracer.TCP && isDeadPID(conn.Pid) {
			deadProcs++
		} else {
			filteredConnections = append(filteredConnections, conn)
		}
	}
	log.Infof("there were %d dead connections in connection capture")

	conns.Conns = filteredConnections
}

func isDeadPID(PID uint32) bool {
	path := util.HostProc(string(PID))
	if _, err := os.Stat(path); err != nil {
		return true
	}
	return false
}
