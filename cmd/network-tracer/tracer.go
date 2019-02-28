package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/cihub/seelog"
	"github.com/mailru/easyjson"

	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/datadog-process-agent/ebpf"
	"github.com/DataDog/datadog-process-agent/net"
)

// ErrTracerUnsupported is the unsupported error prefix, for error-class matching from callers
var ErrTracerUnsupported = errors.New("tracer unsupported")

// NetworkTracer maintains and starts the underlying network connection collection process as well as
// exposes these connections over HTTP (via UDS)
type NetworkTracer struct {
	cfg *config.AgentConfig

	supported bool
	tracer    *ebpf.Tracer
	conn      net.Conn
}

// CreateNetworkTracer creates a NetworkTracer as well as it's UDS socket after confirming that the OS supports BPF-based
// network tracing
func CreateNetworkTracer(cfg *config.AgentConfig) (*NetworkTracer, error) {
	var err error
	nt := &NetworkTracer{}

	// Checking whether the current OS + kernel version is supported by the tracer
	if nt.supported, err = ebpf.IsTracerSupportedByOS(); err != nil {
		return nil, fmt.Errorf("%s: %s", ErrTracerUnsupported, err)
	}

	log.Infof("Creating tracer for: %s", filepath.Base(os.Args[0]))

	t, err := ebpf.NewTracer(config.TracerConfigFromConfig(cfg))
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

// Run makes available the HTTP endpoint for network collection
func (nt *NetworkTracer) Run() {
	http.HandleFunc("/status", func(w http.ResponseWriter, req *http.Request) {})

	http.HandleFunc("/connections", func(w http.ResponseWriter, req *http.Request) {
		// We require to send a client_id to the network state
		var clientID string
		if rawCID := req.URL.Query().Get("client_id"); rawCID != "" {
			clientID = rawCID
		} else { // This is the default client ID
			clientID = ebpf.DEBUGCLIENT
		}

		cs, err := nt.tracer.GetActiveConnections(clientID)
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

		w.Write(buf)
		log.Tracef("/connections: %d connections, %d bytes", len(cs.Conns), len(buf))
	})

	http.HandleFunc("/debug/stats", func(w http.ResponseWriter, req *http.Request) {
		stats, err := nt.tracer.GetStats()
		if err != nil {
			log.Errorf("unable to retrieve tracer stats: %s", err)
			w.WriteHeader(500)
			return
		}

		buf, err := json.Marshal(stats)
		if err != nil {
			log.Errorf("unable to marshal stats into JSON: %s", err)
			w.WriteHeader(500)
			return
		}

		w.Write(buf)
	})

	http.Serve(nt.conn.GetListener(), nil)
}

// Close will stop all network tracing activities
func (nt *NetworkTracer) Close() {
	nt.conn.Stop()
	nt.tracer.Stop()
}
