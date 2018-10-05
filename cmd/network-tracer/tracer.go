package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	log "github.com/cihub/seelog"
	"github.com/mailru/easyjson"

	"github.com/DataDog/datadog-process-agent/net"
	"github.com/DataDog/datadog-process-agent/config"
	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

var TracerUnsupportedError = errors.New("tracer unsupported")

type NetworkTracer struct {
	cfg *config.AgentConfig

	supported bool
	tracer    *tracer.Tracer
	conn      net.Conn
}

func CreateNetworkTracer(cfg *config.AgentConfig) (*NetworkTracer, error) {
	var err error
	nt := &NetworkTracer{}

	// Checking whether the current OS + kernel version is supported by the tracer
	if nt.supported, err = tracer.IsTracerSupportedByOS(); err != nil {
		return nil, fmt.Errorf("%s: %s", TracerUnsupportedError, err)
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

		w.Write(buf)
		log.Debugf("/connections: %d connections, %d bytes", len(cs.Conns), len(buf))
	})

	http.Serve(nt.conn.GetListener(), nil)
}

func (nt *NetworkTracer) Close() {
	nt.conn.Stop()
	nt.tracer.Stop()
}
