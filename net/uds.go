package net

import (
	"fmt"
	"net"
	"os"

	log "github.com/cihub/seelog"

	"github.com/DataDog/datadog-process-agent/config"
)

// UDSListener (Unix Domain Socket Listener)
type UDSListener struct {
	conn       net.Listener
	socketPath string
}

// NewUDSListener returns an idle UDSListener
func NewUDSListener(cfg *config.AgentConfig) (*UDSListener, error) {
	if len(cfg.NetworkTracerSocketPath) == 0 {
		return nil, fmt.Errorf("uds: empty socket path provided")
	}

	addr, err := net.ResolveUnixAddr("unix", cfg.NetworkTracerSocketPath)
	if err != nil {
		return nil, fmt.Errorf("uds: can't ResolveUnixAddr: %v", err)
	}

	conn, err := net.Listen("unix", addr.Name)
	if err != nil {
		return nil, fmt.Errorf("can't listen: %s", err)
	}

	if err := os.Chmod(cfg.NetworkTracerSocketPath, 0722); err != nil {
		return nil, fmt.Errorf("can't set the socket at write only: %s", err)
	}

	listener := &UDSListener{
		conn:       conn,
		socketPath: cfg.NetworkTracerSocketPath,
	}

	log.Debugf("uds: %s successfully initialized", conn.Addr())
	return listener, nil
}

// GetListener will return the underlying Conn's net.Listener
func (l *UDSListener) GetListener() net.Listener {
	return l.conn
}

// Stop closes the UDSListener connection and stops listening
func (l *UDSListener) Stop() {
	l.conn.Close()

	// Socket cleanup on exit - above conn.Close() should remove it, but just in case.
	if err := os.Remove(l.socketPath); err != nil {
		log.Debugf("uds: error removing socket file: %s", err)
	}
}
