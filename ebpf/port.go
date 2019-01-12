package ebpf

import (
	log "github.com/cihub/seelog"
	"path"
	"time"
)

// PortMapping tracks which ports a pid is listening on
type PortMapping struct {
	procRoot string
	config   *Config
	ports    map[uint16]string
}

//NewPortMapping creates a new PortMapping instance
func NewPortMapping(procRoot string, config *Config) *PortMapping {
	return &PortMapping{
		procRoot: procRoot,
		config:   config,
		ports:    make(map[uint16]string),
	}
}

// AddMapping indicates that something is listening on the provided address and port
func (pm *PortMapping) AddMapping(port uint16, address string) {
	pm.ports[port] = address
}

// RemoveMapping indicates that the provided port is no longer being listened on
func (pm *PortMapping) RemoveMapping(port uint16) {
	delete(pm.ports, port)
}

// IsListening returns true if something is listening on the given address and port
func (pm *PortMapping) IsListening(port uint16, address string) bool {
	listenAddr, ok := pm.ports[port]
	if !ok {
		return false
	}

	return listenAddr == address
}

// ReadInitialState reads the /proc filesystem and determines which pids are currently listening on what ports
func (pm *PortMapping) ReadInitialState() error {
	start := time.Now()

	if pm.config.CollectTCPConns {
		if ports, err := readProcNet(path.Join(pm.procRoot, "net/tcp")); err != nil {
			log.Errorf("error reading tcp state: %s", err)
		} else {
			for port, addr := range ports {
				pm.ports[port] = addr
			}
		}

		if pm.config.CollectIPv6Conns {
			if ports, err := readProcNet(path.Join(pm.procRoot, "net/tcp6")); err != nil {
				log.Errorf("error reading tcp6 state: %s", err)
			} else {
				for port, addr := range ports {
					pm.ports[port] = addr
				}
			}
		}
	}

	log.Infof("Read initial pid->port mapping in %s", time.Now().Sub(start))

	return nil
}
