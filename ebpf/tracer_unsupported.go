// +build !linux_bpf

package ebpf

func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNotImplemented
}

func IsTracerSupportedByOS() (bool, error) {
	return false, ErrNotImplemented
}

type Tracer struct{}

func NewTracer(_ *Config) (*Tracer, error) {
	return nil, ErrNotImplemented
}

func (t *Tracer) Start() {}

func (t *Tracer) Stop() {}

func (t *Tracer) GetActiveConnections() (*Connections, error) {
	return nil, ErrNotImplemented
}
