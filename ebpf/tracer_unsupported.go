// +build !linux_bpf

package ebpf

// CurrentKernelVersion is not implemented on non-linux systems
func CurrentKernelVersion() (uint32, error) {
	return 0, ErrNotImplemented
}

// IsTracerSupportedByOS is not implemented on non-linux systems
func IsTracerSupportedByOS() (bool, error) {
	return false, ErrNotImplemented
}

// Tracer is not implemented on non-linux systems
type Tracer struct{}

// NewTracer is not implemented on non-linux systems
func NewTracer(_ *Config) (*Tracer, error) {
	return nil, ErrNotImplemented
}

// Stop is not implemented on non-linux systems
func (t *Tracer) Stop() {}

// GetActiveConnections is not implemented on non-linux systems
func (t *Tracer) GetActiveConnections(_ string) (*Connections, error) {
	return nil, ErrNotImplemented
}

// GetStats returns a map of statistics about the current tracer's internal state
func (t *Tracer) GetStats() (map[string]interface{}, error) {
	return nil, ErrNotImplemented
}
