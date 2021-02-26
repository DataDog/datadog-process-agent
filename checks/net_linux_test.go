package checks

import (
	"errors"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer"
	tracerConfig "github.com/StackVista/tcptracer-bpf/pkg/tracer/config"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestConnectionsCheck_retryTracerInit(t *testing.T) {
	retryDuration := 40 * time.Millisecond
	retryAmount := 3
	testRetry := 0

	for _, tc := range []struct {
		name               string
		mockMakeTracerFunc func(config *tracerConfig.Config) (tracer.Tracer, error)
		expectedTracer     tracer.Tracer
		expectedError      string
	}{
		{
			name: "Returns the tracer when the make tracer function returns one",
			mockMakeTracerFunc: func(config *tracerConfig.Config) (tracer.Tracer, error) {
				return &tracer.LinuxTracer{}, nil
			},
			expectedTracer: &tracer.LinuxTracer{},
			expectedError:  "",
		},
		{
			name: "Returns the tracer when the amount of retries are below the configured amount. ie retrying makes it work.",
			mockMakeTracerFunc: func(config *tracerConfig.Config) (tracer.Tracer, error) {
				if testRetry < retryAmount-1 {
					testRetry = testRetry + 1
					return nil, errors.New("failed to create tracer")
				}
				return &tracer.LinuxTracer{}, nil
			},
			expectedTracer: &tracer.LinuxTracer{},
			expectedError:  "",
		},
		{
			name: "Returns an error when max retries are reached.",
			mockMakeTracerFunc: func(config *tracerConfig.Config) (tracer.Tracer, error) {
				if testRetry <= retryAmount-1 {
					testRetry = testRetry + 1
					return nil, errors.New("failed to create tracer")
				}
				return &tracer.LinuxTracer{}, nil
			},
			expectedTracer: nil,
			expectedError:  "failed to create tracer",
		},
		{
			name: "Return an error when the make tracer function returns an error",
			mockMakeTracerFunc: func(config *tracerConfig.Config) (tracer.Tracer, error) {
				return nil, errors.New("failed to create tracer")
			},
			expectedError: "failed to create tracer",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := retryTracerInit(retryDuration, retryAmount, tracerConfig.DefaultConfig, tc.mockMakeTracerFunc)
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
			assert.EqualValues(t, tc.expectedTracer, tr)

			// reset the test retries
			testRetry = 0
		})
	}
}
