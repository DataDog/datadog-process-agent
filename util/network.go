package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"context"
	"net"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"github.com/DataDog/tcptracer-bpf/pkg/tracer"
)

const (
	statusURL      = "http://unix/status"
	connectionsURL = "http://unix/connections"
)

var (
	globalUtil       *RemoteNetTracerUtil
	globalSocketPath string
)

type RemoteNetTracerUtil struct {
	// Retrier used to setup network tracer
	initRetry retry.Retrier

	socketPath string
	httpClient http.Client
}

func SetNetworkTracerSocketPath(socketPath string) {
	globalSocketPath = socketPath
}

func GetRemoteNetworkTracerUtil() (*RemoteNetTracerUtil, error) {
	if globalSocketPath == "" {
		return nil, fmt.Errorf("remote tracer has no socket path defined")
	}

	if globalUtil == nil {
		globalUtil = newNetworkTracer()
		globalUtil.initRetry.SetupRetrier(&retry.Config{
			Name:          "network-tracer-util",
			AttemptMethod: globalUtil.init,
			Strategy:      retry.RetryCount,
			// 10 tries w/ 30s delays = 5m of trying before permafail
			RetryCount: 10,
			RetryDelay: 30 * time.Second,
		})
	}

	if err := globalUtil.initRetry.TriggerRetry(); err != nil {
		log.Debugf("network tracer init error: %s", err)
		return nil, err
	}

	return globalUtil, nil
}

func (r *RemoteNetTracerUtil) GetConnections() ([]tracer.ConnectionStats, error) {
	// Otherwise, get it remotely (via unix socket), and parse from JSON
	resp, err := r.httpClient.Get(connectionsURL)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("connections request failed: socket %s, url: %s, status code: %d", r.socketPath, connectionsURL, resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	conn := tracer.Connections{}
	if err := json.Unmarshal(body, &conn); err != nil {
		return nil, err
	}

	return conn.Conns, nil
}

func newNetworkTracer() *RemoteNetTracerUtil {
	return &RemoteNetTracerUtil{
		socketPath: globalSocketPath,
		httpClient: http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    5,
				IdleConnTimeout: 90 * time.Second,
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", globalSocketPath)
				},
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}
}

func (r *RemoteNetTracerUtil) init() error {
	if resp, err := r.httpClient.Get(statusURL); err != nil {
		return err
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote tracer status check failed: socket %s, url: %s, status code: %d", r.socketPath, statusURL, resp.StatusCode)
	}
	return nil
}
