package main

import (
	"strings"
	"time"
)

const (
	// HTTPTimeout is the timeout in seconds for process-agent to send process payloads to DataDog
	HTTPTimeout = 20 * time.Second
	// ReqCtxTimeout is the timeout in seconds for process-agent to cancel POST request using context timeout
	ReqCtxTimeout = 30 * time.Second
)

// IsTimeout returns true if the error is due to reaching the timeout limit on the http.client
func isHTTPTimeout(err error) bool {
	if netErr, ok := err.(interface {
		Timeout() bool
	}); ok && netErr.Timeout() {
		return true
	} else if strings.Contains(err.Error(), "use of closed network connection") { //To deprecate when using GO > 1.5
		return true
	}
	return false
}
