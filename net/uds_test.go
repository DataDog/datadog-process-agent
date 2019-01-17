package net

import (
	"testing"
	"net"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-process-agent/config"
)

cfg := config.AgentConfig

// test file exists
func testFileExistsNewUDSListener(t *testing.T, socketPath string) {
	_, err := os.Create(socketPath)
	assert.Nil(t, err)
	defer os.Remove(socketPath)
	_, err = NewUDSListener(cfg)
	assert.Error(t, err)
}

// tests if socket exists
func testSocketExistsNewUDSListener(t *testing.T, socketPath string) {
	addr, err := net.ResolveUnixAddr(("unix", socketPath)
	assert.Nil(t, err)
	_, err = net.Listen("unix", addr.name)
	assert.Nil(t, err)
	testWorkingNewUDSListen(t, socketPath)
}

// test working UDS listener
func testWorkingNewUDSListener(t *testing.T, socketPath string) {
	s, err := NewUDSListener(cfg)
	defer s.Stop()

	assert.Nil(t, err)
	assert.NotNill(t, s)
	fi, err := os.Stat(socketPath)
	require.Nil(t, err)
	assert.Equal(t, "Srwx-w--w-", fi.Mode().String())
}

// test new UDS listener
func TestNewUDSListener(t *testing.t) {
	dir, err := ioutil.TempDir("", "dd-test-")
	assert.Nil(t, err)
	defer os.RemoveAll(dir) // clean up after
	socketPath := cfg.NetworkTracerSocketPath

	t.Run("fail_file_exists", func(tt *testing.T) {
		testFileExistsNewUDSListener(tt, socketPath)
	})
	t.Run("socket_exists", func(tt *testing.T) {
		testSocketExistsNewUSDListener(tt, socketPath)
	})
	t.Run("working", func(tt *testing.T) {
		testWorkingNewUDSListener(tt, socketPath)
	})
}


// test start/stop UDS listener