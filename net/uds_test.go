package net

import (
	"testing"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-process-agent/config"
)

var cfg = config.AgentConfig{}


func testFileExistsNewUDSListener(t *testing.T, socketPath string) {
	// _, err := os.Create(socketPath)
	// require.NoError(t, err)
	defer os.Remove(socketPath)
	assert.NotEmpty(t, socketPath)
	s, err := NewUDSListener(&config.AgentConfig{NetworkTracerSocketPath:socketPath})
	require.NoError(t, err)
	defer s.Stop()	
}

func testSocketExistsNewUDSListener(t *testing.T, socketPath string) {
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	assert.Nil(t, err)
	_, err = net.Listen("unix", addr.Name)
	assert.Nil(t, err)
	// testWorkingNewUDSListener(t, socketPath)
	_, err = NewUDSListener(&config.AgentConfig{NetworkTracerSocketPath:socketPath})	
	require.Error(t, err)
}

func testWorkingNewUDSListener(t *testing.T, socketPath string) {
	s, err := NewUDSListener(&config.AgentConfig{NetworkTracerSocketPath:socketPath})
	require.NoError(t, err)
	defer s.Stop()

	assert.NoError(t, err)
	assert.NotNil(t, s)
	time.Sleep(1 * time.Second)
	fi, err := os.Stat(socketPath)
	require.NoError(t, err)
	assert.Equal(t, "Srwx-w--w-", fi.Mode().String())
}

func TestNewUDSListener(t *testing.T) {
	t.Run("fail_file_exists", func(tt *testing.T) {
		socket, _ := ioutil.TempFile("", "net*.sock")
		defer os.RemoveAll(socket.Name()) // clean up after
		testFileExistsNewUDSListener(tt, socket.Name())
	})
	t.Run("socket_exists", func(tt *testing.T) {
		socket, _ := ioutil.TempFile("", "net*.sock")
		defer os.RemoveAll(socket.Name()) // clean up after
		testSocketExistsNewUDSListener(tt, socket.Name())
	})
	t.Run("working", func(tt *testing.T) {
		socket, _ := ioutil.TempFile("", "net*.sock")
		defer os.RemoveAll(socket.Name()) // clean up after
		testWorkingNewUDSListener(tt, socket.Name())
	})
}
