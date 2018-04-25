package util

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-agent/pkg/util/docker"
)

// ErrNotImplemented is the "not implemented" error given by `gopsutil` when an
// OS doesn't support and API. Unfortunately it's in an internal package so
// we can't import it so we'll copy it here.
var ErrNotImplemented = errors.New("not implemented yet")

// ReadLines reads contents from a file and splits them by new lines.
func ReadLines(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{""}, err
	}
	defer f.Close()

	var ret []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ret = append(ret, scanner.Text())
	}
	return ret, scanner.Err()
}

// GetEnv retrieves the environment variable key. If it does not exist it returns the default.
func GetEnv(key string, dfault string, combineWith ...string) string {
	value := os.Getenv(key)
	if value == "" {
		value = dfault
	}

	switch len(combineWith) {
	case 0:
		return value
	case 1:
		return filepath.Join(value, combineWith[0])
	default:
		var b bytes.Buffer
		b.WriteString(value)
		for _, v := range combineWith {
			b.WriteRune('/')
			b.WriteString(v)
		}
		return b.String()
	}
}

// HostProc returns the location of a host's procfs. This can and will be
// overriden when running inside a container.
func HostProc(combineWith ...string) string {
	return GetEnv("HOST_PROC", "/proc", combineWith...)
}

// HostSys returns the location of a host's /sys. This can and will be overriden
// when running inside a container.
func HostSys(combineWith ...string) string {
	return GetEnv("HOST_SYS", "/sys", combineWith...)
}

// PathExists returns a boolean indicating if the given path exists on the file system.
func PathExists(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	}
	return false
}

// StringInSlice returns true if the given searchString is in the given slice, false otherwise.
func StringInSlice(slice []string, searchString string) bool {
	for _, curString := range slice {
		if curString == searchString {
			return true
		}
	}
	return false
}

// GetDockerSocketPath is only for exposing the sockpath out of the module
func GetDockerSocketPath() (string, error) {
	// If we don't have a docker.sock then return a known error.
	sockPath := GetEnv("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
	if !PathExists(sockPath) {
		return "", docker.ErrDockerNotAvailable
	}
	return sockPath, nil
}
