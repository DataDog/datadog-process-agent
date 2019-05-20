package netlink

import (
	"bufio"
	"io"
	"log"

	agentlog "github.com/DataDog/datadog-agent/pkg/util/log"
)

// getLogger creates a log.Logger which forwards logs to the agent's logging package
func getLogger() *log.Logger {
	reader, writer := io.Pipe()

	flags := 0
	prefix := ""

	logger := log.New(writer, prefix, flags)

	go forwardLogs(reader)

	return logger
}

func forwardLogs(rd io.Reader) {
	scanner := bufio.NewScanner(rd)

	for scanner.Scan() {
		agentlog.Debugf("go-conntrack: %s", scanner.Text())
	}
}
