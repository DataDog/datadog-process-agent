// +build !docker

package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/cihub/seelog"
)

// Handles signals - tells us whether we should exit.
func handleSignals(exit chan bool) {
	sigIn := make(chan os.Signal, 100)
	signal.Notify(sigIn)
	// unix only in all likelihood;  but we don't care.
	for sig := range sigIn {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			log.Criticalf("Caught signal '%s'; terminating.", sig)
			close(exit)
		default:
			log.Warnf("Caught signal %s; continuing/ignoring.", sig)
		}
	}
}
