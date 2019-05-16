//+build linux

package netlink

import (
	"os"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// guessRootNetNSFd guesses the file descriptor of the root net NS
// and returns 0 in case of failure
func guessRootNetNSFd(procRoot string) int {
	for _, path := range []string{
		procRoot + "/1/ns/net",
		"/proc/1/ns/net",
	} {
		file, err := os.Open(path)
		if err != nil {
			log.Debugf("could not attach to net namespace at %s: %v", path, err)
			continue
		}

		log.Debugf("attaching to net namespace at %s", path)
		return int(file.Fd())
	}
	return 0
}
