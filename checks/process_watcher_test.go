package checks

import (
	"fmt"
	"github.com/DataDog/datadog-process-agent/model"
	"testing"

	log "github.com/cihub/seelog"
)

func TestProcessWatcher(t *testing.T) {
	defer log.Flush()

	w := newProcessWatcher()
	w.in <- &model.WatchedProcess{Pid: 24016}
	r := <-w.out

	fmt.Printf("Received output: %s", r.output)
}
