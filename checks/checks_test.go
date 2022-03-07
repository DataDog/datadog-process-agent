package checks

import (
	processUtils "github.com/StackVista/stackstate-process-agent/util"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetSenderWithNoAggregator(t *testing.T) {
	testCheck := GetSender("test-check")

	assert.EqualValues(t, processUtils.LogSender, testCheck)
}
