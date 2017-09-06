package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLogLevelCase(t *testing.T) {
	assert.NoError(t, NewLoggerLevel("DEBUG", defaultLogFilePath))
	assert.NoError(t, NewLoggerLevel("debug", defaultLogFilePath))
	assert.NoError(t, NewLoggerLevel("InFo", defaultLogFilePath))
	assert.NoError(t, NewLoggerLevel("INFO", defaultLogFilePath))
}
