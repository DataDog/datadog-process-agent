package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogLevelCase(t *testing.T) {
	assert.NoError(t, NewLoggerLevel("DEBUG", defaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("debug", defaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("InFo", defaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("INFO", defaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("WARN", defaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("WARNING", defaultLogFilePath, false))
	assert.NoError(t, NewLoggerLevel("notReal", defaultLogFilePath, false))
}
