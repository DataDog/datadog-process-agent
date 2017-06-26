package cache

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	Set("foo", "bar")
	val, ok := Get("foo")
	assert.True(t, ok)
	assert.Equal(t, "bar", val)

	v, ok := Get("bim")
	assert.False(t, ok)
	assert.Nil(t, v)

	SetWithTTL("with-ttl1", "foo", 5*time.Minute)
	val, ok = Get("with-ttl1")
	assert.True(t, ok)
	assert.Equal(t, "foo", val)

	// Set a negative TTL so it expires on look-up
	SetWithTTL("with-ttl2", "bar", -1*time.Second)
	v, ok = Get("with-ttl")
	assert.False(t, ok)
	assert.Nil(t, v)
}
