package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_stripMessage(t *testing.T) {
	assert.Equal(t, "1234567890", stripMessage("1234567890", 11, "..."))
	assert.Equal(t, "1234567890", stripMessage("1234567890", 10, "..."))
	assert.Equal(t, "123...890", stripMessage("1234567890", 9, "..."))
	assert.Equal(t, "12...0", stripMessage("1234567890", 6, "..."))
	assert.Equal(t, "12...90", stripMessage("1234567890", 7, "..."))
	assert.Equal(t, "12...9", stripMessage("123456789", 6, "..."))
	assert.Equal(t, "12...89", stripMessage("123456789", 7, "..."))
}
