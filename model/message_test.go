package model

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeZeroTimestamp(t *testing.T) {
	header := MessageHeader{
		Version:        MessageV3,
		Encoding:       MessageEncodingZstdPB,
		Type:           TypeCollectorProc,
		SubscriptionID: 0,
		OrgID:          0,
		Timestamp:      0,
	}
	headerBytes, err := encodeHeader(header)
	assert.NoError(t, err)
	headerB64 := base64.StdEncoding.EncodeToString(headerBytes)

	// the same values are expected in the StackState receiver
	// make sure of backward compatibility when changing it
	assert.EqualValues(t, "AwIMAAAAAAAAAAAAAAAAAA==", headerB64)
}

func TestEncodeNonZeroTimestamp(t *testing.T) {
	header := MessageHeader{
		Version:        MessageV3,
		Encoding:       MessageEncodingZstdPB,
		Type:           TypeCollectorProc,
		SubscriptionID: 0,
		OrgID:          0,
		Timestamp:      1638527655412,
	}
	headerBytes, err := encodeHeader(header)
	assert.NoError(t, err)
	headerB64 := base64.StdEncoding.EncodeToString(headerBytes)

	// the same values are expected in the StackState receiver
	// make sure of backward compatibility when changing it
	assert.EqualValues(t, "AwIMAAAAAAAAAAF9f9vd9A==", headerB64)
}
