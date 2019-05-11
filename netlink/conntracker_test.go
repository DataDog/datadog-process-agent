package netlink

import (
	"testing"

	ct "github.com/florianl/go-conntrack"
	"github.com/stretchr/testify/assert"
)

func TestIsNat(t *testing.T) {
	c := map[ct.ConnAttrType][]byte{
		ct.AttrOrigIPv4Src: []byte{1, 1, 1, 1},
		ct.AttrOrigIPv4Dst: []byte{2, 2, 2, 2},

		ct.AttrReplIPv4Src: []byte{2, 2, 2, 2},
		ct.AttrReplIPv4Dst: []byte{1, 1, 1, 1},
	}
	assert.False(t, isNAT(c))
}
