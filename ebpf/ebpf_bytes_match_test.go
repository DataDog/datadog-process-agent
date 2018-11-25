package ebpf

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEbpfBytesCorrect(t *testing.T) {
	dir, err := os.Getwd()

	fmt.Println(dir + "/c")
	fs, _ := ioutil.ReadDir(dir + "/c")
	for _, f := range fs {
		fmt.Println(f.Name())
	}

	fs2, _ := ioutil.ReadDir(dir)
	fmt.Println(dir)
	for _, f := range fs2 {
		fmt.Println(f.Name())
	}

	bs, err := ioutil.ReadFile(dir + "/c/tracer-ebpf.o")
	require.NoError(t, err)

	actual, err := tracerEbpfOBytes()
	require.NoError(t, err)

	assert.Equal(t, bs, actual)
}
