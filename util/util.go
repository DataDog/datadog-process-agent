package util

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

var e = struct{}{}

// ReadLines reads contents from a file and splits them by new lines.
func ReadLines(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{""}, err
	}
	defer f.Close()

	var ret []string

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		ret = append(ret, strings.Trim(line, "\n"))
	}

	return ret, nil
}

// GetEnv retrieves the environment variable key. If it does not exist it returns the default.
func GetEnv(key string, dfault string, combineWith ...string) string {
	value := os.Getenv(key)
	if value == "" {
		value = dfault
	}

	switch len(combineWith) {
	case 0:
		return value
	case 1:
		return filepath.Join(value, combineWith[0])
	default:
		all := make([]string, len(combineWith)+1)
		all[0] = value
		copy(all[1:], combineWith)
		return filepath.Join(all...)
	}
}

func HostProc(combineWith ...string) string {
	return GetEnv("HOST_PROC", "/proc", combineWith...)
}

func HostSys(combineWith ...string) string {
	return GetEnv("HOST_SYS", "/sys", combineWith...)
}

func PathExists(filename string) bool {
	if _, err := os.Stat(filename); err == nil {
		return true
	}
	return false
}

// Int32Set is a small map-backed implementation of a set. Not
// thread-safe.
type Int32Set map[int32]struct{}

// NewInt32Set returns a new empty int32 set.
func NewInt32Set() Int32Set {
	return make(Int32Set)
}

// Int32SetFromSlice creates a set from the given slice.
func Int32SetFromSlice(slice []int32) Int32Set {
	s := NewInt32Set()
	s.Fill(slice)
	return s
}

// Add adds a key to the set.
func (ss Int32Set) Add(key int32) {
	ss[key] = e
}

// Delete removes a key from the set
func (ss Int32Set) Delete(key int32) {
	delete(ss, key)
}

// Fill adds many keys to the set.
func (ss Int32Set) Fill(keys []int32) {
	for _, k := range keys {
		ss[k] = e
	}
}

// Contains returns true if the key is in the set, false otherwise.
func (ss Int32Set) Contains(key int32) bool {
	_, ok := ss[key]
	return ok
}

// Len returns then number of elements in the set.
func (ss Int32Set) Len() int {
	return len(ss)
}

// Elements returns the elements in the set as a slice.
func (ss Int32Set) Elements() []int32 {
	keys := make([]int32, 0, len(ss))
	for k := range ss {
		keys = append(keys, k)
	}
	return keys
}
