package config

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DataDog/gopsutil/process"
	log "github.com/cihub/seelog"
)

var (
	defaultSensitiveWords = []string{
		"password", "passwd", "mysql_pwd",
		"access_token", "auth_token",
		"api_key", "apikey",
		"secret", "credentials", "stripetoken"}
)

const (
	defaultCacheTTL = 100
)

// DataScrubber allows the agent to blacklist cmdline arguments that match
// a list of predefined and custom words
type DataScrubber struct {
	Enabled           bool
	SensitivePatterns []*regexp.Regexp
	seenProcess       map[string]struct{}
	cachedCmdlines    map[string][]string
	cacheCycles       uint32
	cacheTTL          uint32
}

// NewDefaultDataScrubber creates a DataScrubber with the default behavior: enabled
// and matching the default sensitive words
func NewDefaultDataScrubber() *DataScrubber {
	newDataScrubber := &DataScrubber{
		Enabled:           true,
		SensitivePatterns: compileStringsToRegex(defaultSensitiveWords),
		seenProcess:       make(map[string]struct{}),
		cachedCmdlines:    make(map[string][]string),
		cacheCycles:       0,
		cacheTTL:          defaultCacheTTL,
	}

	return newDataScrubber
}

// compileStringsToRegex compile each word in the slice into a regex pattern to match
// against the cmdline arguments
// The word must contain only word characters ([a-zA-z0-9_]) or wildcards *
func compileStringsToRegex(words []string) []*regexp.Regexp {
	compiledRegexps := make([]*regexp.Regexp, 0, len(words))
	forbiddenSymbols := regexp.MustCompile("[^a-zA-Z0-9_*]")

	for _, word := range words {
		if forbiddenSymbols.MatchString(word) {
			log.Warnf("data scrubber: %s skipped. The sensitive word must "+
				"contain only alphanumeric characters, underscores or wildcards ('*')", word)
			continue
		}

		if word == "*" {
			log.Warnf("data scrubber: ignoring wildcard-only ('*') sensitive word as it is not supported", word)
			continue
		}

		originalRunes := []rune(word)
		var enhancedWord bytes.Buffer
		valid := true
		for i, rune := range originalRunes {
			if rune == '*' {
				if i == len(originalRunes)-1 {
					enhancedWord.WriteString("[^ =:]*")
				} else if originalRunes[i+1] == '*' {
					log.Warnf("data scrubber: %s skipped. The sensitive word "+
						"must not contain two consecutives '*'", word)
					valid = false
					break
				} else {
					enhancedWord.WriteString(fmt.Sprintf("[^\\s=:$/]*"))
				}
			} else {
				enhancedWord.WriteString(string(rune))
			}
		}

		if !valid {
			continue
		}

		pattern := "(?P<key>( +| -{1,2})(?i)" + enhancedWord.String() + ")(?P<delimiter> +|=|:)(?P<value>[^\\s]*)"
		r, err := regexp.Compile(pattern)
		if err == nil {
			compiledRegexps = append(compiledRegexps, r)
		} else {
			log.Warnf("data scrubber: %s skipped. It couldn't be compiled into a regex expression", word)
		}
	}

	return compiledRegexps
}

// createProcessKey returns an unique identifier for a given process
func createProcessKey(p *process.FilledProcess) string {
	var b bytes.Buffer
	b.WriteString("p:")
	b.WriteString(strconv.Itoa(int(p.Pid)))
	b.WriteString("|c:")
	b.WriteString(strconv.Itoa(int(p.CreateTime)))

	return b.String()
}

// ScrubCmdline uses a cache memory to avoid scrubbing already known
// process' cmdlines
func (ds *DataScrubber) ScrubProcessCommand(p *process.FilledProcess) []string {
	pKey := createProcessKey(p)
	if _, ok := ds.seenProcess[pKey]; !ok {
		ds.seenProcess[pKey] = struct{}{}
		ds.cachedCmdlines[pKey] = ds.scrubCmdline(p.Cmdline)
	}

	return ds.cachedCmdlines[pKey]
}

// IncreaseCacheAge increases one cycle of cache memory age. If it reaches the
// TTL, the cache is restarted
func (ds *DataScrubber) IncreaseCacheAge() {
	ds.cacheCycles++
	if ds.cacheCycles == ds.cacheTTL {
		ds.seenProcess = make(map[string]struct{})
		ds.cachedCmdlines = make(map[string][]string)
		ds.cacheCycles = 0
	}
}

// scrubCmdline hides any cmdline argument value whose key matches one of the patterns
// built from the sensitive words
func (ds *DataScrubber) scrubCmdline(cmdline []string) []string {
	if !ds.Enabled {
		return cmdline
	}

	rawCmdline := strings.Join(cmdline, " ")
	changed := false
	for _, pattern := range ds.SensitivePatterns {
		if pattern.MatchString(rawCmdline) {
			changed = changed || true
			rawCmdline = pattern.ReplaceAllString(rawCmdline, "${key}${delimiter}********")
		}
	}

	if changed {
		return strings.Split(rawCmdline, " ")
	}
	return cmdline
}

// AddCustomSensitiveWords adds custom sensitive words on the DataScrubber object
func (ds *DataScrubber) AddCustomSensitiveWords(words []string) {
	newPatterns := compileStringsToRegex(words)
	ds.SensitivePatterns = append(ds.SensitivePatterns, newPatterns...)
}
