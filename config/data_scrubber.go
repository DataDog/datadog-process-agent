package config

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	log "github.com/cihub/seelog"
)

var (
	defaultSensitiveWords = []string{
		"password", "passwd", "mysql_pwd",
		"access_token", "auth_token",
		"api_key", "apikey",
		"secret", "credentials", "stripetoken"}
)

// DataScrubber allows the agent to blacklist cmdline arguments that match
// a list of predefined and custom words
type DataScrubber struct {
	Enabled           bool
	SensitivePatterns []*regexp.Regexp
}

// NewDefaultDataScrubber creates a DataScrubber with the default behavior: enabled
// and matching the default sensitive words
func NewDefaultDataScrubber() *DataScrubber {
	newDataScrubber := &DataScrubber{
		Enabled:           true,
		SensitivePatterns: CompileStringsToRegex(defaultSensitiveWords),
	}

	return newDataScrubber
}

// CompileStringsToRegex compile each word in the slice into a regex pattern to match
// against the cmdline arguments
// The word must contain only word characters ([a-zA-z0-9_]) or wildcards *
func CompileStringsToRegex(words []string) []*regexp.Regexp {
	compiledRegexps := make([]*regexp.Regexp, 0, len(words))
	forbiddenSymbols := regexp.MustCompile(`[^a-zA-Z0-9_*]`)

	for _, word := range words {
		if forbiddenSymbols.MatchString(word) {
			log.Errorf("warning data scrubber - %s not compiled. The sensitive word must contain only word characters or *", word)
			continue
		}

		originalRunes := []rune(word)
		var enhancedWord bytes.Buffer
		valid := true
		for i, rune := range originalRunes {
			if rune == '*' {
				if i == len(originalRunes)-1 {
					enhancedWord.WriteString("[^ =]*")
				} else if originalRunes[i+1] == '*' {
					log.Errorf("warning data scrubber - %s not compiled. The sensitive word must not contain two consecutives *", word)
					valid = false
					break
				} else {
					enhancedWord.WriteString(fmt.Sprintf("[^%c]*", word[i+1]))
				}
			} else {
				enhancedWord.WriteString(string(rune))
			}
		}

		if !valid {
			continue
		}

		pattern := `(?P<key>( +|-)(?i)` + enhancedWord.String() + `)(?P<delimiter> +|=)(?P<value>[^\s]*)`
		r, err := regexp.Compile(pattern)
		if err == nil {
			compiledRegexps = append(compiledRegexps, r)
		} else {
			log.Errorf("warning data scrubber - %s couldn't be compiled into a regex expression", word)
		}
	}

	return compiledRegexps
}

// ScrubCmdline hides any cmdline argument value whose key matches one of the patterns
// built from the sensitive words
func (ds *DataScrubber) ScrubCmdline(cmdline []string) []string {
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
	newPatterns := CompileStringsToRegex(words)
	ds.SensitivePatterns = append(ds.SensitivePatterns, newPatterns...)
}
