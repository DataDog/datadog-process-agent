package config

import (
	"regexp"
	"strings"

	"github.com/DataDog/dd-go/log"
)

var (
	defaultSensitiveWords = []string{
		"password", "passwd", "mysql_pwd",
		"access_token", "auth_token",
		"api_key", "apikey",
		"secret", "credentials", "stripetoken"}
)

type DataScrubber struct {
	Enabled           bool
	SensitivePatterns []*regexp.Regexp
}

func NewDefaultDataScrubber() *DataScrubber {
	newDataScrubber := &DataScrubber{
		Enabled:           true,
		SensitivePatterns: CompileStringsToRegex(defaultSensitiveWords),
	}

	return newDataScrubber
}

// Compile each word in the list into a regex pattern to match against the cmdline arguments
// The word must contain only word characters ([a-zA-z0-9_])
func CompileStringsToRegex(words []string) []*regexp.Regexp {
	compiledRegexps := make([]*regexp.Regexp, 0, len(words))
	forbiddenSymbols := regexp.MustCompile(`\W`)

	for _, word := range words {
		if forbiddenSymbols.MatchString(word) {
			log.Errorf("warning data scrubber - %s not compiled. The sensitive word must contain only word characters", word)
			continue
		}

		pattern := `(?P<key>( |-)(?i)` + word + `)(?P<delimiter> +|=)(?P<value>[^\s]*)`
		r, err := regexp.Compile(pattern)
		if err == nil {
			compiledRegexps = append(compiledRegexps, r)
		} else {
			log.Errorf("warning data scrubber - %s couldn't be compiled into a regex expression", word)
		}
	}

	return compiledRegexps
}

// Hide any cmdline argument value whose key matches one of the patterns built from the sensitive words
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

// Add custom sensitive words on the DataScrubber object
func (ds *DataScrubber) AddCustomSensitiveWords(words []string) {
	newPatterns := CompileStringsToRegex(words)
	ds.SensitivePatterns = append(ds.SensitivePatterns, newPatterns...)
}
