package config

import (
	"regexp"
	"strings"

	"github.com/DataDog/dd-go/log"
)

var (
	defaultSensitiveWords = []string{"password", "passwd", "mysql_pwd", "access_token", "auth_token", "api_key", "apikey", "secret", "credentials", "stripetoken"}
)

type DataScrubber struct {
	Enabled        bool
	SensitiveWords []*regexp.Regexp
}

func NewDefaultDataScrubber() *DataScrubber {
	newDataScrubber := &DataScrubber{
		Enabled:        true,
		SensitiveWords: CompileStringsToRegex(defaultSensitiveWords),
	}

	return newDataScrubber
}

// Compile each word in the list into a regex pattern to match against the cmdline arguments
func CompileStringsToRegex(words []string) []*regexp.Regexp {
	compiledRegexps := make([]*regexp.Regexp, 0, len(words))
	for _, word := range words {
		pattern := `(?P<key>( |-)(?i)` + word + `)(?P<delimiter> +|=)(?P<value>[^\s]*)`
		r, err := regexp.Compile(pattern)
		if err == nil {
			compiledRegexps = append(compiledRegexps, r)
		} else {
			log.Errorf("warning data scrubber - %s couldn't be compiled to a regex expression", word)
		}
	}

	return compiledRegexps
}

// Hide any cmdline argument value whose key matchs one of the patterns on the argsBlacklist vector
func (ds *DataScrubber) ScrubCmdline(cmdline []string) []string {
	if !ds.Enabled {
		return cmdline
	}

	rawCmdline := strings.Join(cmdline, " ")
	for _, pattern := range ds.SensitiveWords {
		rawCmdline = pattern.ReplaceAllString(rawCmdline, "${key}${delimiter}********")
	}

	return strings.Split(rawCmdline, " ")
}

// Add custom sensitive words on the DataScruber object
func (ds *DataScrubber) AddCustomSensitiveWords(words []string) {
	newPatterns := CompileStringsToRegex(words)

	// Add the new patterns to the existed ones
	ds.SensitiveWords = append(ds.SensitiveWords, newPatterns...)
}
