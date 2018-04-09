package config

import (
	"regexp"
	"strings"
)

var (
	defaultSenstiveWords = []string{"password", "passwd", "mysql_pwd", "access_token", "auth_token", "api_key", "apikey", "secret", "credentials", "stripetoken"}
)

type DataScrubber struct {
	Enabled               bool
	SensitiveWords        []*regexp.Regexp
	DefaultSensitiveWords []*regexp.Regexp
	CustomSensitiveWords  []*regexp.Regexp
}

func NewDefaultDataScrubber() *DataScrubber {
	newDataScrubber := &DataScrubber{
		Enabled:               true,
		SensitiveWords:        CompileStringsToRegex(defaultSenstiveWords),
		DefaultSensitiveWords: CompileStringsToRegex(defaultSenstiveWords),
		CustomSensitiveWords:  make([]*regexp.Regexp, 0, 0),
	}

	return newDataScrubber
}

// Compile each word in the list into a regex pattern to match against the cmdline arguments
func CompileStringsToRegex(words []string) []*regexp.Regexp {
	compiledRegexps := make([]*regexp.Regexp, 0, len(words))
	for _, word := range words {
		pattern := `(?P<key>( |-)(?i)` + word + `)(?P<delimiter> +|=)(?P<value>[^\s]*)`
		r := regexp.MustCompile(pattern)
		compiledRegexps = append(compiledRegexps, r)
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
		rawCmdline = pattern.ReplaceAllString(rawCmdline, `${key}${delimiter}********`)
	}

	return strings.Split(rawCmdline, " ")
}

// Set the custom sensitive words on the DataScruber object
func (ds *DataScrubber) SetCustomSensitiveWords(words []string) {
	ds.CustomSensitiveWords = CompileStringsToRegex(words)

	// Create an unified list of sensitive patterns to match
	ds.SensitiveWords = append(ds.DefaultSensitiveWords, ds.CustomSensitiveWords...)
}
