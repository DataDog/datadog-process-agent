package config

import (
	"regexp"
	"strings"
)

var (
	defaultSenstiveWords = []string{"password", "passwd", "mysql_pwd", "access_token", "auth_token", "api_key", "apikey", "secret", "credentials", "stripetoken"}
)

type DataScrubber struct {
	SensitiveWords           []*regexp.Regexp
	DefaultSensitiveWords    []*regexp.Regexp
	UseDefaultSensitiveWords bool
	CustomSensitiveWords     []*regexp.Regexp
}

func NewDefaultDataScrubber() *DataScrubber {
	newDataScrubber := &DataScrubber{
		SensitiveWords:           CompileStringsToRegex(defaultSenstiveWords),
		DefaultSensitiveWords:    CompileStringsToRegex(defaultSenstiveWords),
		UseDefaultSensitiveWords: true,
		CustomSensitiveWords:     make([]*regexp.Regexp, 0, 0),
	}

	return newDataScrubber
}

// Compile each word in the list into a regex pattern to match against the cmdline arguments
func CompileStringsToRegex(words []string) []*regexp.Regexp {
	compiledRegexps := make([]*regexp.Regexp, 0, len(words))
	for _, word := range words {
		// pattern := `((?i)-{1,2}` + word + `[^= ]*[ =])([^ \n]*)`
		pattern := `(?P<key>( |-)(?i)` + word + `)(?P<delimiter> +|=)(?P<value>[^\s]*)`
		r := regexp.MustCompile(pattern)
		compiledRegexps = append(compiledRegexps, r)
	}

	return compiledRegexps
}

// Hide any cmdline argument value whose key matchs one of the patterns on the argsBlacklist vector
func (ds *DataScrubber) ScrubCmdline(cmdline []string) []string {
	rawCmdline := strings.Join(cmdline, " ")
	for _, pattern := range ds.SensitiveWords {
		// rawCmdline = pattern.ReplaceAllString(rawCmdline, `$1********`)

		rawCmdline = pattern.ReplaceAllString(rawCmdline, `${key}${delimiter}********`)
	}

	return strings.Split(rawCmdline, " ")
}

// Set the custom sensitive words on the DataScruber object
func (ds *DataScrubber) SetCustomSensitiveWords(words []string) {
	ds.CustomSensitiveWords = CompileStringsToRegex(words)

	// Verify if the user chose to use de default sensitive words and create an unified one
	if ds.UseDefaultSensitiveWords {
		ds.SensitiveWords = append(ds.DefaultSensitiveWords, ds.CustomSensitiveWords...)
	} else {
		ds.SensitiveWords = ds.CustomSensitiveWords
	}
}
