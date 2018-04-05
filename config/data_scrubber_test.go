package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupDataScrubber() *DataScrubber {
	customSensitiveWords := []string{
		"consul_token",
		"dd_password",
		"blocked_from_yaml",
	}

	scrubber := NewDefaultDataScrubber()
	scrubber.SetCustomSensitiveWords(customSensitiveWords)

	return scrubber
}

func TestBlacklistedArgs(t *testing.T) {
	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{[]string{"agent", "-password", "1234"}, []string{"agent", "-password", "********"}},
		{[]string{"agent", "--password", "1234"}, []string{"agent", "--password", "********"}},
		{[]string{"agent", "-password=1234"}, []string{"agent", "-password=********"}},
		{[]string{"agent", "--password=1234"}, []string{"agent", "--password=********"}},
		{[]string{"fitz", "-consul_token=1234567890"}, []string{"fitz", "-consul_token=********"}},
		{[]string{"fitz", "--consul_token=1234567890"}, []string{"fitz", "--consul_token=********"}},
		{[]string{"fitz", "-consul_token", "1234567890"}, []string{"fitz", "-consul_token", "********"}},
		{[]string{"fitz", "--consul_token", "1234567890"}, []string{"fitz", "--consul_token", "********"}},
		{[]string{"python ~/test/run.py --password=1234 -password 1234 -open_password=admin -consul_token 2345 -blocked_from_yaml=1234 &"},
			[]string{"python", "~/test/run.py", "--password=********", "-password", "********", "-open_password=admin", "-consul_token", "********", "-blocked_from_yaml=********", "&"}},
		{[]string{"agent", "-PASSWORD", "1234"}, []string{"agent", "-PASSWORD", "********"}},
		{[]string{"agent", "--PASSword", "1234"}, []string{"agent", "--PASSword", "********"}},
		{[]string{"agent", "--PaSsWoRd=1234"}, []string{"agent", "--PaSsWoRd=********"}},
	}

	scrubber := setupDataScrubber()
	t.Log("default regexp", scrubber.DefaultSensitiveWords)
	t.Log("custom regexp", scrubber.CustomSensitiveWords)
	t.Log("merged regexp", scrubber.SensitiveWords)
	for i := range cases {
		cases[i].cmdline = scrubber.ScrubCmdline(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}
}

func TestNoBlacklistedArgs(t *testing.T) {
	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{[]string{"spidly", "-debug_port=2043"}, []string{"spidly", "-debug_port=2043"}},
		{[]string{"agent", "start", "-p", "config.cfg"}, []string{"agent", "start", "-p", "config.cfg"}},
		{[]string{"p1", "-openpassword=admin"}, []string{"p1", "-openpassword=admin"}},
		{[]string{"p1", "-openpassword", "admin"}, []string{"p1", "-openpassword", "admin"}},
	}

	scrubber := setupDataScrubber()
	t.Log("default regexp", scrubber.DefaultSensitiveWords)
	t.Log("custom regexp", scrubber.CustomSensitiveWords)
	t.Log("merged regexp", scrubber.SensitiveWords)
	for i := range cases {
		cases[i].cmdline = scrubber.ScrubCmdline(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}

}

func BenchmarkRegexMatching1(b *testing.B)    { benchmarkRegexMatching(1, b) }
func BenchmarkRegexMatching10(b *testing.B)   { benchmarkRegexMatching(10, b) }
func BenchmarkRegexMatching100(b *testing.B)  { benchmarkRegexMatching(100, b) }
func BenchmarkRegexMatching1000(b *testing.B) { benchmarkRegexMatching(1000, b) }

var avoidOptimization []string

func benchmarkRegexMatching(nbProcesses int, b *testing.B) {
	runningProcesses := make([][]string, nbProcesses)
	foolCmdline := []string{"python ~/test/run.py --password=1234 -password 1234 -password=admin -secret 2345 -credentials=1234 -api_key 2808 &"}
	scrubber := setupDataScrubber()

	for i := 0; i < nbProcesses; i++ {
		runningProcesses = append(runningProcesses, foolCmdline)
	}

	var r []string
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, p := range runningProcesses {
			r = scrubber.ScrubCmdline(p)
		}
	}

	avoidOptimization = r
}

func BenchmarkRegexMatchingOld1(b *testing.B)    { benchmarkOldRegexMatching(1, b) }
func BenchmarkRegexMatchingOld10(b *testing.B)   { benchmarkOldRegexMatching(10, b) }
func BenchmarkRegexMatchingOld100(b *testing.B)  { benchmarkOldRegexMatching(100, b) }
func BenchmarkRegexMatchingOld1000(b *testing.B) { benchmarkOldRegexMatching(1000, b) }

func benchmarkOldRegexMatching(nbProcesses int, b *testing.B) {
	runningProcesses := make([][]string, nbProcesses)
	foolCmdline := []string{"python", "~/test/run.py", "--password=1234", "-password", "1234", "-password=admin", "-secret", "2345", "-credentials=1234", "-api_key", "2808", "&"}
	scrubber := setupDataScrubber()

	for i := 0; i < nbProcesses; i++ {
		runningProcesses = append(runningProcesses, foolCmdline)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, p := range runningProcesses {
			scrubber.ScrubCmdlineOld(p)
		}
	}
}

func BenchmarkRegexCall(b *testing.B) {
	foolCmdline := []string{"python ~/test/run.py --password=1234 -password 1234 -password=admin -open_password 2345 -consul=1234 -p 2808 &"}
	scrubber := setupDataScrubber()

	var r []string
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		r = scrubber.ScrubCmdline(foolCmdline)
	}
	avoidOptimization = r

}
