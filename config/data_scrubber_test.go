package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupDataScrubber(t *testing.T) *DataScrubber {
	customSensitiveWords := []string{
		"consul_token",
		"dd_password",
		"blocked_from_yaml",
		"config",
		"pid",
	}

	scrubber := NewDefaultDataScrubber()
	scrubber.AddCustomSensitiveWords(customSensitiveWords)

	assert.Equal(t, true, scrubber.Enabled)
	assert.Equal(t, len(defaultSensitiveWords)+len(customSensitiveWords), len(scrubber.SensitivePatterns))

	return scrubber
}

func setupDataScrubberWildCard(t *testing.T) *DataScrubber {
	wildcards := []string{
		"*befpass",
		"afterpass*",
		"*both*",
		"mi*le",
		"*pass*d*",
	}

	scrubber := NewDefaultDataScrubber()
	scrubber.AddCustomSensitiveWords(wildcards)

	assert.Equal(t, true, scrubber.Enabled)
	assert.Equal(t, len(defaultSensitiveWords)+len(wildcards), len(scrubber.SensitivePatterns))

	return scrubber
}

func TestUncompilableWord(t *testing.T) {
	customSensitiveWords := []string{
		"consul_token",
		"dd_password",
		"(an_error",
		")a*",
		"[forbidden]",
		"]a*",
		"blocked_from_yaml",
		"*bef",
		"**bef",
		"after*",
		"after**",
		"*both*",
		"**both**",
		"mi*le",
		"mi**le",
		"*",
		"**",
		"*pass*d*",
	}

	validCustomSenstiveWords := []string{
		"consul_token",
		"dd_password",
		"blocked_from_yaml",
	}

	validWildCards := []string{
		"*bef",
		"after*",
		"*both*",
		"mi*le",
		"*pass*d*",
	}

	scrubber := NewDefaultDataScrubber()
	scrubber.AddCustomSensitiveWords(customSensitiveWords)

	assert.Equal(t, true, scrubber.Enabled)
	assert.Equal(t, len(defaultSensitiveWords)+len(validCustomSenstiveWords)+len(validWildCards), len(scrubber.SensitivePatterns))

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{[]string{"process --consul_token=1234"}, []string{"process", "--consul_token=********"}},
		{[]string{"process --dd_password=1234"}, []string{"process", "--dd_password=********"}},
		{[]string{"process --blocked_from_yaml=1234"}, []string{"process", "--blocked_from_yaml=********"}},

		{[]string{"process --onebef=1234"}, []string{"process", "--onebef=********"}},
		{[]string{"process --afterone=1234"}, []string{"process", "--afterone=********"}},
		{[]string{"process --oneboth1=1234"}, []string{"process", "--oneboth1=********"}},
		{[]string{"process --middle=1234"}, []string{"process", "--middle=********"}},
		{[]string{"process --twopasswords=1234,5678"}, []string{"process", "--twopasswords=********"}},
	}

	for i := range cases {
		cases[i].cmdline = scrubber.ScrubCmdline(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}
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
		{[]string{"fitz", "-dd_password", "1234567890"}, []string{"fitz", "-dd_password", "********"}},
		{[]string{"fitz", "dd_password", "1234567890"}, []string{"fitz", "dd_password", "********"}},
		{[]string{"python ~/test/run.py --password=1234 -password 1234 -open_password=admin -consul_token 2345 -blocked_from_yaml=1234 &"},
			[]string{"python", "~/test/run.py", "--password=********", "-password", "********", "-open_password=admin", "-consul_token", "********", "-blocked_from_yaml=********", "&"}},
		{[]string{"agent", "-PASSWORD", "1234"}, []string{"agent", "-PASSWORD", "********"}},
		{[]string{"agent", "--PASSword", "1234"}, []string{"agent", "--PASSword", "********"}},
		{[]string{"agent", "--PaSsWoRd=1234"}, []string{"agent", "--PaSsWoRd=********"}},
		{[]string{"java -password      1234"}, []string{"java", "-password", "", "", "", "", "", "********"}},
		{[]string{"process-agent --config=datadog.yaml --pid=process-agent.pid"}, []string{"process-agent", "--config=********", "--pid=********"}},
		{[]string{"1-password --config=12345"}, []string{"1-password", "--config=********"}},
		{[]string{"java kafka password 1234"}, []string{"java", "kafka", "password", "********"}},
	}

	scrubber := setupDataScrubber(t)

	for i := range cases {
		cases[i].cmdline = scrubber.ScrubCmdline(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}
}

func TestBlacklistedArgsWhenDisabled(t *testing.T) {
	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{[]string{"agent", "-password", "1234"}, []string{"agent", "-password", "1234"}},
		{[]string{"agent", "--password", "1234"}, []string{"agent", "--password", "1234"}},
		{[]string{"agent", "-password=1234"}, []string{"agent", "-password=1234"}},
		{[]string{"agent", "--password=1234"}, []string{"agent", "--password=1234"}},
		{[]string{"fitz", "-consul_token=1234567890"}, []string{"fitz", "-consul_token=1234567890"}},
		{[]string{"fitz", "--consul_token=1234567890"}, []string{"fitz", "--consul_token=1234567890"}},
		{[]string{"fitz", "-consul_token", "1234567890"}, []string{"fitz", "-consul_token", "1234567890"}},
		{[]string{"fitz", "--consul_token", "1234567890"}, []string{"fitz", "--consul_token", "1234567890"}},
		{[]string{"python ~/test/run.py --password=1234 -password 1234 -open_password=admin -consul_token 2345 -blocked_from_yaml=1234 &"},
			[]string{"python ~/test/run.py --password=1234 -password 1234 -open_password=admin -consul_token 2345 -blocked_from_yaml=1234 &"}},
		{[]string{"agent", "-PASSWORD", "1234"}, []string{"agent", "-PASSWORD", "1234"}},
		{[]string{"agent", "--PASSword", "1234"}, []string{"agent", "--PASSword", "1234"}},
		{[]string{"agent", "--PaSsWoRd=1234"}, []string{"agent", "--PaSsWoRd=1234"}},
		{[]string{"java -password      1234"}, []string{"java -password      1234"}},
	}

	scrubber := setupDataScrubber(t)
	scrubber.Enabled = false

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
		{[]string{"spidly", "--debug_port=2043"}, []string{"spidly", "--debug_port=2043"}},
		{[]string{"agent", "start", "-p", "config.cfg"}, []string{"agent", "start", "-p", "config.cfg"}},
		{[]string{"p1", "--openpassword=admin"}, []string{"p1", "--openpassword=admin"}},
		{[]string{"p1", "-openpassword", "admin"}, []string{"p1", "-openpassword", "admin"}},
		{[]string{"java -openpassword 1234"}, []string{"java -openpassword 1234"}},
		{[]string{"java -open_password 1234"}, []string{"java -open_password 1234"}},
		{[]string{"java -passwordOpen 1234"}, []string{"java -passwordOpen 1234"}},
		{[]string{"java -password_open 1234"}, []string{"java -password_open 1234"}},
		{[]string{"java -password1 1234"}, []string{"java -password1 1234"}},
		{[]string{"java -password_1 1234"}, []string{"java -password_1 1234"}},
		{[]string{"java -1password 1234"}, []string{"java -1password 1234"}},
		{[]string{"java -1_password 1234"}, []string{"java -1_password 1234"}},
	}

	scrubber := setupDataScrubber(t)

	for i := range cases {
		cases[i].cmdline = scrubber.ScrubCmdline(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}
}

func TestMatchWildCards(t *testing.T) {
	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{[]string{"spidly", "--befpass=2043", "onebefpass", "1234", "--befpassCustom=1234"},
			[]string{"spidly", "--befpass=********", "onebefpass", "********", "--befpassCustom=1234"}},
		{[]string{"spidly --befpass=2043 onebefpass 1234 --befpassCustom=1234"},
			[]string{"spidly", "--befpass=********", "onebefpass", "********", "--befpassCustom=1234"}},
		{[]string{"spidly   --befpass=2043   onebefpass   1234   --befpassCustom=1234"},
			[]string{"spidly", "", "", "--befpass=********", "", "", "onebefpass", "", "", "********", "", "", "--befpassCustom=1234"}},

		{[]string{"spidly", "--afterpass=2043", "afterpass_1", "1234", "--befafterpass_1=1234"},
			[]string{"spidly", "--afterpass=********", "afterpass_1", "********", "--befafterpass_1=1234"}},
		{[]string{"spidly --afterpass=2043 afterpass_1 1234 --befafterpass_1=1234"},
			[]string{"spidly", "--afterpass=********", "afterpass_1", "********", "--befafterpass_1=1234"}},
		{[]string{"spidly   --afterpass=2043   afterpass_1   1234   --befafterpass_1=1234"},
			[]string{"spidly", "", "", "--afterpass=********", "", "", "afterpass_1", "", "", "********", "", "", "--befafterpass_1=1234"}},

		{[]string{"spidly", "both", "1234", "-dd_both", "1234", "bothafter", "1234", "--dd_bothafter=1234"},
			[]string{"spidly", "both", "********", "-dd_both", "********", "bothafter", "********", "--dd_bothafter=********"}},
		{[]string{"spidly both 1234 -dd_both 1234 bothafter 1234 --dd_bothafter=1234"},
			[]string{"spidly", "both", "********", "-dd_both", "********", "bothafter", "********", "--dd_bothafter=********"}},
		{[]string{"spidly   both   1234   -dd_both   1234   bothafter   1234   --dd_bothafter=1234"},
			[]string{"spidly", "", "", "both", "", "", "********", "", "", "-dd_both", "", "", "********", "", "", "bothafter", "", "", "********", "", "", "--dd_bothafter=********"}},

		{[]string{"spidly", "middle", "1234", "-mile", "1234", "--mill=1234"},
			[]string{"spidly", "middle", "********", "-mile", "********", "--mill=1234"}},
		{[]string{"spidly middle 1234 -mile 1234 --mill=1234"},
			[]string{"spidly", "middle", "********", "-mile", "********", "--mill=1234"}},
		{[]string{"spidly   middle   1234   -mile   1234   --mill=1234"},
			[]string{"spidly", "", "", "middle", "", "", "********", "", "", "-mile", "", "", "********", "", "", "--mill=1234"}},

		{[]string{"spidly", "--passwd=1234", "password", "1234", "-mypassword", "1234", "--passwords=12345,123456", "--mypasswords=1234,123456"},
			[]string{"spidly", "--passwd=********", "password", "********", "-mypassword", "********", "--passwords=********", "--mypasswords=********"}},
		{[]string{"spidly --passwd=1234 password 1234 -mypassword 1234 --passwords=12345,123456 --mypasswords=1234,123456"},
			[]string{"spidly", "--passwd=********", "password", "********", "-mypassword", "********", "--passwords=********", "--mypasswords=********"}},
		{[]string{"spidly   --passwd=1234   password   1234   -mypassword   1234   --passwords=12345,123456   --mypasswords=1234,123456"},
			[]string{"spidly", "", "", "--passwd=********", "", "", "password", "", "", "********", "", "", "-mypassword", "", "", "********",
				"", "", "--passwords=********", "", "", "--mypasswords=********"}},

		{[]string{"run-middle password 12345"}, []string{"run-middle", "password", "********"}},
		{[]string{"generate-password -password 12345"}, []string{"generate-password", "-password", "********"}},
		{[]string{"generate-password --password=12345"}, []string{"generate-password", "--password=********"}},
	}

	scrubber := setupDataScrubberWildCard(t)

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
	foolCmdline := []string{"python ~/test/run.py --password=1234 -password 1234 -password=admin -open_password 2345 -consul=1234 -p 2808 &"}

	customSensitiveWords := []string{
		"consul_token",
		"dd_password",
		"blocked_from_yaml",
	}
	scrubber := NewDefaultDataScrubber()
	scrubber.AddCustomSensitiveWords(customSensitiveWords)

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
