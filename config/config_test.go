package config

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/StackVista/stackstate-agent/pkg/process/util"
	"github.com/StackVista/tcptracer-bpf/pkg/tracer/config"

	"github.com/DataDog/gopsutil/process"
	ddconfig "github.com/StackVista/stackstate-agent/pkg/config"
	"github.com/go-ini/ini"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestBlacklist(t *testing.T) {
	testBlacklist := []string{
		"^getty",
		"^acpid",
		"^atd",
		"^upstart-udev-bridge",
		"^upstart-socket-bridge",
		"^upstart-file-bridge",
		"^dhclient",
		"^dhclient3",
		"^rpc",
		"^dbus-daemon",
		"udevd",
		"^/sbin/",
		"^/usr/sbin/",
		"^/var/ossec/bin/ossec",
		"^rsyslogd",
		"^whoopsie$",
		"^cron$",
		"^CRON$",
		"^/usr/lib/postfix/master$",
		"^qmgr",
		"^pickup",
		"^sleep",
		"^/lib/systemd/systemd-logind$",
		"^/usr/local/bin/goshe dnsmasq$",
	}
	blacklist := make([]*regexp.Regexp, 0, len(testBlacklist))
	for _, b := range testBlacklist {
		r, err := regexp.Compile(b)
		if err == nil {
			blacklist = append(blacklist, r)
		}
	}
	cases := []struct {
		cmdline     []string
		blacklisted bool
	}{
		{[]string{"getty", "-foo", "-bar"}, true},
		{[]string{"rpcbind", "-x"}, true},
		{[]string{"my-rpc-app", "-config foo.ini"}, false},
		{[]string{"rpc.statd", "-L"}, true},
		{[]string{"/usr/sbin/irqbalance"}, true},
	}

	for _, c := range cases {
		assert.Equal(t, c.blacklisted, IsBlacklisted(c.cmdline, blacklist),
			fmt.Sprintf("Case %v failed", c))
	}
}

func TestBlacklistIncludeOnly(t *testing.T) {
	testBlacklist := []string{
		"^[^bla].*",
	}
	blacklist := make([]*regexp.Regexp, 0, len(testBlacklist))
	for _, b := range testBlacklist {
		r, err := regexp.Compile(b)
		if err == nil {
			blacklist = append(blacklist, r)
		}
	}
	cases := []struct {
		cmdline     []string
		blacklisted bool
	}{
		{[]string{"getty", "-foo", "-bar"}, true},
		{[]string{"rpcbind", "-x"}, true},
		{[]string{"my-rpc-app", "-config foo.ini"}, true},
		{[]string{"rpc.statd", "-L"}, true},
		{[]string{"bla"}, false},
		{[]string{"bla -w arguments"}, false},
	}

	for _, c := range cases {
		assert.Equal(t, c.blacklisted, IsBlacklisted(c.cmdline, blacklist),
			fmt.Sprintf("Case %v failed", c))
	}
}

func TestDefaultBlacklist(t *testing.T) {
	var cf *YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"anything: goes",
	}, "\n")), &cf)
	assert.NoError(t, err)

	agentConfig, _ := NewAgentConfig(nil, cf, nil)
	if runtime.GOOS != "windows" {
		assert.True(t, IsBlacklisted([]string{"/usr/sbin/acpid"}, agentConfig.Blacklist))
	} else {
		assert.True(t, IsBlacklisted([]string{"Explorer.EXE"}, agentConfig.Blacklist))
	}
}

func TestDefaultBlacklistWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}

	var cf *YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"anything: goes",
	}, "\n")), &cf)
	assert.NoError(t, err)
	agentConfig, _ := NewAgentConfig(nil, cf, nil)

	for _, tc := range []struct {
		name        string
		processArgs []string
		expected    bool
	}{
		{
			name:        "Should not filter MyOwnApplication.EXE process based on Blacklist",
			processArgs: []string{"MyOwnApplication.EXE"},
			expected:    false,
		},
		{
			name:        "Should filter Explorer.EXE process based on Blacklist",
			processArgs: []string{"Explorer.EXE"},
			expected:    true,
		},
		{
			name:        "Should filter conhost.exe process based on Blacklist",
			processArgs: []string{"conhost.exe"},
			expected:    true,
		},
		{
			name:        "Should filter DllHost.exe process based on Blacklist",
			processArgs: []string{"DllHost.exe"},
			expected:    true,
		},
		{
			name:        "Should filter dwm.exe process based on Blacklist",
			processArgs: []string{"dwm.exe"},
			expected:    true,
		},
		{
			name:        "Should filter tasklist.exe process based on Blacklist",
			processArgs: []string{"tasklist.exe"},
			expected:    true,
		},
		{
			name:        "Should filter VBoxService.exe process based on Blacklist",
			processArgs: []string{"VBoxService.exe"},
			expected:    true,
		},
		{
			name:        "Should filter taskhostw.exe process based on Blacklist",
			processArgs: []string{"taskhostw.exe"},
			expected:    true,
		},
		{
			name:        "Should filter svchost.exe process based on Blacklist",
			processArgs: []string{"svchost.exe"},
			expected:    true,
		},
		{
			name:        "Should filter lsass.exe process based on Blacklist",
			processArgs: []string{"lsass.exe"},
			expected:    true,
		},
		{
			name:        "Should filter msdtc.exe process based on Blacklist",
			processArgs: []string{"msdtc.exe"},
			expected:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter := IsBlacklisted(tc.processArgs, agentConfig.Blacklist)
			assert.Equal(t, tc.expected, filter, "Test: [%s], expected filter: %t, found filter: %t", tc.name, tc.expected, filter)
		})
	}
}

func TestDefaultBlacklistNix(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}

	var cf *YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"anything: goes",
	}, "\n")), &cf)
	assert.NoError(t, err)
	agentConfig, _ := NewAgentConfig(nil, cf, nil)

	for _, tc := range []struct {
		name        string
		processArgs []string
		expected    bool
	}{
		{
			name:        "Should not filter /opt/some-application/bin/app process based on Blacklist",
			processArgs: []string{"/opt/some-application/bin/app", "start", "-h"},
			expected:    false,
		},
		{
			name:        "Should not filter /usr/bin/python2.7 process based on Blacklist",
			processArgs: []string{"/usr/bin/python2.7", "my-py-application"},
			expected:    false,
		},
		{
			name:        "Should not filter /usr/local/openjdk-8/bin/java process based on Blacklist",
			processArgs: []string{"/usr/local/openjdk-8/bin/java", "my-java-application"},
			expected:    false,
		},
		{
			name:        "Should filter sleep process based on Blacklist",
			processArgs: []string{"sleep", "15"},
			expected:    true,
		},
		{
			name:        "Should filter -sh process based on Blacklist",
			processArgs: []string{"-sh", "something"},
			expected:    true,
		},
		{
			name:        "Should filter msdtc.exe process based on Blacklist",
			processArgs: []string{"sshd:", ""},
			expected:    true,
		},
		{
			name:        "Should filter pause process based on Blacklist",
			processArgs: []string{"pause"},
			expected:    true,
		},
		{
			name:        "Should filter /usr/bin/vim process based on Blacklist",
			processArgs: []string{"/usr/bin/vim", "some-text-file"},
			expected:    true,
		},
		{
			name:        "Should filter everything in /usr/sbin based on Blacklist",
			processArgs: []string{"/usr/sbin/everything"},
			expected:    true,
		},
		{
			name:        "Should filter s6-format-filter process based on Blacklist",
			processArgs: []string{"s6-format-filter"},
			expected:    true,
		},
		{
			name:        "Should filter dotnet process based on Blacklist",
			processArgs: []string{"dotnet", "my-dotnet-application"},
			expected:    true,
		},
		{
			name:        "Should filter /usr/bin/containerd process based on Blacklist",
			processArgs: []string{"/usr/bin/containerd"},
			expected:    true,
		},
		{
			name:        "Should filter bash process based on Blacklist",
			processArgs: []string{"bash", "some-bash-process"},
			expected:    true,
		},
		{
			name:        "Should filter docker-container-shim process based on Blacklist",
			processArgs: []string{"docker-container-shim"},
			expected:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter := IsBlacklisted(tc.processArgs, agentConfig.Blacklist)
			assert.Equal(t, tc.expected, filter, "Test: [%s], expected filter: %t, found filter: %t", tc.name, tc.expected, filter)
		})
	}
}

func TestSetFiltersFromEnv(t *testing.T) {
	os.Setenv("STS_PROCESS_CACHE_DURATION_MIN", "2")
	os.Setenv("STS_NETWORK_RELATION_CACHE_DURATION_MIN", "4")
	os.Setenv("STS_PROCESS_FILTER_SHORT_LIVED_QUALIFIER_SECS", "0")
	os.Setenv("STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS", "45")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)

	assert.Equal(t, 2*time.Minute, agentConfig.ProcessCacheDurationMin)
	assert.Equal(t, 4*time.Minute, agentConfig.NetworkRelationCacheDurationMin)
	assert.Equal(t, false, agentConfig.EnableShortLivedProcessFilter)
	assert.Equal(t, 0*time.Second, agentConfig.ShortLivedProcessQualifierSecs)
	assert.Equal(t, true, agentConfig.EnableShortLivedNetworkRelationFilter)
	assert.Equal(t, 45*time.Second, agentConfig.ShortLivedNetworkRelationQualifierSecs)

	os.Unsetenv("STS_PROCESS_CACHE_DURATION_MIN")
	os.Unsetenv("STS_NETWORK_RELATION_CACHE_DURATION_MIN")
	os.Unsetenv("STS_PROCESS_FILTER_SHORT_LIVED_QUALIFIER_SECS")
	os.Unsetenv("STS_NETWORK_RELATION_FILTER_SHORT_LIVED_QUALIFIER_SECS")
}

func TestSetBlacklistFromEnv(t *testing.T) {
	os.Setenv("STS_PROCESS_BLACKLIST_PATTERNS", "^/usr/bin/bashbash,^sshd:")

	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_CPU", "2")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_READ", "4")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_WRITE", "5")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_MEM", "6")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_CPU_THRESHOLD", "30")
	os.Setenv("STS_PROCESS_BLACKLIST_INCLUSIONS_MEM_THRESHOLD", "25")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)
	assert.Equal(t, len(agentConfig.Blacklist), 2)

	assert.Equal(t, agentConfig.AmountTopCPUPercentageUsage, 2)
	assert.Equal(t, agentConfig.AmountTopIOReadUsage, 4)
	assert.Equal(t, agentConfig.AmountTopIOWriteUsage, 5)
	assert.Equal(t, agentConfig.AmountTopMemoryUsage, 6)
	assert.Equal(t, agentConfig.CPUPercentageUsageThreshold, 30)
	assert.Equal(t, agentConfig.MemoryUsageThreshold, 25)

	os.Unsetenv("STS_PROCESS_BLACKLIST_PATTERNS")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_CPU")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_READ")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_IO_WRITE")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_TOP_MEM")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_CPU_THRESHOLD")
	os.Unsetenv("STS_PROCESS_BLACKLIST_INCLUSIONS_MEM_THRESHOLD")
}

func TestSetNetworkTracerInitRetryFromEnv(t *testing.T) {
	os.Setenv("STS_NETWORK_TRACER_INIT_RETRY_DURATION_SEC", "30")
	os.Setenv("STS_NETWORK_TRACER_INIT_RETRY_AMOUNT", "4")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)

	assert.Equal(t, 30*time.Second, agentConfig.NetworkTracerInitRetryDuration)
	assert.Equal(t, 4, agentConfig.NetworkTracerInitRetryAmount)

	os.Unsetenv("STS_NETWORK_TRACER_INIT_RETRY_DURATION_SEC")
	os.Unsetenv("STS_NETWORK_TRACER_INIT_RETRY_AMOUNT")
}

func TestOnlyEnvConfig(t *testing.T) {
	// setting an API Key should be enough to generate valid config
	os.Setenv("DD_API_KEY", "apikey_from_env")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)
	assert.Equal(t, "apikey_from_env", agentConfig.APIEndpoints[0].APIKey)

	os.Setenv("DD_API_KEY", "")
}

func TestOnlyEnvConfigArgsScrubbingEnabled(t *testing.T) {
	os.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)
	assert.Equal(t, true, agentConfig.Scrubber.Enabled)

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
			[]string{"spidly", "--mypasswords=********", "consul_token", "********", "--dd_api_key=********"},
		},
	}

	for i := range cases {
		cases[i].cmdline, _ = agentConfig.Scrubber.scrubCommand(cases[i].cmdline)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}

	os.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "")
}

func TestOnlyEnvConfigArgsScrubbingDisabled(t *testing.T) {
	os.Setenv("DD_SCRUB_ARGS", "false")
	os.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)
	assert.Equal(t, false, agentConfig.Scrubber.Enabled)

	cases := []struct {
		cmdline       []string
		parsedCmdline []string
	}{
		{
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
			[]string{"spidly", "--mypasswords=123,456", "consul_token", "1234", "--dd_api_key=1234"},
		},
	}

	for i := range cases {
		fp := &process.FilledProcess{Cmdline: cases[i].cmdline}
		cases[i].cmdline = agentConfig.Scrubber.ScrubProcessCommand(fp)
		assert.Equal(t, cases[i].parsedCmdline, cases[i].cmdline)
	}

	os.Setenv("DD_SCRUB_ARGS", "")
	os.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "")
}

func TestConfigNewIfExists(t *testing.T) {
	// The file does not exist: no error returned
	conf, err := NewIfExists("/does-not-exist")
	assert.Nil(t, err)
	assert.Nil(t, conf)

	// The file exists but cannot be read for another reason: an error is
	// returned.
	var filename string
	// [BS] This test does not work as root, because root can read everything
	curUser, err := user.Current()
	assert.Nil(t, err)
	if runtime.GOOS != "windows" && curUser.Uid != "0" {

		//go doesn't honor the file permissions, so skip this test on Windows

		filename = "/tmp/process-agent-test-config.ini"
		os.Remove(filename)
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0200) // write only
		assert.Nil(t, err)
		f.Close()
		conf, err = NewIfExists(filename)
		//  [VS]  &config.File{instance:(*ini.File)(0xc4204013b0), Path:"/tmp/process-agent-test-config.ini"}
		assert.NotNil(t, err)
		assert.Nil(t, conf)
		os.Remove(filename)
	}
}

func TestGetHostname(t *testing.T) {
	cfg := NewDefaultAgentConfig()
	h, err := getHostname(cfg.DDAgentPy, cfg.DDAgentBin, cfg.DDAgentPyEnv)
	assert.Nil(t, err)
	assert.NotEqual(t, "", h)
}

func TestDDAgentMultiAPIKeys(t *testing.T) {
	// if no endpoint is given but api_keys are there, match the first api_key
	// with the default endpoint
	assert := assert.New(t)
	ddAgentConf, _ := ini.Load([]byte("[Main]\n\napi_key=foo,bar "))
	configFile := &File{instance: ddAgentConf, Path: "whatever"}
	agentConfig, err := NewAgentConfig(configFile, nil, nil)
	assert.NoError(err)
	assert.Equal(1, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	de, err := url.Parse(defaultEndpoint)
	assert.NoError(err)
	assert.Equal(de.Hostname(), agentConfig.APIEndpoints[0].Endpoint.Hostname())

	ddAgentConf, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"api_key=foo,bar",
		"[process.config]",
		"endpoint=https://process.datadoghq.com,https://process.datadoghq.eu",
	}, "\n")))
	configFile = &File{instance: ddAgentConf, Path: "whatever"}
	agentConfig, err = NewAgentConfig(configFile, nil, nil)
	assert.NoError(err)
	assert.Equal(2, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal("bar", agentConfig.APIEndpoints[1].APIKey)
	assert.Equal("process.datadoghq.eu", agentConfig.APIEndpoints[1].Endpoint.Hostname())

	// if endpoint count is greater than api_key count, drop additional endpoints
	ddAgentConf, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"api_key=foo",
		"[process.config]",
		"endpoint=https://process.datadoghq.com,https://process.datadoghq.eu",
	}, "\n")))
	configFile = &File{instance: ddAgentConf, Path: "whatever"}
	agentConfig, err = NewAgentConfig(configFile, nil, nil)
	assert.NoError(err)
	assert.Equal(1, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
}

func TestDefaultConfig(t *testing.T) {
	assert := assert.New(t)
	agentConfig := NewDefaultAgentConfig()

	// assert that some sane defaults are set
	assert.Equal("info", agentConfig.LogLevel)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	os.Setenv("DOCKER_DD_AGENT", "yes")
	agentConfig = NewDefaultAgentConfig()
	if util.PathExists("/host") {
		assert.Equal(os.Getenv("HOST_PROC"), "/host/proc")
		assert.Equal(os.Getenv("HOST_SYS"), "/host/sys")
	} else {
		assert.Equal(os.Getenv("HOST_PROC"), "")
		assert.Equal(os.Getenv("HOST_SYS"), "")
	}
	os.Setenv("DOCKER_DD_AGENT", "no")
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
}

func TestDDAgentConfigWithNewOpts(t *testing.T) {
	assert := assert.New(t)
	// Check that providing process.* options in the dd-agent conf file works
	dd, _ := ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"hostname = thing",
		"api_key = apikey_12",
		"[process.config]",
		"queue_size = 5",
		"allow_real_time = false",
		"windows_args_refresh_interval = 20",
	}, "\n")))

	conf := &File{instance: dd, Path: "whatever"}
	agentConfig, err := NewAgentConfig(conf, nil, nil)
	assert.NoError(err)

	assert.Equal("apikey_12", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal(5, agentConfig.QueueSize)
	assert.Equal(false, agentConfig.AllowRealTime)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(20, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)
}

func TestDDAgentConfigBothVersions(t *testing.T) {
	assert := assert.New(t)
	// Check that providing process.* options in the dd-agent conf file works
	dd, _ := ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"hostname = thing",
		"api_key = apikey_12",
		"[process.config]",
		"queue_size = 5",
		"allow_real_time = false",
		"windows_args_refresh_interval = 30",
	}, "\n")))

	var ddy *YamlAgentConfig
	processDDURL := "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_config:",
		"  queue_size: 10",
		"  windows:",
		"    args_refresh_interval: 40",
	}, "\n")), &ddy)
	assert.NoError(err)

	conf := &File{instance: dd, Path: "whatever"}
	agentConfig, err := NewAgentConfig(conf, ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(false, agentConfig.AllowRealTime)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(40, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)
}

func TestDDAgentConfigYamlOnly(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	processDDURL := "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  windows:",
		"    args_refresh_interval: 100",
		"    add_new_args: false",
		"  scrub_args: false",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(true, agentConfig.EnableIncrementalPublishing)
	assert.Equal(1*time.Minute, agentConfig.IncrementalPublishingRefreshInterval)
	assert.Equal(processChecks, agentConfig.EnabledChecks)
	assert.Equal(8*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(30*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(100, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(false, agentConfig.Windows.AddNewArgs)
	assert.Equal(false, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	processDDURL = "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"incremental_publishing_enabled: false",
		"incremental_publishing_refresh_interval: 120",
		"process_config:",
		"  enabled: 'false'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  windows:",
		"    args_refresh_interval: -1",
		"    add_new_args: true",
		"  scrub_args: true",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)
	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(false, agentConfig.EnableIncrementalPublishing)
	assert.Equal(2*time.Minute, agentConfig.IncrementalPublishingRefreshInterval)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(-1, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	processDDURL = "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'disabled'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)
	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(15, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	processDDURL = "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'disabled'",
		"  additional_endpoints:",
		"    https://process.datadoghq.eu:",
		"      - foo",
		"      - bar",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)
	eps := agentConfig.APIEndpoints
	assert.Len(agentConfig.APIEndpoints, 3)
	assert.Equal("apikey_20", eps[0].APIKey)
	assert.Equal("my-process-app.datadoghq.com", eps[0].Endpoint.Hostname())
	assert.Equal("foo", eps[1].APIKey)
	assert.Equal("process.datadoghq.eu", eps[1].Endpoint.Hostname())
	assert.Equal("bar", eps[2].APIKey)
	assert.Equal("process.datadoghq.eu", eps[2].Endpoint.Hostname())
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(processChecks, agentConfig.EnabledChecks) // sts
	assert.Equal(15, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	ddy = YamlAgentConfig{}
	site := "datadoghq.eu"
	processDDURL = "http://test-process.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	ddconfig.Datadog.Set("site", site)
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"site: " + site,
		"process_config:",
		"  enabled: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)
	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("test-process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)

	ddy = YamlAgentConfig{}
	site = "datacathq.eu"
	ddconfig.Datadog.Set("process_config.process_dd_url", "")
	ddconfig.Datadog.Set("site", site)
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"site: " + site,
		"process_config:",
		"  enabled: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)
	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datacathq.eu", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)

	ddconfig.Datadog.Set("process_config.process_dd_url", "")
	ddconfig.Datadog.Set("site", "")
}

func TestDDAgentConfigYamlAndNetworkConfig(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	processDDURL := "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  windows:",
		"    args_refresh_interval: 100",
		"    add_new_args: false",
		"  scrub_args: false",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(processChecks, agentConfig.EnabledChecks)
	assert.Equal(8*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(30*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(100, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(false, agentConfig.Windows.AddNewArgs)
	assert.Equal(false, agentConfig.Scrubber.Enabled)

	var netYamlConf YamlAgentConfig
	err = yaml.Unmarshal([]byte(strings.Join([]string{
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  nettracer_socket: /var/my-location/network-tracer.log",
	}, "\n")), &netYamlConf)
	assert.NoError(err)

	agentConfig, err = NewAgentConfig(nil, &ddy, &netYamlConf)

	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(8*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(30*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(100, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(false, agentConfig.Windows.AddNewArgs)
	assert.Equal(false, agentConfig.Scrubber.Enabled)
	assert.Equal("/var/my-location/network-tracer.log", agentConfig.NetworkTracerSocketPath)
	assert.Equal(append(processChecks, "connections"), agentConfig.EnabledChecks)
}

func TestStackStateNetworkConfigFromMainAgentConfig(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	processDDURL := "http://my-process-app.datadoghq.com"
	ddconfig.Datadog.Set("process_config.process_dd_url", processDDURL)
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"  network_relation_cache_duration_min: 10",
		"  process_cache_duration_min: 15",
		"  filters:",
		"    short_lived_processes:",
		"      enabled: 'false'",
		"      qualifier_secs: 20",
		"    short_lived_network_relations:",
		"      enabled: true",
		"      qualifier_secs: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(8*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(30*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(true, agentConfig.NetworkInitialConnectionsFromProc)
	assert.Equal(10000, agentConfig.NetworkTracerMaxConnections)
	assert.Equal(append(processChecks, "connections"), agentConfig.EnabledChecks)
	assert.Equal(10*time.Minute, agentConfig.NetworkRelationCacheDurationMin)
	assert.Equal(15*time.Minute, agentConfig.ProcessCacheDurationMin)
	assert.Equal(false, agentConfig.EnableShortLivedProcessFilter)
	assert.Equal(20*time.Second, agentConfig.ShortLivedProcessQualifierSecs)
	assert.Equal(true, agentConfig.EnableShortLivedNetworkRelationFilter)
	assert.Equal(30*time.Second, agentConfig.ShortLivedNetworkRelationQualifierSecs)
}

func TestStackStateNetworkConfigWithHttpMetricsOptions(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  max_connections: 2000
  network_tracing_enabled: 'true'
  protocol_inspection_enabled: 'true'
  ebpf_debuglog_enabled: 'true'
  http_metrics:
    sketch_type: 'collapsing_highest_dense'
    max_num_bins: 42
    accuracy: 0.123
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	assert.Equal(true, agentConfig.NetworkTracer.EnableProtocolInspection)
	assert.Equal(true, agentConfig.NetworkTracer.EbpfDebuglogEnabled)
	assert.Equal(config.CollapsingHighest, agentConfig.NetworkTracer.HTTPMetrics.SketchType)
	assert.Equal(2000, agentConfig.NetworkTracerMaxConnections)
	assert.Equal(42, agentConfig.NetworkTracer.HTTPMetrics.MaxNumBins)
	assert.Equal(0.123, agentConfig.NetworkTracer.HTTPMetrics.Accuracy)
}

func TestStackStateNetworkConfigDefaultValuesForHttpMetrics(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  network_tracing_enabled: 'true'
  http_metrics:

`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	assert.Equal(true, agentConfig.NetworkTracer.EnableProtocolInspection)
	assert.Equal(config.CollapsingLowest, agentConfig.NetworkTracer.HTTPMetrics.SketchType)
	assert.Equal(1024, agentConfig.NetworkTracer.HTTPMetrics.MaxNumBins)
	assert.Equal(0.01, agentConfig.NetworkTracer.HTTPMetrics.Accuracy)
}
func TestStackStateNetworkConfigProtocolInspectionDisabled(t *testing.T) {
	assert := assert.New(t)
	var ddy YamlAgentConfig
	err := yaml.Unmarshal(
		[]byte(`
network_tracer_config:
  protocol_inspection_enabled: 'false'
`), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	assert.Equal(false, agentConfig.NetworkTracer.EnableProtocolInspection)
}

func TestProxyEnv(t *testing.T) {
	assert := assert.New(t)
	for i, tc := range []struct {
		host     string
		port     int
		user     string
		pass     string
		expected string
	}{
		{
			"example.com",
			1234,
			"",
			"",
			"http://example.com:1234",
		},
		{
			"https://example.com",
			4567,
			"foo",
			"bar",
			"https://foo:bar@example.com:4567",
		},
		{
			"example.com",
			0,
			"foo",
			"",
			"http://foo@example.com:3128",
		},
	} {
		os.Setenv("PROXY_HOST", tc.host)
		if tc.port > 0 {
			os.Setenv("PROXY_PORT", strconv.Itoa(tc.port))
		} else {
			os.Setenv("PROXY_PORT", "")
		}
		os.Setenv("PROXY_USER", tc.user)
		os.Setenv("PROXY_PASSWORD", tc.pass)
		pf, err := proxyFromEnv(nil)
		assert.NoError(err, "proxy case %d had error", i)
		u, err := pf(&http.Request{})
		assert.NoError(err)
		assert.Equal(tc.expected, u.String())
	}
}

func TestEnvOverrides(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("STS_NETWORK_TRACER_MAX_CONNECTIONS", "500")
	os.Setenv("STS_CLUSTER_NAME", "test-override")
	os.Setenv("STS_MAX_PROCESSES_PER_MESSAGE", "501")
	os.Setenv("STS_MAX_CONNECTIONS_PER_MESSAGE", "502")
	os.Setenv("STS_PROTOCOL_INSPECTION_ENABLED", "false")
	os.Setenv("DD_NETWORK_TRACING_ENABLED", "true")
	os.Setenv("STS_EBPF_DEBUG_LOG_ENABLED", "true")

	agentConfig, _ := NewAgentConfig(nil, nil, nil)

	assert.Equal(500, agentConfig.NetworkTracerMaxConnections)
	assert.Equal(501, agentConfig.MaxPerMessage)
	assert.Equal(502, agentConfig.MaxConnectionsPerMessage)
	assert.Equal(false, agentConfig.NetworkTracer.EnableProtocolInspection)
	assert.Equal(true, agentConfig.EnableNetworkTracing)
	assert.Equal(true, agentConfig.NetworkTracer.EbpfDebuglogEnabled)
}

func getURL(f *ini.File) (*url.URL, error) {
	conf := File{
		f,
		"some/path",
	}
	m, _ := conf.GetSection("Main")
	pf, err := getProxySettings(m)
	if err != nil {
		return nil, err
	}
	return pf(&http.Request{})
}

func TestGetProxySettings(t *testing.T) {
	assert := assert.New(t)

	f, _ := ini.Load([]byte("[Main]\n\nproxy_host = myhost"))

	s, err := getURL(f)
	assert.NoError(err)
	assert.Equal("http://myhost:3128", s.String())

	f, _ = ini.Load([]byte("[Main]\n\nproxy_host = http://myhost"))

	s, err = getURL(f)
	assert.NoError(err)
	assert.Equal("http://myhost:3128", s.String())

	f, _ = ini.Load([]byte("[Main]\n\nproxy_host = https://myhost"))

	s, err = getURL(f)
	assert.NoError(err)
	assert.Equal("https://myhost:3128", s.String())

	// generic user name
	f, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"proxy_host = https://myhost",
		"proxy_port = 3129",
		"proxy_user = aaditya",
	}, "\n")))

	s, err = getURL(f)
	assert.NoError(err)

	assert.Equal("https://aaditya@myhost:3129", s.String())

	// special char in user name <3
	f, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"proxy_host = myhost",
		"proxy_port = 3129",
		"proxy_user = léo",
	}, "\n")))

	s, err = getURL(f)
	assert.NoError(err)

	// user is url-encoded and decodes to original string
	assert.Equal("http://l%C3%A9o@myhost:3129", s.String())
	assert.Equal("léo", s.User.Username())

	// generic  user-pass
	f, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"proxy_host = myhost",
		"proxy_port = 3129",
		"proxy_user = aaditya",
		"proxy_password = password_12",
	}, "\n")))

	s, err = getURL(f)
	assert.NoError(err)
	assert.Equal("http://aaditya:password_12@myhost:3129", s.String())

	// user-pass with schemed host
	f, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"proxy_host = https://myhost",
		"proxy_port = 3129",
		"proxy_user = aaditya",
		"proxy_password = password_12",
	}, "\n")))

	s, err = getURL(f)
	assert.NoError(err)
	assert.Equal("https://aaditya:password_12@myhost:3129", s.String())

	// special characters in password
	f, _ = ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"proxy_host = https://myhost",
		"proxy_port = 3129",
		"proxy_user = aaditya",
		"proxy_password = /:!?&=@éÔγλῶσσα",
	}, "\n")))

	s, err = getURL(f)
	assert.NoError(err)

	// password is url-encoded and decodes to the original string
	assert.Equal("https://aaditya:%2F%3A%21%3F&=%40%C3%A9%C3%94%CE%B3%CE%BB%E1%BF%B6%CF%83%CF%83%CE%B1@myhost:3129", s.String())

	pass, _ := s.User.Password()
	assert.Equal("/:!?&=@éÔγλῶσσα", pass)
}

func TestEnvSiteConfig(t *testing.T) {
	ddconfig.Datadog.Set("process_config.process_dd_url", "")
	assert := assert.New(t)
	for _, tc := range []struct {
		site     string
		ddURL    string
		expected string
	}{
		{
			"datadoghq.io",
			"",
			"process.datadoghq.io",
		},
		{
			"",
			"https://process.datadoghq.eu",
			"process.datadoghq.eu",
		},
		{
			"datacathq.eu",
			"https://burrito.com",
			"burrito.com",
		},
	} {
		// Fake the os.Setenv("DD_SITE", tc.site)
		ddconfig.Datadog.Set("site", tc.site)
		os.Setenv("DD_PROCESS_AGENT_URL", tc.ddURL)

		agentConfig, err := NewAgentConfig(nil, &YamlAgentConfig{}, nil)
		assert.NoError(err)
		assert.Equal(tc.expected, agentConfig.APIEndpoints[0].Endpoint.Hostname())
	}
}

func TestIsAffirmative(t *testing.T) {
	value, err := isAffirmative("yes")
	assert.Nil(t, err)
	assert.True(t, value)

	value, err = isAffirmative("True")
	assert.Nil(t, err)
	assert.True(t, value)

	value, err = isAffirmative("1")
	assert.Nil(t, err)
	assert.True(t, value)

	_, err = isAffirmative("")
	assert.NotNil(t, err)

	value, err = isAffirmative("ok")
	assert.Nil(t, err)
	assert.False(t, value)
}

//custom tests

func TestStackStateFallbackAgentConfigToProcessSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("DD_PROCESS_AGENT_URL")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"sts_url: http://default-endpoint.test.stackstate.com",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  process_sts_url: http://process-endpoint.test.stackstate.com",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("process-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestStackStateFallbackAgentConfigToSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("DD_PROCESS_AGENT_URL")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"sts_url: http://default-endpoint.test.stackstate.com",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestStackStateFallbackAgentConfigToEnvSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("DD_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestStackStateFallbackAgentConfigEmptyUrlToEnvSTSUrl(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("DD_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  process_sts_url: ",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

//case 5: STS_URL as env	PROCESS_AGENT_URL as env
func TestStackStatePreferAgentConfigToEnvPROCESS_AGENT_URL(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("DD_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	os.Setenv("DD_PROCESS_AGENT_URL", "http://process-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("process-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

//case 7: STS_URL as env	PROCESS_AGENT_URL as yaml - STS URL wins, more specific
func TestStackStatePreferSTS_STS_URLOverYamlProcessAgentConfig(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("DD_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("STS_STS_URL", "http://default-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  process_sts_url: http://process-endpoint.test.stackstate.com",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("default-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

//case 8: STS_URL as yaml, PROCESS_AGENT_URL as env - ENV wins
func TestStackStatePreferPROCESS_AGENT_URLOverYamlsts_sts_url(t *testing.T) {
	assert := assert.New(t)
	os.Unsetenv("STS_PROCESS_AGENT_URL")
	os.Unsetenv("STS_STS_URL")
	os.Setenv("DD_PROCESS_AGENT_URL", "http://process-endpoint.test.stackstate.com")
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"api_key: apikey_30",
		"sts_url: http://default-endpoint.test.stackstate.com",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'true'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
		"network_tracer_config:",
		"  network_tracing_enabled: 'true'",
		"  initial_connections_from_proc: 'true'",
	}, "\n")), &ddy)
	assert.NoError(err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_30", ep.APIKey)
	assert.Equal("process-endpoint.test.stackstate.com", ep.Endpoint.Hostname())
}

func TestNetworkTracerInitRetry_FromYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"network_tracer_config:",
		"  network_tracer_retry_init_duration_sec: 50",
		"  network_tracer_retry_init_amount: 10",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(t, err)

	assert.Equal(t, 10, agentConfig.NetworkTracerInitRetryAmount)
	assert.Equal(t, 50*time.Second, agentConfig.NetworkTracerInitRetryDuration)
}

func TestStsSkipSllValidation(t *testing.T) {
	_ = os.Setenv("STS_SKIP_SSL_VALIDATION", "true")
	_, err := NewAgentConfig(nil, &YamlAgentConfig{}, nil)
	assert.NoError(t, err)
	assert.Equal(t, "true", ddconfig.Datadog.GetString("skip_ssl_validation"))
}

func TestCheckIntervalCodeDefaults(t *testing.T) {
	agentConfig, err := NewAgentConfig(nil, nil, nil)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(30)*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(t, time.Duration(30)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(30)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestCheckIntervalCodeDefaults_FromYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"process_config:",
		"  intervals:",
		"    container: 10",
		"    process: 10",
		"    connections: 10",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(10)*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(t, time.Duration(10)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(10)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestCheckIntervalCodeDefaults_FromEnv(t *testing.T) {
	os.Setenv("STS_CONTAINER_CHECK_INTERVAL", "15")
	os.Setenv("STS_PROCESS_CHECK_INTERVAL", "15")
	os.Setenv("STS_CONNECTION_CHECK_INTERVAL", "15")

	agentConfig, err := NewAgentConfig(nil, nil, nil)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(15)*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(t, time.Duration(15)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(15)*time.Second, agentConfig.CheckIntervals["connections"])
}

func TestCheckIntervalCodeDefaults_FromEnvOverridesYaml(t *testing.T) {
	var ddy YamlAgentConfig
	err := yaml.Unmarshal([]byte(strings.Join([]string{
		"process_config:",
		"  intervals:",
		"    container: 10",
		"    process: 10",
		"    connections: 10",
	}, "\n")), &ddy)
	assert.NoError(t, err)

	os.Setenv("STS_CONTAINER_CHECK_INTERVAL", "20")
	os.Setenv("STS_PROCESS_CHECK_INTERVAL", "20")
	os.Setenv("STS_CONNECTION_CHECK_INTERVAL", "20")

	agentConfig, err := NewAgentConfig(nil, &ddy, nil)
	assert.NoError(t, err)

	assert.Equal(t, time.Duration(20)*time.Second, agentConfig.CheckIntervals["container"])
	assert.Equal(t, time.Duration(20)*time.Second, agentConfig.CheckIntervals["process"])
	assert.Equal(t, time.Duration(20)*time.Second, agentConfig.CheckIntervals["connections"])
}
