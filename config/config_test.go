package config

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/gopsutil/process"
	"github.com/stretchr/testify/assert"
)

var originalConfig = config.Datadog

func restoreGlobalConfig() {
	config.Datadog = originalConfig
}

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

func TestOnlyEnvConfig(t *testing.T) {
	// setting an API Key should be enough to generate valid config
	os.Setenv("DD_API_KEY", "apikey_from_env")

	agentConfig, _ := NewAgentConfig("", "", "")
	assert.Equal(t, "apikey_from_env", agentConfig.APIEndpoints[0].APIKey)

	os.Setenv("DD_API_KEY", "")
}

func TestOnlyEnvConfigArgsScrubbingEnabled(t *testing.T) {
	os.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	agentConfig, _ := NewAgentConfig("", "", "")
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

	agentConfig, _ := NewAgentConfig("", "", "")
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

func TestGetHostname(t *testing.T) {
	cfg := NewDefaultAgentConfig()
	h, err := getHostname(cfg.DDAgentPy, cfg.DDAgentBin, cfg.DDAgentPyEnv)
	assert.Nil(t, err)
	assert.NotEqual(t, "", h)
}

func TestDDAgentMultiAPIKeys(t *testing.T) {
	assert := assert.New(t)

	// If no endpoint is given but api_keys are there, match the first api_key
	// with the default endpoint
	agentConfig, err := NewAgentConfig("./testdata/TestDDAgentMultiAPIKeys.ini", "", "")
	assert.NoError(err)

	assert.NotNil(agentConfig)

	assert.Equal(1, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())

	agentConfig, err = NewAgentConfig("./testdata/TestDDAgentMultiAPIKeys-2.ini", "", "")
	assert.NoError(err)

	assert.Equal(2, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal("bar", agentConfig.APIEndpoints[1].APIKey)
	assert.Equal("process.datadoghq.eu", agentConfig.APIEndpoints[1].Endpoint.Hostname())

	// If endpoint count is greater than api_key count, drop additional endpoints
	agentConfig, err = NewAgentConfig("./testdata/TestDDAgentMultiAPIKeys-3.ini", "", "")
	assert.NoError(err)

	assert.Equal(1, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
}

func TestDDAgentMultiEndpointsAndAPIKeys(t *testing.T) {
	assert := assert.New(t)

	agentConfig, err := NewAgentConfig("./testdata/TestDDAgentMultiEndpointsAndAPIKeys.ini", "", "")
	assert.NoError(err)

	assert.Equal(2, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("burrito.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal("bar", agentConfig.APIEndpoints[1].APIKey)
	assert.Equal("burrito2.com", agentConfig.APIEndpoints[1].Endpoint.Hostname())
}

func TestDefaultConfig(t *testing.T) {
	assert := assert.New(t)
	agentConfig := NewDefaultAgentConfig()

	// assert that some sane defaults are set
	assert.Equal("info", agentConfig.LogLevel)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	os.Setenv("DOCKER_DD_AGENT", "yes")
	agentConfig = NewDefaultAgentConfig()
	assert.Equal(os.Getenv("HOST_PROC"), "")
	assert.Equal(os.Getenv("HOST_SYS"), "")
	os.Setenv("DOCKER_DD_AGENT", "no")
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
}

func TestDDAgentConfigWithNewOpts(t *testing.T) {
	assert := assert.New(t)
	// Check that providing process.* options in the dd-agent conf file works

	agentConfig, err := NewAgentConfig("./testdata/TestDDAgentConfigWithNewOpts.ini", "", "")
	assert.NoError(err)

	assert.Equal("apikey_12", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal(5, agentConfig.QueueSize)
	assert.Equal(false, agentConfig.AllowRealTime)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(20, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)
}

func TestDDAgentYamlPreferredWhenINIAlsoExists(t *testing.T) {
	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	defer restoreGlobalConfig()

	assert := assert.New(t)
	// Check that providing process.* options in the dd-agent conf file works
	agentConfig, err := NewAgentConfig(
		"./testdata/TestDDAgentYamlPreferredWhenINIAlsoExists.ini",
		"./testdata/TestDDAgentYamlPreferredWhenINIAlsoExists.yaml",
		"",
	)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(40, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)
}

func TestDDAgentConfigYamlOnly(t *testing.T) {
	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	defer restoreGlobalConfig()

	assert := assert.New(t)

	processDDURL := "http://my-process-app.datadoghq.com"
	config.Datadog.Set("process_config.process_dd_url", processDDURL)

	agentConfig, err := NewAgentConfig("", "./testdata/TestDDAgentConfigYamlOnly.yaml", "")
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

	agentConfig, err = NewAgentConfig("", "./testdata/TestDDAgentConfigYamlOnly-2.yaml", "")
	assert.NoError(err)

	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(-1, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	agentConfig, err = NewAgentConfig("", "./testdata/TestDDAgentConfigYamlOnly-3.yaml", "")
	assert.NoError(err)

	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(15, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	agentConfig, err = NewAgentConfig("", "./testdata/TestDDAgentConfigYamlOnly-4.yaml", "")
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
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(15, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	agentConfig, err = NewAgentConfig("", "./testdata/TestDDAgentConfigYamlOnly-5.yaml", "")
	assert.NoError(err)

	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("test-process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)

	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	agentConfig, err = NewAgentConfig("", "./testdata/TestDDAgentConfigYamlOnly-6.yaml", "")
	assert.NoError(err)

	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datacathq.eu", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)
}

func TestDDAgentConfigYamlAndNetworkConfig(t *testing.T) {
	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	defer restoreGlobalConfig()

	assert := assert.New(t)

	agentConfig, err := NewAgentConfig(
		"",
		"./testdata/TestDDAgentConfigYamlAndNetworkConfig.yaml",
		"",
	)
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

	agentConfig, err = NewAgentConfig(
		"",
		"./testdata/TestDDAgentConfigYamlAndNetworkConfig.yaml",
		"./testdata/TestDDAgentConfigYamlAndNetworkConfig-Net.yaml",
	)

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
	assert.False(agentConfig.DisableTCPTracing)
	assert.False(agentConfig.DisableUDPTracing)
	assert.False(agentConfig.DisableIPv6Tracing)

	agentConfig, err = NewAgentConfig(
		"",
		"./testdata/TestDDAgentConfigYamlAndNetworkConfig.yaml",
		"./testdata/TestDDAgentConfigYamlAndNetworkConfig-Net-2.yaml",
	)

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
	assert.True(agentConfig.DisableTCPTracing)
	assert.True(agentConfig.DisableUDPTracing)
	assert.True(agentConfig.DisableIPv6Tracing)
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

/*
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

	// user is url-encoded and decodes to originalConfig string
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

	// password is url-encoded and decodes to the originalConfig string
	assert.Equal("https://aaditya:%2F%3A%21%3F&=%40%C3%A9%C3%94%CE%B3%CE%BB%E1%BF%B6%CF%83%CF%83%CE%B1@myhost:3129", s.String())

	pass, _ := s.User.Password()
	assert.Equal("/:!?&=@éÔγλῶσσα", pass)
}
*/

func TestEnvSiteConfig(t *testing.T) {
	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	defer restoreGlobalConfig()

	assert := assert.New(t)

	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	agentConfig, err := NewAgentConfig("", "./testdata/TestEnvSiteConfig.yaml", "")
	assert.NoError(err)
	assert.Equal("process.datadoghq.io", agentConfig.APIEndpoints[0].Endpoint.Hostname())

	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	agentConfig, err = NewAgentConfig("", "./testdata/TestEnvSiteConfig-2.yaml", "")
	assert.NoError(err)
	assert.Equal("process.datadoghq.eu", agentConfig.APIEndpoints[0].Endpoint.Hostname())

	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	agentConfig, err = NewAgentConfig("", "./testdata/TestEnvSiteConfig-3.yaml", "")
	assert.NoError(err)
	assert.Equal("burrito.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())

	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	os.Setenv("DD_PROCESS_AGENT_URL", "https://test.com")
	agentConfig, err = NewAgentConfig("", "./testdata/TestEnvSiteConfig-3.yaml", "")
	assert.Equal("test.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
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
