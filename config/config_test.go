package config

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	ddconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/gopsutil/process"
	"github.com/go-ini/ini"
	"github.com/stretchr/testify/assert"
)

func newDDConfig() ddconfig.Config {
	return ddconfig.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
}

func newAgentConfig(agentIni, agentYaml, networkYaml io.Reader) (*AgentConfig, error) {
	return NewAgentConfig(newDDConfig(), agentIni, agentYaml, networkYaml)
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

	agentConfig, err := newAgentConfig(nil, nil, nil)
	assert.Nil(t, err)
	assert.Equal(t, "apikey_from_env", agentConfig.APIEndpoints[0].APIKey)

	os.Setenv("DD_API_KEY", "")
}

func TestOnlyEnvConfigArgsScrubbingEnabled(t *testing.T) {
	os.Setenv("DD_CUSTOM_SENSITIVE_WORDS", "*password*,consul_token,*api_key")

	agentConfig, err := newAgentConfig(nil, nil, nil)
	assert.Nil(t, err)
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

	agentConfig, _ := newAgentConfig(nil, nil, nil)
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

func TestConfigNewFromReaderIfExists(t *testing.T) {
	// nil reader
	conf, err := NewFromReaderIfExists(nil)
	assert.Nil(t, err)
	assert.Nil(t, conf)

	// Valid reader
	conf, err = NewFromReaderIfExists(strings.NewReader("[Main]\ntest = 5"))
	assert.Nil(t, err)
	assert.NotNil(t, conf)
}

func TestConfigNewIfExists(t *testing.T) {
	// The file does not exist: no error returned
	conf, err := NewIfExists("/does-not-exist")
	assert.Nil(t, err)
	assert.Nil(t, conf)

	// The file exists but cannot be read for another reason: an error is
	// returned.
	var filename string
	if runtime.GOOS != "windows" {

		//go doesn't honor the file permissions, so skip this test on Windows

		filename = "/tmp/process-agent-test-config.ini"
		os.Remove(filename)
		f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0200) // write only
		assert.Nil(t, err)
		f.Close()
		conf, err = NewIfExists(filename)
		assert.NotNil(t, err)
		assert.Nil(t, conf)
		//os.Remove(filename)
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
	configFile := strings.NewReader("[Main]\n\napi_key=foo,bar ")
	agentConfig, err := newAgentConfig(configFile, nil, nil)
	assert.NoError(err)
	assert.Equal(1, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())

	configFile = strings.NewReader(strings.Join([]string{
		"[Main]",
		"api_key=foo,bar",
		"[process.config]",
		"endpoint=https://process.datadoghq.com,https://process.datadoghq.eu",
	}, "\n"))
	agentConfig, err = newAgentConfig(configFile, nil, nil)
	assert.NoError(err)
	assert.Equal(2, len(agentConfig.APIEndpoints))
	assert.Equal("foo", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal("bar", agentConfig.APIEndpoints[1].APIKey)
	assert.Equal("process.datadoghq.eu", agentConfig.APIEndpoints[1].Endpoint.Hostname())

	// if endpoint count is greater than api_key count, drop additional endpoints
	configFile = strings.NewReader(strings.Join([]string{
		"[Main]",
		"api_key=foo",
		"[process.config]",
		"endpoint=https://process.datadoghq.com,https://process.datadoghq.eu",
	}, "\n"))
	agentConfig, err = newAgentConfig(configFile, nil, nil)
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
	conf := strings.NewReader(strings.Join([]string{
		"[Main]",
		"hostname = thing",
		"api_key = apikey_12",
		"[process.config]",
		"queue_size = 5",
		"allow_real_time = false",
		"windows_args_refresh_interval = 20",
	}, "\n"))

	agentConfig, err := newAgentConfig(conf, nil, nil)
	assert.NoError(err)

	assert.Equal("apikey_12", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal(5, agentConfig.QueueSize)
	assert.Equal(false, agentConfig.AllowRealTime)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(20, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)
}

func TestDDAgentConfigBothVersions(t *testing.T) {
	assert := assert.New(t)
	// Check that providing process.* options in the dd-agent conf file works
	conf := strings.NewReader(strings.Join([]string{
		"[Main]",
		"hostname = thing",
		"api_key = apikey_12",
		"[process.config]",
		"queue_size = 5",
		"allow_real_time = false",
		"windows_args_refresh_interval = 30",
	}, "\n"))

	processDDURL := "http://my-process-app.datadoghq.com"

	ddc := newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)

	ddy := strings.NewReader(strings.Join([]string{
		"api_key: apikey_20",
		"process_config:",
		"  queue_size: 10",
		"  windows:",
		"    args_refresh_interval: 40",
	}, "\n"))

	agentConfig, err := NewAgentConfig(ddc, conf, ddy, nil)
	assert.NoError(err)

	ep := agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(10, agentConfig.QueueSize)
	assert.Equal(false, agentConfig.AllowRealTime)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(40, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)
}

func TestDDAgentConfigYamlOnly(t *testing.T) {
	assert := assert.New(t)
	processDDURL := "http://my-process-app.datadoghq.com"

	ddc := newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)

	ddy := strings.NewReader(strings.Join([]string{
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
	}, "\n"))

	agentConfig, err := NewAgentConfig(ddc, nil, ddy, nil)
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

	processDDURL = "http://my-process-app.datadoghq.com"
	ddc = newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)
	ddy = strings.NewReader(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
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
	}, "\n"))

	agentConfig, err = NewAgentConfig(ddc, nil, ddy, nil)
	assert.NoError(err)
	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(-1, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	processDDURL = "http://my-process-app.datadoghq.com"
	ddc = newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)
	ddy = strings.NewReader(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"process_config:",
		"  enabled: 'disabled'",
		"  queue_size: 10",
		"  intervals:",
		"    container: 8",
		"    process: 30",
	}, "\n"))

	agentConfig, err = NewAgentConfig(ddc, nil, ddy, nil)
	assert.NoError(err)
	ep = agentConfig.APIEndpoints[0]
	assert.Equal("apikey_20", ep.APIKey)
	assert.Equal("my-process-app.datadoghq.com", ep.Endpoint.Hostname())
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
	assert.Equal(15, agentConfig.Windows.ArgsRefreshInterval)
	assert.Equal(true, agentConfig.Windows.AddNewArgs)
	assert.Equal(true, agentConfig.Scrubber.Enabled)

	processDDURL = "http://my-process-app.datadoghq.com"
	ddc = newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)
	ddy = strings.NewReader(strings.Join([]string{
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
	}, "\n"))

	agentConfig, err = NewAgentConfig(ddc, nil, ddy, nil)
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

	site := "datadoghq.eu"
	processDDURL = "http://test-process.datadoghq.com"
	ddc = newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)
	ddc.Set("site", site)
	ddy = strings.NewReader(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"site: " + site,
		"process_config:",
		"  enabled: 'true'",
	}, "\n"))

	agentConfig, err = NewAgentConfig(ddc, nil, ddy, nil)
	assert.NoError(err)
	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("test-process.datadoghq.com", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)

	site = "datacathq.eu"
	ddc = newDDConfig()
	ddc.Set("process_config.process_dd_url", "")
	ddc.Set("site", site)
	ddy = strings.NewReader(strings.Join([]string{
		"api_key: apikey_20",
		"process_agent_enabled: true",
		"site: " + site,
		"process_config:",
		"  enabled: 'true'",
	}, "\n"))

	agentConfig, err = NewAgentConfig(ddc, nil, ddy, nil)
	assert.NoError(err)
	assert.Len(agentConfig.APIEndpoints, 1)
	assert.Equal("apikey_20", agentConfig.APIEndpoints[0].APIKey)
	assert.Equal("process.datacathq.eu", agentConfig.APIEndpoints[0].Endpoint.Hostname())
	assert.Equal(true, agentConfig.Enabled)
}

func TestDDAgentConfigYamlAndNetworkConfig(t *testing.T) {
	assert := assert.New(t)
	processDDURL := "http://my-process-app.datadoghq.com"
	ddc := newDDConfig()
	ddc.Set("process_config.process_dd_url", processDDURL)

	ddy := strings.Join([]string{
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
	}, "\n")

	agentConfig, err := NewAgentConfig(ddc, nil, strings.NewReader(ddy), nil)
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

	nety := strings.Join([]string{
		"network_tracer_config:",
		"  enabled: true",
		"  nettracer_socket: /var/my-location/network-tracer.log",
	}, "\n")

	agentConfig, err = newAgentConfig(nil, strings.NewReader(ddy), strings.NewReader(nety))
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
	ddc := newDDConfig()
	ddc.Set("process_config.process_dd_url", "")
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
		ddc.Set("site", tc.site)
		os.Setenv("DD_PROCESS_AGENT_URL", tc.ddURL)

		agentConfig, err := NewAgentConfig(ddc, nil, nil, nil)
		assert.NoError(err)
		assert.Equal(tc.expected, agentConfig.APIEndpoints[0].Endpoint.Hostname())
	}

}

func TestAgentPyConfig(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("DD_AGENT_PY", "testpy")
	defer os.Unsetenv("DD_AGENT_PY")

	agentConfig, err := newAgentConfig(nil, nil, nil)
	assert.NoError(err)
	assert.Equal("testpy", agentConfig.DDAgentPy)
}

func TestAgentPyEnvConfig(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("DD_AGENT_PY_ENV", "env1=testpyenv1,env2=testpyenv2")
	defer os.Unsetenv("DD_AGENT_PY_ENV")

	agentConfig, err := newAgentConfig(nil, nil, nil)
	assert.NoError(err)
	assert.Equal([]string{"env1=testpyenv1", "env2=testpyenv2"}, agentConfig.DDAgentPyEnv)
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
