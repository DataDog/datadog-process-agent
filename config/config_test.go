package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-ini/ini"
	"github.com/stretchr/testify/assert"
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

func TestOnlyEnvConfig(t *testing.T) {
	// setting an API Key should be enough to generate valid config
	os.Setenv("DD_API_KEY", "apikey_from_env")

	agentConfig, _ := NewAgentConfig(nil, nil)
	assert.Equal(t, "apikey_from_env", agentConfig.APIKey)

	os.Setenv("DD_API_KEY", "")
}

func TestConfigNewIfExists(t *testing.T) {
	// The file does not exist: no error returned
	conf, err := NewIfExists("/does-not-exist")
	assert.Nil(t, err)
	assert.Nil(t, conf)

	// The file exists but cannot be read for another reason: an error is
	// returned.
	filename := "/tmp/process-agent-test-config.ini"
	os.Remove(filename)
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0200) // write only
	assert.Nil(t, err)
	f.Close()
	conf, err = NewIfExists(filename)
	assert.NotNil(t, err)
	assert.Nil(t, conf)
	os.Remove(filename)
}

func TestGetHostname(t *testing.T) {
	cfg := NewDefaultAgentConfig()
	h, err := getHostname(cfg.DDAgentPy, cfg.DDAgentPyEnv)
	assert.Nil(t, err)
	assert.NotEqual(t, "", h)
}

func TestDDAgentMultiAPIKeys(t *testing.T) {
	assert := assert.New(t)
	ddAgentConf, _ := ini.Load([]byte("[Main]\n\napi_key=foo, bar "))
	configFile := &File{instance: ddAgentConf, Path: "whatever"}

	agentConfig, _ := NewAgentConfig(configFile, nil)
	assert.Equal("foo", agentConfig.APIKey)
}

func TestDefaultConfig(t *testing.T) {
	assert := assert.New(t)
	agentConfig := NewDefaultAgentConfig()

	// assert that some sane defaults are set
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal("info", agentConfig.LogLevel)
	assert.Equal(true, agentConfig.AllowRealTime)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)

	os.Setenv("DOCKER_DD_AGENT", "yes")
	agentConfig = NewDefaultAgentConfig()
	assert.Equal(agentConfig.Enabled, false)
	assert.Equal(os.Getenv("HOST_PROC"), "/host/proc")
	assert.Equal(os.Getenv("HOST_SYS"), "/host/sys")
	os.Setenv("DOCKER_DD_AGENT", "no")
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
}

func TestDDAgentConfigWithLegacy(t *testing.T) {
	assert := assert.New(t)

	// Check that legacy conf file overrides dd-agent.conf
	dd, _ := ini.Load([]byte(strings.Join([]string{
		"[Main]",
		"hostname=thing",
		"api_key=apikey_12",
		"process_agent_enabled=true",
	}, "\n")))
	legacy, _ := ini.Load([]byte(strings.Join([]string{
		"[dd-process-agent]",
		"server_url = https://process.datadoghq.com/api/v1/collector",
		"api_key=apikey_13",
		"",
	}, "\n")))

	agentConf := &File{instance: dd, Path: "whatever"}
	legacyConf := &File{instance: legacy, Path: "whatever"}

	agentConfig, err := NewAgentConfig(agentConf, legacyConf)
	assert.NoError(err)

	u, _ := url.Parse("https://process.datadoghq.com/api/v1/collector")
	assert.Equal(u, agentConfig.APIEndpoint)
	assert.Equal("apikey_13", agentConfig.APIKey)
	assert.Equal(agentConfig.EnabledChecks, processChecks)
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
	}, "\n")))

	conf := &File{instance: dd, Path: "whatever"}
	agentConfig, err := NewAgentConfig(conf, nil)
	assert.NoError(err)

	assert.Equal("apikey_12", agentConfig.APIKey)
	assert.Equal(5, agentConfig.QueueSize)
	assert.Equal(false, agentConfig.AllowRealTime)
	assert.Equal(false, agentConfig.Enabled)
	assert.Equal(containerChecks, agentConfig.EnabledChecks)
}
