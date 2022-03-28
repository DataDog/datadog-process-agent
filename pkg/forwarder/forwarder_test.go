package forwarder

import (
	"github.com/StackVista/stackstate-agent/pkg/util/flavor"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"
)

func TestIfFlavorSet(t *testing.T) {
	assert.Equal(t, "process_agent", flavor.GetFlavor())
}

func TestExtractEndpoints(t *testing.T) {
	endpoints := []config.APIEndpoint{
		{
			APIKey:   "API_KEY",
			Endpoint: &url.URL{Scheme: "https", Host: "my-test-host"},
		},
		{
			APIKey:   "DIFFERENT_API_KEY",
			Endpoint: &url.URL{Scheme: "https", Host: "my-test-host"},
		},
		{
			APIKey:   "API_KEY",
			Endpoint: &url.URL{Scheme: "https", Host: "my-test-host-2"},
		},
		{
			APIKey:   "API_KEY",
			Endpoint: &url.URL{Scheme: "https", Host: "my-test-host-3"},
		},
		{
			APIKey:   "API_KEY_2",
			Endpoint: &url.URL{Scheme: "https", Host: "my-test-host", Path: "extra-path"},
		},
	}
	actual := extractEndpoints(endpoints)

	expected := map[string][]string{
		"https://my-test-host":            {"API_KEY", "DIFFERENT_API_KEY"},
		"https://my-test-host-2":          {"API_KEY"},
		"https://my-test-host-3":          {"API_KEY"},
		"https://my-test-host/extra-path": {"API_KEY_2"},
	}

	assert.Equal(t, expected, actual)
}
