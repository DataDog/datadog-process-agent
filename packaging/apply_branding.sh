#!/bin/bash

# https://regex-golang.appspot.com/assets/html/index.html

export REPLACE_SCOPE="../config ../cmd ../checks"
export REPLACE_MODE=-w # "-d"

gofmt -l $REPLACE_MODE -r '"DD_HOSTNAME" -> "STS_HOSTNAME"'  $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_API_KEY" -> "STS_API_KEY"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_CUSTOM_SENSITIVE_WORDS" -> "STS_CUSTOM_SENSITIVE_WORDS"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_SCRUB_ARGS" -> "STS_SCRUB_ARGS"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_CUSTOM_SENSITIVE_WORDS" -> "STS_CUSTOM_SENSITIVE_WORDS"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_LOG_LEVEL" -> "STS_LOG_LEVEL"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_LOGS_STDOUT" -> "STS_LOGS_STDOUT"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_LOG_TO_CONSOLE" -> "STS_LOG_TO_CONSOLE"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_PROCESS_AGENT_ENABLED" -> "STS_PROCESS_AGENT_ENABLED"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_PROCESS_AGENT_URL" -> "STS_PROCESS_AGENT_URL"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_STRIP_PROCESS_ARGS" -> "STS_STRIP_PROCESS_ARGS"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_AGENT_PY" -> "STS_AGENT_PY"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_AGENT_PY_ENV" -> "STS_AGENT_PY_ENV"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_DOGSTATSD_PORT" -> "STS_DOGSTATSD_PORT"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_BIND_HOST" -> "STS_BIND_HOST"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_COLLECT_DOCKER_NETWORK" -> "STS_COLLECT_DOCKER_NETWORK"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_CONTAINER_BLACKLIST" -> "STS_CONTAINER_BLACKLIST"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_CONTAINER_WHITELIST" -> "STS_CONTAINER_WHITELIST"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_CONTAINER_CACHE_DURATION" -> "STS_CONTAINER_CACHE_DURATION"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_PROCESS_AGENT_CONTAINER_SOURCE" -> "STS_PROCESS_AGENT_CONTAINER_SOURCE"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_NETWORK_TRACING_ENABLED" -> "STS_NETWORK_TRACING_ENABLED"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_NETWORK_TRACING_ENABLED" -> "STS_NETWORK_TRACING_ENABLED"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_SITE" -> "STS_SITE"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_USE_LOCAL_NETWORK_TRACER" -> "STS_USE_LOCAL_NETWORK_TRACER"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_NETTRACER_SOCKET" -> "STS_NETTRACER_SOCKET"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"DD_PROCESS_AGENT_URL is invalid: %s" -> "STS_PROCESS_AGENT_URL is invalid: %s"' $REPLACE_SCOPE
# known
sed -i 's/DD_SITE/STS_SITE/g' ../config/config_test.go


# config_nix.go
gofmt -l $REPLACE_MODE -r '"/var/log/datadog/process-agent.log" -> "/var/log/stackstate-agent/process-agent.log"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"/opt/datadog-agent/embedded/bin/python" -> "/opt/stackstate-agent/embedded/bin/python"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"PYTHONPATH=/opt/datadog-agent/agent" -> "PYTHONPATH=/opt/stackstate-agent/agent"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"/opt/datadog-agent/bin/agent/agent" -> "/opt/stackstate-agent/bin/agent/agent"' $REPLACE_SCOPE

# config
gofmt -l $REPLACE_MODE -r '`yaml:"dd_agent_bin"` -> `yaml:"sts_agent_bin"`' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '`yaml:"dd_agent_env"` -> `yaml:"sts_agent_env"`' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"process_config.process_dd_url" -> "process_config.process_sts_url"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"error parsing process_dd_url: %s" -> "error parsing process_sts_url: %s"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"dd_agent_py" -> "sts_agent_py"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"dd_agent_py_env" -> "sts_agent_py_env"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"ddconfig" -> "stsconfig"' $REPLACE_SCOPE

# console changes
gofmt -l $REPLACE_MODE -r '"/etc/datadog-agent/datadog.yaml" -> "/etc/stackstate-agent/stackstate.yaml"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"/opt/datadog-agent/bin/agent/agent" -> "/opt/stackstate-agent/bin/agent/agent"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"Path to dd-agent config" -> "Path to sts-agent config"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"Path to datadog.yaml config" -> "Path to stackstate.yaml config"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"/etc/dd-agent/datadog.conf" -> "/etc/stackstate-agent/stackstate.conf"' $REPLACE_SCOPE

# windows changes
gofmt -l $REPLACE_MODE -r '"datadog-process-agent" -> "stackstate-process-agent"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"c:\\programdata\\datadog\\datadog.yaml" -> "c:\\programdata\\stackstate\\stackstate.yaml"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"c:\\programdata\\datadog\\datadog.conf" -> "c:\\programdata\\stackstate\\stackstate.conf"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"c:\\programdata\\datadog\\conf.d" -> "c:\\programdata\\stackstate\\conf.d"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"c:\\programdata\\datadog\\logs\\process-agent.log" -> "c:\\programdata\\stackstate\\logs\\process-agent.log"' $REPLACE_SCOPE
gofmt -l $REPLACE_MODE -r '"c:\\Program Files\\Datadog\\Datadog Agent\\embedded\\agent.exe" -> "c:\\Program Files\\StackState\\StackState Agent\\embedded\\agent.exe"' $REPLACE_SCOPE
sed -i 's/DataDog/StackState/g' ../cmd/agent/main_windows.go

UNAME="$(uname)"
if [[ $UNAME != MSYS* ]]; then
    echo "Checking replacements..."

    grep -r --include=*.go "\"DD_"  $PWD/../cmd $PWD/../config $PWD/../checks

    RESULT=$?
    if [ $RESULT -eq 0 ]; then
      echo "Please fix branding: there is still something using DD_ prefix"
      exit 1
    else
      echo "Branding was successful, return code $RESULT"
    fi
fi
