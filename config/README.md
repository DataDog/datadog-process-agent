# Agent Configuration

The trace-agent sources configuration from the following locations:

1. The path pointed to by the `-stsconfig` command line flag (default: `/etc/sts-agent/stackstate.conf`)
2. The path pointed to by the `-config` command line flag (default: `/etc/stackstate-agent/stackstate-process-agent.ini`)
3. Environment variables: See full list below


Environment variables will override settings defined in configuration files.

## Classic configuration values, and how the trace-agent treats them
Note that changing these will also change the behavior of the `stackstate-agent` running on the same host.

In the file pointed to by `-stsconfig`

```
[Main]
# Enable the process agent.
process_agent_enabled = true

# process-agent will use this api key when reporting to the StackState backend.
# no default.
api_key =

# process-agent will log it's output with this log level
log_level = INFO
```

Other process-specific config lives in the `[process.config]` section.


## Environment variables
We allow overriding a subset of configuration values from the environment. These
can be useful when running the agent in a Docker container or in other situations
where env vars are preferrable to static files

- `STS_PROCESS_AGENT_ENABLED` - overrides `[Main] process_agent_enabled`
- `STS_HOSTNAME` - overrides `[Main] hostname`
- `STS_API_KEY` - overrides `[Main] api_key`
- `STS_LOG_LEVEL` - overrides `[Main] log_level`


## Logging
Unlike sts-agent, the process-agent does not configure it's own logging and relies on the process manager
to redirect it's output. While standard installs (`apt-get`, `yum`) will log output to `/var/log/statckstate-agent/process-agent.log`,
any non-standard install should attempt to handle STDERR in a sane way
