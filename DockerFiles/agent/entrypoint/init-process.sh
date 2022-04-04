#!/bin/bash

if [[ -z "$STS_API_KEY" ]]; then
    echo "You must set an STS_API_KEY environment variable to run the StackState Trace Agent container"
    exit 1
fi

if [[ -z "$STS_PROCESS_AGENT_URL" ]]; then
    echo "You must set an STS_APM_URL environment variable to run the StackState Trace Agent container"
    exit 1
fi

/opt/stackstate-agent/bin/agent/process-agent -config /etc/stackstate-agent/stackstate-docker.yaml

