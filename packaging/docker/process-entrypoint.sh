#!/bin/bash
#set -e

if [[ $API_KEY ]]; then
	sed -i -e "s/^.*api_key = .*$/api_key = ${API_KEY}/" /etc/dd-agent/dd-process-agent.ini
else
	echo "You must set API_KEY environment variable or include a DD_API_KEY_FILE to run the Docker container"
	exit 1
fi

export PATH="/opt/dd-process-agent/bin:$PATH"

# Start the infrastructure Agent
supervisord -n -c /etc/dd-agent/supervisor.conf &

# Start the process agent
dd-process-agent -config /etc/dd-agent/dd-process-agent.ini