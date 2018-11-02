#!/bin/bash

if [ -z ${PROCESS_AGENT_VERSION+x} ]; then
	# Pick the latest tag by default for our version.
	PROCESS_AGENT_VERSION=$(./version.sh)
	# But we will be building from the master branch in this case.
fi
echo $PROCESS_AGENT_VERSION
FILENAME="process-agent-amd64-$PROCESS_AGENT_VERSION"

WORKSPACE=${WORKSPACE:-$PWD/../}
agent_path="$WORKSPACE"

mkdir -p "$agent_path/packaging/debian/package/opt/stackstate-process-agent/bin/"
mkdir -p "$agent_path/packaging/debian/package/opt/stackstate-process-agent/run/"
mkdir -p "$agent_path/packaging/rpm/package/opt/stackstate-process-agent/bin/"
mkdir -p "$agent_path/packaging/rpm/package/opt/stackstate-process-agent/run/"

# copy the binary
cp "$agent_path/process-agent" "$agent_path/packaging/debian/package/opt/stackstate-process-agent/bin/stackstate-process-agent"
cp "$agent_path/process-agent" "$agent_path/packaging/rpm/package/opt/stackstate-process-agent/bin/stackstate-process-agent"

# make debian package using fpm
echo "Building debian package..."
cd $agent_path/packaging/debian
fpm -s dir -t deb -v "$PROCESS_AGENT_VERSION" -n stackstate-process-agent --license="Simplified BSD License" --maintainer="StackState" --vendor "StackState" \
--url="https://www.stackstate.com/" --category Network --description "An agent for collecting and submitting process information to StackState (https://www.stackstate.com/)" \
 -a "amd64" --before-remove stackstate-process-agent.prerm --after-install stackstate-process-agent.postinst --after-upgrade stackstate-process-agent.postup \
 --before-upgrade stackstate-process-agent.preup --deb-init stackstate-process-agent.init -C $agent_path/packaging/debian/package .

# make rpm package using fpm
echo "Building rpm package..."
cd $agent_path/packaging/rpm
fpm -s dir -t rpm -v "$PROCESS_AGENT_VERSION" -n stackstate-process-agent --license="Simplified BSD License" --maintainer="StackState" --vendor "StackState" \
--url="https://www.stackstate.com/" --category Network --description "An agent for collecting and submitting process information to StackState (https://www.stackstate.com/)" \
 -a "amd64" --rpm-init stackstate-process-agent.init --before-remove stackstate-process-agent.prerm --after-install stackstate-process-agent.postinst --after-upgrade stackstate-process-agent.postup \
 --before-upgrade stackstate-process-agent.preup -C $agent_path/packaging/rpm/package .

