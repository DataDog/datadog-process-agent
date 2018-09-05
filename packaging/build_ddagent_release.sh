#!/bin/sh
set -xe

cd $WORKSPACE/go/src/github.com/StackVista/stackstate-process-agent

# Verify we have the correct environment variables

if [ -z ${AGENT_S3_BUCKET+x} ]; then
	echo "Missing AGENT_S3_BUCKET in environment"
	exit 1;
fi

if [ -z ${PROCESS_AGENT_VERSION+x} ]; then
	git checkout master
	# Pick the latest tag by default for our version.
	PROCESS_AGENT_VERSION=$(git tag | sort | head -1)
	# But we will be building from the master branch in this case.
	FILENAME="process-agent-amd64-master"
else
	git checkout $PROCESS_AGENT_VERSION
	# If we have a version then we'll use it and put it in the name.
	FILENAME="process-agent-amd64-$PROCESS_AGENT_VERSION"
fi

echo "Building Agent v$PROCESS_AGENT_VERSION to $FILENAME"

# Expects gimme to be installed
eval "$(gimme 1.10.1)"

export GOPATH=$WORKSPACE/go
export PATH=$PATH:$GOPATH/bin

agent_path="$WORKSPACE/go/src/github.com/StackVista/stackstate-process-agent"

echo "Getting dependencies..."

cd $agent_path
go get github.com/Masterminds/glide
glide install

echo "Building binaries..."
PROCESS_AGENT_STATIC=true rake build EBPF=$LINUX_EBPF

cp process-agent $FILENAME 
s3cmd sync -v ./$FILENAME s3://$AGENT_S3_BUCKET/
