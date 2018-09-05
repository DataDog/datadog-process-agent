#!/bin/sh

if [ -z ${STS_AWS_BUCKET+x} ]; then
	echo "Missing AGENT_S3_BUCKET in environment"
	exit 1;
fi
WORKSPACE=${WORKSPACE:-$PWD/../}
agent_path="$WORKSPACE"

deb-s3 upload --codename ${CIRCLE_BRANCH:-dirty} --bucket ${STS_AWS_BUCKET:-stackstate-process-agent-test} $WORKSPACE/packaging/debian/*.deb
