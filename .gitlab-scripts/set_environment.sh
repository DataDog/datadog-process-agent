#! /bin/bash

export COMPOSE_INTERACTIVE_NO_CLI=1

#
export CURRENT_BRANCH=${CI_COMMIT_REF_NAME:-$(git rev-parse --abbrev-ref HEAD)}
echo "CURRENT_BRANCH set to: $CURRENT_BRANCH"
# Docker host can be retrieved by inspecting the routing table and getting the default gateway (i.e. for route
# destination 0.0.0.0).

# /proc/net/route contains this in hex format, so extract this first with awk and then convert that to an actual ip-address

hexaddr=$(awk '$2 == "00000000" {print $3}' /proc/net/route | head -n 1)
ipaddr=$(printf "%d." $(
  echo $hexaddr | sed 's/../0x& /g' | tr ' ' '\n' | tac
  ) | sed 's/\.$/\n/')

export DOCKER_HOST_IP=$ipaddr
echo "DOCKER_HOST_IP set to: ${DOCKER_HOST_IP}"