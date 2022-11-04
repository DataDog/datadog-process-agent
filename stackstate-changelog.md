# StackState Process Agent releases

## 4.0.9
**Improvement**
- Build process-agent with go 1.16

**Bugfix**
- Fix cgroup metrics acquisition for containers ([STAC-18119](https://stackstate.atlassian.net/browse/STAC-18119))

## 4.0.8
**Features**
- Add metrics to "process" check of process-agent ([STAC-16983](https://stackstate.atlassian.net/browse/STAC-16983))

**Bugfix**
- Fix default enabled checks ([STAC-16953](https://stackstate.atlassian.net/browse/STAC-16953))
- Limited size of a message for self-health state check ([STAC-17340](https://stackstate.atlassian.net/browse/STAC-17340))

## 4.0.7
**Bugfix**
- Remove some Kubernetes processes from blacklist

## 4.0.6
**Bugfix**
- Fix warning message to not have an "error" string

## 4.0.5
**Features**
- Reporting CPU throttling metrics for containers
- Reporting checks topology along with health states of those (to see faulted checks in StackState UI)

## 4.0.4
**Improvements**
- Support running process agent as a separate container in StackState Agent helm chart

**Bugfix**
- Fix hostname when process agent is running in a separate container

## 4.0.3
**Improvements**
- Use updated main agent which is now using go.mod

## 4.0.2
**Bugfix**
- Fix infinitely growing memory usage

## 4.0.1
**Bugfix**
- Process agent will send HTTP response times when they are zero's

## 4.0.0
**Features**
- Support for Containerd and CRI-O container runtimes

**Improvements**
- Moved from Gopkg.toml to go.mod

## 3.0.3
**Improvement**
- Set process agent check intervals to be default 30 seconds, added ENV variable overrides for process agent check intervals

## 3.0.1

**Bugfix**
- Process agent now acknowledges STS_SKIP_SSL_VALIDATION environment variable

## 3.0.0

**Bugfix**
- Fixed endianness in payload data

## 2.8.7

**Bugfix**
- Fixed bytes sent/received metrics for network connections going enormously high sometimes. 

## 2.8.6

**Bugfix**
- Namespaces are not always reported for containers/processes running in k8s
- Increase network connection tracking limits and make them configurable 
- Pods merge with the same ip address while using argo 

## 2.7.8

**Features**
- Added collection interval to payload 

## 2.7.7

**Bugfix**
- Fixed bytes sent/received metrics for network connections going enormously high sometimes

## 2.7.6

**Bugfix**
- Fix rebranding script to include `DOCKER_DD_AGENT` and `DD_APM_ANALYZED_SPANS`
- When setting `STS_PROCESS_AGENT_ENABLED` do not disable container checks

## 2.7.5

**Bugfix**
- fix versioning script

## 2.7.4

**Features**
- Pass the cluster name along with the process metric information so that StackState can determine that the metrics came from Kuberentes/OpenShift.
