# StackState Process Agent releases

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
