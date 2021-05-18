# StackState Process Agent releases

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
