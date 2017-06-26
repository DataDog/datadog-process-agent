# Datadog Process Agent in Docker

This allows you to run the dd-process-agent _and_ standard dd-agent in a Docker container. We inherit from the [docker-dd-agent](https://github.com/DataDog/docker-dd-agent) container so you may want to refer to that README for custom overrides and options.

(Note that because we inherit from the docker-dd-agent image, you should _only run this image, not both_).

## Quick Start

The default image is ready-to-go. You just need to set your API_KEY in the environment.

```
docker run -d --name dd-agent \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc/:/host/proc/:ro \
  -v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro \
  -v /etc/passwd:/etc/passwd \
  -e HOST_PROC=/host/proc \
  -e HOST_SYS=/host/sys \
  -e API_KEY={your_api_key_here} \
  -e SD_BACKEND=docker \
  datadoghq/dd-process-agent
```

If you are running on Amazon Linux, use the following instead:

```
docker run -d --name dd-agent \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /proc/:/host/proc/:ro \
  -v /cgroup/:/host/sys/fs/cgroup:ro \
  -v /etc/passwd:/etc/passwd \
  -e API_KEY={your_api_key_here} \
  -e HOST_PROC=/host/proc \
  -e HOST_SYS=/host/sys \
  -e SD_BACKEND=docker \
  datadoghq/dd-process-agent
```

## Notes

* We mount the host `/etc/passwd` so that UID resolution maps to host-level usernames.
* Both `/proc` and `/sys` are mounted in order to access all processes running on the host instead of just what's available to the container.