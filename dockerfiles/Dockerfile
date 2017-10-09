# Run it with docker run -d --name dd-process-agent -e DOCKER_DD_AGENT=yes -e API_KEY=YOUR_API_KEY -v /var/run/docker.sock:/var/run/docker.sock:ro -v /proc/:/host/proc/:ro -v /sys/fs/cgroup/:/host/sys/fs/cgroup:ro process:latest
FROM golang:1.9.0-alpine3.6

MAINTAINER Datadog <package@datadoghq.com>

ENV DOCKER_DD_AGENT=yes

ADD https://s3.amazonaws.com/datad0g-process-agent/process-agent-amd64-5.17.2 /process-agent

COPY datadog.conf /etc/dd-agent/datadog.conf

RUN chmod +x /process-agent

CMD /process-agent -ddconfig /etc/dd-agent/datadog.conf
