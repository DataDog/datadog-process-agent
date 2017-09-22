FROM golang:1.9.0-alpine3.6

MAINTAINER Datadog <package@datadoghq.com>

ADD https://s3.amazonaws.com/datad0g-process-agent/process-agent-amd64-5.17.2 /process-agent

COPY datadog.conf /etc/dd-agent/datadog.conf
COPY dd-process-agent.ini /etc/dd-agent/dd-process-agent.ini

RUN  chmod g+x /process-agent \
  && mkdir /var/log/datadog/ \
  && chmod -R g+w /var/log/datadog

USER 1001

CMD /process-agent -config /etc/dd-agent/dd-process-agent.ini -ddconfig /etc/dd-agent/datadog.conf
