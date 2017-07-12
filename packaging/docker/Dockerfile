FROM datadog/docker-dd-agent:latest

MAINTAINER Datadog <package@datadoghq.com>

ENV DOCKER_DD_AGENT=yes \
    AGENT_VERSION=0.99.34 \
    DD_PROCESS_AGENT_ENABLED=true

# Install the Agent
RUN echo "deb http://apt.datad0g.com/ process main" > /etc/apt/sources.list.d/datadog.list \
 && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C7A7DA52 \
 && apt-get update \
 && apt-get install --no-install-recommends -y dd-process-agent="${AGENT_VERSION}" \
 && apt-get install --no-install-recommends -y ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Configure the Agent
RUN mv /etc/dd-agent/dd-process-agent.ini.example /etc/dd-agent/dd-process-agent.ini \
 || chmod +x /etc/init.d/dd-process-agent

COPY ./process-entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh", "/process-entrypoint.sh"]
