FROM artifactory.tooling.stackstate.io/docker-virtual/stackstate/stackstate-process-agent-runner-gitlab:runner_centos7-20220218

ARG UID
ARG GID
ARG MYUSER=root

# Used for copy agent source from mount point
RUN yum install -y inotify-tools rsync

RUN mkdir -p $GOPATH/src
RUN mkdir -p $GOPATH/pkg
# Add local user to match id/gid of host user
RUN #(groupadd -g $GID $MYUSER || true) && \
    useradd -m -u $UID -g $GID $MYUSER -s /bin/sh

# Ensure local user can run all root commands
RUN usermod -aG root $MYUSER && \
    chmod g+rx /root && \
    chown -R $MYUSER /go/src && \
    chown -R $MYUSER /go/pkg

# external docker volume
# if we don't precreate it we do not get the permission we want

USER root

COPY ./local_init.sh /local_init.sh


ENTRYPOINT []
CMD ["bash", "--init-file", "/local_init.sh"]
