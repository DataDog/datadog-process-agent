FROM centos:7

ENV SYSTEMD_VERSION=219
ENV GIT_VERSION=2.21.0
ENV GOLANG_VERSION=1.16.15
ARG GIMME_URL=raw.githubusercontent.com/travis-ci/gimme/master/gimme
ARG GIMME_DEBUG=0
ENV RBENV_VERSION=2.4.4
ENV BUNDLER_VERSION=1.15.3

RUN yum -y --enablerepo=extras install epel-release
RUN yum -y install curl-devel expat-devel gettext-devel perl-ExtUtils-MakeMaker \
                   gcc make openssl-devel libssh-dev bzip2 bzip2-devel readline-devel \
                   zlib-devel patch gcc-c++ file rpm-build openssh-clients byacc
RUN yum -y install python3

# Provide systemd header files needed to build the agent systemd module (journald log collector)
RUN curl "https://codeload.github.com/systemd/systemd/tar.gz/v$SYSTEMD_VERSION" -o "systemd-$SYSTEMD_VERSION.tar.gz" \
    && tar xzf systemd-$SYSTEMD_VERSION.tar.gz \
    && mv systemd-$SYSTEMD_VERSION/src/systemd/ /usr/include/

RUN curl "https://mirrors.edge.kernel.org/pub/software/scm/git/git-$GIT_VERSION.tar.gz" -o "git-$GIT_VERSION.tar.gz" \
    && tar xzf git-$GIT_VERSION.tar.gz \
    && cd git-$GIT_VERSION \
    && make prefix=/usr/src/git all \
    && make prefix=/usr/src/git install

ENV PATH=$PATH:/usr/src/git/bin

RUN curl "https://bootstrap.pypa.io/pip/3.6/get-pip.py" -o "get-pip.py" \
    && python3 --version \
    && python3 get-pip.py \
    && rm get-pip.py \
    && pip install virtualenv==15.2.0

RUN eval "$(curl -sL https://$GIMME_URL | \
    GIMME_GO_VERSION="$GOLANG_VERSION" \
    GIMME_DEBUG=$GIMME_DEBUG \
    bash)"

ENV GOPATH /go
ENV GOBIN /root/.gimme/versions/go"$GOLANG_VERSION".linux.amd64/bin
ENV PATH="$HOME"/bin:/root/.gimme/versions/go"$GOLANG_VERSION".linux.amd64/bin:/usr/local/go/bin:/go/src/github.com/bin:$PATH

RUN mkdir -p $GOPATH $HOME/bin/ /usr/local/go/bin \
    && echo $PATH && go version

WORKDIR $GOPATH

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

RUN go get -u golang.org/x/lint/golint

RUN git clone https://github.com/rbenv/rbenv.git /usr/local/rbenv \
    &&  git clone https://github.com/rbenv/ruby-build.git /usr/local/rbenv/plugins/ruby-build \
    &&  git clone https://github.com/jf/rbenv-gemset.git /usr/local/rbenv/plugins/rbenv-gemset \
    &&  /usr/local/rbenv/plugins/ruby-build/install.sh

ENV PATH /usr/local/rbenv/bin:$PATH
ENV RBENV_ROOT /usr/local/rbenv

RUN echo 'export RBENV_ROOT=/usr/local/rbenv' >> /etc/profile.d/rbenv.sh \
    &&  echo 'export PATH=/usr/local/rbenv/bin:$PATH' >> /etc/profile.d/rbenv.sh \
    &&  echo 'eval "$(rbenv init -)"' >> /etc/profile.d/rbenv.sh

RUN echo 'export RBENV_ROOT=/usr/local/rbenv' >> /root/.bashrc \
    &&  echo 'export PATH=/usr/local/rbenv/bin:$PATH' >> /root/.bashrc \
    &&  echo 'eval "$(rbenv init -)"' >> /root/.bashrc

ENV CONFIGURE_OPTS --disable-install-doc
ENV PATH /usr/local/rbenv/bin:/usr/local/rbenv/shims:$PATH

RUN eval "$(rbenv init -)"; rbenv install $RBENV_VERSION \
    &&  eval "$(rbenv init -)"; rbenv global $RBENV_VERSION \
    &&  eval "$(rbenv init -)"; gem update --system \
    &&  eval "$(rbenv init -)"; gem install bundler -f --version "$BUNDLER_VERSION" \
    &&  rm -rf /tmp/*

ENV GEM_HOME /usr/local/bundle
ENV BUNDLE_PATH="$GEM_HOME" \
    BUNDLE_BIN="$GEM_HOME/bin" \
    BUNDLE_SILENCE_ROOT_WARNING=1 \
    BUNDLE_APP_CONFIG="$GEM_HOME"
ENV PATH $BUNDLE_BIN:$PATH
RUN mkdir -p "$GEM_HOME" "$BUNDLE_BIN" \
    && chmod 777 "$GEM_HOME" "$BUNDLE_BIN"

RUN git config --global user.email "gitlab@stackstate" && git config --global user.name "Gitlab Stackstate"

RUN pip install awscli boto3 sts-rpm-s3

RUN yum -y install net-snmp-devel python-deltarpm yum-utils libtool rpm-sign createrepo

ADD rpmmacros /root/.rpmmacros

RUN yum install -y rsync \
    && gem install rake fpm deb-s3 \
    && curl https://glide.sh/get | sh

# Provide kernel 4.4 header that include eBPF header needed to build linux network tracer
RUN curl -OL http://mirrors.coreix.net/elrepo-archive-archive/kernel/el6/x86_64/RPMS/kernel-lt-headers-4.4.176-1.el6.elrepo.x86_64.rpm  \
    && rpm2cpio kernel-lt-headers-4.4.176-1.el6.elrepo.x86_64.rpm | cpio -idm \
    && rsync -r ./usr/ /usr/ \
    && rm -rf kernel-lt-headers-4.4.176-1.el6.elrepo.x86_64.rpm ./usr

## Upgrade gcc to 4.7 needed to build gobpf/elf
#RUN curl https://people.centos.org/tru/devtools-1.1/devtools-1.1.repo -o /etc/yum.repos.d/devtools-1.1.repo \
#    && yum install -y devtoolset-1.1-gcc
