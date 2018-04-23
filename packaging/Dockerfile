#
# dd-process-agent
# Jenkins Dockerfile
#
# Used by Jenkins to build process-agent package
#

FROM quay.io/datadog/jenkins-slave

MAINTAINER Shang Wang <shang.wang@datadoghq.com>

RUN apt-get update && \
    apt-get install --no-install-recommends -qq -y software-properties-common && \
    apt-add-repository ppa:brightbox/ruby-ng && \
    apt-get update && \
    apt-get install -y build-essential debhelper git gnupg rake curl devscripts ruby-dev zlib1g-dev libxml2-dev wget rpm debsigs expect ruby2.3 ruby2.3-dev createrepo python-dateutil python-dev
RUN gem install deb-s3 fpm inifile

RUN wget http://downloads.sourceforge.net/project/s3tools/s3cmd/1.5.2/s3cmd-1.5.2.tar.gz && \
	tar -xzvf s3cmd-1.5.2.tar.gz && \
	ln -s `pwd`/s3cmd-1.5.2/s3cmd /usr/bin/s3cmd

RUN curl -sL -o /usr/local/bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme && \
    chmod +x /usr/local/bin/gimme

RUN wget http://www.musl-libc.org/releases/musl-1.1.10.tar.gz && \
    tar -xvf musl-1.1.10.tar.gz && \
    cd musl-1.1.10 && ./configure && make && sudo make install

ENV GOPATH=/go
ENV PATH=/go/bin:$PATH
RUN gimme 1.10
