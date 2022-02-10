FROM stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-base-20220210

RUN yum install -y rsync \
    && gem install rake fpm deb-s3 \
    && curl https://glide.sh/get | sh

# Provide kernel 4.4 header that include eBPF header needed to build linux network tracer
RUN curl -OL https://elrepo.org/linux/kernel/el6/x86_64/RPMS/kernel-lt-headers-4.4.176-1.el6.elrepo.x86_64.rpm \
    && rpm2cpio kernel-lt-headers-4.4.176-1.el6.elrepo.x86_64.rpm | cpio -idm \
    && rsync -r ./usr/ /usr/ \
    && rm -rf kernel-lt-headers-4.4.176-1.el6.elrepo.x86_64.rpm ./usr

# Upgrade gcc to 4.7 needed to build gobpf/elf
RUN curl https://people.centos.org/tru/devtools-1.1/devtools-1.1.repo -o /etc/yum.repos.d/devtools-1.1.repo \
    && yum install -y devtoolset-1.1-gcc
