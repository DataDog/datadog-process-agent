RUNTIMETAG := $(shell date +%Y%m%d)

build:
	docker build -t docker.io/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-base-$(RUNTIMETAG) .
push:
	docker push docker.io/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-base-$(RUNTIMETAG)

