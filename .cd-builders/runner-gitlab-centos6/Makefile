RUNTIMETAG := $(shell date +%Y%m%d)

build:
	docker build -t stackstate/stackstate-process-agent-runner-gitlab:centos6-$(RUNTIMETAG) .

push:
	docker push stackstate/stackstate-process-agent-runner-gitlab:centos6-$(RUNTIMETAG)
