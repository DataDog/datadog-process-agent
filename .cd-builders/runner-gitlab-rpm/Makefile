RUNTIMETAG := $(shell date +%Y%m%d)
DOCKER_REPOSITORY ?= docker.io
BASE_RUNNER_IMAGE_VERSION ?= deb7_latest

version:
	echo $(RUNTIMETAG) | tail -1 > version.txt

build:
	docker build -t $(DOCKER_REPOSITORY)/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-$(RUNTIMETAG) .

push:
	docker push $(DOCKER_REPOSITORY)/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner-$(RUNTIMETAG)

try:
	docker run -it $(DOCKER_REPOSITORY)/stackstate/stackstate-process-agent-runner-gitlab:centos6-runner$(RUNTIMETAG) bash