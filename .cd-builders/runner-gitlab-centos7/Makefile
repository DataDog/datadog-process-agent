RUNTIMETAG := $(shell date +%Y%m%d)

build:
	docker build -t docker.io/stackstate/stackstate-process-agent-runner-gitlab:runner_centos7$(RUNTIMETAG) .
push:
	docker push docker.io/stackstate/stackstate-process-agent-runner-gitlab:runner_centos7$(RUNTIMETAG)

