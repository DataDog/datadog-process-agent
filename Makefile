# TODO: Move this to a Rakefile, for consistenc

DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=packaging/Dockerfile-ebpf
DOCKER_IMAGE?=datadog/tracer-bpf-builder

# If you can use docker without being root, you can do "make SUDO="
SUDO=$(shell docker info >/dev/null 2>&1 || echo "sudo -E")

# Generate and install eBPF program via gobindata
ebpf: build-docker-image build-ebpf-object

build-docker-image:
	$(SUDO) docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-ebpf-object: build-docker-image
	$(SUDO) docker run --rm -e DEBUG=$(DEBUG) \
		-e CIRCLE_BUILD_URL=$(CIRCLE_BUILD_URL) \
		-v $(PWD):/src:ro \
		-v $(PWD)/ebpf:/ebpf/ \
		--workdir=/src \
		$(DOCKER_IMAGE) \
		make -f ebpf/c/tracer-ebpf.mk build
	sudo chown -R $(UID):$(UID) ebpf

# Build & run dockerized `nettop` command for testing
# $ make nettop
nettop: ebpf
	sudo docker build -t "ebpf-nettop" . -f packaging/Dockerfile-nettop
	sudo docker run \
		--net=host \
		--cap-add=SYS_ADMIN \
		--privileged \
		-v /sys/kernel/debug:/sys/kernel/debug \
		ebpf-nettop

test:
	go list ./... | grep -v vendor | sudo -E PATH=${PATH} GOCACHE=off xargs go test -tags 'linux_bpf'

# TODO: Add linux_bpf tag so it runs CI tests w/ eBPF enabled
ci-test: build-ebpf-object
	go list ./... | grep -v vendor | sudo -E PATH=${PATH} GOCACHE=off xargs go test -tags ''
