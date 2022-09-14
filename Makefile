.SHELLFLAGS = -ec

SHELL         := /bin/bash
.DEFAULT_GOAL := dev

UID    ?= $(shell id -u)
GID    ?= $(shell id -g)
# Workaround for target completion, because Makefile does not like : in the target commands
colon  := :

LOCAL_BUILD_IMAGE  = stackstate-process-agent-local-build
VOLUME_GO_PKG_NAME = ${LOCAL_BUILD_IMAGE}-go-volume
AGENT_SOURCE_MOUNT = /stackstate-process-agent-mount
PROJECT_DIR        = /go/src/github.com/StackVista/stackstate-process-agent

DOCKER_ENV		   = --env PROJECT_DIR=${PROJECT_DIR} \
                     --env artifactory_user=${ARTIFACTORY_USER} \
                     --env artifactory_password=${ARTIFACTORY_PASSWORD} \
                     --env ARTIFACTORY_PYPI_URL="artifactory.tooling.stackstate.io/artifactory/api/pypi/pypi-local/simple" \
                     --env PYTHON_RUNTIME=2


build:
	cd Dockerfiles/local_builder && \
	docker build -t ${LOCAL_BUILD_IMAGE} \
		--build-arg UID=${UID} \
		--build-arg GID=${GID} \
		.

# Volume sharing can be used for agent application development
dev: build
	docker run -it --rm \
        --name ${LOCAL_BUILD_IMAGE} \
        --mount source=${VOLUME_GO_PKG_NAME},target=/go/pkg \
        --volume ${PWD}${colon}${PROJECT_DIR} \
        ${DOCKER_ENV} ${LOCAL_BUILD_IMAGE}

# Source copy can be used for Omnibus package build
omnibus: build
	docker run -it --rm \
        --user root \
        --name ${LOCAL_BUILD_IMAGE} \
        --mount source=${VOLUME_GO_PKG_NAME},target=/go/pkg \
        --volume ${PWD}${colon}${AGENT_SOURCE_MOUNT}${colon}ro \
        --env AGENT_SOURCE_MOUNT=${AGENT_SOURCE_MOUNT} \
        ${DOCKER_ENV} ${LOCAL_BUILD_IMAGE} ${COPY_MOUNT}


shell:
	docker exec -ti ${LOCAL_BUILD_IMAGE} bash --init-file /local_init.sh


.PHONY: build dev omnibus shell
