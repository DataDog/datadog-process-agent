#!/bin/sh

set -xe

IMAGE_TAG=$1
IMAGE_REPO=$2
ARTIFACT_PATH=$3
PUSH_LATEST="${4:-false}"


echo $IMAGE_TAG
echo $IMAGE_REPO
echo $ARTIFACT_PATH

cp $ARTIFACT_PATH DockerFiles/agent

docker build -t stackstate/${IMAGE_REPO}:${IMAGE_TAG} DockerFiles/agent


docker login -u $docker_user -p $docker_password
docker push stackstate/${IMAGE_REPO}:${IMAGE_TAG}

if [ "$PUSH_LATEST" = "true" ]; then
    docker tag stackstate/${IMAGE_REPO}:${IMAGE_TAG} stackstate/${IMAGE_REPO}:latest
    echo 'Pushing release to latest'
    docker push stackstate/${IMAGE_REPO}:latest
fi