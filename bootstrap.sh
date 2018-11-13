#!/usr/bin/env bash

sudo apt-get install -y \
    rake \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

sudo add-apt-repository ppa:gophers/archive
sudo add-apt-repository ppa:masterminds/glide

sudo apt-get update && sudo apt-get install -y mercurial golang-1.10-go docker-ce glide gogoprotobuf

# INSTALL PROTOBUF
# Make sure you grab the latest version
curl -OL https://github.com/google/protobuf/releases/download/v3.3.0/protoc-3.3.0-linux-x86_64.zip

# Unzip
unzip protoc-3.3.0-linux-x86_64.zip -d protoc3

# Move protoc to /usr/local/bin/
sudo mv protoc3/bin/* /usr/local/bin/

# Move protoc3/include to /usr/local/include/
sudo mv protoc3/include/* /usr/local/include/

# Remove protoc3 and proto zip file
sudo rm protoc-3.3.0-linux-x86_64.zip
sudo rm -rf	protoc3/

# Move go to /usr/bin/go
sudo cp /usr/lib/go-1.10/bin/go /usr/bin/go

# Add GOPATH to env 
echo "GOPATH=/opt/stackstate-go" > /etc/environment
