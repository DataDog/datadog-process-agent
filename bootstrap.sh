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

sudo apt-get update && sudo apt-get install -y mercurial golang-1.10-go docker-ce glide

# Install additional dependencies to test with the process agent
arr=($@)
## now loop through the above array
for i in "${arr[@]}"
do
    case $i in
        "java")
            echo "Installing Java..."
            sudo apt-get update \
                && sudo apt-get install -y openjdk-8-jdk
            ;;
        "mysql")
            echo "Installing MySQL..."
            sudo apt-get update \
                && sudo apt-get install -y mysql-server \
                && systemctl status mysql.service
            ;;
        "postgresql")
            echo "Installing Postgresql..."
            sudo apt-get update \
                && sudo apt-get install -y postgresql postgresql-contrib
            ;;
        "tomcat")
            echo "Installing Tomcat..."
            sudo apt-get update \
                && sudo groupadd tomcat \
                && sudo useradd -s /bin/false -g tomcat -d /opt/tomcat tomcat \
                && cd /tmp \
                && curl -O http://apache.cs.uu.nl/tomcat/tomcat-9/v9.0.13/bin/apache-tomcat-9.0.13.tar.gz \
                && sudo mkdir /opt/tomcat \
                && sudo tar xzvf apache-tomcat-9*tar.gz -C /opt/tomcat --strip-components=1 \
                && cd /opt/tomcat \
                && sudo chgrp -R tomcat /opt/tomcat \
                && sudo chmod -R g+r conf \
                && sudo chmod g+x conf \
                && sudo chown -R tomcat bin/ webapps/ work/ temp/ logs/ \
                && sudo -u tomcat /opt/tomcat/bin/startup.sh
            ;;
        *)
            echo "${i} is not supported"
            ;;
    esac
done

# Add vagrant user to docker group
sudo usermod -aG docker vagrant

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

# Define GOPATH and add it to profile
export GOPATH="/opt/stackstate-go"
echo "GOPATH=\$GOPATH" >> ~/.profile
echo "PATH=\$PATH:\$GOPATH/bin" >> ~/.profile

source ~/.profile

# Install the gogo-proto binaries from the vendor directory to make sure we have the correct version
cd /opt/stackstate-go/src/github.com/StackVista/stackstate-process-agent/vendor/github.com/gogo/protobuf && make install
