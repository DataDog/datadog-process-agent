#!/usr/bin/env bash

cd "$(dirname "$0")/.."

set -e

if [[ -f Vagrantfile ]]; then
  echo "detected vagrant file; will clean up"
  vagrant destroy -f
  rm Vagrantfile
fi

cat <<EOD > Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "hashicorp-vagrant/ubuntu-16.04"
  config.vm.synced_folder "$GOPATH/src/github.com/DataDog", "/home/vagrant/go/src/github.com/DataDog"
end
EOD

vagrant up

# docker setup
cat <<EOD | vagrant ssh
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo sh -c 'echo "deb https://download.docker.com/linux/ubuntu xenial stable" >> /etc/apt/sources.list'
sudo apt-get update
sudo apt-get install -y docker-ce
sudo groupadd docker
sudo usermod -aG docker vagrant
sudo service docker start
EOD

# golang setup
cat <<EOD | vagrant ssh
sudo apt-get install -y golang
echo 'export GOPATH=/home/vagrant/go' > ~/.bashrc
EOD

# necessary to get group membership to be respected
vagrant reload

echo "your development environment is ready; use \`vagrant ssh\` to ssh in"
