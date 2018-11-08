Vagrant.configure("2") do |config|

  config.vm.define "process-agent" do |vm|
    vm.vm.box = "ubuntu/bionic64"
    vm.vm.hostname = 'process-agent'
    vm.vm.box_url = "ubuntu/bionic64"

    vm.vm.network :private_network, ip: "192.168.56.101"

    config.vm.synced_folder "../../../..", "/opt/stackstate-go"
    config.vm.provision :shell, path: "bootstrap.sh"

    vm.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--memory", 1024]
      v.customize ["modifyvm", :id, "--name", "process-agent"]
    end
  end

  config.vm.define "agent2" do |agent2|
    agent2.vm.box = "ubuntu/xenial64"
    agent2.vm.hostname = 'agent2'
    agent2.vm.box_url = "ubuntu/xenial64"

    agent2.vm.network :private_network, ip: "192.168.56.102"

    config.vm.synced_folder ".", "/opt/stackstate-process-agent"

    agent2.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--memory", 512]
      v.customize ["modifyvm", :id, "--name", "agent2"]
    end
  end

end
