Vagrant.configure("2") do |config|

  config.vm.define "agent1" do |agent1|
    agent1.vm.box = "ubuntu/xenial64"
    agent1.vm.hostname = 'agent1'
    agent1.vm.box_url = "ubuntu/xenial64"

    agent1.vm.network :private_network, ip: "192.168.56.101"

    config.vm.synced_folder ".", "/opt/stackstate-process-agent"

    agent1.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--memory", 512]
      v.customize ["modifyvm", :id, "--name", "agent1"]
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
