Vagrant.configure("2") do |config|

  vm_mem = ENV["MEM"] || 512
  processes_to_install = ENV["PROCESSES"] || ""

  config.vm.define "process-agent-test" do |agent1|
    agent1.vm.box = "ubuntu/bionic64"
    agent1.vm.hostname = 'process-agent'
    agent1.vm.box_url = "ubuntu/bionic64"

    agent1.vm.network :private_network, ip: "192.168.56.101"

    config.vm.synced_folder "../../../..", "/opt/stackstate-go"
    config.vm.provision :shell, :path => "bootstrap.sh", :privileged => false, :args => processes_to_install

    agent1.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--memory", vm_mem]
      v.customize ["modifyvm", :id, "--name", "process-agent-test"]
    end
  end

  config.vm.define "process-agent-clean" do |agent2|
    agent2.vm.box = "ubuntu/xenial64"
    agent2.vm.hostname = 'agent2'
    agent2.vm.box_url = "ubuntu/xenial64"

    agent2.vm.network :private_network, ip: "192.168.56.102"

    config.vm.synced_folder "../../../..", "/opt/stackstate-go"

    agent2.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--memory", vm_mem]
      v.customize ["modifyvm", :id, "--name", "process-agent-clean"]
    end
  end

end
