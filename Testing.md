# Testing

Pre-requisites:

* Build the process-agent

## Local

Make sure to change in the `conf-dev.yaml` the address of the StackState backend to `localhost`.

Now run the agent locally using the dev config provided:

```
sudo ./process-agent -config conf-dev.yaml
```

Let's create a network connection :

```
# in one terminal:
$ nc -l 61234

# in another terminal:
$ yes | nc 192.168.56.101 61234
```

Check StackState UI and you should be able to find to netcat processes connected by a relation.

## With separate VMs

Pre-requisites:

* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* [Vagrant](https://www.vagrantup.com/downloads.html)

Make sure to change in the `conf-dev.yaml` the address of the StackState backend to `192.168.56.1`.

There is `Vagrantfile` setup that creates 2 Ubuntu Xenial64 vms and 1 Windows 2016 Server:

```
$ vagrant up

# in one terminal:
$ vagrant ssh process-agent-test
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
$ sudo ./process-agent -config conf-dev.yaml

# in another terminal:
$ vagrant ssh process-agent-clean
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
$ sudo ./process-agent -config conf-dev.yaml

# in another terminal:
$ vagrant ssh process-agent-win
> cd %GOPATH%/src/github.com/StackVista/stackstate-process-agent
> process-agent -config conf-dev.yaml
```

For instance now we can expect a network connection between the 2 VMs:

```
# in one terminal:
$ vagrant ssh process-agent-test
$ nc -l 61234

# in another terminal:
$ vagrant ssh process-agent-clean
$ yes | nc 192.168.56.101 61234
```

Check StackState UI and you should be able to find to netcat processes, running on 2 different VMs, 
connected by a relation.
