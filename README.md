# Datadog Process Agent

[![CircleCI](https://circleci.com/gh/DataDog/datadog-process-agent.svg?style=svg)](https://circleci.com/gh/DataDog/datadog-process-agent)

## Installation

See the [Live Processes docs](https://docs.datadoghq.com/graphing/infrastructure/process/#installation) for installation instructions.

## Development or running from source

Pre-requisites:

* `go >= 1.10.1`
* `rake`

Check out the repo in your `$GOPATH`

```
cd $GOPATH/src/github.com/DataDog
git clone git@github.com:DataDog/datadog-process-agent.git
cd datadog-process-agent
```

Pull down the latest dependencies via `dep`:

```
rake deps
rake install
```

You can now run the Agent on the command-line:

`process-agent -config $PATH_TO_PROCESS_CONFIG_FILE`

If you modify any of the `.proto` files you _must_ rebuild the *.pb.go files with

```
rake protobuf
```

## Contributing

In order for your contributions you will be required to sign a CLA. When a PR is opened a bot will prompt you to sign the CLA. Once signed you will be set for all contributions going forward.

## Development
The easiest way to build and test is inside a Vagrant VM. You can provision the VM by running `./tools/dev_setup.sh` and SSHing into the VM with `vagrant ssh` (vagrant must be installed.)

The VM will mount your local $GOPATH, so you can edit source code with your editor of choice.

For development on the network-tracer, `rake ebpf:nettop` will run a small testing program which periodically prints statistics about TCP/UDP traffic inside the VM.
