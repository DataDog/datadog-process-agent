# StackState Process Agent

[![CircleCI](https://circleci.com/gh/StackVista/stackstate-process-agent.svg?style=svg)](https://circleci.com/gh/StackVista/stackstate-process-agent)

## Installation

See the [Live Processes docs](https://docs.datadoghq.com/graphing/infrastructure/process/#installation) for installation instructions.

## Development or running from source

Pre-requisites:

* `go >= 1.10.1`
* `rake`

Check out the repo in your `$GOPATH`

```
cd $GOPATH/StackVista
git clone git@github.com:StackVista/stackstate-process-agent
cd stackstate-process-agent
```

Pull down the latest dependencies via `glide` and build the process-agent:

```
rake deps
rake build
```

You can now run the Agent on the command-line:

```
sudo ./process-agent -config $PATH_TO_PROCESS_CONFIG_FILE
```

## Regenerating proto files

If you modify any of the `.proto` files you _must_ rebuild the `*.pb.go` files.

First make sure you install the gogo-proto binaries from the `./vendor`:

```
cd vendor/github.com/gogo/protobuf
make install
```

and then:

```
rake protobuf
```

## Development or Running with Vagrant
There is a Vagrantfile in the root directory, that can be used to create a vagrant vm where the StackState process agent can be run.

```
$ vagrant up process-agent
...
$ vagrant ssh process-agent
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
```

## Testing

Instructions related to manual testing can be found in [Testing.md](Testing.md)

## Contributing

In order for your contributions you will be required to sign a CLA. When a PR is opened a bot will prompt you to sign the CLA. Once signed you will be set for all contributions going forward.
