# Datadog Process Agent

[![CircleCI](https://circleci.com/gh/DataDog/datadog-process-agent.svg?style=svg)](https://circleci.com/gh/DataDog/datadog-process-agent)

## Run on Linux, Docker or Kubernetes

Follow the installation steps on [http://docs.datadoghq.com/guides/process/](http://docs.datadoghq.com/guides/process/) for your OS version.

OR

Grab the latest release from the [releases page](https://github.com/DataDog/datadog-process-agent/releases) and run from the command line:

```
dd-process-agent -config $PATH_TO_PROCESS_CONFIG_FILE
```

## Development or running from source

Pre-requisites:

* `go >= 1.9.4`
* `rake`

Check out the repo in your `$GOPATH`

```
cd $GOPATH/DataDog
git clone git@github.com:DataDog/dd-process-agent
cd dd-process-agent
```

Pull down the latest dependencies via `glide`:

```
rake deps
rake install
```

You can now run the Agent on the command-line:

`dd-process-agent -config $PATH_TO_PROCESS_CONFIG_FILE`

If you modify any of the `.proto` files you _must_ rebuild the *.pb.go files with

```
rake protobuf
```

## Contributing

In order for your contributions you will be required to sign a CLA. When a PR is opened a bot will prompt you to sign the CLA. Once signed you will be set for all contributions going forward.


## Run on Mac or Windows

Coming soon...


