# Datadog Process Agent

[![CircleCI](https://circleci.com/gh/DataDog/datadog-process-agent.svg?style=svg)](https://circleci.com/gh/DataDog/datadog-process-agent)

## Run on Linux

Follow the installation steps on [http://docs.datadoghq.com/guides/process/](http://docs.datadoghq.com/guides/process/) for your OS version.

OR

Grab the latest release from the [releases page](https://github.com/DataDog/dd-process-agent/releases) and run from the command line:

```
dd-process-agent -config $PATH_TO_PROCESS_CONFIG_FILE
```

## Run on Mac

Coming soon...

## Run on Windows

Coming soon..

## Development or running from source

Pre-requisites:

* `go >= 1.8.3`
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
go install
```

You can now run the Agent on the command-line:

`dd-process-agent -config $PATH_TO_PROCESS_CONFIG_FILE`

If you modify any of the `.proto` files you _must_ rebuild the *.pb.go files with

```
rake protobuf
```
