# Datadog Process Agent

## Run on Linux

Follow the installation steps on [http://docs.datadoghq.com/guides/process/](http://docs.datadoghq.com/guides/process/) for your OS version.

OR

Grab the latest release from the [releases page](https://github.com/DataDog/datadog-process-agent/releases) and run from the command line:

```
dd-process-agent -config $PATH_TO_PROCESS_CONFIG_FILE
```

## Running in Docker

See our [Docker README](https://github.com/DataDog/datadog-process-agent/blob/master/packaging/docker/README.md) for the full details.

## Running in Kubernetes

See our [Kubernetes README](https://github.com/DataDog/datadog-process-agent/blob/master/packaging/docker/README.md) for the full details.

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
rake install
```

You can now run the Agent on the command-line:

`dd-process-agent -config $PATH_TO_PROCESS_CONFIG_FILE`

If you modify any of the `.proto` files you _must_ rebuild the *.pb.go files with

```
rake protobuf
```

## Run on Mac or Windows

Coming soon...


