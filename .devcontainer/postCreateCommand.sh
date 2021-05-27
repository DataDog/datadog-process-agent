#!/bin/sh

go get github.com/golang/dep/cmd/dep
go get github.com/awalterschulze/goderive
dep ensure -v -vendor-only
go generate ./...

sudo apt-get update
sudo apt-get install rake

(cd vendor/github.com/gogo/protobuf && make install)
