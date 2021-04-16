#!/bin/sh

go get github.com/golang/dep/cmd/dep
go get github.com/awalterschulze/goderive
dep ensure -v -vendor-only
go generate ./...

(cd vendor/github.com/gogo/protobuf && make install)
