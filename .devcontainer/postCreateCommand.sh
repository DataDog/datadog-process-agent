#!/bin/sh

sudo chown vscode: /go/src/github.com
go get github.com/golang/dep/cmd/dep
dep ensure -v -vendor-only
