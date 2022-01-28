#!/bin/sh

go get github.com/awalterschulze/goderive
go generate ./...

sudo apt-get update
sudo apt-get install rake
