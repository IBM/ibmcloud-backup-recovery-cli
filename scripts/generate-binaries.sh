#!/bin/bash

# build cross compatible binaries to publish

# create a bin directory if one does not already exist
if [ ! -d "bin" ]; then
  echo "Directory created for binaries: ./bin/"
  mkdir bin
fi

# build for osx
env GOOS=darwin GOARCH=amd64 go build main.go
mv main bin/ibmcloud-br-cli-darwin-amd64
echo "Binary created for OSX: ./bin/ibmcloud-br-cli-darwin-amd64"

# build for apple silicon (M1, etc.)
env GOOS=darwin GOARCH=arm64 go build main.go
mv main bin/ibmcloud-br-cli-darwin-arm64
echo "Binary created for Apple Silicon: ./bin/ibmcloud-br-cli-darwin-arm64"

# build for linux
env GOOS=linux GOARCH=amd64 go build main.go
mv main bin/ibmcloud-br-cli-linux-amd64
echo "Binary created for Linux (AMD): ./bin/ibmcloud-br-cli-linux-amd64"

# build for linux
env GOOS=linux GOARCH=arm64 go build main.go
mv main bin/ibmcloud-br-cli-linux-arm64
echo "Binary created for Linux (ARM): ./bin/ibmcloud-br-cli-linux-arm64"

# build for windows
env GOOS=windows GOARCH=amd64 go build main.go
mv main.exe bin/ibmcloud-br-cli-windows-amd64.exe
echo "Binary created for Windows: ./bin/ibmcloud-br-cli-windows-amd64.exe"
