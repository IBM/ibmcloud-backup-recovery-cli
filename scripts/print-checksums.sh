#!/bin/bash

# print the checksums for each binary file
# these are used when publishling plugins

declare -a binaries=(
  "./bin/ibmcloud-br-cli-darwin-amd64"
  "./bin/ibmcloud-br-cli-darwin-arm64"
  "./bin/ibmcloud-br-cli-linux-amd64"
  "./bin/ibmcloud-br-cli-linux-arm64"
  "./bin/ibmcloud-br-cli-windows-amd64.exe"
)

for binary in "${binaries[@]}"
do
  if [ -f $binary ]; then
    shasum -a 1 $binary
  else
    echo "File not found: $binary"
  fi
done
