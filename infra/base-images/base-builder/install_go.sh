#!/bin/bash -eux
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd /tmp

export GOROOT=/root/.go

# First, install standard Go 1.25.0 for bootstrapping
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
mkdir temp-go
tar -C temp-go/ -xzf go1.25.0.linux-amd64.tar.gz
mkdir /root/.go/
mv temp-go/go/* /root/.go/
rm -rf temp-go go1.25.0.linux-amd64.tar.gz

echo 'Set "GOPATH=/root/go"'
echo 'Set "PATH=$PATH:/root/.go/bin:$GOPATH/bin"'

# Install legacy go-fuzz tools using standard Go
go install github.com/mdempsky/go114-fuzz-build@latest
ln -s $GOPATH/bin/go114-fuzz-build $GOPATH/bin/go-fuzz

# Build signal handler
if [ -f "$GOPATH/gosigfuzz/gosigfuzz.c" ]; then
    clang -c $GOPATH/gosigfuzz/gosigfuzz.c -o $GOPATH/gosigfuzz/gosigfuzz.o
fi

cd /tmp
git clone https://github.com/AdamKorcz/go-118-fuzz-build
cd go-118-fuzz-build
go build
mv go-118-fuzz-build $GOPATH/bin/

# Build v2 binaries
git checkout v2
go build .
mv go-118-fuzz-build $GOPATH/bin/go-118-fuzz-build_v2
pushd cmd/convertLibFuzzerTestcaseToStdLibGo
  go build . && mv convertLibFuzzerTestcaseToStdLibGo $GOPATH/bin/
popd
pushd cmd/addStdLibCorpusToFuzzer
  go build . && mv addStdLibCorpusToFuzzer $GOPATH/bin/
popd
cd /tmp
rm -rf go-118-fuzz-build

# Now build and install the custom Go fork with native libFuzzer support
# This replaces the standard Go installation
echo "Building Go fork with native libFuzzer support..."
cd /tmp
git clone --depth 1 --branch libfuzzer-integration https://github.com/AdamKorcz/go.git go-libfuzzer-fork
cd go-libfuzzer-fork/src

# Use the standard Go we installed as the bootstrap compiler
export GOROOT_BOOTSTRAP=/root/.go

# Build the custom Go
./make.bash

# Replace the standard Go with the custom build
rm -rf /root/.go/*
mv /tmp/go-libfuzzer-fork/* /root/.go/
cd /tmp
rm -rf go-libfuzzer-fork

echo "Go with native libFuzzer support installed successfully"
go version
