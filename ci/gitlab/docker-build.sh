#!/bin/sh

# build a docker image to test tuf-test-vectors

set -ex

docker build -t advancedtelematic/tuf-test-vectors -f "./Dockerfile.tuf-test-vectors" ../../
