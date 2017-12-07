#!/bin/bash

docker build -t digital_signature_lib_test -f Dockerfile.test .

docker run -d --rm \
-it \
--mount type=bind,source="$(pwd)",target=/home/digital_signature.api mixtest:latest

