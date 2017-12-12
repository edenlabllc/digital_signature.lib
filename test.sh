#!/bin/bash

docker build -t digital_signature_lib_test -f Dockerfile.test .

docker run --rm -it digital_signature_lib_test:latest

