#!/bin/bash

IMAGE=$(docker build -f Dockerfile.test . | tail -1 | awk '{ print $NF }')

docker run --rm -it $IMAGE /bin/bash -c 'cd /home/digital_signature.lib; mix test'

docker rmi $IMAGE
