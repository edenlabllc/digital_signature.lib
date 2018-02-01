#!/bin/bash

IMAGE=$(docker build -f Dockerfile.test . | tail -1 | awk '{ print $NF }')

CONTAINER=$(docker run -d $IMAGE /bin/bash -c 'cd /home/digital_signature.lib; mix test')

docker attach $CONTAINER

RC=$(docker wait $CONTAINER)

docker rm $CONTAINER

#docker rmi $IMAGE

#exit $RC
