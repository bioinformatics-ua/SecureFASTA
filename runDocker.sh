#!/bin/bash

set -x

docker build . -t secure-fasta
docker run -v $(pwd):/data \
            secure-fasta \
            $@