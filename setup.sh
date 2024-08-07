#!/bin/bash

# if [[ -z "$ND_LOCAL" ]]; then
#     ND_HOST="localhost"
# else
#     host=$(ifconfig | grep -E 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | awk '{ print $2 }' | cut -d: -f2 | head -n1)
#     echo $host
#     ND_HOST=$host
# fi

# export ND_HOST