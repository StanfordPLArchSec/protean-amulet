#!/bin/bash

set -e

long=0
if [[ "$1" == "-l" ]]; then
    long=1
fi

for path in "$@"; do
    if (( long )); then
        printf "%s " "$path"
    fi
    tail -1 "$path"
done
