#!/bin/bash

set -e

script_dir=$(dirname ${BASH_SOURCE[0]})
src=$script_dir/src

YAML=$script_dir/cache_and_tlb.yaml

for ((i=0; i<25; ++i)); do
    $src/cli.py fuzz -s $script_dir/base.json --nonstop --ruby --protean=None --protean-pred-mode=Predict --protean-pred-size=1024 -i 140 -n 200 -c $YAML -p protean-$i >&log-$i.txt &
done
