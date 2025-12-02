#!/bin/bash

set -e

for path in "$@"; do
    grep -o "Progress: [0-9]\+" "$path" | tail -1 | awk '{print $2 + 1}'
done | awk '{x += $0} END { print x }'
