#!/usr/bin/env python3

import argparse
import re
import sys

parser = argparse.ArgumentParser()
parser.add_argument("log", nargs="+")
args = parser.parse_args()

def get_seconds(path):
    l = []
    with open(path) as f:
        for line in f:
            if m := re.fullmatch(r"Duration Elapsed: (\d+)hrs-(\d+)mins-(\d+)secs", line.strip()):
                s = int(m.group(3)) + int(m.group(2)) * 60 + int(m.group(1)) * 60 * 60
                l.append(s)
    if len(l) == 0:
        print(f"ERROR: missing duration: {path}", file=sys.stderr)
        exit(1)
    return l[-1]

l = [get_seconds(log) for log in args.log]
print(sum(l), max(l))
