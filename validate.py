#!/usr/bin/env python3

import argparse
import glob
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("logpath", nargs="+")
parser.add_argument("--count", "-n", type=int)
args = parser.parse_args()
error = False

for logpath in args.logpath:
    with open(logpath) as f:
        for line in f:
            pass
        line = line.strip()
        oklist = [
            'Violation found - Check results',
            'Fuzzer finished without finding violations',
        ]
        if line not in oklist:
            print(f'ERROR: {logpath}: {line}', file=sys.stderr)
            error = True

# Check count.
if args.count and args.count != len(args.logpath):
    print(f"ERROR: expected {args.count} logs, but got {len(args.logpath)}")
    error = 1 

exit(int(error))
