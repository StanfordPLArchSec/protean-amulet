#!/usr/bin/env python3

import pickle
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("pickles", nargs="+")
parser.add_argument("-n", type=int, default=1)
parser.add_argument("-l", action="store_true")
args = parser.parse_args()

def strip_pickle(path, n):
    with open(path, "rb") as f:
        x = pickle.load(f)
    assert type(x) is list
    x = x[-n:]
    with open(path, "wb") as f:
        pickle.dump(x, f)

def pickle_length(path):
    with open(path, "rb") as f:
        x = pickle.load(f)
    print(len(x))

for path in args.pickles:
    if args.l:
        pickle_length(path)
    else:
        strip_pickle(path, args.n)
