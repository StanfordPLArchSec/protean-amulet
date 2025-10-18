# Amulet with Protean Support
This is a fork of Amulet with a number of added features enabling the testing of hardware-software codesigned Spectre defenses like Protean.
The original Amulet README is [here](README.orig.md).

An overview of the added features:
- [LLVM-IR Test Generator](#LLVM-Test-Generator)
- [Protean Support](#Protean-Support)
- [PROT-SEQ Contract](#PROT-SEQ-Contract)
- [Bugfixes](#Bugfixes)
- [Documentation of Amulet False Positives](#Amulet-False-Positives)


## LLVM-IR Test Generator
Mainline Amulet only supports generating random assembly tests.
However, hardware-software defenses like Protean (as well as software-only defenses like speculative load hardening) need to be able to compile input test cases with a specific compiler pass to ensure security.
Thus, we added a new LLVM-IR test generator to Amulet.
Our test generator is based on the [llvm-stress](https://llvm.org/docs/CommandGuide/llvm-stress.html) tool that comes with LLVM, with a number of tweaks to make it generate more interesting, diverse, and compact test cases featuring ample conditional branches.
To build the LLVM test generator, clone our ProtCC fork of LLVM [here](https://anonymous.4open.science/r/protcc) and build as follows:
```sh
cd /path/to/protcc
cmake -S llvm -B build
cmake --build build --target llvm-stress
```
To see how to use our custom fork of `llvm-stress`, see [src/generator_llvm.py].

We also provide an out-of-tree LLVM-IR pass in [Sandbox.cpp](/Sandbox.cpp) for sandboxing the randomly generated LLVM-IR program to ensure that it does not crash at runtime.
We will release instructions for compiling this later.

## Protean Support
We merged Amulet's modifications to gem5 into a fork of our Protean gem5 branch, which you can find [here](https://anonymous.4open.science/r/protean-gem5-amulet).

## PROT-SEQ Contract
Protean hardware upholds a novel contract, called PROT-SEQ. Put simply, PROT-SEQ exposes all data in ProtISA-unprotected registers and memory locations at each step of the sequential (i.e., architectural) execution of the program
as well as the value of all sensitive operands of sequentially executed transmitters.
In other words, PROT-SEQ extends CT-SEQ to additionally expose all unprotected registers that are written to and all unprotected memory locations that are read from at each step of the execution.

## Bugfixes
- At the start of each test case execution, mainline Amulet's ARCH-SEQ contract accidentally exposes the final register state of the *previous* test case, not the initial register state of the *current* test case, is it should.

## Amulet False Positives
We encountered an additional bug in mainline Amulet that we have not (yet) fixed:
the base address of the gem5 sandbox differs from the base address of the unicorn sandbox, resulting in rare false positives, in which Amulet reports incorrectly reports a security violation due to the test case taking a different architectural execution path in gem5 than in unicorn.
