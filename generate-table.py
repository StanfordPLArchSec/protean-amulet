#!/usr/bin/env python3

import argparse
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("snakemake_command", nargs="+")
parser.add_argument("--num-instances", "-n", type=int, default=100)
parser.add_argument("--skip-fuzz", action="store_true")
parser.add_argument("--skip-triage", action="store_true")

args = parser.parse_args()

# Collect the list of configurations and targets.
observer_generator_pairs = [
    ("prot", "llvm.rand"),
    ("cts", "llvm.cts"),
    ("ct", "llvm.ct"),
    ("ct", "llvm.unr"),
]
configs = []
fuzz_targets = []
triage_targets = []
for defense in ["none", "prottrack", "protdelay"]:
    for observer, generator in observer_generator_pairs:
        for adversary in ["cache", "commit"]:
            configs.append((defense, observer, generator, adversary))
            for idx in range(0, args.num_instances):
                fuzz_targets.append(f"{defense}-{observer}-{generator}-{adversary}/log-{idx}.txt")
            triage_targets.append(f"{defense}-{observer}-{generator}-{adversary}/triage")


# Run the fuzzing experiments.
fuzz_command = args.snakemake_command + fuzz_targets
if not args.skip_fuzz:
    subprocess.run(fuzz_command, check=True, shell=True)

print("[*] Finished running experiments.", file=sys.stderr)
print("[*] Triaging findings now.", file=sys.stderr)

# Triage findings.
triage_command = args.snakemake_command + ["-j1"] + triage_targets
if not args.skip_triage:
    subprocess.run(triage_command, check=True, shell=True)

# Process triage results.
results = collections.defaultdict(lambda: collections.defaultdict(int))
for defense, observer, generator, adversary in configs:
    l = results[(defense, observer, generator)]
    path = f"{defense}-{observer}-{generator}-{adversary}/triage"
    violations = json.loads(pathlib.Path(path).read_text())
    for violation in violations.values():
        l[violation["result"]] += 1

# Print totals.
def observer_pretty(observer):
    observer = observer.upper()
    if observer == "PROT":
        observer = "UNPROT"
    return observer

for observer, generator in observer_generator_pairs:
    # Contract.
    contract = r"\tt " + f"{observer_pretty(observer)}-SEQ"

    # Instrumentation.
    instrumentation = "ProtCC-" + generator.removeprefix("llvm.").upper()

    # Defenses.
    defenses = []
    for defense in ["none", "prottrack", "protdelay"]:
        d = results[(defense, observer, generator)]["true-positive"]
        true_positives = d["true-positives"]
        false_positives = d["false-positive"]
        assert len(d) == 2
        defenses.append(r"\textbf{" + str(true_positives) +
                        r"} (" + str(false_positives) + ")")

    # Print out line.
    line = " & ".join([contract, instrumentation, *defenses])
    print(line)

