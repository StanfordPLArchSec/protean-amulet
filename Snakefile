num_instances = 100
# Changed from 140 to 5, since the 'commit' microarchitectural observer
# finds many more violations.
num_inputs = int(config.get("inputs", "5"))
num_programs = int(config.get("programs", "200"))

verbose = bool(int(config.get("verbose", "0")))

class Defense:
    name = None
    gem5_dir = None
    script_opts = []

    def __init__(self, name, gem5_dir, script_opts):
        self.name = name
        self.gem5_dir = gem5_dir
        self.script_opts = script_opts

defenses = [
    Defense(
        name = "none",
        gem5_dir = "gem5/base",
        script_opts = [],
    ),
    Defense(
        name = "prottrack",
        gem5_dir = "gem5/protean",
        script_opts = ["--mieros=Track", "--mieros-pred-mode=Predict", "--mieros-pred-size=1024", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "protdelay",
        gem5_dir = "gem5/protean",
        script_opts = ["--mieros=Delay", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "stt",
        gem5_dir = "gem5/stt",
        script_opts = ["--stt", "--implicit-channel=Lazy", "--stt-bugfixes", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "spt",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--fwdUntaint=1", "--bwdUntaint=1", "--enableShadowL1=1", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "spt-sb",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--disableUntaint=1", "--speculation-model=AtRet"],
    ),
]

def get_defense(w) -> Defense:
    for defense in defenses:
        if defense.name == w.defense:
            return defense
    assert False, f"No defense '{w.defense}' found"

rule run_amulet_instance:
    output: "{defense}-{observer}-{generator}/log-{idx}.txt"
    wildcard_constraints:
        idx = r"[0-9]+"
    params:
        gem5_dir = lambda w: get_defense(w).gem5_dir,
        script_opts = lambda w: get_defense(w).script_opts,
        result_dir = lambda w: \
            expand("{defense}-{observer}-{generator}", **w),
        verbose_args = ["--ipc-show-output"] if verbose else [],
    retries: 3
    shell:
        "./src/cli.py fuzz --gen-seed=$RANDOM$RANDOM -s base.json "
        "--generator={wildcards.generator} --ruby --gem5-script-opts='{params.script_opts}' "
        f"-i {num_inputs} -n {num_programs} "
        "-c cache_and_tlb_{wildcards.observer}.yaml "
        "--result-dir={params.result_dir}/ "
        "-p {params.result_dir}-{wildcards.idx} "
        "--gem5-path={params.gem5_dir} --gem5-binary={params.gem5_dir}/build/X86/gem5.opt "
        "{params.verbose_args} "
        "> {output} && "
        "! grep -q '^Buggy test' {output}"

rule run_experiment_i:
    output: "{defense}-{observer}-{generator}/all.{i}"
    input:
        lambda w: expand("{defense}-{observer}-{generator}/log-{idx}.txt", **w, idx=range(0, int(w.i)))
    shell:
        "touch {output}"
        
rule run_experiment:
    output: "{defense}-{observer}-{generator}/all"
    input:
        lambda w: expand("{defense}-{observer}-{generator}/log-{idx}.txt", **w, idx=range(0, num_instances))
    shell:
        "touch {output}"

rule getcmd_amulet_instance:
    output: "{defense}-{observer}-{generator}/results/{resultdir}/run.sh"
    params:
        resultdir = "{defense}-{observer}-{generator}/results/{resultdir}"
    run:
        cmd = [
            "./src/cli.py", "fuzz",
            "--ipc-show-output", "-s", "base.json",
            "--generator=llvm", "--ruby",
            "-i", "1", "-n", "1",
            "-c", os.path.join(wildcards.resultdir,
                               "configuration.yaml"),
            "--verbose",
        ]        
