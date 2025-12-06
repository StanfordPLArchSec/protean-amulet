num_instances = 100
# Changed from 140 to 5, since the 'commit' microarchitectural observer
# finds many more violations.
num_programs = int(config.get("programs", "200"))

verbose = bool(int(config.get("verbose", "0")))

retries = int(config.get("retries", "2"))

re_dotted_word = r"(\w|\.)+"

container: "amulet.sif"

wildcard_constraints:
    defense = re_dotted_word,
    observer = re_dotted_word,
    generator = re_dotted_word,
    attacker = re_dotted_word,

class Defense:
    name = None
    gem5_dir = None
    script_opts = []

    def __init__(self, name, gem5_dir, script_opts):
        self.name = name
        self.gem5_dir = gem5_dir
        self.script_opts = script_opts

    def clone(self):
        return Defense(
            name = self.name,
            gem5_dir = self.gem5_dir,
            script_opts = list(self.script_opts),
        )

    def splat(self, opts):
        defenses = []
        for i in range(len(opts) + 1):
            defenses.append(self.clone())
            defenses[-1].name += f".{i}"
            defenses[-1].script_opts.extend(opts[:i])
        return defenses

defenses = [
    Defense(
        name = "none",
        gem5_dir = "gem5/base",
        script_opts = [],
    ),
    Defense(
        name = "prottrack",
        gem5_dir = "gem5/protean",
        script_opts = ["--protean=Track", "--protean-pred-mode=Predict", "--protean-pred-size=1024", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "protdelay",
        gem5_dir = "gem5/protean",
        script_opts = ["--protean=Delay", "--speculation-model=AtRet", "--protean-delay-flags-opt"],
    ),
    *Defense(
        name = "stt",
        gem5_dir = "gem5/stt",
        script_opts = ["--stt", "--implicit-channel=Lazy", "--speculation-model=AtRet"],
    ).splat(["--stt-bugfix-store", "--more-transmit-insts=3", "--stt-bugfix-pending"]),
    *Defense(
        name = "spt",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--fwdUntaint=1", "--bwdUntaint=1", "--enableShadowL1=1", "--speculation-model=AtRet"],
    ).splat(["--moreTransmitInsts=3", "--spt-bugfix-pending", "--spt-bugfix-rename", "--spt-bugfix-datasize"]),
    *Defense(
        name = "sptsb",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--disableUntaint=1", "--speculation-model=AtRet"],
    ).splat(["--moreTransmitInsts=3", "--spt-bugfix-pending"]),
]

def get_defense(w) -> Defense:
    for defense in defenses:
        if defense.name == w.defense:
            return defense
    assert False, f"No defense '{w.defense}' found"

def get_observer(w) -> str:
    s = w.observer
    if s == "ct":
        s = "ctx"
    return s
    
def get_attacker(w) -> str:
    d = {
        "cache": ["data_cache", "dtlb"],
        "commit": ["data_cache", "dtlb", "commit"],
    }
    return str(d[w.attacker])

def get_inputs(w) -> int:
    d = {
        "cache": 140,
        "commit": 5,
    }
    return d[w.attacker]

rule gen_amulet_config:
    output: "{defense}-{observer}-{generator}-{attacker}/configuration.yaml"
    input: "config-template.yaml"
    params:
        observer = get_observer,
        attacker = get_attacker,
    shell:
        "ARCH_OBS='{params.observer}' "
        "UARCH_OBS='{params.attacker}' "
        "envsubst <{input} >{output}"

rule run_amulet_instance:
    input:
        config = "{defense}-{observer}-{generator}-{attacker}/configuration.yaml"
    output: "{defense}-{observer}-{generator}-{attacker}/log-{idx}.txt"
    wildcard_constraints:
        idx = r"[0-9]+"
    params:
        gem5_dir = lambda w: get_defense(w).gem5_dir,
        script_opts = lambda w: get_defense(w).script_opts,
        result_dir = lambda w: \
            expand("{defense}-{observer}-{generator}-{attacker}", **w),
        verbose_args = ["--ipc-show-output", "--verbose"] if verbose else [],
        num_inputs = get_inputs,
        timeout = 3600 * 4, # timeout for fuzzing job
    retries: retries
    resources:
        runtime = 24 * 60 # 24 hours.
    shell:
        "ulimit -c unlimited && ulimit -c -S unlimited && "
        "PYTHONUNBUFFERED=1 stdbuf -o0 -e0 "
        "./src/cli.py fuzz --gen-seed=$RANDOM$RANDOM -s base.json "
        "--generator={wildcards.generator} --ruby "
        "--gem5-script-opts='{params.script_opts}' "
        "-i {params.num_inputs} -n {num_programs} "
        "-c {input.config} "
        "--result-dir={params.result_dir}/ "
        "-p {params.result_dir}-{wildcards.idx} "
        "--gem5-path={params.gem5_dir} --gem5-binary={params.gem5_dir}/build/X86/gem5.opt "
        "--timeout={params.timeout} "
        "{params.verbose_args} "
        "> {output} 2>&1 && "
        "! grep '^Buggy test' {output}"

rule run_experiment_i:
    output: "{defense}-{observer}-{generator}-{attacker}/all.{i}"
    input:
        lambda w: expand("{defense}-{observer}-{generator}-{attacker}/log-{idx}.txt", **w, idx=range(0, int(w.i)))
    shell:
        "touch {output}"
        
rule run_experiment:
    output: "{defense}-{observer}-{generator}-{attacker}/all"
    input:
        lambda w: expand("{defense}-{observer}-{generator}-{attacker}/log-{idx}.txt", **w, idx=range(0, num_instances))
    shell:
        "touch {output}"

include: "rules/triage.smk"
