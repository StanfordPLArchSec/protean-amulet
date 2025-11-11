num_instances = 100
# Changed from 140 to 5, since the 'commit' microarchitectural observer
# finds many more violations.
num_inputs = int(config.get("inputs", "5"))
num_programs = int(config.get("programs", "200"))

verbose = bool(int(config.get("verbose", "0")))

retries = int(config.get("retries", "2"))

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
        name = "protean.track",
        gem5_dir = "gem5/protean",
        script_opts = ["--protean=Track", "--protean-pred-mode=Predict", "--protean-pred-size=1024", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "protean.delay",
        gem5_dir = "gem5/protean",
        script_opts = ["--protean=Delay", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "stt.0",
        gem5_dir = "gem5/stt",
        script_opts = ["--stt", "--implicit-channel=Lazy", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "stt.1",
        gem5_dir = "gem5/stt",
        script_opts = ["--stt", "--implicit-channel=Lazy", "--speculation-model=AtRet", "--stt-bugfix-store"],
    ),
    Defense(
        name = "stt.2",
        gem5_dir = "gem5/stt",
        script_opts = ["--stt", "--implicit-channel=Lazy", "--speculation-model=AtRet", "--stt-bugfix-store", "--stt-bugfix-pending"],
    ),
    Defense(
        name = "spt.0",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--fwdUntaint=1", "--bwdUntaint=1", "--enableShadowL1=1", "--speculation-model=AtRet"],
    ),
    Defense(
        name = "spt.1",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--fwdUntaint=1", "--bwdUntaint=1", "--enableShadowL1=1", "--speculation-model=AtRet",
                       "--spt-bugfix-pending"],
    ),
    Defense(
        name = "spt.sb",
        gem5_dir = "gem5/spt",
        script_opts = ["--spt", "--disableUntaint=1", "--speculation-model=AtRet", "--spt-bugfix-pending"],
    ),
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
        "commit": ["commit"],
    }
    return str(d[w.attacker])

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
    retries: retries
    shell:
        "./src/cli.py fuzz --gen-seed=$RANDOM$RANDOM -s base.json "
        "--generator={wildcards.generator} --ruby "
        "--gem5-script-opts='{params.script_opts}' "
        f"-i {num_inputs} -n {num_programs} "
        "-c {input.config} "
        "--result-dir={params.result_dir}/ "
        "-p {params.result_dir}-{wildcards.idx} "
        "--gem5-path={params.gem5_dir} --gem5-binary={params.gem5_dir}/build/X86/gem5.opt "
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
