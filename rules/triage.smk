import os
import re
import json
import glob

def result_path(suffix):
    return os.path.join("{defense}-{observer}-{generator}-{attacker}",
                        "results", "{result}", suffix)

def search_file(pattern, path):
    matches = []
    with open(path) as f:
        for line in f:
            if m := re.search(pattern, line):
                matches.append(m)
    return matches

def search_file_one(pattern, path):
    matches = search_file(pattern, path)
    if len(matches) != 1:
        print(f"expected 1 match, got {len(matches)}: pattern={pattern}, path={path}",
              file=sys.stderr)
        raise ValueError("")
    return matches[0]

def get_ctrace_from_file(path):
    return search_file_one(r"^ctraces: (\[.*\])$", path).group(1)

def get_htrace_from_file(path):
    return search_file_one(r"^htraces: (\[.*\])$", path).group(1)

def triage_flags_impl(w):
    if x := config.get("triage_flags"):
        return x
    elif w.observer == "arch":
        return "ExecAll,FmtTicksOff"
    else:
        return "ExecEnable,ExecUser,ExecMacro,ExecMicro,FmtTicksOff"

def triage_flags(w):
    return triage_flags_impl(w) + ",FmtTicksOff"

timeout = 300
    
rule result_inorder_single:
    output:
        directory(result_path("inorder_{input}"))
    input:
        config = result_path("configuration.yaml"),
        pickle = result_path("inputpickle_{input}.pkl"),
        asm = result_path("test_case_rvzr_input1.asm"),
    wildcard_constraints:
        input = r"(primer|reference)"
    params:
        gem5_debug_flags = triage_flags,
        timeout = timeout,
    shell:
        "rm -rf {output} && "
        "mkdir -p {output} && "
        "GEM5_DEBUG_FLAGS={params.gem5_debug_flags} "
        "GEM5_DEBUG_FILE=$(realpath {output}/dbgout.txt) "
        "timeout {params.timeout} ./src/cli.py fuzz --generator={wildcards.generator} "
        " --cpu-type=X86TimingSimpleCPU -s base.json --ruby "
        "--protean=None --ipc-show-output --gem5-path=gem5/protean --gem5-binary=gem5/protean/build/X86/gem5.opt "
        "-i 1 -n 1 -c {input.config} --verbose -ic {input.pickle} -t {input.asm} --result-dir={output}/results "
        "-p protean-check-inorder-{wildcards.input} "
        ">{output}/stdout.txt 2>{output}/stderr.txt "

def do_triage_str(input):
        inorder_input_stdout = \
            list(map(lambda d: os.path.join(d, "stdout.txt"), input.inorder))
        inorder_input_dbgout = \
            list(map(lambda d: os.path.join(d, "dbgout.txt"), input.inorder))
        ooo_input_stdout = \
            list(map(lambda d: os.path.join(d, "stdout.txt"), input.ooo))
        ooo_input_dbgout = \
            list(map(lambda d: os.path.join(d, "dbgout.txt"), input.ooo))
        ctraces1, ctraces2 = map(get_ctrace_from_file, ooo_input_stdout)
        htraces1, htraces2 = map(get_htrace_from_file, ooo_input_stdout)
        if ctraces1 != ctraces2:
            return {
                "result": "false-positive",
                "reason": "mismatching-ctraces",
            }
        if htraces1 == htraces2:
            return {
                "result": "false-positive",
                "reason": "matching-htraces",
            }
        # Do the dbgout's match? 
        with open(ooo_input_dbgout[0]) as f1, \
             open(ooo_input_dbgout[1]) as f2:
            for l1, l2 in zip(f1, f2):
                if l1 != l2:
                    return {
                        "result": "false-positive",
                        "reason": "mismatching-dbgouts",
                        "culprit-lines": [l1, l2],
                    }
        # Was there a unicorn exception?
        errs = search_file(r"Unhandled CPU exception \(UC_ERR_EXCEPTION\)",
                           inorder_input_stdout[0])
        if len(errs) > 0:
            return {
                "result": "false-positive",
                "reason": "unicorn-exception",
            }
        
        # True violation.
        return {
            "result": "true-positive",
            "reason": "none",
        }

def do_triage(input, output):
    result = do_triage_str(input)
    with open(output, "wt") as f:
        json.dump(result, f)
        f.write("\n")
        
rule result_triage:
    output:
        result_path("triage.json")
    input:
        inorder = lambda w: \
            expand(result_path("inorder_{input}"), **w,
                   input=["reference", "primer"]),
        ooo = lambda w: \
            expand(result_path("ooo_{input}"), **w,
                   input=["reference", "primer"]),
    run:
        output, = output
        do_triage(input, output)

def list_results(wildcards):
    results_dir, = \
        expand("{defense}-{observer}-{generator}-{attacker}/results", **wildcards)
    return glob.glob(os.path.join(results_dir, "*hrs-*mins-*secs*"))

rule triage_all:
    output:
        "{defense}-{observer}-{generator}-{attacker}/triage"
    input:
        lambda w: [os.path.join(d, "triage.json") for d in list_results(w)]
    shell:
        "for x in {input}; do echo $x; clang-format $x; done > {output}"
        
rule result_ooo_single:
    output:
        directory(result_path("ooo_{input}"))
    input:
        config = result_path("configuration.yaml"),
        pickle = result_path("inputpickle_{input}.pkl"),
        asm = result_path("test_case_rvzr_input1.asm"),
    wildcard_constraints:
        input = r"(primer|reference)"
    params:
        gem5_dir = lambda w: get_defense(w).gem5_dir,
        script_opts = lambda w: get_defense(w).script_opts,
        triage_flags = triage_flags,
        timeout = timeout,
    shell:
        "rm -rf {output} && "
        "mkdir -p {output} && "
        "GEM5_DEBUG_FLAGS={params.triage_flags} "
        "GEM5_DEBUG_FILE=$(realpath {output}/dbgout.txt) "
        "timeout {params.timeout} ./src/cli.py fuzz --generator={wildcards.generator} "
        "    --cpu-type=X86O3CPU -s base.json --ruby "
        "    --gem5-script-opts='{params.script_opts}' "
        "    --ipc-show-output --gem5-path={params.gem5_dir} "
        "    --gem5-binary={params.gem5_dir}/build/X86/gem5.opt "
        "    -i 1 -n 1 -c {input.config} --verbose -ic {input.pickle} "
        "    -t {input.asm} --result-dir={output}/results "
        "    -p protean-check-ooo-{wildcards.input} "
        "    >{output}/stdout.txt 2>{output}/stderr.txt "
        
rule result_ooo_triage:
    output:
        result_path("ooo")
    input:
        lambda w: expand(result_path("ooo_{input}"), **w,
                                     input=["reference", "primer"])

rule result_inorder_triage:
    output:
        result_path("inorder")
    input:
        lambda w: expand(result_path("inorder_{input}"), **w,
                         input=["reference", "primer"])
        
