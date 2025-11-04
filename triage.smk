import os

def result_inorder_path(suffix):
    return os.path.join("{defense}-{observer}-{generator}/results/{result}/", suffix)

rule result_inorder:
    output:
        directory(result_inorder_path("inorder_{input}"))
    input:
        config = result_inorder_path("configuration.yaml"),
        pickle = result_inorder_path("inputpickle_{input}.pkl"),
        asm = result_inorder_path("test_case_rvzr_input1.asm"),
    wildcard_constraints:
        input = r"(primer|reference)"
    shell:
        "rm -rf {output} && "
        "mkdir -p {outdir} && "
        "./inorder.sh --generator={wildcards.generator} timeout 15 ./src/cli.py fuzz --cpu-type=X86TimingSimpleCPU -s base.json --ruby "
        "--protean=None --ipc-show-output --gem5-path=gem5/protean --gem5-binary=gem5/protean/build/X86/gem5.opt "
        "-i 1 -n 1 -c {input.config} --verbose -ic {input.pickle} -t {input.asm} --result-dir={output} -p protean-check-{wildcards.input} "
        ">{output}/stdout.txt 2>&1 "
