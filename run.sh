#!/bin/bash

set -e

source venv/bin/activate

script_dir=$(dirname ${BASH_SOURCE[0]})
src=$script_dir/src

YAML=$script_dir/cache_and_tlb_ct.yaml
YAML_PROT=$script_dir/cache_and_tlb_prot.yaml

protean_args=(--protean=Track --protean-pred-mode=Predict --protean-pred-size=1024) # --debug-flags=O3CPU)
generator=--generator=llvm
# generator=--generator=const:tmp2.asm

if [[ "$I" == "" ]]; then
	I=100
fi

if [[ "$NAME" = "" ]]; then
    NAME=protean
fi

run_debug() {
    i=0
    $src/cli.py fuzz --gen-seed=$RANDOM$RANDOM --ipc-show-output --verbose -s $script_dir/base.json --generator=random --ruby ${protean_args[@]} -i 140 -n 200 -c $YAML_PROT -p protean-$i
}

run_bench() {
    for ((i=0; i<100; ++i)); do
        $src/cli.py fuzz --gen-seed=$RANDOM$RANDOM -s $script_dir/base.json $generator --ruby ${protean_args[@]} -i 140 -n 200 -c $YAML -p protean-$i >&log-$i.txt &
    done
}

# TODO: run_bench_archx
run_bench_archx() {
    name=protean-arch$1
    results_dir=$name/
    mkdir -p $results_dir
    for ((i=0; i<$I; ++i)); do
        $src/cli.py fuzz \
                    --gen-seed=$RANDOM$RANDOM \
                    -s $script_dir/base.json \
                    --generator=random \
                    --ruby --protean=$2 --protean-pred-mode=Predict --protean-pred-size=1024 \
                    -i 140 -n 200 \
                    -c cache_and_tlb_arch.yaml \
                    --result-dir=$results_dir \
                    -p $name-$i >&$results_dir/log-$i.txt &
    done
}

run_bench_archnone() {
    run_bench_archx none None
}

run_bench_archdelay() {
    run_bench_archx delay Delay
}

run_bench_archtrack() {
    run_bench_archx track Track
}

run_bench_ctx() {
    name=protean-ct$1
    results_dir=$name/
    mkdir -p $results_dir
    for ((i=0; i<$I; ++i)); do
        $src/cli.py fuzz \
                    --gen-seed=$RANDOM$RANDOM \
                    -s $script_dir/base.json \
                    --generator=llvm \
                    --ruby --protean=$2 --protean-pred-mode=Predict --protean-pred-size=1024 \
                    -i 140 -n 200 \
                    -c cache_and_tlb_ct.yaml \
                    --result-dir=$results_dir \
                    -p $name-$i >&$results_dir/log-$i.txt &
    done
}

run_bench_ctnone() {
    run_bench_ctx none None
}

run_bench_ctdelay() {
    run_bench_ctx delay Delay
}

run_bench_cttrack() {
    run_bench_ctx track Track
}

run_bench_ctunmod() {
    name=protean-ctunmod$1
    results_dir=$name/
    mkdir -p $results_dir
    for ((i=0; i<25; ++i)); do
        $src/cli.py fuzz \
                    --gen-seed=$RANDOM$RANDOM \
                    -s $script_dir/base.json \
                    --generator=llvm-unmod \
                    --ruby --protean=$2 --protean-pred-mode=Predict --protean-pred-size=1024 \
                    -i 140 -n 200 \
                    -c cache_and_tlb_ct.yaml \
                    --result-dir=$results_dir \
                    -p $name-$i >&$results_dir/log-$i.txt &
    done

}

run_bench_ctunmoddelay() {
    run_bench_ctunmod delay Delay
}

run_bench_ctunmodtrack() {
    run_bench_ctunmod track Track
}

run_bench_cts() {
    name=protean-cts$1
    results_dir=$name/
    mkdir -p $results_dir
    for ((i=0; i<25; ++i)); do
        $src/cli.py fuzz \
                    --gen-seed=$RANDOM$RANDOM \
                    -s $script_dir/base.json \
                    --generator=llvm-cts \
                    --ruby --protean=$2 --protean-pred-mode=Predict --protean-pred-size=1024 \
                    -i 140 -n 200 \
                    -c cache_and_tlb_ct.yaml \
                    --result-dir=$results_dir \
                    -p $name-$i >&$results_dir/log-$i.txt &
    done
}

run_bench_ctsdelay() {
    run_bench_cts delay Delay
}

run_bench_ctstrack() {
    run_bench_cts track Track
}

run_bench_protx() {
    name=protean-prot$1
    results_dir=$name/
    mkdir -p $results_dir
    for ((i=0; i<$I; ++i)); do
        $src/cli.py fuzz \
                    --gen-seed=$RANDOM$RANDOM \
                    -s $script_dir/base.json \
                    --generator=random \
                    --ruby --protean=$2 --protean-pred-mode=Predict --protean-pred-size=1024 \
                    -i 140 -n 200 \
                    -c cache_and_tlb_prot.yaml \
                    --result-dir=$results_dir \
                    -p $name-$i >&$results_dir/log-$i.txt &
    done
}

run_bench_protnone() {
    run_bench_protx none None
}

run_bench_protdelay() {
    run_bench_protx delay Delay
}

run_bench_prottrack() {
    run_bench_protx track Track
}

run_check() {
    tmp1=`mktemp`
    tmp2=`mktemp`
    asm=$1/test_case_rvzr_input1.asm
    if [[ "$2" != "" ]]; then
        asm="$3"
    fi
    extra_args=""
    # extra_args="--ipc-show-output"
    conf=$1/configuration.yaml
    gem5_dir=gem5/spt2
    protean_args=(--gem5-path=$gem5_dir --gem5-binary=$gem5_dir/build/X86/gem5.opt)
    # protean_args+=(--gem5-script-opts='--stt --implicit-channel=Lazy --speculation-model=AtRet')
    protean_args+=(--gem5-script-opts='--spt --fwdUntaint=1 --bwdUntaint=1 --enableShadowL1=1 --spt-bugfix-pending --speculation-model=AtRet')
    # protean_args+=(--gem5-script-opts='--mieros=Delay --speculation-model=AtRet')
    generator=llvm.arch
    GEM5_DEBUG_FILE=$PWD/dbgout1.txt $src/cli.py fuzz --ipc-show-output -s $script_dir/base.json $extra_args --generator=$generator --ruby "${protean_args[@]}" -i 1 -n 1 -c $conf --verbose -ic $1/inputpickle_reference.pkl -t $asm -p protean-check-0 | tee $tmp1
    GEM5_DEBUG_FILE=$PWD/dbgout2.txt $src/cli.py fuzz -s $script_dir/base.json $extra_args --generator=$generator --ruby "${protean_args[@]}" -i 1 -n 1 -c $conf --verbose -ic $1/inputpickle_primer.pkl -t $asm -p protean-check-1 | tee $tmp2
    num_ctraces=$(cat $tmp1 $tmp2 | grep ctrace | uniq | wc -l | cut -d' ' -f1)
    num_htraces=$(cat $tmp1 $tmp2 | grep htrace | uniq | wc -l | cut -d' ' -f1)
    if (( $num_ctraces != 1 )); then
        echo "[*] false positive (mismatching ctraces): $1"
        return 0
    elif (( $num_htraces == 1 )); then
        echo "[*] false positive (matching htraces): $1"
        return 0
    else
        echo "[*] true positive: $1"
        grep -e ctrace -e htrace $tmp1 $tmp2
        return 1
    fi
}

cmd=$1
shift 1

run_$cmd "$@"
