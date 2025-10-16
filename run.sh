#!/bin/bash

set -e

script_dir=$(dirname ${BASH_SOURCE[0]})
src=$script_dir/src

YAML=$script_dir/cache_and_tlb.yaml
YAML_PROT=$script_dir/cache_and_tlb_prot.yaml

protean_args=(--protean=Track --protean-pred-mode=Predict --protean-pred-size=1024) # --debug-flags=O3CPU)
generator=--generator=llvm
# generator=--generator=const:tmp2.asm

if [[ "$NAME" = "" ]]; then
    NAME=protean
fi

run_debug() {
    i=0
    # --nonstop
    $src/cli.py fuzz --gen-seed=$RANDOM$RANDOM --ipc-show-output --verbose -s $script_dir/base.json --generator=random --ruby ${protean_args[@]} -i 140 -n 200 -c $YAML_PROT -p protean-$i
}

run_bench() {
    for ((i=0; i<100; ++i)); do
        # --nonstop
        $src/cli.py fuzz --gen-seed=$RANDOM$RANDOM -s $script_dir/base.json $generator --ruby ${protean_args[@]} -i 140 -n 200 -c $YAML -p protean-$i >&log-$i.txt &
    done
}

# TODO: run_bench_archx

run_bench_ctx() {
    name=protean-ct$1
    results_dir=$name/
    mkdir -p $results_dir
    for ((i=0; i<100; ++i)); do
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
     for ((i=0; i<25; ++i)); do
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

run_analyze() {
    python3 $src/analyse_ipc_violation.py --args="--ruby ${protean_args[*]} -c $YAML" "$@"
}

run_one() {
    # Join the pickles?
    # python3 -c 'import pickle; x = pickle.load(open("violation/inputpickle_input2.pkl", "rb")) + pickle.load(open("violation/inputpickle_input2.pkl", "rb")); pickle.dump(x, open("violation/inputpickle_merged.pkl", "wb"))'
    # $src/cli.py fuzz -s $script_dir/base.json $generator --ruby ${protean_args[@]} -i 1 -n 1 -c $YAML --verbose -ic violation/inputpickle_merged.pkl -t $1
    $src/cli.py fuzz -s $script_dir/base.json $generator --ruby ${protean_args[@]} -i 1 -n 1 -c $YAML --verbose -ic violation/inputpickle_$1.pkl -t violation/test_case_rvzr_input1.asm --analysis_run
}

run_check() {
    tmp1=`mktemp`
    tmp2=`mktemp`
    asm=$1/test_case_rvzr_input1.asm
    if [[ "$2" != "" ]]; then
        asm="$2"
    fi
    extra_args=""
    # extra_args="--ipc-show-output"
    conf=$1/configuration.yaml
    rm -f ~/log.out
    $src/cli.py fuzz -s $script_dir/base.json $extra_args --generator=llvm --ruby ${protean_args[@]} -i 1 -n 1 -c $conf --verbose -ic $1/inputpickle_reference.pkl -t $asm -p protean-check-0 | tee $tmp1
    mv ~/log.out dbgout1.txt
    $src/cli.py fuzz -s $script_dir/base.json $extra_args --generator=llvm --ruby ${protean_args[@]} -i 1 -n 1 -c $conf --verbose -ic $1/inputpickle_primer.pkl -t $asm -p protean-check-1 | tee $tmp2
    mv ~/log.out dbgout2.txt
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
