#!/bin/bash

set -e
set -u

script_dir=./

dirs=()
verbose=0
while (( $# )); do
    case "$1" in
        --generator)
            generator="$2"
            shift 2
            ;;
        --verbose)
            verbose=1
            shift 1
            ;;
        *)
            dirs+=("$1")
            shift 1
            ;;
    esac
done

cat_if() {
    if (( $1 > 0 )); then
        cat
    else
        cat >/dev/null
    fi
}

run_one() {
    dbgout=$(realpath $3)
    rm -f $dbgout
    # GEM5_DEBUG_FLAGS=FmtTicksOff,ExecEnable,ExecUser,ExecEffAddr,ExecMacro,ExecResult \
        GEM5_DEBUG_FLAGS=CtSeqTrace \
        GEM5_DEBUG_FILE=$dbgout \
        ./src/cli.py fuzz \
        -s $script_dir/base.json --generator=$generator --ruby --protean=None \
        -i 1 -n 1 -c $conf --verbose -ic $1/inputpickle_$2.pkl -t $asm -p protean-check-$2 | cat_if $verbose
}

run_check() {
    tmp1=`mktemp`
    tmp2=`mktemp`
    asm=$1/test_case_rvzr_input1.asm
    extra_args=""
    # extra_args="--ipc-show-output"
    conf=$1/configuration.yaml
    rm -f ~/log.out
    run_one $1 reference dbgout1.txt
    run_one $1 primer dbgout2.txt
    # num_ctraces=$(cat $tmp1 $tmp2 | grep ctrace | uniq | wc -l | cut -d' ' -f1)
    # num_htraces=$(cat $tmp1 $tmp2 | grep htrace | uniq | wc -l | cut -d' ' -f1)
    # if (( $num_ctraces != 1 )); then
    #     echo "[*] false positive (mismatching ctraces): $1"
    #     return 0
    # elif (( $num_htraces == 1 )); then
    #     echo "[*] false positive (matching htraces): $1"
    #     return 0
    # else
    #     echo "[*] true positive: $1"
    #     grep -e ctrace -e htrace $tmp1 $tmp2
    #     return 1
    # fi
    diff -q dbgout1.txt dbgout2.txt
}

for violation in "${dirs[@]}"; do
    if run_check "$violation"; then
        # True Positive
        echo TRUE-POSITIVE $violation
    else
        echo FALSE-POSITIVE $violation
    fi
done
