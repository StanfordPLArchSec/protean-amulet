#!/bin/bash

set -e
set -u

script_dir=./

source venv/bin/activate

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
    timeout 15 ./src/cli.py fuzz \
                 --cpu-type=X86TimingSimpleCPU \
                 -s $script_dir/base.json --generator=$generator --ruby --protean=None \
                 --ipc-show-output \
                 --gem5-path=gem5/protean --gem5-binary=gem5/protean/build/X86/gem5.opt \
                 -i 1 -n 1 -c $conf --verbose -ic $1/inputpickle_$2.pkl -t $asm -p protean-check-$2 | tee $3
}

get_num_uops() {
    grep simOps results/protean-check-$1/stats_input1.txt | tail -1
}

run_check() {
    tmp1=$PWD/classify-log-1.txt
    tmp2=$PWD/classify-log-2.txt
    asm=$1/test_case_rvzr_input1.asm
    conf=$1/configuration.yaml
    rm -f ~/log.out
    GEM5_DEBUG_FILE=$PWD/dbgout1.txt run_one $1 reference $tmp1
    GEM5_DEBUG_FILE=$PWD/dbgout2.txt run_one $1 primer $tmp2
    num_ctraces=$(cat $tmp1 $tmp2 | grep ctrace | uniq | wc -l | cut -d' ' -f1)
    num_htraces=$(cat $tmp1 $tmp2 | grep htrace | uniq | wc -l | cut -d' ' -f1)
    if (( $num_ctraces != 1 )); then
        echo "BUG: mismatching ctraces" >&2
        exit 1
    elif (( num_htraces > 1 )); then
        # violation
        # echo "[*] true positive: $1"
        if (( verbose )); then
            echo $tmp1 $tmp2
            grep -e ctrace -e htrace $tmp1 $tmp2
        fi
        return 1
    elif ! diff <(get_num_uops reference) <(get_num_uops primer) >/dev/null 2>/dev/null; then
        if (( verbose )); then
            git diff --no-index <(get_num_uops reference) <(get_num_uops primer) || :
        fi
        return 1
    else
        # no violation
        if (( verbose )); then
            echo results/protean-check-{reference,primer}/stats_input1.txt
            get_num_uops reference
            get_num_uops primer
        fi
        return 0
    fi
}

for violation in "${dirs[@]}"; do
    if ! run_check "$violation"; then
        echo VIOLATION $violation
    else
        echo OK $violation
    fi
done
