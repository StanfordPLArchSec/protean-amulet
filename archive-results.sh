#!/bin/bash

set -eu

root="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
ref="$root/reference"

usage() {
    cat <<EOF
usage: $0 [-hkvs] amulet-run-dir...
-h   print help
-k   keep going past validation errors
-v   verbose output
-s   skip validation
EOF
}

keep_going=0
verbose=0
no_validate=0
while getopts "hkvs" optc; do
    case $optc in
        h)
            usage
            exit 0
            ;;
        k)
            keep_going=1
            ;;
        v)
            verbose=1
            ;;
        s)
            no_validate=1
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done
shift $((OPTIND - 1))

do_archive() {
    base="$(basename "$1")"

    # validation steps before copying.
    if (( ! no_validate )); then
        if ! "$root/validate.py" -n100 "$1"/log-*.txt; then
            echo "ERROR: $1: validation failed!" >&2
            return 1
        fi

        if [[ ! -f "$1"/triage ]]; then
            echo "ERROR: $1/triage: doesn't exist" >&2
            return 1
        fi
        
        if ! python3 -m json < "$1"/triage > /dev/null; then
            echo "ERROR: $1/triage: not valid json" >&2
            return 1
        fi
    fi


    d="$ref/$base"
    mkdir -p "$d"
    cp "$1"/triage "$d"/triage
}

mkdir -p "$root/reference"
exit_code=0
for d in "$@"; do
    if (( verbose )); then
        echo "INFO: preparing to archive $d" >&2
    fi
    if ! do_archive "$d"; then
        exit_code=$?
        if (( ! keep_going )); then
            exit $exit_code
        fi
    fi
    if (( verbose )); then
        echo "INFO: done archiving $d" >&2
    fi
done
