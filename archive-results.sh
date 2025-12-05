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
        if ! "$root/validate.py" "$1"/log-*.txt; then
            echo "ERROR: $1: validation failed!" >&2
            return 1
        fi
        num_logs=$(ls "$1"/log-*.txt | wc -l)
        if (( num_logs != 100 )); then
            echo "ERROR: missing logs!" >&2
            return 1
        fi
    fi
    d="$ref/$base"
    if [[ -d "$d" ]]; then
        echo "WARNING: directory already exists, skipping: $d" >&2
        return 1
    fi

    # do the copy
    cp -r "$1" "$ref/$base"

    # do the compression
    pushd "$d" >/dev/null
    tar --xz -cf logs.tar.xz log-*.txt
    rm log-*.txt
    if [[ -d results ]]; then
        tar --xz -cf results.tar.xz results
        rm -r results
    fi
    popd >/dev/null
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
