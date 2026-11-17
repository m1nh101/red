#!/usr/bin/env bash
# Usage: upload.sh PWD_PATH [NAME]
#   PWD_PATH  positional argument: local directory containing the file
#   NAME      optional positional argument: file name (default: payload.bin)
#   Local file uploaded = PWD_PATH + NAME

set -euo pipefail

KEY="/workspaces/binary_exploitation/scripts/key"   # fixed SSH key path, set this directly

usage() {
    echo "Usage: $0 PWD_PATH [NAME]" >&2
    exit 1
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
fi

case "$1" in
    -h|--help) usage ;;
esac

PWD_PATH="$1"
NAME="${2:-payload.bin}"

# Ensure the directory path ends with a single slash before joining the name
PWD_PATH="${PWD_PATH%/}/"
FULL_PATH="${PWD_PATH}${NAME}"

if [[ ! -f "$KEY" ]]; then
    echo "Error: key file not found: $KEY" >&2
    exit 1
fi

if [[ ! -f "$FULL_PATH" ]]; then
    echo "Error: file not found: $FULL_PATH" >&2
    exit 1
fi

scp -i "$KEY" "$FULL_PATH" hacker@dojo.pwn.college:/home/hacker