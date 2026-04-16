#!/bin/bash

# mhlver - An MHL tool to verify them all
readonly MHLVER_VERSION="1.0"

# Copyright (c) 2026 Luis Gómez Gutiérrez
# Licensed under the MIT License

# Colours used
readonly RED='\033[0;31m'
readonly RESET='\033[0m'

function show_help() {
	echo "mhlver v$MHLVER_VERSION. Find and verify source MHL files or directories"
	echo
	echo "Usage: mhlver [options] <path>"
	echo 
	echo "Options:"
	echo "  -d : Add datestamp for report"
	echo "  -v : Verbose"
    echo "  -h : Show this help message"
	echo "  --version  : Print version"
	exit 0
}

function get_abs_path() {
    local user_path="${1:-.}"
    if [[ -d "$user_path" ]]; then
        (cd "$user_path" && pwd)
    elif [[ -f "$user_path" ]]; then
        echo "$(cd "$(dirname "$user_path")" && pwd)/$(basename "$user_path")"
    else
        echo "$user_path"
    fi
}

function log_success() {
    local msg=$1
    if $datestamp; then
        echo "[$(date '+%Y.%m.%d-%H:%M:%S')] ✅ $msg"
    else
        echo "✅ $msg"
    fi
}

function log_error() {
    local msg=$1
    if $datestamp; then
        echo -e "${RED}[$(date '+%Y.%m.%d-%H:%M:%S')] ❌ $msg${RESET}" >&2
    else
        echo -e "${RED}❌ $msg${RESET}" >&2
    fi
}

function verify_item() {
    local target=$1
    local is_ascmhl=false
    
    [[ "$target" == *"ascmhl"* ]] && is_ascmhl=true

    if $is_ascmhl; then
        # ASC-MHL usually requires the grandparent directory for context
        local grandparent=$(dirname "$(dirname "$target")")
        ascmhl-debug verify $verbose_flag "$grandparent"
        if [[ $? -eq 0 ]]; then
            log_success "MHL verified: $(basename "$grandparent")"
        else
            log_error "Manual verification required for $grandparent"
        fi
    else
        mhl verify -f "$target"
        if [[ $? -eq 0 ]]; then
            log_success "MHL verified: $(basename "$target")"
        else
            log_error "Verification failed for $target"
        fi
    fi
}

# Long-format flags
[[ "$1" == "--version" ]] && { echo "$MHLVER_VERSION"; exit 0; }
[[ "$1" == "--help" ]] && show_help

# Short-format flags
datestamp=false
verbose_flag=""

while getopts "dvh" option
do
	case $option in
		d) datestamp=true ;;
		v) verbose_flag="-v" ;;
		h) show_help ;;
		*) show_help ;;
	esac
done
shift "$((OPTIND-1))"

# Resolve source (Default to current directory)
src=$(get_abs_path "${1:-$(pwd)}")

if [[ ! -e "$src" ]]; then
    log_error "Argument should be a file or directory that exists in the filesystem"
    exit 2
fi

# --- Execution ---

if [ -f "$src" ]; then
    verify_item "$src"
elif [ -d "$src" ]; then
    lastgrandparent=""
    # find command avoids hidden/system files and sorts for consistency
    while read -r f; do
        parent=$(dirname "$f")
        grandparent=$(dirname "$parent")
        
        if [[ "$parent" == *"/ascmhl" ]]; then
            # Avoid redundant checks if multiple .mhl files exist in same ascmhl folder
            if [[ "$grandparent" != "$lastgrandparent" ]]; then
                $datestamp && echo '---'
                verify_item "$f"
                lastgrandparent="$grandparent"
            fi
        else
            $datestamp && echo '---'
            verify_item "$f"
        fi
    done < <(find "${src%/}" -mindepth 1 -type f -iname "*.mhl" ! -iname "._*" | sort)
fi