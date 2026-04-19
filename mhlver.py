#!/usr/bin/env python3

# mhlver - One MHL tool to verify them all
# Copyright (c) 2026 Luis Gómez Gutiérrez
# Licensed under the MIT License

import sys
import argparse, subprocess
from datetime import datetime
from pathlib import Path

MHLVER_VERSION = "1.1"

# Colours used
RED = '\033[0;31m'
ORANGE = '\033[38;5;208m'
RESET = '\033[0m'

# Print standard help message
def show_help():
    print(f"mhlver v{MHLVER_VERSION}. Find and verify source MHL files or directories\n")
    print("Usage: mhlver [options] <path>\n")
    print("Options:")
    print("  -d, --datestamp : Preprend datestamp for reporting")
    print("  -s, --schema    : Validate XML Schema Definition (MHL v1 only)")
    print("  -v, --verbose   : Verbose")
    print("  -h, --help      : Show this help message")
    print("  --version       : Print version")
    sys.exit(0)

# Log successful verifications
def log_success(msg: str, datestamp: bool):
    if datestamp:
        print(f"[{datetime.now().strftime('%Y.%m.%d-%H:%M:%S')}] ✅ {msg}")
    else:
        print(f"✅ {msg}")

# Log error states
def log_error(msg: str, datestamp: bool):
    if datestamp:
        print(f"{RED}[{datetime.now().strftime('%Y.%m.%d-%H:%M:%S')}] ❌ {msg}{RESET}", file=sys.stderr)
    else:
        print(f"{RED}❌ {msg}{RESET}", file=sys.stderr)

# Verify single MHL or ASC-MHL target
def verify_item(target: Path, datestamp: bool, verbose: bool, schema: bool):
    target_str = str(target)
    target_name = target.name

    # Determine if ASC-MHL based on path presence
    is_ascmhl = "ascmhl" in target.parts or target_name.find("ascmhl") != -1

    # Legacy MHL (MHL 1.0)
    if not is_ascmhl:
        cmd = ["simple-mhl", "verify", target_str]
        
        if schema:
            cmd.append("--schema")

        try:
            # Capture stdout only, let stderr flow to terminal natively
            result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
            exit_code = result.returncode
            output = result.stdout.strip()
            
            if exit_code == 0:
                log_success(f"MHL verified: {target_name}", datestamp)
            elif exit_code == 10:
                log_success(f"MHL verified: {target_name}", datestamp)
                # Python already printed the "Read more..." URL to stderr
            elif exit_code == 20:
                print(f"🚨 {ORANGE}Malformed XML: {target_name} cannot be read.{RESET}")
            elif exit_code == 30:
                log_error(f"Verification failed: {target_name}", datestamp)
                print(f"{RED}{output}{RESET}")
            elif exit_code == 40:
                log_error(f"Verification failed: {target_name}", datestamp)
                print(f"{RED}{output}{RESET}")
                # Python already printed "Schema non-compliant" to stderr
            else:
                print(f"🚨 {ORANGE}System error: {exit_code} for {target_name}{RESET}")
                
        except FileNotFoundError:
            print(f"🚨 {ORANGE}System error: 'simple-mhl' command not found. Ensure it is in your PATH.{RESET}")

    # ASC-MHL (MHL 2.0)
    else:
        grandparent = target.parent.parent
        
        cmd = ["ascmhl-debug", "verify"]
        if verbose:
            cmd.append("-v")
        cmd.append(str(grandparent))
        
        try:
            result = subprocess.run(cmd)
            if result.returncode == 0:
                log_success(f"ASC-MHL verified: {grandparent.name}", datestamp)
            else:
                log_error(f"Manual verification required for {grandparent}", datestamp)
        except FileNotFoundError:
            print(f"🚨 {ORANGE}System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.{RESET}")


def main():
    parser = argparse.ArgumentParser(add_help=False)
    
    # Flag definitions
    parser.add_argument("-d", "--datestamp", action="store_true")
    parser.add_argument("-s", "--schema", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("path", nargs="?", default=".")

    args = parser.parse_args()

    if args.version:
        print(MHLVER_VERSION)
        sys.exit(0)

    if args.help:
        show_help()

    # Resolve source (Default to current directory)
    src = Path(args.path).resolve()

    if not src.exists():
        log_error("Argument should be a file or directory that exists in the filesystem", args.datestamp)
        sys.exit(2)

    # --- Execution ---
    if src.is_file():
        verify_item(src, args.datestamp, args.verbose, args.schema)
        
    elif src.is_dir():
        lastgrandparent = None
        
        # find command avoids hidden/system files and sorts for consistency
        mhl_files = []
        for file_path in src.rglob("*.[mM][hH][lL]"):
            if not file_path.name.startswith("._"):
                mhl_files.append(file_path)
                
        mhl_files.sort()

        for f in mhl_files:
            parent = f.parent
            grandparent = parent.parent

            if parent.name.endswith("ascmhl"):
                # Avoid redundant checks if multiple .mhl files exist in same ascmhl folder
                if grandparent != lastgrandparent:
                    if args.datestamp:
                        print('---')
                    verify_item(f, args.datestamp, args.verbose, args.schema)
                    lastgrandparent = grandparent
            else:
                if args.datestamp:
                    print('---')
                verify_item(f, args.datestamp, args.verbose, args.schema)

if __name__ == "__main__":
    main()