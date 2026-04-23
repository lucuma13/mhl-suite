#!/usr/bin/env python3

# mhlver - One MHL tool to verify them all
# Copyright (c) 2026 Luis Gómez Gutiérrez
# Licensed under the MIT License

import sys
import argparse
import subprocess
import shutil
from datetime import datetime
from pathlib import Path

MHLVER_VERSION = "1.1.2"

# Colours used
RED = '\033[0;31m'
ORANGE = '\033[38;5;208m'
RESET = '\033[0m'

# Print standard help message
def show_help():
    print(f"mhlver v{MHLVER_VERSION}. Find and verify source MHL files or directories\n")
    print("Usage: mhlver [options] <path>\n")
    print("Options:")
    print("  -d, --datestamp        : Prepend datestamp for reporting")
    print("  -s, --xsd-schema-check : Validate XML Schema Definition")
    print("  -v, --verbose          : Verbose")
    print("  -h, --help             : Show this help message")
    print("  --version              : Print version")
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

# Find commands in the same venv as the script, falling back to the system PATH
def get_command_path(cmd_name):
    # Search the bin directory of the current virtual environment/prefix
    venv_bin = Path(sys.prefix) / ("Scripts" if sys.platform == "win32" else "bin")
    cmd_path = venv_bin / cmd_name
    
    if cmd_path.exists():
        return str(cmd_path)
    
    # Fallback to system PATH (e.g. if direnv is active or tool is global)
    return shutil.which(cmd_name)

# Verify single MHL or ASC-MHL target
def verify_item(target: Path, datestamp: bool, verbose: bool, schema: bool) -> int:
    target_str = str(target)
    target_name = target.name

    # Determine if ASC-MHL based on path presence
    is_ascmhl = "ascmhl" in target.parts or target_name.find("ascmhl") != -1

    # Legacy MHL (MHL 1.0)
    if not is_ascmhl:
        cmd = ["simple-mhl", "xsd-schema-check" if schema else "verify", target_str]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
            exit_code = result.returncode

            if exit_code == 0:
                log_success(f"MHL verified: {target_name}", datestamp)
            elif exit_code == 10:
                log_error(f"Schema non-compliant: {target_name}", datestamp)
            elif exit_code == 20:
                print(f"🚨 {ORANGE}Malformed XML: {target_name} cannot be read.{RESET}")
            elif exit_code in [30, 40]:
                 log_error(f"Verification failed: {target_name}", datestamp)
                 print(f"{RED}{result.stdout.strip()}{RESET}")
            else:
                print(f"🚨 {ORANGE}System error: {exit_code} for {target_name}{RESET}")
                
            return exit_code

        except FileNotFoundError:
            print(f"🚨 {ORANGE}System error: 'simple-mhl' command not found. Ensure it is in your PATH.{RESET}")
            return 127

    # ASC-MHL (MHL 2.0)
    else:
        # Resolve the mhl-suite directory containing the XSD folder
        suite_dir = Path(__file__).resolve().parent

        # Look for ascmhl-debug specifically as it contains the verification logic
        cmd_path = get_command_path("ascmhl-debug")
    
        if not cmd_path:
            print("🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.")
            return 127


        if schema:
            cmd = [cmd_path, "xsd-schema-check", target_str]
        else:
            grandparent = target.parent.parent
            cmd = [cmd_path, "verify"]
            if verbose:
                cmd.append("-v")
            cmd.append(str(grandparent))
            
        try:
            # Execute with cwd set to suite_dir so ascmhl finds the xsd folder
            result = subprocess.run(cmd, cwd=suite_dir if suite_dir.exists() else None)
            if result.returncode == 0:
                log_success(f"ASC-MHL {'schema valid' if schema else 'verified'}: {target_name}", datestamp)
            else:
                log_error(f"Manual verification required for {grandparent}", datestamp)
            return result.returncode
        except FileNotFoundError:
            print(f"🚨 {ORANGE}System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.{RESET}")
            return 127

def find_mhl_files(root: Path):
    #Yield MHL files while skipping macOS resource forks
    for p in root.rglob("*.[mM][hH][lL]"):
        if not p.name.startswith("._"):
            yield p

def main():
    parser = argparse.ArgumentParser(add_help=False)
    # ... (rest of your existing argparse code)
    # -----------------------------
    parser = argparse.ArgumentParser(add_help=False)
    
    # Flag definitions
    parser.add_argument("-d", "--datestamp", action="store_true")
    parser.add_argument("-s", "--xsd-schema-check", action="store_true")
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

    # Initialise the default exit status
    exit_status = 0

    # --- Execution ---
    if src.is_file():
        exit_status = verify_item(src, args.datestamp, args.verbose, args.xsd_schema_check)
        
    elif src.is_dir():
        lastgrandparent = None

        # Recursively iterate through files, filter macOS resource forks, and sort results.
        mhl_files = sorted(find_mhl_files(src))

        for f in mhl_files:
            parent = f.parent
            grandparent = parent.parent

            # ASC-MHL redundancy check if multiple .mhl files exist in same ascmhl folder
            if parent.name.endswith("ascmhl"):
                if grandparent == lastgrandparent:
                    continue
                lastgrandparent = grandparent

            if args.datestamp:
                print('---')

            # Capture the result and update exit_status if it's the first error
            current_code = verify_item(f, args.datestamp, args.verbose, args.xsd_schema_check)
            if exit_status == 0:
                exit_status = current_code

    sys.exit(exit_status)


if __name__ == "__main__":
    main()