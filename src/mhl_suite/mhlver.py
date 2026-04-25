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

MHLVER_VERSION = "1.1.4"

# Colours used (suppressed when output is not a terminal)
if sys.stdout.isatty():
    RED = '\033[0;31m'
    ORANGE = '\033[38;5;208m'
    RESET = '\033[0m'
else:
    RED = ORANGE = RESET = ''

def log_success(msg: str, report_file=None):
    """Log successful verifications."""
    line = f"[{datetime.now().strftime('%Y.%m.%d-%H:%M:%S')}] {msg}" if report_file else msg
    print(line)
    if report_file:
        report_file.write(line + "\n")


def log_error(msg: str, report_file=None):
    """Log error states."""
    prefix = f"[{datetime.now().strftime('%Y.%m.%d-%H:%M:%S')}] " if report_file else ""
    print(f"{RED}{prefix}{msg}{RESET}", file=sys.stderr)
    if report_file:
        report_file.write(f"{prefix}{msg}\n")


def get_command_path(cmd_name):
    """Find a command in the active venv's bin, falling back to the system PATH."""
    venv_bin = Path(sys.prefix) / ("Scripts" if sys.platform == "win32" else "bin")
    cmd_path = venv_bin / cmd_name
    if cmd_path.exists():
        return str(cmd_path)
    return shutil.which(cmd_name)

def verify_item(target: Path, verbose: bool, schema: bool, report_file=None) -> int:
    """Verify a single MHL or ASC-MHL target, returning an exit code."""
    target_str = str(target)
    target_name = target.name

    # Determine if ASC-MHL by checking whether any path component is exactly "ascmhl"
    is_ascmhl = "ascmhl" in target.parts

    # --- Legacy MHL (MHL 1.0) ---
    if not is_ascmhl:
        cmd = ["simple-mhl", "xsd-schema-check" if schema else "verify", target_str]
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            exit_code = result.returncode
            subprocess_out = (result.stdout.strip() + "\n" + result.stderr.strip()).strip()

            if exit_code == 0:
                log_success(f"{'✅ MHL verified' if not schema else '📝 MHL schema valid'}: {target_name}", report_file)
            elif exit_code == 10:
                log_error(f"⚠️ Schema non-compliant: {target_name}", report_file)
            elif exit_code == 20:
                msg = f"🚨 {ORANGE}Malformed XML: {target_name} cannot be read.{RESET}"
                print(msg)
                if report_file:
                    report_file.write(f"🚨 Malformed XML: {target_name} cannot be read.\n")
            elif exit_code in [30, 40]:
                log_error(f"❌ Verification failed: {target_name}", report_file)
            else:
                msg = f"🚨 {ORANGE}System error: {exit_code} for {target_name}{RESET}"
                print(msg)
                if report_file:
                    report_file.write(f"🚨 System error: {exit_code} for {target_name}\n")

            if subprocess_out and report_file:
                report_file.write(subprocess_out + "\n")
            if subprocess_out and exit_code != 0:
                print(f"{RED}{subprocess_out}{RESET}")

            return exit_code

        except FileNotFoundError:
            msg = f"🚨 {ORANGE}System error: 'simple-mhl' command not found. Ensure it is in your PATH.{RESET}"
            print(msg)
            if report_file:
                report_file.write("🚨 System error: 'simple-mhl' command not found. Ensure it is in your PATH.\n")
            return 127

    # --- ASC-MHL (MHL 2.0) ---
    else:
        # Resolve the mhl-suite directory containing the XSD folder
        suite_dir = Path(__file__).resolve().parent

        cmd_path = get_command_path("ascmhl-debug")
        if not cmd_path:
            msg = f"🚨 {ORANGE}System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.{RESET}"
            print(msg)
            if report_file:
                report_file.write("🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.\n")
            return 127

        grandparent = target.parent.parent

        if schema:
            cmd = [cmd_path, "xsd-schema-check", target_str]
        else:
            cmd = [cmd_path, "verify"]
            if verbose:
                cmd.append("-v")
            cmd.append(str(grandparent))

        cwd = suite_dir if suite_dir.exists() else None
        if not cwd:
            log_error("suite_dir does not exist; ascmhl-debug may not find its XSD files.", report_file)

        try:
            if schema:
                # Check the .mhl manifest file against the manifest schema
                result_mhl = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                mhl_code = result_mhl.returncode
                mhl_out = (result_mhl.stdout.strip() + "\n" + result_mhl.stderr.strip()).strip()

                # Check the ascmhl_chain.xml against the directory schema
                chain_file = target.parent / "ascmhl_chain.xml"
                result_chain = subprocess.run(
                    [cmd_path, "xsd-schema-check", "--directory_file", str(chain_file)],
                    cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                chain_code = result_chain.returncode
                chain_out = (result_chain.stdout.strip() + "\n" + result_chain.stderr.strip()).strip()

                if mhl_code == 0:
                    log_success(f"📝 ASC-MHL manifest schema valid: {target}", report_file)
                elif mhl_code == 11:
                    log_error(f"⚠️ ASC-MHL schema non-compliant: {target}", report_file)
                else:
                    msg = f"🚨 {ORANGE}Unexpected error: {mhl_code} for {target}{RESET}"
                    print(msg)
                    if report_file:
                        report_file.write(f"🚨 Unexpected error: {mhl_code} for {target}\n")

                if mhl_out and report_file:
                    report_file.write(mhl_out + "\n")
                if mhl_out and mhl_code != 0:
                    print(f"{RED}{mhl_out}{RESET}", file=sys.stderr)

                if chain_code == 0:
                    log_success(f"📝 ASC-MHL directory schema valid: {chain_file}", report_file)
                elif chain_code == 11:
                    log_error(f"⚠️ ASC-MHL schema non-compliant: {chain_file}", report_file)
                else:
                    msg = f"🚨 {ORANGE}Unexpected error: {chain_code} for {chain_file}{RESET}"
                    print(msg)
                    if report_file:
                        report_file.write(f"🚨 Unexpected error: {chain_code} for {chain_file}\n")

                if chain_out and report_file:
                    report_file.write(chain_out + "\n")
                if chain_out and chain_code != 0:
                    print(f"{RED}{chain_out}{RESET}", file=sys.stderr)

                return mhl_code if mhl_code != 0 else chain_code
            else:
                result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                subprocess_out = (result.stdout.strip() + "\n" + result.stderr.strip()).strip()

                if result.returncode == 0:
                    log_success(f"✅ ASC-MHL verified: {target_name}", report_file)
                else:
                    log_error(f"❌ Manual verification required for {grandparent}", report_file)

                if subprocess_out and report_file:
                    report_file.write(subprocess_out + "\n")
                if subprocess_out and result.returncode != 0:
                    print(f"{RED}{subprocess_out}{RESET}", file=sys.stderr)

                return result.returncode
        except FileNotFoundError:
            msg = f"🚨 {ORANGE}System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.{RESET}"
            print(msg)
            if report_file:
                report_file.write("🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.\n")
            return 127


def find_mhl_files(root: Path):
    """Yield MHL files recursively, skipping macOS resource forks."""
    for p in root.rglob("*.[mM][hH][lL]"):
        if not p.name.startswith("._"):
            yield p


def main():
    parser = argparse.ArgumentParser(
        prog="mhlver",
        description="One tool to verify them all: find and verify source MHL files or directories.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("-r", "--report", action="store_true", help="export timestamped report to the target path directory")
    parser.add_argument("-s", "--xsd-schema-check", action="store_true", help="validate XML Schema Definition")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    parser.add_argument("--version", action="version", version=MHLVER_VERSION)
    parser.add_argument("path", nargs="?", default=".", help="path to MHL file or directory (if omitted, uses current directory)")

    args = parser.parse_args()

    # Resolve source (defaults to current directory)
    src = Path(args.path).resolve()

    if not src.exists():
        log_error("Argument should be a file or directory that exists in the filesystem")
        sys.exit(2)

    # Open report file if -r was requested
    report_file = None
    if args.report:
        report_dir = src if src.is_dir() else src.parent
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"mhlver_report_{src.name}_{timestamp_str}.log"
        report_path = report_dir / report_name
        report_file = open(report_path, "w", encoding="utf-8")
        report_file.write(f"mhlver v{MHLVER_VERSION} report — {datetime.now().strftime('%Y.%m.%d %H:%M:%S')}\n")
        report_file.write(f"path: {src}\n")
        report_file.write("---\n")

    exit_status = 0

    try:
        if src.is_file():
            exit_status = verify_item(src, args.verbose, args.xsd_schema_check, report_file)

        elif src.is_dir():
            lastgrandparent = None

            # Recursively iterate, filter macOS resource forks, and sort results
            mhl_files = sorted(find_mhl_files(src))

            for f in mhl_files:
                parent = f.parent
                grandparent = parent.parent

                # ASC-MHL redundancy check: skip duplicate entries for the same ascmhl folder
                if parent.name == "ascmhl":
                    if grandparent == lastgrandparent:
                        continue
                    lastgrandparent = grandparent

                if report_file:
                    report_file.write('---\n')

                current_code = verify_item(f, args.verbose, args.xsd_schema_check, report_file)

                # Preserve the first non-zero exit code encountered
                if exit_status == 0:
                    exit_status = current_code

        if exit_status == 0:
            summary = "✅ MHL scan and verification completed. All MHL files found have been successfully verified."
            log_success(summary, report_file)
        else:
            summary = "❌ Verification failed for some of the MHL files. See details above."
            log_error(summary, report_file)

    finally:
        if report_file:
            report_file.write("---\n")
            report_file.write(f"exit status: {exit_status}\n")
            report_file.close()
            print(f"report saved to: {report_path}")

    sys.exit(exit_status)


if __name__ == "__main__":
    main()