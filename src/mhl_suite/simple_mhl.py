#!/usr/bin/env python3
# simple-mhl - Modern verification and sealing tool for legacy MHL files

import argparse
import getpass
import hashlib
import importlib.resources
import os
import platform
import sys
from datetime import datetime, timezone

import xxhash
from lxml import etree

VERSION = "1.0.1"

# Supported hash algorithms
ALGO_MAP = {
    "xxhash":     (xxhash.xxh64, "xxhash64be"),
    "xxh64":      (xxhash.xxh64, "xxhash64be"),
    "xxhash64":   (xxhash.xxh64, "xxhash64be"),
    "xxhash64be": (xxhash.xxh64, "xxhash64be"),
    "md5":        (hashlib.md5,  "md5"),
    "sha1":       (hashlib.sha1, "sha1"),
}

# Tags recognised during verification (superset of ALGO_MAP keys)
SUPPORTED_HASH_TAGS = frozenset(ALGO_MAP.keys()) | {"xxhash128", "xxhash3_64", "null"}


def get_xsd_path():
    """Locate the bundled XSD, returning its path or None on failure."""
    try:
        with importlib.resources.path("mhl_suite.xsd", "MediaHashList_v1_1.xsd") as p:
            return str(p)
    except (ImportError, FileNotFoundError, TypeError):
        pass

    local_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "xsd", "MediaHashList_v1_1.xsd"
    )
    if os.path.exists(local_path):
        return local_path

    sys.stderr.write(f"Error: Could not locate MediaHashList_v1_1.xsd (tried {local_path})\n")
    return None


def main():
    parser = argparse.ArgumentParser(
        prog="simple-mhl",
        description="Modern verification and sealing tool for legacy MHL files",
    )
    subparsers = parser.add_subparsers(dest="command")
    parser.add_argument("--version", action="version", version=VERSION)

    seal_p = subparsers.add_parser("seal", help="seal directory (MHL file generated at the root)")
    seal_p.add_argument("path", help="path to directory to seal")
    seal_p.add_argument("-a", "--algorithm", default="xxhash", help="hash algorithm: xxhash64 (default), md5, sha1")
    seal_p.add_argument("--dont-reseal", action="store_true", help="abort if an MHL file already exists at root")
    seal_p.set_defaults(func=lambda a: seal(a.path, a.algorithm, a.dont_reseal))

    verify_p = subparsers.add_parser("verify", help="verify an MHL file")
    verify_p.add_argument("path", help="path to MHL file")
    verify_p.set_defaults(func=lambda a: verify(a.path))

    xsd_p = subparsers.add_parser("xsd-schema-check", help="validation of XML Schema Definition (XSD)")
    xsd_p.add_argument("path", help="path to MHL file")
    xsd_p.set_defaults(func=lambda a: validate_schema(a.path))

    args = parser.parse_args()
    args.func(args)


def get_hash(filepath, algo_key):
    """Hash a file using the specified algorithm key."""
    if algo_key not in ALGO_MAP:
        raise ValueError(f"Unsupported hash algorithm: {algo_key}")
    hasher_func = ALGO_MAP[algo_key][0]
    hasher = hasher_func()
    with open(filepath, "rb") as f:
        # Read in 8 MB chunks for large-file efficiency
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# ------------ Seal command ------------

def seal(root, algorithm, dont_reseal):
    """Walk root, hash every non-hidden file, and write a dated MHL manifest."""
    # Resolve absolute path
    root = os.path.abspath(root)
    base_name = os.path.basename(root)

    # Generate timestamp
    now_dt = datetime.now(timezone.utc)
    timestamp = now_dt.strftime("%Y-%m-%d_%H%M%S")
    mhl_name = f"{base_name}_{timestamp}.mhl"
    mhl_path = os.path.join(root, mhl_name)

    # Handle filename collisions
    if os.path.exists(mhl_path):
        if dont_reseal:
            sys.exit(0)
        counter = 1
        while os.path.exists(os.path.join(root, f"{base_name}_{timestamp}_{counter}.mhl")):
            counter += 1
        mhl_path = os.path.join(root, f"{base_name}_{timestamp}_{counter}.mhl")

    # Initialise XML root element and populate the creatorinfo block
    now_iso = now_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    doc = etree.Element("hashlist", version="1.1")
    etree.SubElement(doc, "creationdate").text = now_iso
    info = etree.SubElement(doc, "creatorinfo")
    for k, v in [
        ("username",   getpass.getuser()),
        ("hostname",   platform.node()),
        ("tool",       f"simple-mhl v{VERSION}"),
        ("startdate",  now_iso),
        ("finishdate", now_iso),
    ]:
        etree.SubElement(info, k).text = v

    xml_tag = ALGO_MAP.get(algorithm, (None, "xxhash64be"))[1]

    # Construct hash entries using os.walk efficiently
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))

        for filename in sorted(filenames):
            if filename.startswith('.'):
                continue

            filepath = os.path.join(dirpath, filename)

            # Skip the MHL file being written to avoid self-hashing
            if filepath == mhl_path:
                continue

            rel_path = os.path.relpath(filepath, root)

            try:
                stat_result = os.stat(filepath)
            except OSError:
                continue

            # Create hash entry
            h_el = etree.SubElement(doc, "hash")
            etree.SubElement(h_el, "file").text = rel_path.replace('\\', '/')
            etree.SubElement(h_el, "size").text = str(stat_result.st_size)
            mtime_utc = datetime.fromtimestamp(stat_result.st_mtime, timezone.utc)
            etree.SubElement(h_el, "lastmodificationdate").text = mtime_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
            etree.SubElement(h_el, xml_tag).text = get_hash(filepath, algorithm)
            etree.SubElement(h_el, "hashdate").text = now_iso

    # Update finishdate now that all hashing is complete
    finish_el = info.find("finishdate")
    if finish_el is not None:
        finish_el.text = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    # Serialise the constructed XML tree to disk with formatting
    etree.ElementTree(doc).write(mhl_path, xml_declaration=True, encoding='UTF-8', pretty_print=True)


# ------------ Verify command ------------

def verify(mhl_file):
    """Verify each file listed in an MHL manifest against its stored hash(es)."""
    if not os.path.exists(mhl_file):
        sys.stderr.write(f"Verification Error: {mhl_file} not found\n")
        sys.exit(1)

    mhl_dir = os.path.abspath(os.path.dirname(mhl_file))

    # Parse the MHL file into a tree and conditionally evaluates it against the XSD
    try:
        tree = etree.parse(mhl_file)
    except etree.XMLSyntaxError:
        sys.exit(20)

    missing = []
    mismatches = []

    # Compare the declared payloads with the actual files
    for h in tree.xpath("//*[local-name()='hash']"):
        fname_list = h.xpath(".//*[local-name()='file']/text()")
        if not fname_list:
            continue

        # Normalise path separators (Windows compatibility)
        fname = fname_list[0].replace('/', os.sep)

        # Block directory traversal
        fpath = os.path.abspath(os.path.join(mhl_dir, fname))
        if os.path.commonpath([mhl_dir, fpath]) != mhl_dir:
            mismatches.append(f"Security: Blocked traversal attempt for {fname}")
            continue

        # Find the first supported hash node
        h_node = next(
            (
                node for node in h.xpath(".//*")
                if (node.tag.split('}')[-1] if '}' in node.tag else node.tag) in SUPPORTED_HASH_TAGS
            ),
            None,
        )
        if h_node is None:
            mismatches.append(f"No supported hash found for: {fname}")
            continue

        tag = h_node.tag.split('}')[-1] if '}' in h_node.tag else h_node.tag
        expected = h_node.text

        if not os.path.exists(fpath):
            missing.append(f"Missing file: {fname} cannot be found")
            continue

        calculated_hex = get_hash(fpath, tag)

        # Legacy check: <xxhash> was stored as a decimal integer in some older MHL files
        if tag == "xxhash" and expected.isdigit():
            if str(int(calculated_hex, 16)) != expected:
                mismatches.append(fname)
        else:
            if calculated_hex != expected:
                mismatches.append(fname)

    errors = missing + mismatches
    if errors:
        print("\n".join(errors))
        # Exit 30 = missing files only; exit 40 = hash mismatches present
        sys.exit(30 if not mismatches else 40)


# ------------ Schema Validation ------------

def validate_schema(mhl_file):
    """Validate an MHL file against the bundled XSD schema."""
    xsd_path = get_xsd_path()
    if not xsd_path:
        sys.stderr.write("Verification Error: Could not locate MediaHashList_v1_1.xsd\n")
        sys.exit(1)

    try:
        tree = etree.parse(mhl_file)
        xsd = etree.XMLSchema(etree.parse(xsd_path))
        if not xsd.validate(tree):
            for err in xsd.error_log:
                sys.stderr.write(f"Schema Error: {err.message} (line {err.line})\n")
            sys.exit(10)
    except etree.XMLSyntaxError as e:
        sys.stderr.write(f"XML Parsing Error: {e}\n")
        sys.exit(20)
    except OSError as e:
        sys.stderr.write(f"File Error: {e}\n")
        sys.exit(20)


if __name__ == "__main__":
    main()