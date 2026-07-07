# mhl-suite

[![PyPI Version](https://img.shields.io/pypi/v/mhl-suite.svg)](https://pypi.org/project/mhl-suite/)
![OS](https://img.shields.io/badge/OS-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)
[![CI](https://github.com/lucuma13/mhl-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/lucuma13/mhl-suite/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/lucuma13/mhl-suite/graph/badge.svg?token=X6Z7IRDZ6U)](https://codecov.io/github/lucuma13/mhl-suite)

`mhl-suite` is a toolkit for sealing and verifying MHL files. It consists of two primary executables:

* `mhlver`: one tool to verify them all. Recursively verifies every MHL file under a path (both classic flat MHL and ASC-MHL), with a per-file progress bar, reports and optional XSD schema validation. The official [ASC-MHL](https://github.com/ascmitc/mhl) library runs in-process alongside the classic-MHL engine from `simple-mhl`. Both verify with the same smart parallel hashing, giving ASC-MHL verification a speed-up over the reference implementation.
* `simple-mhl`: a modern sealing and verification tool, for classic flat MHL files. A successor of the discontinued [mhl-tool](https://github.com/pomfort/mhl-tool) and backwards compatible with legacy manifests - 2 to 5 times faster (smart parallel hashing), full support for standard `xxhash64be` hashes, correct NFC/NFD handling independently of the filesystem, XSD schema validation features, cleaner output and structured exit codes.

Both tools use smart parallel hashing. They measure real sequential hashing throughput, aggregate read speed (across several concurrent streams), and the in-memory speed of the selected hash algorithm(s) to always achieve the highest performance in any volume (HDD, SSD, RAID, NAS or SAN) and parallelise only if it pays off.

### 🚀 Installation

1. Install the `uv` package manager with the [official installer](https://docs.astral.sh/uv/getting-started/installation/), or:
* macOS: `brew install uv`
* Windows: `winget install astral-sh.uv`
* Linux (Debian): `apt-get install uv`
<!--
* Linux (RHEL): `yum install uv`
* Linux (SUSE): `zypper install python-uv`
* Linux (Arch): `pacman -S muv`
-->

2. Install the toolkit:

```
uv tool install mhl-suite
```

3. Test the installation (if the command is not recognised try `uv tool update-shell` and restart your terminal):

```
mhlver --version; simple-mhl --version
```

### 📖 Usage examples

Verify MHL files (both classic and ASC-MHL):

```bash
mhlver path/to/file.mhl
mhlver path/to/directory/                  # every manifest found
mhlver                                     # current directory
```

Create a report after verification:
```bash
mhlver --report path/to/directory/
```

Quick size-only check:
```bash
mhlver --size-only path/to/directory/
```

Seal a directory:

```bash
simple-mhl seal path/to/directory/
simple-mhl seal -a md5 -a xxhash path/to/directory/        # use both MD5 and xxhash algorithms
simple-mhl seal -o path/to/output/mhl path/to/directory/   # write the MHL into a parent directory
```

Validate XML Schema Definition of a file:

```bash
mhlver --xsd-schema-check path/to/file
```

Run `simple-mhl --help` and `mhlver --help` to see the full list of options.
