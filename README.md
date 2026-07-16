# mhl-suite

[![PyPI Version](https://img.shields.io/pypi/v/mhl-suite.svg)](https://pypi.org/project/mhl-suite/)
![OS](https://img.shields.io/badge/OS-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![ty](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ty/main/assets/badge/v0.json)](https://github.com/astral-sh/ty)
[![CI](https://github.com/lucuma13/mhl-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/lucuma13/mhl-suite/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/lucuma13/mhl-suite/graph/badge.svg?token=X6Z7IRDZ6U)](https://codecov.io/github/lucuma13/mhl-suite)

`mhl-suite` is a toolkit for sealing and verifying MHL files. It consists of three primary executables:

* `mhlver`: one tool to verify them all. Recursively verifies every MHL file under a path (both classic flat MHL and ASC-MHL), with a per-file progress bar, reports and optional XSD schema validation. Verifying an ASC MHL history appends a new generation recording the results by default, `-R/--read-only` verifies without writing anything – useful for locked, WORM or archived media (it flattens the history and verifies the in-memory manifest).
* `simple-mhl`: a modern sealing and verification tool, for classic flat MHL files. A successor of the discontinued [mhl-tool](https://github.com/pomfort/mhl-tool) and backwards compatible with legacy manifests - twice as fast (smart parallel hashing), real support for `xxh64`, NFC/NFD handling, XSD schema validation features, cleaner output and structured exit codes.
* `advanced-mhl`: a chain-of-custody tool, for ASC MHL histories. An actively maintained implementation of the [ASC MHL Specification](https://theasc.com/society/ancillary-committees/asc-mhl), fast by design: size pre-checks before hashing, smart parallel hashing, NFC/NFD handling, interoperable with the [reference implementation](https://github.com/ascmitc/mhl) — tested against it, and with several of its known verification issues fixed.

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
mhlver --version; simple-mhl --version; advanced-mhl --version
```

#### Alternative (macOS only)

Install with [Homebrew](https://brew.sh/): `brew install lucuma13/dit/mhl-suite`


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
simple-mhl seal -a md5 -a xxh64 path/to/directory/         # use both MD5 and xxh64 algorithms
simple-mhl seal -o path/to/output/mhl path/to/directory/   # write the MHL into a parent directory
```

Create a new verification generation on the ASC MHL history:

```bash
advanced-mhl generate path/to/directory/
```

Validate XML Schema Definition of a file:

```bash
mhlver --xsd-schema-check path/to/file
```

Run any tool with `--help` to see the full list of options.

### 🔤 Unicode filenames

Unicode allows the same visible filename to be written with different byte sequences: in `rosé.mov` the é can be a single precomposed code point (U+00E9 – the NFC form) or a decomposed `e` followed by a combining accent (U+0301 – the NFD form). Filesystems split on what they store and how they look names up:

| Filesystem | Storage normalisation | Normalisation sensitivity |
|:---:|:---:|:---:|
| NTFS, FAT32, exFAT, ext4 | preserving | sensitive |
| APFS | preserving | insensitive |
| HFS+ | forcing | insensitive |

A name's byte form can therefore change in transit through an offload – HFS+ round-trips rewrite it with no data corruption at all. The picture is fragile even on a single macOS machine, when reading an exFAT volume with colliding Unicode filenames: Finder and `ls` can disagree about how many files exist, while `cp` and Finder may copy different data. So the byte form of a filename is not stable enough to carry identity: a file's identity is its contents, not its path.

Verification tools split into two camps over this: some compare manifest paths to disk byte-for-byte, others tolerate normalisation differences. `mhl-suite` is built for interoperability:

* Sealing records names verbatim. The exact bytes the filesystem reports land in the manifest. Since recorded bytes are only as meaningful as the filesystem that reported them, we also include seal-context on the manifest (OS, kernel, filesystem, driver).
* Sealing refuses ambiguous sources. If two names in the tree are Unicode-equivalent, the seal aborts before any hashing and names both byte forms. Such trees would silently merge, overwrite, or lose one file's data on the first copy to a normalisation-insensitive volume, and no manifest could tell the resulting entries apart – refusing early, while the source media is still in hand, is the only moment this is fixable.
* Verifying matches bytes first, equivalence second. A name whose normalisation form drifted still verifies via Unicode equivalence – but only when the match cannot guess wrong. If equivalent forms coexist on disk or in the manifest, no fallback is attempted and the discrepancy is reported as plain missing/unknown findings.

### 📊 Performance

All tools use smart parallel hashing. They measure real sequential hashing throughput, the aggregate read speed (across several concurrent streams), and the in-memory speed of the selected hash algorithm to always achieve the highest performance in any volume. They parallelise only when it pays off, which is when a hash can't keep the storage busy on its own.

<table>
  <thead>
    <tr>
      <th align="center">Storage</th>
      <th align="center">Algorithm</th>
      <th align="center">Bottleneck</th>
      <th align="center">Ref. implementation</th>
      <th align="center">mhl-suite</th>
      <th align="center">Result</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2" align="center">SSD</td>
      <td align="center">xxh64</td>
      <td align="center">disk</td>
      <td align="center">3.14 GB/s</td>
      <td align="center">3.04 GB/s</td>
      <td align="center">1×</td>
    </tr>
    <tr>
      <td align="center">MD5</td>
      <td align="center">hash</td>
      <td align="center">0.93 GB/s</td>
      <td align="center">1.86 GB/s</td>
      <td align="center">2×</td>
    </tr>
    <tr>
      <td rowspan="2" align="center">12-bay NAS</td>
      <td align="center">xxh64</td>
      <td align="center">read concurrency</td>
      <td align="center">0.72 GB/s</td>
      <td align="center">1.06 GB/s</td>
      <td align="center">1.5×</td>
    </tr>
    <tr>
      <td align="center">MD5</td>
      <td align="center">read concurrency</td>
      <td align="center">0.54 GB/s</td>
      <td align="center">1.10 GB/s</td>
      <td align="center">2×</td>
    </tr>
  </tbody>
</table>

Measured over an 80 GB media set with the OS page cache evicted before every pass and the hash algorithm pinned. The reference implementations are [ascmhl](https://github.com/ascmitc/mhl) and [mhl-tool](https://github.com/pomfort/mhl-tool).
