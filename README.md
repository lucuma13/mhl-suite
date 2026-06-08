# mhl-suite

`mhl-suite` is a toolkit for sealing and verifying MHL files. It consists of two primary executables:

* `mhlver`: one tool to verify them all. A wrapper that verifies MHLs recursively in a directory, with optional XSD schema validation and reporting. It delegates to `simple-mhl` for legacy flat MHLs and to [ascmhl](https://github.com/ascmitc/mhl) for ASC-MHL.
* `simple-mhl`: a modern sealing and verification tool, for legacy MHL files. A successor of the discontinued [mhl-tool](https://github.com/pomfort/mhl-tool) and backwards compatible with its manifests - 2 to 5 times faster, full support for standard `xxhash64be` hashes, XSD schema validation features, cleaner output and structured exit codes.

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

Verify MHL files (both flat and ASC-MHL):

```bash
mhlver path/to/file.mhl
mhlver path/to/directory/
mhlver                                     # verify current directory
```

Seal a directory:

```bash
simple-mhl seal path/to/directory/
simple-mhl seal -a md5 path/to/directory/   # use MD5 algorithm
```

Validate XML Schema Definition of a file:

```bash
mhlver --xsd-schema-check path/to/file
```

Run `simple-mhl --help` and `mhlver --help` to see the full list of options.
