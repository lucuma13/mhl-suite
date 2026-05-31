# mhl-suite

`mhl-suite` is a toolkit for sealing and verifying MHL files. It consists of two primary executables:

* `mhlver`: one tool to verify them all. A wrapper that automatically detects MHL versions (legacy and ASC-MHL) and runs verification recursively across a directory, with optional XSD schema validation and reporting. It delegates to `simple-mhl` for legacy files and to [ascmhl](https://github.com/ascmitc/mhl) for modern manifests.
* `simple-mhl`: a modern sealing and verification tool, for legacy MHL files. A successor of the discontinued [mhl-tool](https://github.com/pomfort/mhl-tool) and backwards compatible with its manifests: it's 2 to 5 times faster, it fully supports standard `xxhash64be` hashes, and it features XSD schema validation, as well as cleaner output and structured exit codes.

`mhl-suite` is written in [Python](https://www.python.org/) and it integrates [xxhash](https://github.com/ifduyue/python-xxhash), [lxml](https://lxml.de/) and [ascmhl](https://pypi.org/project/ascmhl/).

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

```bash
uv tool install mhl-suite
```

3. Test the installation (if the command is not recognised try `uv tool update-shell` and restart Terminal):

```bash
mhlver --version
simple-mhl --version
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