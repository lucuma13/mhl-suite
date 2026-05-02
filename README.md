# mhl-suite

`mhl-suite` is a toolkit for sealing and verifying MHL files. It consists of two primary executables:

* `mhlver`: one tool to verify them all. A wrapper that automatically detects MHL versions (legacy and ASC-MHL) and runs verification recursively across a directory, with optional XSD schema validation and reporting. It delegates to `simple-mhl` for legacy files and to [ascmhl](https://github.com/ascmitc/mhl) for modern manifests.
* `simple-mhl`: a modern sealing and verification tool, for legacy MHL files. A successor of the discontinued [mhl-tool](https://github.com/pomfort/mhl-tool) and backwards compatible with its manifests: it's 2 to 5 times faster, it fully supports standard `xxhash64be` hashes, and it features XSD schema validation, as well as cleaner output and structured exit codes.

`mhl-suite` is written in [Python](https://www.python.org/) and it integrates [xxhash](https://github.com/ifduyue/python-xxhash), [lxml](https://lxml.de/) and [ascmhl](https://pypi.org/project/ascmhl/).

### 🚀 Installation

1. Install the `uv` package manager with the [official installer](https://docs.astral.sh/uv/getting-started/installation/) (or `brew install uv` on macOS / Linux).

2. Install the toolkit:

```
uv tool install mhl-suite
```

### 📖 Usage

##### `mhlver`

Verify an MHL file or recursively verify all MHL files under a directory:

```bash
mhlver path/to/file.mhl
mhlver path/to/directory/
mhlver                            # verifies the current directory
```

  ```
  options:
    -r, --report           : export a timestamped report log to the target directory
    -s, --xsd-schema-check : validate XML Schema Definition
  ```


##### `simple-mhl`

Seal a directory or verify an existing MHL file:

```bash
simple-mhl seal path/to/directory/
simple-mhl seal -a md5 path/to/directory/
simple-mhl verify path/to/file.mhl
```

  ```
  commands:
    seal              : seal directory (MHL file generated at the root)
      -a, --algorithm : hash algorithm: xxhash (default), md5, sha1
      --dont-reseal   : abort silently if an MHL with the same timestamp already exists
    verify            : verify an MHL file
    xsd-schema-check  : validate XML Schema Definition
  ```

### 📊 Benchmark

`simple-mhl` has been tested against real-world media workloads. Sample throughput on a 2 TB workload:

| Algorithm | Seal       | Verify     |
|-----------|-----------:|-----------:|
| xxhash    | 2480 MB/s  | 2680 MB/s  |
| md5       |  560 MB/s  |  560 MB/s  |
| sha1      |  680 MB/s  |  690 MB/s  |
