# mhl-suite

`mhl-suite` is an essential toolkit for sealing and verifying MHL files. It consists of two primary executables:
* `mhlver`: one tool to verify them all. This is a wrapper that automatically detects MHL versions (legacy and ASC-MHL) and manages recursive directory verification and reporting. It delegates verification to `simple-mhl` for legacy files and [ascmhl](https://github.com/ascmitc/mhl) for modern manifests.
* `simple-mhl`: a modern verification and sealing tool, for legacy MHL files. A successor of the discontinued [mhl-tool](https://github.com/pomfort/mhl-tool), it additionally features a compliance validator for XML Schema Definition (XSD), and supports modern algorithms traditionally only available on MHL 2.0 (xxh3-64 and xxh128).

### 🛠️ Dependencies

`mhlver` integrates the following open-source components:
* [Python](https://docs.python.org/3/license.html) 3.9+ © 2001-2026 Python Software Foundation (PSF)
* [python-xxhash](https://github.com/ifduyue/python-xxhash) © 2014-2026 Yue Du (BSD-2-Clause)
* [lxml](https://lxml.de/) © 2004-2026 Stefan Behnel, et al. (BSD-3-Clause)
* [ASC-MHL](https://pypi.org/project/ascmhl/) 1.2 © 2022-2026 Academy of Motion Picture Arts and Sciences (MIT)

### 🚀 Installation

#### macOS and Linux

1. Install [Homebrew](https://brew.sh/) (if not already installed):
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. Tap and install:
```
brew tap lucuma13/dit
brew install mhl-suite
```

#### Windows
1. Download and install [Python 3.9+](https://www.python.org/downloads/windows/). Ensure "Add Python to PATH" is checked during installation.

2. Install toolkit:

```
pip install mhl-suite
```

### 📖 Usage

##### `mhlver`

```
mhlver [options] <path>

Options:
  -d, --datestamp   : Preprend datestamp for reporting
  -s, --schema      : Validate XML Schema Definition (MHL v1 only)
  -v, --verbose     : Verbose
  -h, --help        : Show this help message
  --version         : Print version
```

Note: `<path>` can be a single file or a directory, or the current directory if left blank.


##### `simple-mhl`

```
simple-mhl <command> [options] <path>

Commands / Options:
  seal              : Seal directory (MHL file will be generated at the root)
    -a, --algorithm : Algorithm: xxhash (default), md5, sha1, xxh128, xxh3_64
    --dont-reseal   : Abort operation if an MHL file already exists at root
  verify            : Verify an MHL file and hash values
    -s, --schema    : Validate XML against MHL v1.1 XSD
  -h, --help        : Show this help message
  --version         : Print version
```