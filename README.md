# mhlver

Another MHL tool to verify them all

#### 📋 Description

`mhlver` is a streamlined CLI utility designed to find and verify Media Hash List files (MHL), it support both legacy MHL 1.1 and ASC-MHL 2.0.

#### 💻 Compatibility

* macOS
* Linux

#### 🛠️ Dependencies

`mhlver` relies on the following metadata engines:

* [MHL Tool](https://mediahashlist.org/mhl-tool/) v1.31 © 2022-2026 MediaArea.net SARL (MIT)
* [ASC-MHL](https://pypi.org/project/ascmhl/) v1.2 © 2020-2026 Academy of Motion Picture Arts and Sciences (MIT)

#### 🚀 Installation

1. Install [Homebrew](https://brew.sh/) (if not already installed):
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. Tap and install:
```
brew tap lucuma13/homebrew-dit
brew install mhlver
```

#### 📖 Usage

`mhlver [options] <path>`

| Option | Description |
| :---: | :--- |
| `-d` | Prepends a datestamp for reporting |
| `-v` | Increase verbosity |
| `-h` | Show help message |
| `--version` | Print version |

The `<path>` can be a single file or a directory, or the current directory if left blank.