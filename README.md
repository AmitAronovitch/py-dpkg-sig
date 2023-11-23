# py-dpkg-sig
This is a minimal and partial replacement for the [dpkg-sig](https://packages.debian.org/buster/dpkg-sig) tool, which
was used by certain packagers to sign and verify .deb file, and removed from Debian 12.

The original tool seems be unmaintained and [problematic](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=995113), but
some third-party packagers still use it to sign their packages. For the purpose of verifying such packages, I found it 
easier to write a simple standalone script than trying to maintain the old tool.

Currently, `py-dpkg-sig` only supports the verify command (I am not even sure it supports the full spec of the old tool, but it
did work successfuly for the packages I needed to verify). But feel free to experiment/extend/fork.

## Installation

Preferably inside a Python virtual-env, use pip:
```shell
pip install git+https://github.com/AmitAronovitch/py-dpkg-sig.git@master
```

## Usage

1. Import the public key of the packager of the package you wish to verify (they should have documentation for that).

2. Use the packaged cli script to verify, specifying the path to the deb file.
   ```
   dpkg-sig verify --verbose path_to/my_package.deb
   ```
   Or, if you saved the signer's pubkey in a standalone keyring, you can specify the name (or full path) to that:
   ```
   dpkg-sig verify --verbose --keyring my_keyring path_to/my_package.deb
   ```
