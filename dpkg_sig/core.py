import os
from typing import NamedTuple, List
from functools import cached_property
import hashlib
import arpy
import gnupg

GPG_PREFIX = b'_gpg'
BUILDER_FILENAME = b'_gpgbuilder'


class DebsignError(RuntimeError):
    pass


# ControlReader
# Ideally, should support control files:
#     https://www.debian.org/doc/debian-policy/ch-controlfields.html
# However, right now we support only the features used in dpkg-sig's "_gpgbuilder" file:
# + assumes the input contains only one stanza
# + does not handle the special chars '-', '#'
# + assumed any continuation is for a "multiline" field (no "folded" support),
# and strips the initial whitespace from continuation lines.
class ControlReader:
    def __init__(self):
        self._last_key = None
        self.data = {}

    def _parse_field(self, line):
        plc = line.index(':')
        self._last_key = key = line[:plc]
        value = line[plc+1:].lstrip()
        self.data[key] = value

    def _parse_continuation(self, cont):
        value = '\n'.join([self.data[self._last_key], cont])
        self.data[self._last_key] = value

    def _parse_line(self, line):
        stripped = line.lstrip()
        if len(line) != len(stripped):
            self._parse_continuation(stripped)
        else:
            self._parse_field(line)

    @classmethod
    def parse_lines(cls, lines):
        """
        parse stanza from line-iterable object (e.g. a text-mode file object)
        """
        reader = cls()
        for line in lines:
            reader._parse_line(line)
        return reader.data


class SignatureData(NamedTuple):
    md5_hex: str
    sha1_hex: str
    length: int
    name: str

    @classmethod
    def from_line(cls, line):
        md5, sha1, l, name = line.split()
        return cls(md5, sha1, int(l), name)


class DebsignData:
    """
    parsed contents of the _gpgbuilder file (after gpg armor removed)
    """
    def __init__(self, content: str):
        self.data = ControlReader.parse_lines(content.splitlines())
        self._parse_files_data(self.data['Files'])

    def _parse_files_data(self, files_content: str):
        self.files_data = files_data = {}
        lines = files_content.splitlines()
        if len(lines[0].strip()):
            raise DebsignError('first line of Files: entry must be null')
        for line in lines[1:]:
            sig_data = SignatureData.from_line(line)
            files_data[sig_data.name] = sig_data


def _convert_keyring_arg(keyring_arg):
    """
    The gnupg package is lacking support of Path objects in the keyring argument.
    It expects a string, list of strings, or None.
    """
    if not keyring_arg:
        return keyring_arg
    elif isinstance(keyring_arg, List):
        return [os.fspath(x) for x in keyring_arg]
    else:
        return os.fspath(keyring_arg)


class DebFile:
    def __init__(self, path, keyring=None):
        if not path.suffix == '.deb':
            raise DebsignError(f'{path} must have .deb suffix')
        self.ar = arpy.Archive(path)
        self.gpg = gnupg.GPG(keyring=_convert_keyring_arg(keyring))

    def iter_gpgfiles(self):
        for name in self.ar.namelist():
            if not name.startswith(GPG_PREFIX):
                continue
            with self.ar.open(name) as f:
                yield f

    def gpgbuilder_file(self):
        gpgfiles = list(self.iter_gpgfiles())
        if len(gpgfiles) != 1:
            raise DebsignError('archive must have exactly one _gpg file')
        file = gpgfiles[0]
        if file.header.name != BUILDER_FILENAME:
            raise DebsignError(
                f'{file.header.name}: name of the _gpg file must be "{BUILDER_FILENAME}"')
        return file

    def _verify_signature(self, filedata: arpy.ArchiveFileData):
        verified = self.gpg.verify_file(filedata, extra_args=['-o', '-'])
        if not verified.valid:
            raise DebsignError(f'failed validation: {verified.status}')
        return verified.data.decode('utf8')

    @cached_property
    def debsign_data(self):
        f = self.gpgbuilder_file()
        verified = self._verify_signature(f)
        return DebsignData(verified)

    def verify_debsign_item(self, item):
        with self.ar.open(item.name.encode('utf8')) as f:
            data = f.read()
        if len(data) != item.length:
            raise DebsignError(f'{data.name}: mismatching file length')
        hash = hashlib.md5(data)
        if hash.hexdigest() != item.md5_hex:
            raise DebsignError(f'{data.name}: mismatching md5 hash')
        hash = hashlib.sha1(data)
        if hash.hexdigest() != item.sha1_hex:
            raise DebsignError(f'{data.name}: mismatching sha1 hash')

    def verify_debsign(self, verbose=False):
        for sigitem in self.debsign_data.files_data.values():
            self.verify_debsign_item(sigitem)
            if verbose:
                print(f'{sigitem.name}: OK')
