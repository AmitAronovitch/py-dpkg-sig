from pathlib import Path
from dpkg_sig import DebFile

DATA_PATH = Path('tests/data')
DEBFILE_PATH = DATA_PATH / 'test_package.deb'
KEYRING_PATH = DATA_PATH / 'test_keyring.gpg'


def test_debsign():
    dsdata = DebFile(DEBFILE_PATH, keyring=KEYRING_PATH).debsign_data
    for sigdata in dsdata.files_data.values():
        assert len(sigdata.md5_hex) == 32
        assert len(sigdata.sha1_hex) == 40


def test_gpgbuilder():
    deb = DebFile(DEBFILE_PATH)
    builder = deb.gpgbuilder_file()
    assert builder.header.name == b'_gpgbuilder'
