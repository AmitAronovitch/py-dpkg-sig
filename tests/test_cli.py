from typer.testing import CliRunner
from dpkg_sig.core import DebsignError
from dpkg_sig.cli import app

DATA_PATH = 'tests/data'
DEBFILE_PATH = DATA_PATH + '/test_package.deb'
KEYRING_PATH = DATA_PATH + '/test_keyring.gpg'
EXPECTED_FILES = ['debian-binary', 'dummy.tar.xz']
runner = CliRunner()


def test_app():
    result = runner.invoke(app, ['verify', '--help'])
    assert 'verify' in result.stdout
    assert result.exit_code == 0


def test_verify():
    result = runner.invoke(app, ['verify', DEBFILE_PATH])
    assert isinstance(result.exception, DebsignError)
    result = runner.invoke(app, [
        'verify', '--verbose', '--keyring', KEYRING_PATH,
        DEBFILE_PATH])
    assert result.exit_code == 0
    for fname in EXPECTED_FILES:
        assert fname in result.stdout
