from typing import Optional, Annotated
from pathlib import Path
import typer
from dpkg_sig import DebFile

app = typer.Typer()


@app.command()
def verify(deb_path: Path, keyring: Optional[str] = None,
           verbose: Annotated[bool, typer.Option('--verbose')] = False):
    deb = DebFile(deb_path, keyring)
    deb.verify_debsign(verbose=verbose)


@app.command(hidden=True)
def sign():
    raise NotImplementedError


if __name__ == '__main__':
    app()
