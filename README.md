[![CI](https://github.com/vpetrigo/bitrock-unpacker/actions/workflows/ci.yml/badge.svg)](https://github.com/vpetrigo/bitrock-unpacker/actions/workflows/ci.yml)
[![PyPI - Version](https://img.shields.io/pypi/v/bitrock-unpacker)](https://pypi.org/project/bitrock-unpacker)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/bitrock-unpacker)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/bitrock-unpacker?period=monthly&units=INTERNATIONAL_SYSTEM&left_color=GREY&right_color=GREEN&left_text=downloads%2Fmonth)](https://pepy.tech/projects/bitrock-unpacker)

# BitRock unpacker prototype

`bitrock_unpacker` is a module for extracting content of BitRock/InstallBuilder installers
without Tcl/TclKit.

I created that repo since I was not able to run original Tcl unpacker
from [here](https://gist.github.com/mickael9/0b902da7c13207d1b86e) on Windows.

Run without installing:

```powershell
uvx bitrock-unpacker --help
```

Run as a module:

```powershell
python -m bitrock_unpacker --help
```

If installed, it also exposes:

```powershell
bitrock-unpacker --help
```

## Current capabilities

- Parses PE overlay boundaries.
- Locates BitRock/CookFS markers.
- Recovers `manifest.txt` from the embedded zlib stream.
- Parses old CookFS `CFS0002` suffix/page tables.
- Decompresses CookFS pages: raw, raw deflate, bzip2, and LZMA-Alone.
- Decodes the CookFS `CFS2.200` fsindex.
- Lists and extracts files by fsindex path.
- Stitches BitRock big-file chunks named `___bitrockBigFileN` into their base file by default.

## Limitations

- Encrypted/proprietary `maui::util` payloads are not supported.
- Full installer post-processing is out of scope; extraction writes archive contents.
- Full extraction requires `--yes-all` when no `--limit` is supplied.

Use `--raw-chunks` to show or extract hidden `___bitrockBigFileN` chunk files instead of stitching them.

## Quick checks

The `pyproject.toml` metadata exposes the `bitrock-unpacker` console script, so
the same CLI can be checked through `uv run` without installing it globally:

```powershell
python -m bitrock_unpacker <installer.exe> --manifest-only --debug
python -m bitrock_unpacker <installer.exe> --list-pages --limit 5
python -m bitrock_unpacker <installer.exe> --list-files --limit 10
```

Extract one file:

```powershell
python -m bitrock_unpacker <installer.exe> `
  --path path/inside/archive.txt `
  --extract $env:TEMP\files `
  --limit 1
```

Inspect raw hidden chunks:

```powershell
python -m bitrock_unpacker <installer.exe> `
  --raw-chunks `
  --list-files `
  --path path/inside/archive.bin___bitrockBigFile1 `
  --limit 5
```

Full stitched extraction can be large:

```powershell
python -m bitrock_unpacker <installer.exe> --extract out --yes-all
```

## Development

Validate the project metadata and run the self-test:

```powershell
python -c "import tomllib; tomllib.load(open('pyproject.toml','rb')); print('pyproject: ok')"
python -m py_compile bitrock_unpacker\*.py
```
