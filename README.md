# probe-tool

`probe` is a multi-module security testing CLI for CTF practice and authorized security learning.

## Install

```bash
pip install probe-tool
```

For local development:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
probe --help
probe encode base64 "hello world"
probe hash identify "5f4dcc3b5aa765d61d8327deb882cf99"
probe network scan example.com --top 20
```

Only run scanning and brute-force commands against systems you own or have explicit permission to test.
