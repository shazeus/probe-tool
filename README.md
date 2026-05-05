# probe-tool

`probe` is a multi-module security testing CLI for CTF practice and authorized security learning.

<img width="1555" height="828" alt="demo" src="https://github.com/user-attachments/assets/2d8595f1-31bc-45a6-9401-c49c9f317a01" />

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
