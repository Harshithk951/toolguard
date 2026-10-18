# ToolGuard

ToolGuard is an offline Node 22 CLI that statically scans MCP configurations and
tool manifests. It has no runtime dependencies, never starts configured
commands, and never contacts configured URLs.

## Setup

Use Node 22. With `nvm`, the checked-in version file can be selected with:

```sh
nvm use
npm ci
```

`npm ci` is reproducible and installs no runtime packages. If `nvm` is not
available, install Node 22 directly and confirm it with `node --version`.

## Run

Run the CLI through Node, or use the package bin after a local npm link:

```sh
node bin/toolguard.js scan examples/clean --format terminal
node bin/toolguard.js scan examples/malicious --format json --output report.json
```

The scan is offline by design: configured commands are never executed and URLs
are never fetched.

## Test

Run the complete offline test suite with:

```sh
npm test
```

## Usage

```sh
node bin/toolguard.js scan path/to/config.json
node bin/toolguard.js scan configs/ --format json --output report.json
node bin/toolguard.js scan configs/ --format html --output report.html
cat manifest.json | node bin/toolguard.js scan --stdin --stdin-name manifest.json
```

Directories are scanned recursively for `.json` files. `.git`, `node_modules`,
and symlinked directories are skipped. Explicit files are scanned regardless of
extension, but their contents must be strict JSON. JSONC, YAML, and JavaScript
are intentionally not evaluated.

Exit codes:

* `0` — scan completed with no findings
* `1` — scan completed with one or more findings
* `2` — usage, input, decoding, or JSON parsing error
* `3` — unexpected internal error

## Output

The default terminal report includes the number of files, servers, tools,
findings, maximum severity score, and each finding. `--format json` emits a
stable machine-readable report. `--format html` emits a self-contained report
with inline CSS and no external resources.

Use `--root DIR` to control the relative paths shown in reports. Output is
deterministic: it contains no timestamps, hostnames, network data, or random
identifiers.

## Checks

```sh
npm test
docker build --pull=false --network=none -t toolguard:22-offline .
docker run --rm --network=none toolguard:22-offline --help
```

The reproducible one-command Docker gate is:

```sh
docker build --pull=false --network=none -t toolguard:22-offline . && docker run --rm --network=none --entrypoint node toolguard:22-offline --test
```

The base image must already be available locally because the build is explicitly
network-disabled.
