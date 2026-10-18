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

Run the CLI through Node, or create a local npm link and use the package bin:

```sh
node bin/toolguard.js scan examples/clean --format terminal
node bin/toolguard.js scan examples/malicious --format json --output report.json
npm link
toolguard scan examples/clean --format terminal
```

The scan is offline by design: configured commands are never executed and URLs
are never fetched.

## Test

Run the complete offline test suite with:

```sh
npm test
```

## Usage

The following commands are runnable from a clean clone:

```sh
node bin/toolguard.js scan test/fixtures/clean.json
node bin/toolguard.js scan examples/clean --format json --output toolguard-report.json
node bin/toolguard.js scan examples/clean --format html --output toolguard-report.html
cat test/fixtures/clean.json | node bin/toolguard.js scan --stdin --stdin-name manifest.json
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
deterministic: it contains no timestamps, runtime host information, network
responses, or random identifiers. Findings may include host and scheme metadata
extracted from configured URLs.

## Checks

```sh
npm test
docker build -t toolguard .
docker run --rm --network none toolguard npm test
```

The Docker test gate is:

```sh
docker build -t toolguard . && docker run --rm --network none toolguard npm test
```

To run the CLI inside the image, provide the complete command because the
Dockerfile uses `CMD` rather than an entrypoint:

```sh
docker run --rm --network none toolguard node bin/toolguard.js scan examples/clean --format terminal
```

For a fully offline rebuild using a locally cached base image, use:

```sh
docker build --pull=false --network=none -t toolguard:22-offline .
docker run --rm --network=none toolguard:22-offline npm test
```

## GitHub Actions

To enable this in a consuming repository, save the following as
`.github/workflows/toolguard.yml`. It runs the tests and scans a checked-in MCP
configuration. Replace `examples/clean` with the directory your project wants
to guard.

```yaml
name: ToolGuard
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version-file: .nvmrc
          cache: npm
      - run: npm ci
      - run: npm test
      - run: node bin/toolguard.js scan examples/clean --format terminal
```
