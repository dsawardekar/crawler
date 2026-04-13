# NPM Malware Scanner

A Python tool for scanning Node.js projects to detect malicious packages in dependencies.

Note: Malware list needs to be supplied by the user. Repo includes a default list of malware packages

UNDER DEVELOPMENT - USE AT YOUR OWN RISK

## Screenshots

### Catalog Mode
![Catalog Mode](screenshots/catalog.png)

### Scan Mode
![Scan Mode](screenshots/scan.png)

## Features

- Catalog all `package.json` files on the filesystem
- Scan with a **malware IOC list** (`--malwares`), **CVE-style semver ranges** (`--advisories` JSON), or **both**
- Reference **`examples/`**: advisory JSON and IOC list templates (axios, React RSC, Next.js)
- By default, **skips** catalog paths under `node_modules/` to avoid duplicate hits from hoisted deps (`--include-node-modules` to opt in)
- JSON findings include **`finding_type`**: `malware` or `advisory`
- **No pip dependencies** for runtime (Python 3.10+ stdlib only)

## Documentation

- **[CVE / Cursor workflow and changelog-style notes](docs/CURSOR_AND_CVE_SCANNING.md)** — how to use AI to author advisory JSON, merge files, and run large scans safely.

## Installation

No additional runtime dependencies beyond Python 3.10+ standard library. Optional: `pytest` for tests (see `requirements.txt`).

## Usage

### Catalog Mode

Find all `package.json` files on the system:

```bash
./crawler.py catalog [options]
# or
python3 crawler.py catalog [options]
```

Options:
- `--output FILE`: Output file for package.json paths (default: packages.txt)
- `--path PATH`: Starting path for filesystem scan (default: /)

Example:
```bash
./crawler.py catalog --output my_packages.txt --path /home/user/projects
# or
python3 crawler.py catalog --output my_packages.txt --path /home/user/projects
```

### Scan Mode

Scan projects for malicious packages:

```bash
./crawler.py scan [options]
# or
python3 crawler.py scan [options]
```

Required:

- `--catalog FILE`: File containing `package.json` paths to scan (one path per line)

Provide **at least one** of:

- `--malwares FILE`: Malicious packages list (exact `pkg@version` or `pkg` for any version)
- `--advisories FILE`: JSON with semver vulnerable ranges (see `examples/*.example.json`)

Optional:

- `--output FILE`: Save findings as JSON (defaults to stdout)
- `--verbose`: Per-path progress on stderr
- `--include-node-modules`: Also scan `package.json` paths under `node_modules/`

Examples:

```bash
python3 crawler.py scan --catalog packages.txt --malwares malwares.txt --output results.json
python3 crawler.py scan --catalog packages.txt --advisories examples/advisories_axios.example.json --output cve_results.json
python3 crawler.py scan --catalog packages.txt --malwares malwares.txt --advisories examples/advisories_axios.example.json --output combined.json
```

## Malware Database Format

The malware packages file should contain one package per line:

```
# All versions of this package are malicious
malicious-package

# Only specific versions are malicious
another-package@1.2.3
bad-package@2.0.0

# Scoped packages are supported
@scope/malicious-package@1.0.0
```

## Output Format

### Catalog Mode
Outputs a simple text file with one package.json path per line.

### Scan Mode
When malware is detected, displays:
```
--- 🚨 MALWARE DETECTED ---
Package: malicious-package@1.2.3
Location: /path/to/node_modules/malicious-package
```

JSON output is one object per finding (malware or advisory), including **`finding_type`**. Malware example:

```json
{
    "finding_type": "malware",
    "project_package_json": "/path/to/project/package.json",
    "node_modules_path": "/path/to/node_modules",
    "malicious_package": "malicious-package",
    "found_version": "1.2.3"
}
```

Advisory matches add fields such as **`package`**, **`advisory_id`**, and **`references`**.

## Workflow

1. **Catalog**: Find all package.json files
   ```bash
   ./crawler.py catalog --output packages.txt
   # or
   python3 crawler.py catalog --output packages.txt
   ```

2. **Scan**: Check IOC list, advisories JSON, or both
   ```bash
   python3 crawler.py scan --catalog packages.txt --malwares malwares.txt
   python3 crawler.py scan --catalog packages.txt --advisories examples/advisories_axios.example.json
   ```

3. **Review**: Inspect stderr summaries and the JSON output; upgrade or remove affected dependencies as needed

## Examples

### Basic scan of current directory
```bash
./crawler.py catalog --path . --output local_packages.txt
./crawler.py scan --catalog local_packages.txt --malwares malwares.txt
# or
python3 crawler.py catalog --path . --output local_packages.txt
python3 crawler.py scan --catalog local_packages.txt --malwares malwares.txt
```

### System-wide scan

Note: Default catalog starts from /, recursively.

```bash
sudo ./crawler.py catalog --output system_packages.txt
sudo ./crawler.py scan --catalog system_packages.txt --malwares malwares.txt --output scan_results.json
# or
sudo python3 crawler.py catalog --output system_packages.txt
sudo python3 crawler.py scan --catalog system_packages.txt --malwares malwares.txt --output scan_results.json
```

### Testing

Unit tests can be run using:

```bash
pytest test_crawler.py
```

### License

This project is licensed under the MIT License.