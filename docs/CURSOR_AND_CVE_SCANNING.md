# CVE advisories, Cursor / AI workflow, and what changed

This document summarizes how the scanner evolved, how to run it at scale, and how to use an AI assistant (for example Cursor) to turn public security advisories into JSON the tool can consume.

---

## What changed (high level)

These capabilities were added or refined over the original malware-only scanner:

| Area | Behavior |
|------|----------|
| **Two rule sources** | `scan` accepts **`--malwares`** (IOC text list), **`--advisories`** (JSON with semver ranges), or **both** in one run. At least one is required. |
| **Advisory JSON format** | Top-level object with a **`packages`** map: each key is an npm package name; each value is a list of advisory objects with **`id`**, **`vulnerable_ranges`**, optional **`title`** / **`references`** / **`notes`**. |
| **Semver ranges (stdlib)** | Ranges are evaluated with a **pure standard-library** matcher (no `pip install`). Clauses look like `>=1.0.0,<2.0.0`; use **comma** or **space** between clauses in one range string. Multiple strings in `vulnerable_ranges` are **OR**; constraints inside one string are **AND**. |
| **Catalog noise** | By default, catalog paths under **`.../node_modules/.../package.json`** are **skipped** during `scan`, because hoisted dependencies would otherwise produce one hit per nested `package.json`. Use **`--include-node-modules`** to restore the old behavior. |
| **Finding types** | JSON output includes **`finding_type`**: `malware` (exact IOC) or `advisory` (range match). |
| **Example rules** | Reference files live under **`examples/`** (advisory JSON + IOC list templates: axios, React RSC, Next.js). |
| **Runtime dependencies** | None for normal use; **`requirements.txt`** only notes optional **`pytest`** for tests. |

The core **`catalog`** mode (walk the filesystem and list `package.json` paths) is unchanged in purpose.

---

## End-to-end: catalog then scan

1. **Build a catalog** of `package.json` paths (narrow the path to avoid scanning the whole disk unless you mean to):

   ```bash
   python3 crawler.py catalog --output packages.txt --path "$HOME/projects"
   ```

2. **Scan** with malware list, advisories JSON, or both:

   ```bash
   # IOC / exact versions only
   python3 crawler.py scan --catalog packages.txt --malwares malwares.txt --output findings_malware.json

   # CVE-style ranges only
   python3 crawler.py scan --catalog packages.txt --advisories examples/advisories_axios.example.json --output findings_cve.json

   # Both
   python3 crawler.py scan --catalog packages.txt --malwares malwares.txt --advisories my_advisories.json --output findings.json
   ```

3. **Exit codes**: `0` = no findings, `2` = one or more findings, `1` = configuration or input error.

Stderr prints **which rule sources are active** and how many catalog paths were **skipped** under `node_modules/` (when applicable).

---

## Limitations (important)

- The scanner checks packages under the **resolved** `node_modules` directory for each remaining catalog path (walk **up** from the project folder). It does **not** recurse into every nested `node_modules` tree. Hoisted installs are usually visible at the project root `node_modules`; deeply nested-only installs may be missed.
- Range matching is **not** full npm `semver` (no `^` / `~` in a single token). Prefer explicit **`>=` / `<`** windows like the files in **`examples/`**.
- **Skipping** `node_modules/**/package.json` catalog entries reduces duplicate reports; it does not replace **`npm audit`** or a full dependency graph tool for every transitive edge.

---

## Using Cursor (or another AI) to create advisory JSON

### 1. Give the model a template

Point the assistant at an existing file in **`examples/`**, for example:

- `examples/advisories_axios.example.json`
- `examples/advisories_react_rsc_GHSA-479c-33wc-g2pg.example.json`
- `examples/advisories_nextjs_GHSA-q4gf-8mx6-v5v3.example.json`

Ask it to **keep the same JSON shape** so `crawler.py` keeps working.

### 2. Paste the official source

Paste or link the **GitHub Security Advisory** or **NVD/CVE** page. Ask for:

- **Exact npm package name(s)** as published on npm (e.g. `next`, `react-server-dom-webpack`, `axios`).
- **Affected version ranges** translated into this tool’s syntax: one or more entries in `vulnerable_ranges`, each entry a string of **AND** clauses, **OR** across array elements.

Example prompt pattern:

> Using the same structure as `examples/advisories_axios.example.json`, add an advisories file for [paste GHSA or CVE URL]. Use package keys exactly as on npm. Express affected versions as `vulnerable_ranges` with `>=` and `<` bounds matching the patched versions from the advisory.

### 3. Merge multiple advisories

The tool reads **one JSON file** per `--advisories` flag. To combine GHSA A and GHSA B you can:

- Ask the AI to **merge** two objects: under `"packages"`, combine keys; if the same package appears twice, **merge** the advisory arrays (list of objects), **or**
- Run **two scans** with different `--advisories` files and merge output yourself.

### 4. Validate quickly

After the file is written:

```bash
python3 crawler.py scan --catalog packages.txt --advisories path/to/new_advisories.json --output /tmp/test_findings.json
```

Use a **small catalog** (e.g. one line pointing at a known-vulnerable project) first, then run against your full `packages.txt`.

### 5. Optional: project rules for Cursor

The repo may include **`.cursor/rules/`** (for example `repo-reference.mdc`) so future sessions know where **`examples/`** lives and how `scan` behaves. You can add a rule: “When adding CVE coverage, extend or add JSON under `examples/` using the existing schema.”

---

## File naming (new advisory JSON files)

When you (or an assistant) add a new file, use:

**`advisories_<library>_<id>.json`**

- **`<library>`**: Short label for the ecosystem or primary package (lowercase, underscores), e.g. `axios`, `nextjs`, `react_rsc`.
- **`<id>`**: Prefer **`CVE-YYYY-NNNN`** when the advisory has a CVE; otherwise use **`GHSA-xxxx-xxxx-xxxx`**.

Examples: `advisories_axios_CVE-2026-25639.json`, `advisories_nextjs_GHSA-q4gf-8mx6-v5v3.json`.

Files under **`examples/`** that ship with the repo use a **`.example.json`** suffix so you can copy them and drop `.example` for real rules. Each example JSON also includes a top-level **`_instructions`** field (ignored by the scanner) repeating this pattern.

## Reference: minimal advisory object shape

```json
{
  "packages": {
    "package-name-on-npm": [
      {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "title": "Short description",
        "references": ["https://github.com/..."],
        "vulnerable_ranges": [">=1.0.0,<1.2.3", ">=2.0.0,<2.5.0"]
      }
    ]
  }
}
```

- **`id`**: required string (GHSA id, CVE id, or your label).
- **`vulnerable_ranges`**: required non-empty array of strings.
- **`title`**, **`references`**, **`notes`**: optional; included in stderr/JSON for humans.

---

## Related files in this repo

| Path | Purpose |
|------|---------|
| `crawler.py` | CLI: `catalog`, `scan` |
| `examples/*.example.json` | Advisory JSON you can copy or hand to an AI as a template |
| `examples/malwares_axios_IOC.example.txt` | IOC list format (exact `@version` pins) |
| `test_crawler.py` | Regression tests |
| `requirements.txt` | No runtime deps; optional pytest note |

For a concise machine-oriented overview of the repository layout, see **`.cursor/rules/repo-reference.mdc`** if present.
