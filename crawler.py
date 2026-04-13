#!/usr/bin/env python3

from __future__ import annotations

import os
import re
import sys
import json
import argparse
import shutil
import itertools
from dataclasses import dataclass, asdict
from typing import Any, Iterator

# --- Data Structure for Findings ---

@dataclass
class PackageMatch:
    project_package_json: str
    node_modules_path: str
    malicious_package: str
    found_version: str


@dataclass
class AdvisoryMatch:
    project_package_json: str
    node_modules_path: str
    package: str
    found_version: str
    advisory_id: str
    advisory_title: str | None
    references: list[str]


@dataclass
class AdvisoryRule:
    advisory_id: str
    advisory_title: str | None
    references: list[str]
    # Each entry is one "vulnerable_ranges" string: AND of (operator, bound_version).
    specifier_sets: list[tuple[tuple[str, str], ...]]

# --- Immutable Helper Functions ---


_CONSTRAINT_OP_RE = re.compile(r"^(?P<op><=|>=|==|!=|<|>)\s*(?P<ver>.+)$")


def _split_core_and_prerelease(version: str) -> tuple[str, str | None]:
    s = version.strip().lstrip("vV")
    if not s:
        raise ValueError("empty version")
    if "+" in s:
        s = s.split("+", 1)[0]
    if "-" in s:
        core, pre = s.split("-", 1)
        core, pre = core.strip(), pre.strip()
        return core, pre or None
    return s.strip(), None


def _core_numeric_tuple(core: str) -> tuple[int, ...]:
    if not core:
        return (0,)
    parts: list[int] = []
    for seg in core.split("."):
        num = ""
        for c in seg:
            if c.isdigit():
                num += c
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts) if parts else (0,)


def _prerelease_identifiers(pre: str) -> tuple[tuple[int, int | str], ...]:
    ids: list[tuple[int, int | str]] = []
    for p in pre.split("."):
        p = p.strip()
        if not p:
            continue
        if p.isdigit():
            ids.append((0, int(p)))
        else:
            ids.append((1, p.lower()))
    return tuple(ids)


def _semver_sort_key(version: str) -> tuple[Any, ...]:
    core, pre = _split_core_and_prerelease(version)
    ct = _core_numeric_tuple(core)
    if pre is None:
        return (ct, 1, ())
    return (ct, 0, _prerelease_identifiers(pre))


def _compare_keys(a: tuple[Any, ...], b: tuple[Any, ...]) -> int:
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def _key_satisfies_op(version_key: tuple[Any, ...], op: str, bound_key: tuple[Any, ...]) -> bool:
    c = _compare_keys(version_key, bound_key)
    if op == ">=":
        return c >= 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == "<":
        return c < 0
    if op == "==":
        return c == 0
    if op == "!=":
        return c != 0
    return False


def _parse_constraint_group(normalized: str) -> tuple[tuple[str, str], ...] | None:
    specs: list[tuple[str, str]] = []
    for part in normalized.split(","):
        part = part.strip()
        if not part:
            continue
        m = _CONSTRAINT_OP_RE.match(part)
        if not m:
            return None
        specs.append((m.group("op"), m.group("ver").strip()))
    return tuple(specs) if specs else None


def _version_matches_constraint_group(version_str: str, group: tuple[tuple[str, str], ...]) -> bool:
    try:
        vkey = _semver_sort_key(version_str)
    except ValueError:
        return False
    for op, bound in group:
        try:
            bkey = _semver_sort_key(bound)
        except ValueError:
            return False
        if not _key_satisfies_op(vkey, op, bkey):
            return False
    return True


def _version_matches_specifier_sets(version_str: str, groups: list[tuple[tuple[str, str], ...]]) -> bool:
    for group in groups:
        if _version_matches_constraint_group(version_str, group):
            return True
    return False

def parse_malware_file(filepath: str) -> dict[str, list[str]]:
    malware = {}
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.rsplit('@', 1)

                if len(parts) == 1 or not parts[0]:
                    package_name = parts[0] if len(parts) == 1 else '@' + parts[1]
                    malware[package_name] = []
                else:
                    package_name, version = parts
                    if malware.get(package_name) == []:
                        continue
                    if package_name not in malware:
                        malware[package_name] = []
                    malware[package_name].append(version)
    except FileNotFoundError:
        print(f"Error: Malware packages file not found at '{filepath}'", file=sys.stderr)
        sys.exit(1)
    return malware

def read_json_file(filepath: str) -> dict | None:
    if not os.path.exists(filepath): return None
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def _normalize_range_to_specifiers(range_str: str) -> str:
    s = range_str.strip()
    if not s:
        return s
    if "," in s:
        parts = [p.strip() for p in s.split(",") if p.strip()]
    else:
        parts = [p.strip() for p in re.split(r"\s+(?=[<>=!])", s) if p.strip()]
    return ",".join(parts)


def _compile_vulnerable_ranges(ranges: list[str], advisory_id: str) -> list[tuple[tuple[str, str], ...]]:
    compiled: list[tuple[tuple[str, str], ...]] = []
    for r in ranges:
        normalized = _normalize_range_to_specifiers(r)
        if not normalized:
            continue
        parsed = _parse_constraint_group(normalized)
        if parsed is None:
            print(
                f"Warning: skipping invalid range '{r}' for advisory '{advisory_id}' "
                "(expected clauses like >=1.0.0,<2.0.0).",
                file=sys.stderr,
            )
            continue
        compiled.append(parsed)
    return compiled


def load_advisories_json(filepath: str) -> dict[str, list[AdvisoryRule]]:
    data = read_json_file(filepath)
    if data is None:
        print(f"Error: Could not read or parse advisories JSON at '{filepath}'", file=sys.stderr)
        sys.exit(1)
    raw_packages = data.get("packages")
    if not isinstance(raw_packages, dict):
        print("Error: advisories JSON must contain a top-level object 'packages'.", file=sys.stderr)
        sys.exit(1)

    out: dict[str, list[AdvisoryRule]] = {}
    for pkg_name, entries in raw_packages.items():
        if not isinstance(pkg_name, str) or not pkg_name.strip():
            continue
        if not isinstance(entries, list):
            print(f"Warning: 'packages.{pkg_name}' must be a list; skipping.", file=sys.stderr)
            continue
        rules: list[AdvisoryRule] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            adv_id = entry.get("id")
            if not adv_id or not isinstance(adv_id, str):
                print(
                    f"Warning: advisory entry for '{pkg_name}' missing string 'id'; skipping.",
                    file=sys.stderr,
                )
                continue
            vr = entry.get("vulnerable_ranges")
            if not isinstance(vr, list) or not vr:
                print(
                    f"Warning: advisory '{adv_id}' for '{pkg_name}' missing 'vulnerable_ranges'; skipping.",
                    file=sys.stderr,
                )
                continue
            range_strs = [x for x in vr if isinstance(x, str) and x.strip()]
            spec_sets = _compile_vulnerable_ranges(range_strs, adv_id)
            if not spec_sets:
                print(
                    f"Warning: advisory '{adv_id}' for '{pkg_name}' has no valid ranges; skipping.",
                    file=sys.stderr,
                )
                continue
            title = entry.get("title")
            title_str = title if isinstance(title, str) else None
            refs_raw = entry.get("references", [])
            refs: list[str] = (
                [r for r in refs_raw if isinstance(r, str) and r.strip()]
                if isinstance(refs_raw, list)
                else []
            )
            rules.append(
                AdvisoryRule(
                    advisory_id=adv_id,
                    advisory_title=title_str,
                    references=refs,
                    specifier_sets=spec_sets,
                )
            )
        if rules:
            out[pkg_name] = rules
    return out


def _read_projects_file(filepath: str) -> list[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)


def _is_package_json_under_node_modules(package_json_path: str) -> bool:
    """True if path is .../node_modules/.../package.json (a dependency's manifest, not the app/workspace)."""
    parts = os.path.normpath(os.path.abspath(package_json_path)).split(os.sep)
    if len(parts) < 2 or parts[-1] != "package.json":
        return False
    return "node_modules" in parts[:-1]

def _report_finding(match: PackageMatch | AdvisoryMatch, out_file):
    if isinstance(match, AdvisoryMatch):
        module_path = os.path.join(match.node_modules_path, match.package)
        print("\n" + "--- ⚠️  ADVISORY (CVE RANGE) ---", file=sys.stderr)
        print(f"Package: {match.package}@{match.found_version}", file=sys.stderr)
        print(f"Advisory: {match.advisory_id}", file=sys.stderr)
        if match.advisory_title:
            print(f"Title: {match.advisory_title}", file=sys.stderr)
        print(f"Location: {module_path}", file=sys.stderr)
        if match.references:
            print("References:", file=sys.stderr)
            for ref in match.references:
                print(f"  - {ref}", file=sys.stderr)
        payload = {**asdict(match), "finding_type": "advisory"}
        out_file.write(json.dumps(payload, indent=4) + "\n")
        return

    infected_module_path = os.path.join(match.node_modules_path, match.malicious_package)
    print("\n" + "--- 🚨 MALWARE DETECTED ---", file=sys.stderr)
    print(f"Package: {match.malicious_package}@{match.found_version}", file=sys.stderr)
    print(f"Location: {infected_module_path}", file=sys.stderr)
    payload = {**asdict(match), "finding_type": "malware"}
    out_file.write(json.dumps(payload, indent=4) + "\n")

# --- Scanner Classes ---

class PackageJSONScanner:
    
    def scan(self, output_filepath: str, start_path: str = '/'):
        print(f"Starting catalog of 'package.json' files from '{start_path}'...", file=sys.stderr)
        count = 0
        spinner = itertools.cycle(['-', '/', '|', '\\'])
        try:
            with open(output_filepath, 'w') as out_file:
                for i, (root, _, files) in enumerate(os.walk(start_path, topdown=True, onerror=lambda e: None)):
                    if i % 100 == 0:
                        print(f"\r{next(spinner)} Scanning... Found: {count}", end="", file=sys.stderr)
                    if 'package.json' in files:
                        full_path = os.path.join(root, 'package.json')
                        out_file.write(f"{full_path}\n")
                        count += 1
        except IOError as e:
            print(f"\nError writing to output file '{output_filepath}': {e}", file=sys.stderr)
        
        print(f"\r{' ' * 30}\r", end="", file=sys.stderr)
        print(f"Catalog complete. Total 'package.json' files found: {count}", file=sys.stderr)
        print(f"Results saved to '{output_filepath}'", file=sys.stderr)


class PackageScanner:
    
    def __init__(
        self,
        malware_packages: dict[str, list[str]],
        advisory_by_package: dict[str, list[AdvisoryRule]] | None = None,
    ):
        self.malware_packages = malware_packages
        self.advisory_by_package = advisory_by_package or {}

    def get_node_modules(self, package_json_path: str) -> str | None:
        current_path = os.path.dirname(os.path.abspath(package_json_path))
        while current_path != os.path.dirname(current_path):
            node_modules_path = os.path.join(current_path, 'node_modules')
            if os.path.isdir(node_modules_path):
                return node_modules_path
            current_path = os.path.dirname(current_path)
        
        node_modules_at_root = os.path.join(current_path, 'node_modules')
        if os.path.isdir(node_modules_at_root):
            return node_modules_at_root

        return None


    def _check_package(self, node_modules_path: str, pkg_name: str, malicious_versions: list[str]) -> str | None:
        if not node_modules_path or not os.path.isdir(node_modules_path): return None
        pkg_dir = os.path.join(node_modules_path, pkg_name)
        if not os.path.isdir(pkg_dir): return None
        
        inner_pkg_json_path = os.path.join(pkg_dir, 'package.json')
        package_data = read_json_file(inner_pkg_json_path)
        if not package_data or 'version' not in package_data: return None
        
        found_version = package_data['version']
        if not malicious_versions or found_version in malicious_versions:
            return found_version
        return None

    def _get_installed_version(self, node_modules_path: str | None, pkg_name: str) -> str | None:
        if not node_modules_path or not os.path.isdir(node_modules_path):
            return None
        pkg_dir = os.path.join(node_modules_path, pkg_name)
        if not os.path.isdir(pkg_dir):
            return None
        inner_pkg_json_path = os.path.join(pkg_dir, "package.json")
        package_data = read_json_file(inner_pkg_json_path)
        if not package_data or "version" not in package_data:
            return None
        ver = package_data["version"]
        return ver if isinstance(ver, str) else None

    def scan(self, project_package_json: str) -> Iterator[PackageMatch | AdvisoryMatch]:
        node_modules_path = self.get_node_modules(project_package_json)
        for pkg_name, malicious_versions in self.malware_packages.items():
            if found_version := self._check_package(node_modules_path, pkg_name, malicious_versions):
                yield PackageMatch(project_package_json, node_modules_path, pkg_name, found_version)

        for pkg_name, rules in self.advisory_by_package.items():
            found_version = self._get_installed_version(node_modules_path, pkg_name)
            if not found_version:
                continue
            for rule in rules:
                if _version_matches_specifier_sets(found_version, rule.specifier_sets):
                    yield AdvisoryMatch(
                        project_package_json=project_package_json,
                        node_modules_path=node_modules_path or "",
                        package=pkg_name,
                        found_version=found_version,
                        advisory_id=rule.advisory_id,
                        advisory_title=rule.advisory_title,
                        references=list(rule.references),
                    )

# --- Main System Orchestrator Logic ---

def _perform_scan_loop(args, scanner, project_paths, out_file, term_width):
    found_count = 0
    total_projects = len(project_paths)
    spinner = itertools.cycle(['-', '/', '|', '\\'])
    infected_packages = set()

    for i, project_path in enumerate(project_paths):
        if args.verbose:
            progress_text = f"Scanning {i+1}/{total_projects}: {project_path}"
            display_text = (progress_text[:term_width-1] + '..') if len(progress_text) > term_width else progress_text
            print(f"\r{display_text:<{term_width}}", end="", file=sys.stderr)
        else:
            if i % 100 == 0:
                print(f"\r{next(spinner)} Scanning {i+1}/{total_projects}", end="", file=sys.stderr)
        
        for match in scanner.scan(project_path):
            if found_count == 0 and sys.stderr.isatty():
                print(f"\r{' ' * term_width}\r", end="", file=sys.stderr)
            found_count += 1
            if isinstance(match, AdvisoryMatch):
                infected_packages.add(f"{match.package}@{match.found_version} [{match.advisory_id}]")
            else:
                infected_packages.add(f"{match.malicious_package}@{match.found_version}")
            _report_finding(match, out_file)
    
    return found_count, sorted(infected_packages)

def run_catalog_mode(args):
    cataloger = PackageJSONScanner()
    cataloger.scan(args.output, args.path)
    sys.exit(0)

def run_scan_mode(args):
    if not args.malwares and not args.advisories:
        print("Error: provide --malwares and/or --advisories.", file=sys.stderr)
        sys.exit(1)

    malware_db: dict[str, list[str]] = {}
    if args.malwares:
        malware_db = parse_malware_file(args.malwares)

    advisory_by_pkg: dict[str, list[AdvisoryRule]] = {}
    if args.advisories:
        advisory_by_pkg = load_advisories_json(args.advisories)

    if not malware_db and not advisory_by_pkg:
        print(
            "No rules to apply: malware list is empty and no advisories were loaded. Exiting.",
            file=sys.stderr,
        )
        sys.exit(1)

    rule_parts: list[str] = []
    if malware_db:
        rule_parts.append(f"malware IOC list ({len(malware_db)} package name(s))")
    if advisory_by_pkg:
        rule_parts.append(f"advisories JSON ({len(advisory_by_pkg)} package name(s))")
    print("Active rules: " + " + ".join(rule_parts) + ".", file=sys.stderr)

    project_paths = _read_projects_file(args.catalog)
    if not project_paths:
        print("No projects to scan. The input file is empty.", file=sys.stderr)
        sys.exit(1)

    if not args.include_node_modules:
        before = len(project_paths)
        project_paths = [p for p in project_paths if not _is_package_json_under_node_modules(p)]
        skip_count = before - len(project_paths)
        if skip_count:
            print(
                f"Skipping {skip_count} package.json path(s) under node_modules/ "
                f"(same hoisted install would repeat per dependency). "
                f"Use --include-node-modules to include them.",
                file=sys.stderr,
            )
    if not project_paths:
        print(
            "No projects left to scan after skipping paths under node_modules/. "
            "Use --include-node-modules if you need those paths.",
            file=sys.stderr,
        )
        sys.exit(1)

    scanner = PackageScanner(malware_db, advisory_by_pkg)
    term_width, _ = shutil.get_terminal_size(fallback=(80, 24))
    print(f"Starting scan of {len(project_paths)} package.json location(s)...", file=sys.stderr)
    
    if args.output:
        with open(args.output, 'w') as out_file:
            found_count, infected_packages = _perform_scan_loop(args, scanner, project_paths, out_file, term_width)
    else:
        found_count, infected_packages = _perform_scan_loop(args, scanner, project_paths, sys.stdout, term_width)

    print(f"\r{' ' * term_width}\r", end="", file=sys.stderr)
    print(f"Scan complete. Found {found_count} finding(s) (malware and/or advisory matches).", file=sys.stderr)
    
    if found_count > 0:
        print("\nFindings:", file=sys.stderr)
        for package in infected_packages:
            print(f"  - {package}", file=sys.stderr)
        if args.output:
            print(f"Findings saved to '{args.output}'", file=sys.stderr)
        sys.exit(2)
    else:
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="A malware scanner for Node.js packages.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    parser_catalog = subparsers.add_parser("catalog", help="Find all package.json files on the system.")
    parser_catalog.add_argument("--output", default="packages.txt", help="Output file for package.json paths.")
    parser_catalog.add_argument("--path", default="/", help="Starting path for the filesystem scan.")

    parser_scan = subparsers.add_parser(
        "scan",
        help="Scan projects for IOC matches (malware list) and/or semver CVE-style ranges (advisories JSON).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supply at least one rule source (you may use both in the same run):
  Malware list only:   scan --catalog PATHS.txt --malwares malwares.txt
  Advisories only:     scan --catalog PATHS.txt --advisories advisories.json
  Both together:       scan --catalog PATHS.txt --malwares malwares.txt --advisories advisories.json

The same catalog filtering applies (by default, paths under node_modules/ are skipped).
""".strip(),
    )
    parser_scan.add_argument("--catalog", required=True, help="File with package.json paths to scan.")
    parser_scan.add_argument(
        "--malwares",
        metavar="FILE",
        help="Text file: exact malicious package@version lines (optional if --advisories is set).",
    )
    parser_scan.add_argument(
        "--advisories",
        metavar="FILE",
        help="JSON file: semver vulnerable ranges per package (see examples/*.example.json). Optional if --malwares is set.",
    )
    parser_scan.add_argument("--output", help="File to save scan findings (JSON format). Defaults to standard output.")
    parser_scan.add_argument("--verbose", action="store_true", help="Enable verbose, path-by-path progress reporting.")
    parser_scan.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Scan package.json files under node_modules/ too (default: skip, to avoid duplicate hits from hoisted deps).",
    )

    args = parser.parse_args()
    
    if args.mode == "catalog":
        run_catalog_mode(args)
    elif args.mode == "scan":
        run_scan_mode(args)

if __name__ == "__main__":
    main()