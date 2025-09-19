#!/usr/bin/env python3

import os
import sys
import json
import argparse
import shutil
import itertools
from dataclasses import dataclass, asdict

# --- Data Structure for Findings ---

@dataclass
class PackageMatch:
    project_package_json: str
    node_modules_path: str
    malicious_package: str
    found_version: str

# --- Immutable Helper Functions ---

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

def _read_projects_file(filepath: str) -> list[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Input file '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)

def _report_finding(match: PackageMatch, out_file):
    infected_module_path = os.path.join(match.node_modules_path, match.malicious_package)
    print("\n" + "--- 🚨 MALWARE DETECTED ---", file=sys.stderr)
    print(f"Package: {match.malicious_package}@{match.found_version}", file=sys.stderr)
    print(f"Location: {infected_module_path}", file=sys.stderr)
    finding_json = json.dumps(asdict(match), indent=4)
    out_file.write(finding_json + "\n")

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
    
    def __init__(self, malware_packages: dict[str, list[str]]):
        self.malware_packages = malware_packages

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

    def scan(self, project_package_json: str):
        node_modules_path = self.get_node_modules(project_package_json)
        for pkg_name, malicious_versions in self.malware_packages.items():
            if found_version := self._check_package(node_modules_path, pkg_name, malicious_versions):
                yield PackageMatch(project_package_json, node_modules_path, pkg_name, found_version)

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
            infected_packages.add(f"{match.malicious_package}@{match.found_version}")
            _report_finding(match, out_file)
    
    return found_count, sorted(infected_packages)

def run_catalog_mode(args):
    cataloger = PackageJSONScanner()
    cataloger.scan(args.output, args.path)
    sys.exit(0)

def run_scan_mode(args):
    malware_db = parse_malware_file(args.malwares)
    if not malware_db:
        print("Malware database is empty or could not be read. Exiting.", file=sys.stderr)
        sys.exit(1)

    project_paths = _read_projects_file(args.catalog)
    if not project_paths:
        print("No projects to scan. The input file is empty.", file=sys.stderr)
        sys.exit(1)

    scanner = PackageScanner(malware_db)
    term_width, _ = shutil.get_terminal_size(fallback=(80, 24))
    print(f"Starting scan of {len(project_paths)} packages...", file=sys.stderr)
    
    if args.output:
        with open(args.output, 'w') as out_file:
            found_count, infected_packages = _perform_scan_loop(args, scanner, project_paths, out_file, term_width)
    else:
        found_count, infected_packages = _perform_scan_loop(args, scanner, project_paths, sys.stdout, term_width)

    print(f"\r{' ' * term_width}\r", end="", file=sys.stderr)
    print(f"Scan complete. Found {found_count} instances of malicious packages.", file=sys.stderr)
    
    if found_count > 0:
        print("\nInfected packages found:", file=sys.stderr)
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

    parser_scan = subparsers.add_parser("scan", help="Scan packages for known malware packages.")
    parser_scan.add_argument("--catalog", required=True, help="File with package.json paths to scan.")
    parser_scan.add_argument("--malwares", required=True, help="File listing malicious packages (pkg@version or just pkg).")
    parser_scan.add_argument("--output", help="File to save scan findings (JSON format). Defaults to standard output.")
    parser_scan.add_argument("--verbose", action="store_true", help="Enable verbose, path-by-path progress reporting.")

    args = parser.parse_args()
    
    if args.mode == "catalog":
        run_catalog_mode(args)
    elif args.mode == "scan":
        run_scan_mode(args)

if __name__ == "__main__":
    main()