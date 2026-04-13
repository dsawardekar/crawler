import json

import pytest
from pathlib import Path
from crawler import (
    AdvisoryMatch,
    PackageJSONScanner,
    PackageMatch,
    PackageScanner,
    _is_package_json_under_node_modules,
    load_advisories_json,
    parse_malware_file,
)

@pytest.fixture
def scanner():
    return PackageScanner(malware_packages={})

@pytest.fixture
def mock_project_with_node_modules(tmp_path: Path) -> Path:
    workspace_dir = tmp_path / "workspace"
    node_modules_dir = workspace_dir / "node_modules"

    react_dir = node_modules_dir / "react"
    react_dir.mkdir(parents=True)
    (react_dir / "package.json").write_text('{"name": "react", "version": "18.2.0"}')

    angular_dir = node_modules_dir / "@angular" / "core"
    angular_dir.mkdir(parents=True)
    (angular_dir / "package.json").write_text('{"name": "@angular/core", "version": "14.0.0"}')

    project_dir = workspace_dir / "packages" / "my-app"
    project_dir.mkdir(parents=True)
    pkg_json_path = project_dir / "package.json"
    pkg_json_path.touch()

    return pkg_json_path

@pytest.fixture
def mock_filesystem_for_catalog(tmp_path: Path) -> Path:
    root = tmp_path / "scan_root"
    project_a_deep = root / "project_a" / "src" / "deep"
    project_a_deep.mkdir(parents=True)
    (root / "project_a" / "package.json").touch()
    (project_a_deep / "package.json").touch()

    project_b = root / "project_b"
    project_b.mkdir()
    (project_b / "package.json").touch()

    (root / "empty_project").mkdir()

    return root

def test_should_parse_simple_package_with_version(tmp_path):
    malware_file = tmp_path / "malware.txt"
    malware_file.write_text("react@18.2.0")
    result = parse_malware_file(malware_file)
    assert result["react"] == ["18.2.0"]

def test_should_parse_versionless_package_as_match_all(tmp_path):
    malware_file = tmp_path / "malware.txt"
    malware_file.write_text("lodash")
    result = parse_malware_file(malware_file)
    assert result["lodash"] == []

def test_should_parse_scoped_package_with_version(tmp_path):
    malware_file = tmp_path / "malware.txt"
    malware_file.write_text("@angular/core@14.0.0")
    result = parse_malware_file(malware_file)
    assert result["@angular/core"] == ["14.0.0"]

def test_should_parse_scoped_versionless_package(tmp_path):
    malware_file = tmp_path / "malware.txt"
    malware_file.write_text("@nestjs/common")
    result = parse_malware_file(malware_file)
    assert result["@nestjs/common"] == []

def test_should_handle_line_with_leading_and_trailing_whitespace(tmp_path):
    malware_file = tmp_path / "malware.txt"
    malware_file.write_text("  request@2.88.2  ")
    result = parse_malware_file(malware_file)
    assert result["request"] == ["2.88.2"]

def test_should_gracefully_handle_invalid_entry(tmp_path):
    malware_file = tmp_path / "malware.txt"
    malware_file.write_text("@1.2.3")
    result = parse_malware_file(malware_file)
    assert result["@1.2.3"] == []

def test_should_find_node_modules_in_same_directory(tmp_path, scanner):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "node_modules").mkdir()
    pkg_json = project_dir / "package.json"
    pkg_json.touch()
    assert scanner.get_node_modules(pkg_json) == str(project_dir / "node_modules")

def test_should_find_node_modules_in_parent_directory(tmp_path, scanner):
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "node_modules").mkdir()
    project_dir = workspace_dir / "packages" / "my-app"
    project_dir.mkdir(parents=True)
    pkg_json = project_dir / "package.json"
    pkg_json.touch()
    assert scanner.get_node_modules(pkg_json) == str(workspace_dir / "node_modules")

def test_should_return_none_if_node_modules_is_not_found(tmp_path, scanner):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    pkg_json = project_dir / "package.json"
    pkg_json.touch()
    assert scanner.get_node_modules(pkg_json) is None

def test_should_return_version_on_specific_version_match(scanner, mock_project_with_node_modules):
    node_modules_path = mock_project_with_node_modules.parent.parent.parent / "node_modules"
    result = scanner._check_package(node_modules_path, "react", ["18.2.0"])
    assert result == "18.2.0"

def test_should_return_none_on_version_mismatch(scanner, mock_project_with_node_modules):
    node_modules_path = mock_project_with_node_modules.parent.parent.parent / "node_modules"
    result = scanner._check_package(node_modules_path, "react", ["16.8.0"])
    assert result is None

def test_should_return_version_on_match_all_rule(scanner, mock_project_with_node_modules):
    node_modules_path = mock_project_with_node_modules.parent.parent.parent / "node_modules"
    result = scanner._check_package(node_modules_path, "react", [])
    assert result == "18.2.0"

def test_should_return_none_if_package_json_is_malformed(scanner, tmp_path):
    node_modules_path = tmp_path / "node_modules"
    pkg_dir = node_modules_path / "bad-json-pkg"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.json").write_text('{"name": "bad", "version": "1.0.0"')
    result = scanner._check_package(node_modules_path, "bad-json-pkg", [])
    assert result is None

def test_catalog_should_find_all_package_json_files(tmp_path, mock_filesystem_for_catalog):
    cataloger = PackageJSONScanner()
    output_file = tmp_path / "catalog.txt"
    cataloger.scan(output_file, start_path=mock_filesystem_for_catalog)
    
    lines = output_file.read_text().strip().splitlines()
    assert len(lines) == 3

def test_catalog_should_write_correct_paths_to_output_file(tmp_path, mock_filesystem_for_catalog):
    cataloger = PackageJSONScanner()
    output_file = tmp_path / "catalog.txt"
    cataloger.scan(output_file, start_path=mock_filesystem_for_catalog)
    
    found_paths = set(output_file.read_text().strip().splitlines())
    expected_path = mock_filesystem_for_catalog / "project_a" / "src" / "deep" / "package.json"
    assert str(expected_path) in found_paths

def test_catalog_should_produce_an_empty_file_if_no_files_found(tmp_path):
    cataloger = PackageJSONScanner()
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    output_file = tmp_path / "catalog.txt"
    cataloger.scan(output_file, start_path=empty_dir)

    content = output_file.read_text()
    assert content == ""

def test_scan_should_find_malware_with_specific_version(mock_project_with_node_modules):
    malware_db = {"react": ["18.2.0"]}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    assert len(findings) == 1

def test_scan_should_yield_correct_package_match_object(mock_project_with_node_modules):
    malware_db = {"react": ["18.2.0"]}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    finding = findings[0]
    assert finding.malicious_package == "react"

def test_scan_should_not_find_malware_if_version_mismatches(mock_project_with_node_modules):
    malware_db = {"react": ["16.0.0"]}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    assert len(findings) == 0

def test_scan_should_find_malware_with_any_version_rule(mock_project_with_node_modules):
    malware_db = {"react": []}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    assert len(findings) == 1

def test_scan_should_not_find_malware_if_package_is_absent(mock_project_with_node_modules):
    malware_db = {"non-existent-package": []}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    assert len(findings) == 0

def test_scan_should_find_scoped_malware_package(mock_project_with_node_modules):
    malware_db = {"@angular/core": ["14.0.0"]}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    assert len(findings) == 1

def test_scan_should_find_multiple_malicious_packages(mock_project_with_node_modules):
    malware_db = {"react": [], "@angular/core": ["14.0.0"]}
    scanner = PackageScanner(malware_db)
    findings = list(scanner.scan(mock_project_with_node_modules))
    assert len(findings) == 2


def test_should_load_advisories_json_with_semver_ranges(tmp_path):
    adv = tmp_path / "adv.json"
    adv.write_text(
        json.dumps(
            {
                "packages": {
                    "axios": [
                        {
                            "id": "CVE-TEST",
                            "title": "Test",
                            "references": ["https://example.invalid/cve"],
                            "vulnerable_ranges": [">=0.0.0,<1.13.5"],
                        }
                    ]
                }
            }
        )
    )
    loaded = load_advisories_json(str(adv))
    assert "axios" in loaded
    assert loaded["axios"][0].advisory_id == "CVE-TEST"
    assert len(loaded["axios"][0].specifier_sets) == 1


def test_advisory_scan_should_flag_version_inside_range(tmp_path):
    workspace_dir = tmp_path / "workspace"
    node_modules_dir = workspace_dir / "node_modules"
    axios_dir = node_modules_dir / "axios"
    axios_dir.mkdir(parents=True)
    (axios_dir / "package.json").write_text('{"name":"axios","version":"1.13.2"}')
    project_dir = workspace_dir / "packages" / "my-app"
    project_dir.mkdir(parents=True)
    pkg_json = project_dir / "package.json"
    pkg_json.touch()

    adv = tmp_path / "adv.json"
    adv.write_text(
        json.dumps(
            {
                "packages": {
                    "axios": [
                        {"id": "CVE-TEST", "vulnerable_ranges": [">=0.0.0,<1.13.5"]}
                    ]
                }
            }
        )
    )
    advisories = load_advisories_json(str(adv))
    scanner = PackageScanner({}, advisories)
    findings = list(scanner.scan(pkg_json))
    assert len(findings) == 1
    assert isinstance(findings[0], AdvisoryMatch)
    assert findings[0].package == "axios"
    assert findings[0].found_version == "1.13.2"


def test_advisory_scan_should_not_flag_patched_version(tmp_path):
    workspace_dir = tmp_path / "workspace"
    axios_dir = workspace_dir / "node_modules" / "axios"
    axios_dir.mkdir(parents=True)
    (axios_dir / "package.json").write_text('{"name":"axios","version":"1.13.5"}')
    pkg_json = workspace_dir / "package.json"
    pkg_json.touch()

    adv = tmp_path / "adv.json"
    adv.write_text(
        json.dumps(
            {
                "packages": {
                    "axios": [
                        {"id": "CVE-TEST", "vulnerable_ranges": [">=0.0.0,<1.13.5"]}
                    ]
                }
            }
        )
    )
    advisories = load_advisories_json(str(adv))
    scanner = PackageScanner({}, advisories)
    assert list(scanner.scan(pkg_json)) == []


def test_should_treat_path_under_node_modules_as_dependency_manifest():
    assert _is_package_json_under_node_modules("/proj/node_modules/q/package.json")
    assert _is_package_json_under_node_modules("/proj/node_modules/@scope/pkg/package.json")


def test_should_not_treat_workspace_package_as_node_modules_manifest():
    assert not _is_package_json_under_node_modules("/proj/package.json")
    assert not _is_package_json_under_node_modules("/proj/packages/my-app/package.json")


def test_hoisted_axios_reported_once_when_nested_package_json_paths_filtered(tmp_path):
    workspace = tmp_path / "w"
    nm = workspace / "node_modules"
    (nm / "axios").mkdir(parents=True)
    (nm / "axios" / "package.json").write_text('{"version":"1.13.2"}')
    (nm / "q").mkdir(parents=True)
    (nm / "q" / "package.json").write_text('{"name":"q","version":"1.0.0"}')
    app = workspace / "package.json"
    app.touch()
    nested_q = nm / "q" / "package.json"

    adv = tmp_path / "adv.json"
    adv.write_text(
        '{"packages":{"axios":[{"id":"X","vulnerable_ranges":[">=0.0.0,<2.0.0"]}]}}'
    )
    rules = load_advisories_json(str(adv))
    scanner = PackageScanner({}, rules)

    paths_both = [str(app), str(nested_q)]
    count_both = sum(1 for p in paths_both for _ in scanner.scan(p))
    assert count_both == 2

    paths_filtered = [p for p in paths_both if not _is_package_json_under_node_modules(p)]
    count_filtered = sum(1 for p in paths_filtered for _ in scanner.scan(p))
    assert count_filtered == 1


def test_space_separated_range_in_json_should_work(tmp_path):
    workspace_dir = tmp_path / "workspace"
    axios_dir = workspace_dir / "node_modules" / "axios"
    axios_dir.mkdir(parents=True)
    (axios_dir / "package.json").write_text('{"name":"axios","version":"1.0.0"}')
    pkg_json = workspace_dir / "package.json"
    pkg_json.touch()

    adv = tmp_path / "adv.json"
    adv.write_text(
        json.dumps(
            {
                "packages": {
                    "axios": [
                        {"id": "CVE-TEST", "vulnerable_ranges": [">=0.0.0 <1.13.5"]}
                    ]
                }
            }
        )
    )
    advisories = load_advisories_json(str(adv))
    scanner = PackageScanner({}, advisories)
    assert len(list(scanner.scan(pkg_json))) == 1