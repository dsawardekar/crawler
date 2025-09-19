import pytest
from pathlib import Path
from crawler import parse_malware_file, PackageScanner, PackageJSONScanner, PackageMatch

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