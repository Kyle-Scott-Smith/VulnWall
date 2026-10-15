"""Tests for scanners/trivy.py — parsing Trivy JSON and driving the Trivy CLI.
subprocess and shutil.which are replaced so no real Trivy/Docker is needed."""
import json
import subprocess

import pytest

from scanners import trivy as trivy_module
from scanners.trivy import TrivyScanner

T = TrivyScanner()


def _report(*results):
    return {"Results": list(results)}


def _result(target, *vulns):
    return {"Target": target, "Vulnerabilities": list(vulns)}


# ---------------------------------------------------------------------------
# can_parse / parse
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("data,expected", [
    ({"Results": []}, True),
    ({"Results": [{"Target": "x"}]}, True),
    ({"Results": None}, False),
    ({"Results": {}}, False),
    ({"vulnerabilities": []}, False),
    ([], False),
    (None, False),
    ("Results", False),
])
def test_can_parse(data, expected):
    assert T.can_parse(data) is expected


def test_parse_maps_every_field_and_tags_the_source():
    vuln = {"VulnerabilityID": "CVE-2024-1", "PkgName": "openssl", "InstalledVersion": "1.1.1", "Severity": "CRITICAL",
            "Title": "Heap overflow", "Description": "Bad.", "References": ["https://a.example/1"],
            "PublishedDate": "2024-01-02T00:00:00Z", "CVSS": {"nvd": {"V3Score": 9.8}}}
    (out,) = T.parse(_report(_result("alpine:3.18 (alpine 3.18)", vuln)))
    assert out == {
        "cve": "CVE-2024-1", "package": "openssl", "installedVersion": "1.1.1", "severity": "Critical", "cvss": 9.8,
        "title": "Heap overflow", "description": "Bad.", "references": ["https://a.example/1"],
        "publishedDate": "2024-01-02T00:00:00Z", "asset": "alpine:3.18 (alpine 3.18)", "source": "trivy",
    }


def test_parse_flattens_multiple_targets_and_keeps_each_asset():
    out = T.parse(_report(_result("img (os)", {"VulnerabilityID": "CVE-1"}), _result("app/package.json", {"VulnerabilityID": "CVE-2"})))
    assert [(v["cve"], v["asset"]) for v in out] == [("CVE-1", "img (os)"), ("CVE-2", "app/package.json")]


def test_parse_applies_normalisation_defaults():
    (out,) = T.parse(_report({"Vulnerabilities": [{"VulnerabilityID": "CVE-9"}]}))
    assert out["asset"] == "unknown" and out["severity"] == "Unknown" and out["title"] == "CVE-9" and out["references"] == []


def test_parse_skips_junk_without_crashing():
    data = _report("a string", None, 5, {"Target": "t", "Vulnerabilities": None}, {"Target": "t2"},
                   {"Target": "t3", "Vulnerabilities": ["junk", None, {"VulnerabilityID": "CVE-OK"}]})
    assert [v["cve"] for v in T.parse(data)] == ["CVE-OK"]


def test_parse_of_a_clean_scan_is_empty():
    assert T.parse({"Results": []}) == []
    assert T.parse({"Results": [{"Target": "t"}]}) == []


# ---------------------------------------------------------------------------
# _extract_cvss
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vuln,expected", [
    ({"CVSS": {"nvd": {"V3Score": 7.5, "V2Score": 5.0}}}, 7.5),
    ({"CVSS": {"nvd": {"V2Score": 5.0}, "redhat": {"V3Score": 8.1}}}, 8.1),     # V3 from ANY source beats V2
    ({"CVSS": {"nvd": {"V2Score": 5.0}}}, 5.0),
    ({"CVSS": {"nvd": {"V3Score": 0.0}}}, 0.0),                                   # zero is a score, not "missing"
    ({"CVSS": {"nvd": {}, "ghsa": "junk"}}, None),
    ({"CVSS": {}}, None),
    ({"CVSS": None}, None),
    ({"CVSS": "9.8"}, None),
    ({}, None),
])
def test_extract_cvss(vuln, expected):
    assert TrivyScanner._extract_cvss(vuln) == expected


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("target", [
    "myapp:latest", "ghcr.io/org/app:1.2.3", "registry.example.com:5000/team/app@sha256:abc123", "relative/path",
    "https://github.com/org/repo", "a", "nginx",
])
def test_valid_targets(target):
    TrivyScanner._validate_target(target)


@pytest.mark.xfail(strict=True, reason="BUG: the pattern requires an alphanumeric first character, so absolute "
                                        "paths like /app (a normal `fs` scan target) are rejected even though the "
                                        "comment above _TARGET_PATTERN says file paths match. Allow a leading '/' "
                                        "(but still not '-'), then remove this marker.")
@pytest.mark.parametrize("target", ["/app", "/home/user/project"])
def test_absolute_filesystem_paths_are_valid_targets(target):
    TrivyScanner._validate_target(target)


@pytest.mark.parametrize("target,message", [
    ("", "required"), (None, "required"), (123, "required"),
    ("--reset", "cannot start with"), ("-v", "cannot start with"),
    ("x" * 513, "too long"),
    ("a b", "invalid characters"), ("a;rm -rf /", "invalid characters"), ("a$(whoami)", "invalid characters"),
    ("a`id`", "invalid characters"), ("a|b", "invalid characters"), ("a&&b", "invalid characters"),
    ("a\nb", "invalid characters"), ("a\"b", "invalid characters"), (".hidden", "invalid characters"),
])
def test_invalid_targets_are_rejected(target, message):
    with pytest.raises(ValueError, match=message):
        TrivyScanner._validate_target(target)


def test_512_characters_is_the_longest_allowed_target():
    TrivyScanner._validate_target("a" * 512)


# ---------------------------------------------------------------------------
# run()
# ---------------------------------------------------------------------------
class Proc:
    def __init__(self, returncode=0, stdout="{}", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


@pytest.fixture()
def sh(monkeypatch):
    """Both CLIs 'installed'; subprocess.run records calls and returns `sh.result`."""
    class Shell:
        calls = []
        result = Proc(stdout=json.dumps({"Results": []}))
        installed = {"trivy", "docker"}
        timeout = False

    def which(name):
        return f"/usr/bin/{name}" if name in Shell.installed else None

    def run(cmd, **kw):
        Shell.calls.append((cmd, kw))
        if Shell.timeout:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        return Shell.result

    Shell.calls = []
    monkeypatch.setattr(trivy_module.shutil, "which", which)
    monkeypatch.setattr(trivy_module.subprocess, "run", run)
    return Shell


def test_local_run_builds_the_expected_command_and_returns_parsed_json(sh):
    sh.result = Proc(stdout='{"Results": [{"Target": "x"}]}')
    assert T.run("myapp:latest") == {"Results": [{"Target": "x"}]}
    cmd, kw = sh.calls[0]
    assert cmd == ["trivy", "image", "--format", "json", "myapp:latest"]
    assert kw["capture_output"] is True and kw["text"] is True and kw["timeout"] == 300
    assert "shell" not in kw  # never a shell


@pytest.mark.parametrize("scan_type", ["image", "fs", "repo"])
def test_scan_types(sh, scan_type):
    T.run("target", scan_type=scan_type)
    assert sh.calls[0][0][1] == scan_type


def test_custom_timeout_is_forwarded(sh):
    T.run("t", timeout=42)
    assert sh.calls[0][1]["timeout"] == 42


def test_docker_mode_runs_the_official_image(sh):
    T.run("myapp:latest", mode="docker")
    assert sh.calls[0][0] == ["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                              "aquasec/trivy:latest", "image", "--format", "json", "myapp:latest"]


def test_validation_happens_before_anything_is_executed(sh):
    for bad in ("--flag", "a b", ""):
        with pytest.raises(ValueError):
            T.run(bad)
    with pytest.raises(ValueError, match="scan_type"):
        T.run("ok", scan_type="sbom")
    with pytest.raises(ValueError, match="mode"):
        T.run("ok", mode="kubernetes")
    assert sh.calls == []


def test_missing_cli_is_a_clear_error(sh):
    sh.installed = {"docker"}
    with pytest.raises(RuntimeError, match="Trivy CLI not found"):
        T.run("x")
    sh.installed = {"trivy"}
    with pytest.raises(RuntimeError, match="'docker' CLI was not found"):
        T.run("x", mode="docker")


def test_timeout_is_reported(sh):
    sh.timeout = True
    with pytest.raises(RuntimeError, match="timed out after 300s"):
        T.run("x")


def test_nonzero_exit_includes_truncated_stderr(sh):
    sh.result = Proc(returncode=1, stderr="  " + "E" * 800 + "  ")
    with pytest.raises(RuntimeError) as e:
        T.run("x")
    assert str(e.value).startswith("Trivy scan failed: EEE") and str(e.value).count("E") == 500


def test_non_json_output_is_reported(sh):
    sh.result = Proc(stdout="Not JSON at all")
    with pytest.raises(RuntimeError, match="valid JSON"):
        T.run("x")


# ---------------------------------------------------------------------------
# Private registries
# ---------------------------------------------------------------------------
CREDS = dict(registry_url="reg.example.com", registry_username="bot", registry_password="s3cret")


def test_local_mode_logs_in_via_stdin_so_the_password_never_hits_argv(sh):
    T.run("reg.example.com/app:1", **CREDS)
    login, scan = sh.calls
    assert login[0] == ["trivy", "registry", "login", "--username", "bot", "--password-stdin", "reg.example.com"]
    assert login[1]["input"] == "s3cret" and login[1]["timeout"] == 30
    assert "s3cret" not in " ".join(scan[0]) and "s3cret" not in " ".join(login[0])


def test_docker_mode_passes_credentials_as_environment_variables(sh):
    T.run("reg.example.com/app:1", mode="docker", **CREDS)
    cmd = sh.calls[0][0]
    assert ["-e", "TRIVY_USERNAME=bot", "-e", "TRIVY_PASSWORD=s3cret"] == cmd[cmd.index("-e"):cmd.index("aquasec/trivy:latest")]
    assert len(sh.calls) == 1  # no separate login step


@pytest.mark.parametrize("missing", ["registry_url", "registry_username", "registry_password"])
def test_incomplete_credentials_mean_no_login_at_all(sh, missing):
    T.run("x", **{**CREDS, missing: None})
    assert len(sh.calls) == 1 and "login" not in sh.calls[0][0]


def test_failed_registry_login_stops_the_scan(sh):
    sh.result = Proc(returncode=1, stderr="unauthorized: bad credentials")
    with pytest.raises(RuntimeError, match="Private registry login failed: unauthorized"):
        T.run("x", **CREDS)
    assert len(sh.calls) == 1


def test_registry_login_timeout(sh):
    sh.timeout = True
    with pytest.raises(RuntimeError, match="Timed out logging into the private registry"):
        T.run("x", **CREDS)
