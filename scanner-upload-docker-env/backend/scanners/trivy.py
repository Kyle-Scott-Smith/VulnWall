import json
import re
import shutil
import subprocess

from .base import BaseScanner
from .utils import normalize_vuln

# Deliberately conservative: image refs, file paths, and repo URLs all match
# this, but shell metacharacters and flag-injection attempts (leading "-")
# don't.
_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")


class TrivyScanner(BaseScanner):
    name = "trivy"

    def can_parse(self, data) -> bool:
        return isinstance(data, dict) and isinstance(data.get("Results"), list)

    def parse(self, data) -> list:
        vulnerabilities = []
        for result in data.get("Results", []) or []:
            if not isinstance(result, dict):
                continue
            asset = result.get("Target")
            for vuln in result.get("Vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                vulnerabilities.append(normalize_vuln(
                    cve=vuln.get("VulnerabilityID"),
                    package=vuln.get("PkgName"),
                    installedVersion=vuln.get("InstalledVersion"),
                    severity=vuln.get("Severity"),
                    cvss=self._extract_cvss(vuln),
                    title=vuln.get("Title"),
                    description=vuln.get("Description"),
                    references=vuln.get("References"),
                    publishedDate=vuln.get("PublishedDate"),
                    asset=asset,
                    source=self.name,
                ))
        return vulnerabilities

    def run(self, target: str, scan_type: str = "image", mode: str = "local", timeout: int = 300) -> dict:
        """Trigger a live Trivy scan.

        target: image ref ("myapp:latest"), filesystem path, or repo URL
        scan_type: "image" | "fs" | "repo"
        mode: "local" (trivy CLI must be on PATH) | "docker" (runs the
              official aquasec/trivy image via `docker run`; needs the
              backend host to have Docker + socket access)
        """
        self._validate_target(target)
        if scan_type not in ("image", "fs", "repo"):
            raise ValueError("scan_type must be one of: image, fs, repo")

        if mode == "docker":
            if not shutil.which("docker"):
                raise RuntimeError("mode='docker' requested but the 'docker' CLI was not found on PATH")
            cmd = [
                "docker", "run", "--rm",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "aquasec/trivy:latest", scan_type, "--format", "json", target,
            ]
        elif mode == "local":
            if not shutil.which("trivy"):
                raise RuntimeError("Trivy CLI not found on PATH. Install it, or pass mode='docker'.")
            cmd = ["trivy", scan_type, "--format", "json", target]
        else:
            raise ValueError("mode must be 'local' or 'docker'")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Trivy scan timed out after {timeout}s")

        if result.returncode != 0:
            raise RuntimeError(f"Trivy scan failed: {result.stderr.strip()[:500]}")

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise RuntimeError("Trivy did not return valid JSON output")

    @staticmethod
    def _extract_cvss(vuln):
        """Trivy nests CVSS scores under a vendor key (nvd, redhat, ghsa, ...).
        Prefer a V3 score from any source, then fall back to V2."""
        cvss_block = vuln.get("CVSS")
        if not isinstance(cvss_block, dict):
            return None
        for source in cvss_block.values():
            if isinstance(source, dict) and source.get("V3Score") is not None:
                return source["V3Score"]
        for source in cvss_block.values():
            if isinstance(source, dict) and source.get("V2Score") is not None:
                return source["V2Score"]
        return None

    @staticmethod
    def _validate_target(target: str):
        # subprocess.run() with a list (no shell=True) already prevents shell
        # injection, but this still stops flag-injection (a target like
        # "--reset" being interpreted as a Trivy flag) and garbage input.
        if not target or not isinstance(target, str):
            raise ValueError("target is required")
        if len(target) > 512:
            raise ValueError("target is too long")
        if target.startswith("-"):
            raise ValueError("target cannot start with '-'")
        if not _TARGET_PATTERN.match(target):
            raise ValueError("target contains invalid characters")
