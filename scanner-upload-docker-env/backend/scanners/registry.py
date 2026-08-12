from .tenable import TenableScanner
from .trivy import TrivyScanner

# To add a new scanner: implement BaseScanner in its own file (see trivy.py
# for a scanner that supports live triggering, tenable.py for one that
# drives a vendor API), then register an instance here. Nothing else in the
# app needs to change.
SCANNERS = {
    "trivy": TrivyScanner(),
    "tenable": TenableScanner(),
}


def detect_scanner(data):
    """Given already-JSON-decoded upload data, find the scanner plugin that
    recognizes its shape. Returns None if nothing matches."""
    for scanner in SCANNERS.values():
        if scanner.can_parse(data):
            return scanner
    return None


def get_scanner(name):
    scanner = SCANNERS.get(name)
    if scanner is None:
        raise ValueError(f"Unknown scanner '{name}'. Available: {', '.join(SCANNERS)}")
    return scanner
