from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """Common interface every scanner plugin implements. To add a new
    scanner: subclass this, implement can_parse()/parse() (and run() if the
    scanner supports triggering a live scan), then register it in
    scanners/registry.py. Nothing else in the app needs to change — the
    upload endpoint, the live-scan endpoint, and the frontend all work off
    this shared interface.
    """

    name = "base"

    @abstractmethod
    def can_parse(self, data) -> bool:
        """Return True if `data` (already JSON-decoded) looks like this
        scanner's report format. Used to auto-detect scanner type on upload
        so the caller doesn't have to specify which scanner produced a file.
        """

    @abstractmethod
    def parse(self, data) -> list:
        """Convert raw scanner JSON into a list of normalized vulnerability
        dicts. Every scanner must return the same shape (see
        scanners/utils.py: normalize_vuln) so the frontend never needs to
        know which scanner a finding came from.
        """

    def run(self, target: str, **kwargs) -> dict:
        """Trigger a live scan against `target` and return the raw JSON
        report (the same shape parse() expects). Optional: scanners that
        only support uploading a pre-generated report (no CLI/API trigger)
        can leave this raising NotImplementedError.
        """
        raise NotImplementedError(f"{self.name} scanner does not support triggering a live scan")

    def supports_run(self) -> bool:
        return type(self).run is not BaseScanner.run
