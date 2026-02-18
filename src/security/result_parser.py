"""Shared parsing utilities for security tool output formats."""

import csv
import io
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import SeverityLevel

logger = logging.getLogger(__name__)


class ResultParser:
    """Utility functions for parsing common tool output formats."""

    @staticmethod
    def parse_csv_output(
        text: str, delimiter: str = ","
    ) -> List[Dict[str, str]]:
        """Parse CSV text into a list of dicts via csv.DictReader."""
        reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
        return list(reader)

    @staticmethod
    def parse_json_file(path: Union[str, Path]) -> Any:
        """Parse JSON from a file path."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)

    @staticmethod
    def parse_json_string(text: str) -> Any:
        """Parse JSON from a string."""
        return json.loads(text)

    @staticmethod
    def parse_clamscan_log(text: str) -> Dict[str, Any]:
        """Parse ClamAV clamscan output text.

        Returns dict with:
          - 'detections': list of {'file': path, 'malware': name}
          - 'summary': dict with scan statistics
        """
        detections: List[Dict[str, str]] = []
        summary: Dict[str, str] = {}
        in_summary = False

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Detection lines: "/path/to/file: MalwareName FOUND"
            if line.endswith("FOUND"):
                parts = line.rsplit(":", 1)
                if len(parts) == 2:
                    file_path = parts[0].strip()
                    malware = parts[1].strip().replace(" FOUND", "")
                    detections.append({"file": file_path, "malware": malware})

            # Summary section starts with "----------- SCAN SUMMARY -----------"
            if "SCAN SUMMARY" in line:
                in_summary = True
                continue

            if in_summary and ":" in line:
                key, value = line.split(":", 1)
                summary[key.strip()] = value.strip()

        return {"detections": detections, "summary": summary}

    @staticmethod
    def parse_hollows_hunter_report(report_dir: Union[str, Path]) -> List[Dict[str, Any]]:
        """Parse HollowsHunter output directory.

        HollowsHunter creates a directory structure like:
          <output_dir>/
            scan_report.json           # Overall summary
            <pid>/
              scan_report.json         # Per-process report
              <module_dumps>...

        Returns list of per-process findings dicts.
        """
        report_dir = Path(report_dir)
        findings: List[Dict[str, Any]] = []

        # Look for the top-level scan_report.json
        top_report = report_dir / "scan_report.json"
        if top_report.exists():
            try:
                data = json.loads(top_report.read_text(encoding="utf-8", errors="replace"))
                scanned = data.get("scanned", {})
                for pid_str, process_info in scanned.items():
                    if isinstance(process_info, dict):
                        total_suspicious = process_info.get("replaced", 0) + \
                                          process_info.get("implanted", 0) + \
                                          process_info.get("hdr_modified", 0) + \
                                          process_info.get("patched", 0) + \
                                          process_info.get("iat_hooked", 0) + \
                                          process_info.get("unreachable_file", 0) + \
                                          process_info.get("other", 0)
                        if total_suspicious > 0:
                            findings.append({
                                "pid": pid_str,
                                "name": process_info.get("name", "unknown"),
                                "replaced": process_info.get("replaced", 0),
                                "implanted": process_info.get("implanted", 0),
                                "hdr_modified": process_info.get("hdr_modified", 0),
                                "patched": process_info.get("patched", 0),
                                "iat_hooked": process_info.get("iat_hooked", 0),
                                "unreachable_file": process_info.get("unreachable_file", 0),
                                "other": process_info.get("other", 0),
                                "total_suspicious": total_suspicious,
                            })
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to parse HollowsHunter report: {e}")

        # Also check per-process subdirectories
        for subdir in report_dir.iterdir():
            if subdir.is_dir() and subdir.name.isdigit():
                per_proc_report = subdir / "scan_report.json"
                if per_proc_report.exists():
                    try:
                        data = json.loads(
                            per_proc_report.read_text(encoding="utf-8", errors="replace")
                        )
                        # Per-process reports have the same structure
                        total_suspicious = data.get("replaced", 0) + \
                                          data.get("implanted", 0) + \
                                          data.get("hdr_modified", 0) + \
                                          data.get("patched", 0)
                        if total_suspicious > 0:
                            findings.append({
                                "pid": subdir.name,
                                "name": data.get("main_image_path", "unknown"),
                                "replaced": data.get("replaced", 0),
                                "implanted": data.get("implanted", 0),
                                "hdr_modified": data.get("hdr_modified", 0),
                                "patched": data.get("patched", 0),
                                "total_suspicious": total_suspicious,
                            })
                    except (json.JSONDecodeError, OSError) as e:
                        logger.error(f"Failed to parse per-process report {per_proc_report}: {e}")

        return findings

    @staticmethod
    def severity_from_hayabusa_level(level: str) -> SeverityLevel:
        """Map Hayabusa detection levels to SeverityLevel."""
        mapping = {
            "critical": SeverityLevel.CRITICAL,
            "crit": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "med": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "informational": SeverityLevel.INFO,
            "info": SeverityLevel.INFO,
        }
        return mapping.get(level.lower().strip(), SeverityLevel.INFO)

    @staticmethod
    def severity_from_sigma_level(level: str) -> SeverityLevel:
        """Map Sigma rule levels to SeverityLevel."""
        mapping = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "informational": SeverityLevel.INFO,
        }
        return mapping.get(level.lower().strip(), SeverityLevel.INFO)
