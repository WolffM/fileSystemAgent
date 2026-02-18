"""Tests for result parsing utilities and scanner output parsers."""

import json
import pytest
from pathlib import Path

from src.security.models import SeverityLevel
from src.security.result_parser import ResultParser


class TestParseCsvOutput:
    def test_basic_csv(self):
        text = "name,value,status\nalpha,1,ok\nbeta,2,fail\n"
        rows = ResultParser.parse_csv_output(text)
        assert len(rows) == 2
        assert rows[0]["name"] == "alpha"
        assert rows[1]["status"] == "fail"

    def test_empty_csv(self):
        text = ""
        rows = ResultParser.parse_csv_output(text)
        assert rows == []

    def test_tab_delimited(self):
        text = "col1\tcol2\na\tb\n"
        rows = ResultParser.parse_csv_output(text, delimiter="\t")
        assert len(rows) == 1
        assert rows[0]["col1"] == "a"


class TestParseClamscanLog:
    def test_parse_fixture(self, fixtures_dir):
        text = (fixtures_dir / "clamscan_output.log").read_text()
        result = ResultParser.parse_clamscan_log(text)

        assert len(result["detections"]) == 3
        assert result["detections"][0]["malware"] == "Eicar-Signature"
        assert result["detections"][0]["file"] == "C:\\Users\\test\\Downloads\\eicar.txt"
        assert result["detections"][1]["malware"] == "Win.Trojan.Generic-12345"
        assert result["detections"][2]["malware"] == "Win.Malware.Agent-67890"

        assert result["summary"]["Infected files"] == "3"
        assert result["summary"]["Scanned files"] == "42"

    def test_no_detections(self):
        text = (
            "C:\\clean.txt: OK\n"
            "\n"
            "----------- SCAN SUMMARY -----------\n"
            "Infected files: 0\n"
            "Scanned files: 1\n"
        )
        result = ResultParser.parse_clamscan_log(text)
        assert len(result["detections"]) == 0
        assert result["summary"]["Infected files"] == "0"

    def test_empty_input(self):
        result = ResultParser.parse_clamscan_log("")
        assert result["detections"] == []
        assert result["summary"] == {}


class TestParseHollowsHunterReport:
    def test_parse_fixture(self, fixtures_dir, tmp_path):
        # Copy fixture to a directory structure HollowsHunter would create
        output_dir = tmp_path / "hh_output"
        output_dir.mkdir()

        fixture_data = json.loads(
            (fixtures_dir / "hollows_hunter_output.json").read_text()
        )
        (output_dir / "scan_report.json").write_text(json.dumps(fixture_data))

        findings = ResultParser.parse_hollows_hunter_report(output_dir)

        # Two processes have anomalies (4567 and 8901), notepad is clean
        assert len(findings) == 2

        pid_4567 = next(f for f in findings if f["pid"] == "4567")
        assert pid_4567["name"] == "suspicious.exe"
        assert pid_4567["replaced"] == 2
        assert pid_4567["implanted"] == 1
        assert pid_4567["total_suspicious"] == 3

        pid_8901 = next(f for f in findings if f["pid"] == "8901")
        assert pid_8901["hdr_modified"] == 1
        assert pid_8901["patched"] == 3
        assert pid_8901["iat_hooked"] == 2
        assert pid_8901["total_suspicious"] == 6

    def test_empty_directory(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        findings = ResultParser.parse_hollows_hunter_report(empty_dir)
        assert findings == []

    def test_per_process_subdirectory(self, tmp_path):
        output_dir = tmp_path / "hh_output"
        output_dir.mkdir()

        # Create a per-process subdirectory report
        pid_dir = output_dir / "9999"
        pid_dir.mkdir()
        per_proc_report = {
            "main_image_path": "C:\\Windows\\malware.exe",
            "replaced": 1,
            "implanted": 0,
            "hdr_modified": 0,
            "patched": 2,
        }
        (pid_dir / "scan_report.json").write_text(json.dumps(per_proc_report))

        findings = ResultParser.parse_hollows_hunter_report(output_dir)
        assert len(findings) == 1
        assert findings[0]["pid"] == "9999"
        assert findings[0]["total_suspicious"] == 3


class TestSeverityMapping:
    @pytest.mark.parametrize(
        "level,expected",
        [
            ("critical", SeverityLevel.CRITICAL),
            ("crit", SeverityLevel.CRITICAL),
            ("high", SeverityLevel.HIGH),
            ("medium", SeverityLevel.MEDIUM),
            ("med", SeverityLevel.MEDIUM),
            ("low", SeverityLevel.LOW),
            ("informational", SeverityLevel.INFO),
            ("info", SeverityLevel.INFO),
            ("CRITICAL", SeverityLevel.CRITICAL),
            ("  High  ", SeverityLevel.HIGH),
            ("unknown", SeverityLevel.INFO),
        ],
    )
    def test_hayabusa_levels(self, level, expected):
        assert ResultParser.severity_from_hayabusa_level(level) == expected

    @pytest.mark.parametrize(
        "level,expected",
        [
            ("critical", SeverityLevel.CRITICAL),
            ("high", SeverityLevel.HIGH),
            ("medium", SeverityLevel.MEDIUM),
            ("low", SeverityLevel.LOW),
            ("informational", SeverityLevel.INFO),
        ],
    )
    def test_sigma_levels(self, level, expected):
        assert ResultParser.severity_from_sigma_level(level) == expected


class TestParseJsonFile:
    def test_valid_json(self, tmp_path):
        data = {"key": "value", "nested": {"a": 1}}
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data))
        result = ResultParser.parse_json_file(f)
        assert result == data

    def test_json_string(self):
        text = '{"items": [1, 2, 3]}'
        result = ResultParser.parse_json_string(text)
        assert result["items"] == [1, 2, 3]
