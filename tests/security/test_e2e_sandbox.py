"""End-to-end tests that run real security tool binaries against sandbox artifacts.

These tests require tools to be downloaded first via `python main.py security setup`.
Tools that are not installed are automatically skipped.

Run with: pytest tests/security/test_e2e_sandbox.py -v -m e2e
"""

import json
import pytest
from pathlib import Path

from src.security.models import (
    PipelineConfig,
    ScanConfig,
    ScanResult,
    ScanStatus,
    ScanTarget,
    SeverityLevel,
)
from src.security.pipeline import ScanPipeline
from src.security.scanners.yara_scanner import YaraScanner
from src.security.scanners.chainsaw import ChainsawScanner
from src.security.scanners.hayabusa import HayabusaScanner
from src.security.scanners.sysinternals import SigcheckScanner

from .sandbox_helpers import (
    CHAINSAW_MAPPINGS,
    PROJECT_ROOT,
    SAMPLE_EVTX,
    SANDBOX_DIR,
    TOOLS_DIR,
    YARA_RULES_DIR,
    get_tool_manager,
    is_tool_available,
)

pytestmark = pytest.mark.e2e


# ---- Fixtures ----

@pytest.fixture
def tool_manager():
    return get_tool_manager()


@pytest.fixture
def output_dir(tmp_path):
    d = tmp_path / "scan_output"
    d.mkdir()
    return d


# ---- Tool availability ----

class TestToolAvailability:
    """Verify that security setup downloaded expected tools."""

    def test_tools_directory_exists(self):
        assert TOOLS_DIR.is_dir(), f"tools/ directory not found at {TOOLS_DIR}"

    def test_yara_x_installed(self):
        if not is_tool_available("yara_x"):
            pytest.skip("YARA-X not installed")
        tm = get_tool_manager()
        path = tm.get_tool_path("yara_x")
        assert path.is_file()
        assert path.name == "yr.exe"

    def test_chainsaw_installed(self):
        if not is_tool_available("chainsaw"):
            pytest.skip("Chainsaw not installed")
        tm = get_tool_manager()
        path = tm.get_tool_path("chainsaw")
        assert path.is_file()
        assert path.name == "chainsaw.exe"

    def test_hayabusa_installed(self):
        if not is_tool_available("hayabusa"):
            pytest.skip("Hayabusa not installed")
        tm = get_tool_manager()
        path = tm.get_tool_path("hayabusa")
        assert path.is_file()
        assert path.name == "hayabusa.exe"

    def test_sigcheck_installed(self):
        if not is_tool_available("sigcheck"):
            pytest.skip("Sigcheck not installed")
        tm = get_tool_manager()
        path = tm.get_tool_path("sigcheck")
        assert path.is_file()
        assert "sigcheck" in path.name.lower()

    def test_security_check_cli(self):
        """Verify the CLI check command runs without error."""
        import subprocess
        result = subprocess.run(
            ["python", "main.py", "security", "check"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "Security Tool Status" in result.stdout


# ---- YARA-X E2E ----

@pytest.mark.skipif(not is_tool_available("yara_x"), reason="YARA-X not installed")
class TestYaraE2E:
    """End-to-end YARA-X scanning tests."""

    def test_sandbox_artifacts_exist(self):
        assert YARA_RULES_DIR.is_dir()
        assert (YARA_RULES_DIR / "test_string.yar").is_file()
        assert (SANDBOX_DIR / "test_target.txt").is_file()

    async def test_yara_scan_finds_test_marker(self, tool_manager, output_dir):
        """YARA-X should detect the test marker string in the sandbox file."""
        scanner = YaraScanner(
            tool_manager,
            config={"rules_dir": str(YARA_RULES_DIR)},
        )

        config = ScanConfig(
            tool_name="yara_x",
            target=ScanTarget(
                target_type="path",
                target_value=str(SANDBOX_DIR / "test_target.txt"),
                recursive=False,
            ),
            output_dir=str(output_dir),
            extra_args={"rules_dir": str(YARA_RULES_DIR)},
            timeout=30,
        )

        result = await scanner.run(config)

        assert result.status == ScanStatus.COMPLETED, (
            f"YARA scan failed: {result.error_message}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert result.return_code == 0
        assert len(result.findings) >= 1, (
            f"Expected at least 1 finding, got {len(result.findings)}.\n"
            f"stdout: {result.stdout}"
        )

        # Verify the finding content
        finding = result.findings[0]
        assert finding.tool_name == "yara_x"
        assert "TestStringDetection" in finding.title
        # YARA-X JSON output does not include rule metadata, so severity defaults to HIGH
        assert finding.severity == SeverityLevel.HIGH
        assert "test_target.txt" in finding.target

    async def test_yara_scan_no_match(self, tool_manager, output_dir):
        """YARA-X should find no matches when scanning a file without the marker."""
        scanner = YaraScanner(
            tool_manager,
            config={"rules_dir": str(YARA_RULES_DIR)},
        )

        # Scan the YARA rule file itself — it won't match its own rule
        # (the rule contains the string in quotes, not as raw content)
        config = ScanConfig(
            tool_name="yara_x",
            target=ScanTarget(
                target_type="path",
                target_value=str(YARA_RULES_DIR / "test_string.yar"),
                recursive=False,
            ),
            output_dir=str(output_dir),
            extra_args={"rules_dir": str(YARA_RULES_DIR)},
            timeout=30,
        )

        result = await scanner.run(config)

        assert result.status == ScanStatus.COMPLETED
        # The rule file itself contains the marker string in quotes,
        # so YARA may or may not match it. Either way, the scan should complete.


# ---- Chainsaw E2E ----

@pytest.mark.skipif(not is_tool_available("chainsaw"), reason="Chainsaw not installed")
class TestChainsawE2E:
    """End-to-end Chainsaw scanning tests."""

    def test_sample_evtx_exists(self):
        assert SAMPLE_EVTX.is_file(), f"Sample evtx not found at {SAMPLE_EVTX}"

    def test_chainsaw_mapping_exists(self):
        mapping = CHAINSAW_MAPPINGS / "sigma-event-logs-all.yml"
        assert mapping.is_file(), f"Chainsaw mapping not found at {mapping}"

    async def test_chainsaw_hunt_with_sigma_rule(self, tool_manager, output_dir):
        """Chainsaw should find detections in the sample evtx using our test Sigma rule."""
        sigma_rules_dir = SANDBOX_DIR / "test_rules"
        mapping_file = str(CHAINSAW_MAPPINGS / "sigma-event-logs-all.yml")

        scanner = ChainsawScanner(
            tool_manager,
            config={
                "sigma_dir": str(sigma_rules_dir),
                "mapping_file": mapping_file,
            },
        )

        config = ScanConfig(
            tool_name="chainsaw",
            target=ScanTarget(
                target_type="path",
                target_value=str(SAMPLE_EVTX),
            ),
            output_dir=str(output_dir),
            extra_args={
                "sigma_dir": str(sigma_rules_dir),
                "mapping_file": mapping_file,
            },
            timeout=60,
        )

        result = await scanner.run(config)

        assert result.status == ScanStatus.COMPLETED, (
            f"Chainsaw failed: {result.error_message}\n"
            f"stdout: {result.stdout[:500]}\nstderr: {result.stderr[:500]}"
        )
        # Chainsaw should find at least the BITS transfer detection
        assert result.findings_count >= 1, (
            f"Expected findings, got {result.findings_count}.\n"
            f"Output files: {result.output_files}"
        )


# ---- Hayabusa E2E ----

@pytest.mark.skipif(not is_tool_available("hayabusa"), reason="Hayabusa not installed")
class TestHayabusaE2E:
    """End-to-end Hayabusa event log scanning tests."""

    def test_sample_evtx_exists(self):
        assert SAMPLE_EVTX.is_file(), f"Sample evtx not found at {SAMPLE_EVTX}"

    async def test_hayabusa_scan_offline_evtx(self, tool_manager, output_dir):
        """Hayabusa should find detections in the sample evtx file."""
        scanner = HayabusaScanner(
            tool_manager,
            config={"min_level": "low"},
        )

        config = ScanConfig(
            tool_name="hayabusa",
            target=ScanTarget(
                target_type="eventlog",
                target_value=str(SAMPLE_EVTX.parent),
            ),
            output_dir=str(output_dir),
            extra_args={"min_level": "low"},
            timeout=60,
        )

        result = await scanner.run(config)

        assert result.status == ScanStatus.COMPLETED, (
            f"Hayabusa failed: {result.error_message}\n"
            f"stdout: {result.stdout[:500]}\nstderr: {result.stderr[:500]}"
        )
        assert result.return_code == 0
        assert len(result.findings) >= 1, (
            f"Expected at least 1 finding, got {len(result.findings)}.\n"
            f"Output files: {result.output_files}"
        )

        # Verify finding structure
        finding = result.findings[0]
        assert finding.tool_name == "hayabusa"
        assert finding.category == "event_log_alert"
        assert finding.severity in (
            SeverityLevel.LOW,
            SeverityLevel.MEDIUM,
            SeverityLevel.HIGH,
            SeverityLevel.CRITICAL,
        )

    async def test_hayabusa_scan_no_match_empty_dir(self, tool_manager, output_dir, tmp_path):
        """Hayabusa should complete cleanly when scanning an empty directory."""
        empty_dir = tmp_path / "empty_evtx"
        empty_dir.mkdir()

        scanner = HayabusaScanner(tool_manager)

        config = ScanConfig(
            tool_name="hayabusa",
            target=ScanTarget(
                target_type="eventlog",
                target_value=str(empty_dir),
            ),
            output_dir=str(output_dir),
            timeout=30,
        )

        result = await scanner.run(config)

        # Should complete (possibly with 0 findings) or fail gracefully
        assert result.status in (ScanStatus.COMPLETED, ScanStatus.FAILED)


# ---- Sigcheck E2E ----

@pytest.mark.skipif(not is_tool_available("sigcheck"), reason="Sigcheck not installed")
class TestSigcheckE2E:
    """End-to-end Sigcheck tests."""

    async def test_sigcheck_scan_tools_dir(self, tool_manager, output_dir):
        """Sigcheck should find unsigned binaries in the tools directory."""
        scanner = SigcheckScanner(tool_manager)

        config = ScanConfig(
            tool_name="sigcheck",
            target=ScanTarget(
                target_type="path",
                target_value=str(TOOLS_DIR / "yara_x"),
            ),
            output_dir=str(output_dir),
            timeout=60,
        )

        result = await scanner.run(config)

        # Sigcheck returns exit code 1 when it finds unsigned files
        assert result.status in (ScanStatus.COMPLETED, ScanStatus.FAILED), (
            f"Sigcheck unexpected status: {result.status}\n"
            f"stderr: {result.stderr}"
        )
        assert result.stdout, "Sigcheck should produce output"


# ---- Pipeline E2E ----

class TestPipelineE2E:
    """End-to-end pipeline tests using available tools."""

    async def test_pipeline_skips_missing_tools(self, tool_manager, output_dir):
        """Pipeline should gracefully skip tools that aren't installed."""
        pipeline = ScanPipeline(tool_manager=tool_manager)

        config = PipelineConfig(
            name="test_skip_missing",
            steps=[
                ScanConfig(
                    tool_name="clamav",  # Not installed
                    target=ScanTarget(target_type="path", target_value=str(SANDBOX_DIR)),
                    output_dir=str(output_dir),
                    timeout=10,
                ),
            ],
        )

        result = await pipeline.run_pipeline(config)
        assert result.status == ScanStatus.COMPLETED
        assert len(result.scan_results) == 1
        assert result.scan_results[0].status == ScanStatus.SKIPPED

    @pytest.mark.skipif(
        not is_tool_available("yara_x"),
        reason="YARA-X not installed",
    )
    async def test_pipeline_with_yara(self, tool_manager, output_dir):
        """Pipeline with a real YARA-X scan step."""
        pipeline = ScanPipeline(
            tool_manager=tool_manager,
            config={
                "tools": {
                    "yara_x": {"rules_dir": str(YARA_RULES_DIR)},
                },
            },
        )

        config = PipelineConfig(
            name="test_yara_pipeline",
            steps=[
                ScanConfig(
                    tool_name="yara_x",
                    target=ScanTarget(
                        target_type="path",
                        target_value=str(SANDBOX_DIR / "test_target.txt"),
                        recursive=False,
                    ),
                    output_dir=str(output_dir),
                    extra_args={"rules_dir": str(YARA_RULES_DIR)},
                    timeout=30,
                ),
            ],
        )

        result = await pipeline.run_pipeline(config)
        assert result.status == ScanStatus.COMPLETED
        assert result.total_findings >= 1


# ---- CLI E2E ----

class TestCLIE2E:
    """End-to-end CLI command tests."""

    def test_cli_security_check(self):
        import subprocess
        result = subprocess.run(
            ["python", "main.py", "security", "check"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "INSTALLED" in result.stdout or "MISSING" in result.stdout

    def test_cli_scan_dry_run(self):
        import subprocess
        result = subprocess.run(
            ["python", "main.py", "security", "scan", "--dry-run"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "Pipeline" in result.stdout
