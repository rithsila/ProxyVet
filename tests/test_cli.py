from typer.testing import CliRunner
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone
import pytest
from proxyvet.cli.main import app
from proxyvet.core.models import Verdict, VerdictResult

runner = CliRunner()

def make_mock_result(ip, verdict=Verdict.CLEAN, score=10.0, reasons=None, drift=False, prev_verdict=None, prev_score=None):
    if reasons is None:
        reasons = ["No suspicious flags raised"]
    return VerdictResult(
        ip=ip,
        verdict=verdict,
        composite_score=score,
        reasons=reasons,
        signals=[],
        checked_at=datetime.now(timezone.utc),
        drift_detected=drift,
        previous_verdict=prev_verdict,
        previous_score=prev_score
    )

def test_cli_help():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "check" in res.stdout or "batch" in res.stdout

@patch("proxyvet.cli.main.get_engine")
def test_cli_check_clean(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(return_value=make_mock_result("1.1.1.1", Verdict.CLEAN, 10.0))
    mock_get_engine.return_value = mock_engine

    res = runner.invoke(app, ["check", "1.1.1.1"])
    assert res.exit_code == 0
    assert "IP" in res.stdout
    assert "Verdict" in res.stdout
    assert "CLEAN" in res.stdout
    assert "Composite Score" in res.stdout
    assert "10.0/100.0" in res.stdout
    assert "No suspicious flags raised" in res.stdout
    assert "+" in res.stdout  # table border
    mock_engine.vet_ip.assert_called_once_with("1.1.1.1", force_refresh=False)

@patch("proxyvet.cli.main.get_engine")
def test_cli_check_force(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(return_value=make_mock_result("1.1.1.1", Verdict.CLEAN, 10.0))
    mock_get_engine.return_value = mock_engine

    res = runner.invoke(app, ["check", "1.1.1.1", "--force"])
    assert res.exit_code == 0
    mock_engine.vet_ip.assert_called_once_with("1.1.1.1", force_refresh=True)

@patch("proxyvet.cli.main.get_engine")
def test_cli_check_force_short(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(return_value=make_mock_result("1.1.1.1", Verdict.CLEAN, 10.0))
    mock_get_engine.return_value = mock_engine

    res = runner.invoke(app, ["check", "1.1.1.1", "-f"])
    assert res.exit_code == 0
    mock_engine.vet_ip.assert_called_once_with("1.1.1.1", force_refresh=True)

@patch("proxyvet.cli.main.get_engine")
def test_cli_check_drift(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(return_value=make_mock_result(
        "1.1.1.1", Verdict.BURNED, 100.0, ["Tor exit node detected"],
        drift=True, prev_verdict=Verdict.CLEAN, prev_score=10.0
    ))
    mock_get_engine.return_value = mock_engine

    res = runner.invoke(app, ["check", "1.1.1.1"])
    assert res.exit_code == 0
    assert "[WARNING] Drift detected! Previous: CLEAN (10.0)" in res.stdout

def test_cli_batch_file_not_found():
    res = runner.invoke(app, ["batch", "nonexistent_file_xyz.txt"])
    assert res.exit_code == 1
    output = res.stdout
    if not output and hasattr(res, "stderr"):
        output = res.stderr
    assert "Error: File nonexistent_file_xyz.txt not found." in output

@patch("proxyvet.cli.main.get_engine")
def test_cli_batch_success(mock_get_engine, tmp_path):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(side_effect=lambda ip, force_refresh=False: make_mock_result(
        ip,
        verdict=Verdict.CLEAN if ip == "1.1.1.1" else Verdict.BURNED,
        score=10.0 if ip == "1.1.1.1" else 100.0
    ))
    mock_get_engine.return_value = mock_engine

    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.1.1.1\n8.8.8.8\n")

    res = runner.invoke(app, ["batch", str(ip_file)])
    assert res.exit_code == 0
    assert "Vetting 2 IPs..." in res.stdout
    assert "Batch Results Summary:" in res.stdout
    assert "1.1.1.1          | CLEAN    |  10.0" in res.stdout
    assert "8.8.8.8          | BURNED   | 100.0" in res.stdout

@patch("proxyvet.cli.main.get_engine")
def test_cli_batch_force(mock_get_engine, tmp_path):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(return_value=make_mock_result("1.1.1.1", Verdict.CLEAN, 10.0))
    mock_get_engine.return_value = mock_engine

    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.1.1.1\n")

    res = runner.invoke(app, ["batch", str(ip_file), "--force"])
    assert res.exit_code == 0
    mock_engine.vet_ip.assert_called_once_with("1.1.1.1", force_refresh=True)

@patch("proxyvet.cli.main.get_engine")
def test_cli_check_json(mock_get_engine):
    import json
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(return_value=make_mock_result("1.1.1.1", Verdict.CLEAN, 10.0))
    mock_get_engine.return_value = mock_engine

    res = runner.invoke(app, ["check", "1.1.1.1", "--json"])
    assert res.exit_code == 0
    # Should be valid JSON representation of the model
    data = json.loads(res.stdout)
    assert data["ip"] == "1.1.1.1"
    assert data["verdict"] == "CLEAN"
    assert data["composite_score"] == 10.0

@patch("proxyvet.cli.main.get_engine")
def test_cli_batch_json(mock_get_engine, tmp_path):
    import json
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(side_effect=lambda ip, force_refresh=False: make_mock_result(
        ip,
        verdict=Verdict.CLEAN if ip == "1.1.1.1" else Verdict.BURNED,
        score=10.0 if ip == "1.1.1.1" else 100.0
    ))
    mock_get_engine.return_value = mock_engine

    ip_file = tmp_path / "ips.txt"
    ip_file.write_text("1.1.1.1\n8.8.8.8\n")

    res = runner.invoke(app, ["batch", str(ip_file), "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["ip"] == "1.1.1.1"
    assert data[0]["verdict"] == "CLEAN"
    assert data[1]["ip"] == "8.8.8.8"
    assert data[1]["verdict"] == "BURNED"

def test_cli_batch_empty_file(tmp_path):
    ip_file = tmp_path / "empty_ips.txt"
    ip_file.write_text("\n   \n\n")

    res = runner.invoke(app, ["batch", str(ip_file)])
    assert res.exit_code == 1
    output = res.stdout
    if not output and hasattr(res, "stderr"):
        output = res.stderr
    assert "Error: Validation failed" in output or "empty" in output.lower()

def test_cli_check_invalid_octets():
    res = runner.invoke(app, ["check", "999.999.999.999"])
    assert res.exit_code == 1
    output = res.stdout
    if not output and hasattr(res, "stderr"):
        output = res.stderr
    assert "Error: Invalid IP address format." in output

def test_cli_batch_invalid_octets(tmp_path):
    ip_file = tmp_path / "invalid_ips.txt"
    ip_file.write_text("1.1.1.1\n999.999.999.999\n")

    res = runner.invoke(app, ["batch", str(ip_file)])
    assert res.exit_code == 1
    output = res.stdout
    if not output and hasattr(res, "stderr"):
        output = res.stderr
    assert "Error: Invalid IP address format: 999.999.999.999" in output
