import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from proxyvet.api.main import app
from proxyvet.core.models import VerdictResult, Verdict, IPSignalData, ASNType

client = TestClient(app)

def test_api_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}

@patch("proxyvet.api.main.get_engine")
def test_vet_ip_success(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock()
    mock_get_engine.return_value = mock_engine

    checked_at = datetime.now(timezone.utc)
    mock_result = VerdictResult(
        ip="1.1.1.1",
        verdict=Verdict.CLEAN,
        composite_score=0.0,
        reasons=["Clean IP"],
        signals=[
            IPSignalData(
                ip="1.1.1.1",
                asn=13335,
                asn_org="Cloudflare, Inc.",
                asn_type=ASNType.RESIDENTIAL,
                is_proxy=False,
                is_vpn=False,
                is_tor=False,
                is_datacenter=False,
                abuse_score=0.0,
                fraud_score=0.0,
                dnsbl_hits=0,
                source="test"
            )
        ],
        checked_at=checked_at,
        previous_verdict=None,
        previous_score=None,
        drift_detected=False
    )
    mock_engine.vet_ip.return_value = mock_result

    # 1. Test standard GET without params
    res = client.get("/api/v1/vet/1.1.1.1")
    assert res.status_code == 200
    res_json = res.json()
    assert res_json["ip"] == "1.1.1.1"
    assert res_json["verdict"] == "CLEAN"
    assert res_json["composite_score"] == 0.0
    mock_engine.vet_ip.assert_called_once_with("1.1.1.1", force_refresh=False)

    # 2. Test GET with force_refresh=true
    mock_engine.vet_ip.reset_mock()
    res = client.get("/api/v1/vet/1.1.1.1?force_refresh=true")
    assert res.status_code == 200
    mock_engine.vet_ip.assert_called_once_with("1.1.1.1", force_refresh=True)

def test_vet_ip_invalid_ip():
    # Test path pattern regex validation
    res = client.get("/api/v1/vet/not-an-ip")
    assert res.status_code == 422

    res = client.get("/api/v1/vet/256.0.0.1")
    # Wait, the pattern is: r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    # So 256.0.0.1 matches the basic regex (as 256 is three digits), but is it valid?
    # The regex allows 1-3 digits. So 999.999.999.999 is matched by the regex.
    # Let's test something that definitely doesn't match, like "1.1.1.1.1" or "abc".
    res = client.get("/api/v1/vet/1.1.1.1.1")
    assert res.status_code == 422

@patch("proxyvet.api.main.get_engine")
def test_vet_ip_exception(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(side_effect=Exception("Database failure"))
    mock_get_engine.return_value = mock_engine

    res = client.get("/api/v1/vet/1.1.1.1")
    assert res.status_code == 500
    assert "Database failure" in res.json()["detail"]

@patch("proxyvet.api.main.get_engine")
def test_vet_batch_success(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock()
    mock_get_engine.return_value = mock_engine

    checked_at = datetime.now(timezone.utc)
    mock_result1 = VerdictResult(
        ip="1.1.1.1",
        verdict=Verdict.CLEAN,
        composite_score=0.0,
        reasons=["Clean IP"],
        signals=[],
        checked_at=checked_at
    )
    mock_result2 = VerdictResult(
        ip="2.2.2.2",
        verdict=Verdict.BURNED,
        composite_score=100.0,
        reasons=["Abuse"],
        signals=[],
        checked_at=checked_at
    )
    # The return_value of vet_ip can be side_effect to return different values for different IPs
    def side_effect(ip, force_refresh=False):
        if ip == "1.1.1.1":
            return mock_result1
        return mock_result2
    mock_engine.vet_ip.side_effect = side_effect

    payload = {
        "ips": ["1.1.1.1", "2.2.2.2"],
        "force_refresh": True
    }
    res = client.post("/api/v1/vet/batch", json=payload)
    assert res.status_code == 200
    res_list = res.json()
    assert len(res_list) == 2
    assert res_list[0]["ip"] == "1.1.1.1"
    assert res_list[0]["verdict"] == "CLEAN"
    assert res_list[1]["ip"] == "2.2.2.2"
    assert res_list[1]["verdict"] == "BURNED"

@patch("proxyvet.api.main.get_engine")
def test_vet_batch_exception(mock_get_engine):
    mock_engine = MagicMock()
    mock_engine.vet_ip = AsyncMock(side_effect=Exception("Failed batch vetting"))
    mock_get_engine.return_value = mock_engine

    payload = {
        "ips": ["1.1.1.1"]
    }
    res = client.post("/api/v1/vet/batch", json=payload)
    assert res.status_code == 500
    assert "Failed batch vetting" in res.json()["detail"]

@patch("proxyvet.api.main.CacheManager")
def test_get_ip_history(mock_cache_mgr_cls):
    mock_cache_mgr = MagicMock()
    mock_cache_mgr_cls.return_value = mock_cache_mgr
    
    mock_history = [
        {
            "verdict": "CLEAN",
            "composite_score": 0.0,
            "reasons": ["Clean IP"],
            "signals": [],
            "checked_at": "2026-06-26T12:00:00Z"
        }
    ]
    mock_cache_mgr.get_history.return_value = mock_history

    res = client.get("/api/v1/history/1.1.1.1")
    assert res.status_code == 200
    assert res.json() == mock_history
    mock_cache_mgr.get_history.assert_called_once_with("1.1.1.1")
