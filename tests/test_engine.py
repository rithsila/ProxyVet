import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.models import Verdict, ASNType, IPSignalData

@pytest.mark.anyio
async def test_engine_hard_gate_tor():
    # Setup mock config, cache, and checkers
    engine = VerdictEngine(settings=AsyncMock(), cache_mgr=AsyncMock(), checkers=[])
    
    # Mock checker output having Tor exit = True
    sig = IPSignalData(ip="1.1.1.1", is_tor=True, source="test")
    
    verdict_res = engine.evaluate_signals("1.1.1.1", [sig])
    assert verdict_res.verdict == Verdict.BURNED
    assert "Tor exit node detected" in verdict_res.reasons


@pytest.mark.anyio
async def test_engine_evaluate_signals_rules():
    engine = VerdictEngine(settings=AsyncMock(), cache_mgr=AsyncMock(), checkers=[])
    
    # Test case 1: Multiple proxy/VPN sources
    sig1 = IPSignalData(ip="1.1.1.1", is_proxy=True, source="src1")
    sig2 = IPSignalData(ip="1.1.1.1", is_vpn=True, source="src2")
    res = engine.evaluate_signals("1.1.1.1", [sig1, sig2])
    assert res.verdict == Verdict.BURNED
    assert "Flagged as proxy/VPN by multiple sources" in res.reasons[0]

    # Test case 2: DNSBL hits
    sig3 = IPSignalData(ip="1.1.1.1", dnsbl_hits=2, source="src3")
    res = engine.evaluate_signals("1.1.1.1", [sig3])
    assert res.verdict == Verdict.BURNED
    assert "Listed on 2 spam blocklist(s)" in res.reasons[0]

    # Test case 3: Severe abuse score
    sig4 = IPSignalData(ip="1.1.1.1", abuse_score=95, source="src4")
    res = engine.evaluate_signals("1.1.1.1", [sig4])
    assert res.verdict == Verdict.BURNED
    assert "Severe abuse score of 95.0% from src4" in res.reasons[0]

    # Test case 4: Soft score: Datacenter (+50) + single proxy (+30) -> 80 (BURNED)
    sig5 = IPSignalData(ip="1.1.1.1", asn_type=ASNType.DATACENTER, is_proxy=True, source="src5")
    res = engine.evaluate_signals("1.1.1.1", [sig5])
    assert res.verdict == Verdict.BURNED
    assert res.composite_score == 80.0
    assert any("Datacenter ASN detected" in r for r in res.reasons)
    assert any("Suspicious: flagged as proxy/VPN" in r for r in res.reasons)

    # Test case 5: Soft score: Business (+15) + abuse score 50 (0.4*50 = 20) -> 35 (CAUTION)
    sig6 = IPSignalData(ip="1.1.1.1", asn_type=ASNType.BUSINESS, abuse_score=50, source="src6")
    res = engine.evaluate_signals("1.1.1.1", [sig6])
    assert res.verdict == Verdict.CAUTION
    assert res.composite_score == 35.0

    # Test case 6: Soft score: Mobile (-10) -> score 0 (CLEAN)
    sig7 = IPSignalData(ip="1.1.1.1", asn_type=ASNType.MOBILE, source="src7")
    res = engine.evaluate_signals("1.1.1.1", [sig7])
    assert res.verdict == Verdict.CLEAN
    assert res.composite_score == 0.0

    # Test case 7: ASN mismatch (+10)
    sig8a = IPSignalData(ip="1.1.1.1", asn_type=ASNType.BUSINESS, source="src8a")
    sig8b = IPSignalData(ip="1.1.1.1", asn_type=ASNType.RESIDENTIAL, source="src8b")
    res = engine.evaluate_signals("1.1.1.1", [sig8a, sig8b])
    assert res.composite_score == 25.0  # 15 (Business) + 10 (Mismatch) = 25
    assert res.verdict == Verdict.CLEAN  # threshold > 25 is CAUTION, <= 25 is CLEAN
    assert any("Source ASN classification mismatch" in r for r in res.reasons)


@pytest.mark.anyio
async def test_engine_vet_ip_cache_hit():
    cache_mgr = MagicMock()
    checker = MagicMock()
    checker.name = "test_checker"
    checker.cache_ttl_hours = 12
    checker.check = AsyncMock()
    
    cached_signal = IPSignalData(ip="1.1.1.1", is_tor=False, asn_type=ASNType.MOBILE, source="test_checker")
    cache_mgr.get_cached_signal.return_value = cached_signal
    cache_mgr.get_history.return_value = []
    
    engine = VerdictEngine(settings=MagicMock(), cache_mgr=cache_mgr, checkers=[checker])
    res = await engine.vet_ip("1.1.1.1")
    
    assert res.ip == "1.1.1.1"
    assert res.verdict == Verdict.CLEAN
    cache_mgr.get_cached_signal.assert_called_once_with("1.1.1.1", "test_checker", 12)
    checker.check.assert_not_called()
    cache_mgr.save_cached_signal.assert_not_called()
    cache_mgr.save_history.assert_called_once_with(res)


@pytest.mark.anyio
async def test_engine_vet_ip_cache_miss():
    cache_mgr = MagicMock()
    checker = MagicMock()
    checker.name = "test_checker"
    checker.cache_ttl_hours = 12
    checker.check = AsyncMock()
    
    fresh_signal = IPSignalData(ip="1.1.1.1", is_tor=False, asn_type=ASNType.MOBILE, source="test_checker")
    cache_mgr.get_cached_signal.return_value = None
    checker.check.return_value = fresh_signal
    cache_mgr.get_history.return_value = []
    
    engine = VerdictEngine(settings=MagicMock(), cache_mgr=cache_mgr, checkers=[checker])
    res = await engine.vet_ip("1.1.1.1")
    
    assert res.ip == "1.1.1.1"
    cache_mgr.get_cached_signal.assert_called_once_with("1.1.1.1", "test_checker", 12)
    checker.check.assert_called_once_with("1.1.1.1")
    cache_mgr.save_cached_signal.assert_called_once_with(fresh_signal)
    cache_mgr.save_history.assert_called_once_with(res)


@pytest.mark.anyio
async def test_engine_vet_ip_force_refresh():
    cache_mgr = MagicMock()
    checker = MagicMock()
    checker.name = "test_checker"
    checker.cache_ttl_hours = 12
    checker.check = AsyncMock()
    
    fresh_signal = IPSignalData(ip="1.1.1.1", is_tor=False, asn_type=ASNType.MOBILE, source="test_checker")
    checker.check.return_value = fresh_signal
    cache_mgr.get_history.return_value = []
    
    engine = VerdictEngine(settings=MagicMock(), cache_mgr=cache_mgr, checkers=[checker])
    res = await engine.vet_ip("1.1.1.1", force_refresh=True)
    
    assert res.ip == "1.1.1.1"
    cache_mgr.get_cached_signal.assert_not_called()
    checker.check.assert_called_once_with("1.1.1.1")
    cache_mgr.save_cached_signal.assert_called_once_with(fresh_signal)
    cache_mgr.save_history.assert_called_once_with(res)


@pytest.mark.anyio
async def test_engine_vet_ip_drift_detection():
    cache_mgr = MagicMock()
    checker = MagicMock()
    checker.name = "test_checker"
    checker.cache_ttl_hours = 12
    checker.check = AsyncMock()
    
    # Verdict will be BURNED because of is_tor=True
    fresh_signal = IPSignalData(ip="1.1.1.1", is_tor=True, source="test_checker")
    cache_mgr.get_cached_signal.return_value = None
    checker.check.return_value = fresh_signal
    
    # History contains previous CLEAN verdict
    cache_mgr.get_history.return_value = [
        {"verdict": "CLEAN", "composite_score": 10.0, "reasons": [], "signals": [], "checked_at": "2026-06-26T00:00:00Z"}
    ]
    
    engine = VerdictEngine(settings=MagicMock(), cache_mgr=cache_mgr, checkers=[checker])
    res = await engine.vet_ip("1.1.1.1")
    
    assert res.drift_detected is True
    assert res.previous_verdict == Verdict.CLEAN
    assert res.previous_score == 10.0
    
    # History contains previous BURNED verdict (no drift)
    cache_mgr.get_history.return_value = [
        {"verdict": "BURNED", "composite_score": 100.0, "reasons": [], "signals": [], "checked_at": "2026-06-26T00:00:00Z"}
    ]
    res2 = await engine.vet_ip("1.1.1.1")
    assert res2.drift_detected is False
    assert res2.previous_verdict == Verdict.BURNED
    assert res2.previous_score == 100.0

