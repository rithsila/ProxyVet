import pytest
from datetime import datetime, timedelta, timezone
from proxyvet.core.cache import CacheManager
from proxyvet.core.models import IPSignalData, ASNType, Verdict, VerdictResult

@pytest.fixture
def cache_mgr(tmp_path):
    db_file = str(tmp_path / "test.db")
    mgr = CacheManager(db_file)
    mgr.init_db()
    return mgr

def test_cache_set_get(cache_mgr):
    sig = IPSignalData(ip="8.8.8.8", asn=15169, source="test", asn_type=ASNType.DATACENTER)
    cache_mgr.save_cached_signal(sig)
    retrieved = cache_mgr.get_cached_signal("8.8.8.8", "test", ttl_hours=1)
    assert retrieved is not None
    assert retrieved.asn == 15169

def test_cache_expiration(cache_mgr):
    sig = IPSignalData(ip="8.8.8.8", asn=15169, source="test", asn_type=ASNType.DATACENTER)
    cache_mgr.save_cached_signal(sig)
    
    # Manually backdate the updated_at timestamp in the database to 2 hours ago
    two_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    with cache_mgr._get_conn() as conn:
        conn.execute("UPDATE cache SET updated_at = ? WHERE ip = ? AND source = ?", (two_hours_ago, "8.8.8.8", "test"))
    
    # ttl_hours = 1 should result in expired (None)
    retrieved_expired = cache_mgr.get_cached_signal("8.8.8.8", "test", ttl_hours=1)
    assert retrieved_expired is None
    
    # ttl_hours = 3 should result in valid (retrieved)
    retrieved_valid = cache_mgr.get_cached_signal("8.8.8.8", "test", ttl_hours=3)
    assert retrieved_valid is not None
    assert retrieved_valid.asn == 15169

def test_history_save_get(cache_mgr):
    sig1 = IPSignalData(ip="8.8.8.8", asn=15169, source="test1", asn_type=ASNType.DATACENTER)
    sig2 = IPSignalData(ip="8.8.8.8", asn=15169, source="test2", asn_type=ASNType.DATACENTER)
    
    now = datetime.now(timezone.utc)
    res = VerdictResult(
        ip="8.8.8.8",
        verdict=Verdict.CAUTION,
        composite_score=0.5,
        reasons=["High abuse score"],
        signals=[sig1, sig2],
        checked_at=now
    )
    
    cache_mgr.save_history(res)
    history = cache_mgr.get_history("8.8.8.8")
    assert len(history) == 1
    record = history[0]
    assert record["verdict"] == "CAUTION"
    assert record["composite_score"] == 0.5
    assert record["reasons"] == ["High abuse score"]
    assert len(record["signals"]) == 2
    assert record["signals"][0]["source"] == "test1"
    assert record["signals"][1]["source"] == "test2"
    assert record["checked_at"] == now.isoformat()

def test_history_empty(cache_mgr):
    history = cache_mgr.get_history("1.1.1.1")
    assert history == []
