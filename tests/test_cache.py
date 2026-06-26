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

def test_cache_validation_error_tolerance(cache_mgr):
    # Manually insert invalid JSON schema into cache
    with cache_mgr._get_conn() as conn:
        conn.execute(
            "INSERT INTO cache (ip, source, data, updated_at) VALUES (?, ?, ?, ?)",
            ("1.2.3.4", "test", '{"invalid_field": true}', datetime.now(timezone.utc).isoformat())
        )
    # The ValidationError should be caught, resulting in a cache miss (None)
    assert cache_mgr.get_cached_signal("1.2.3.4", "test", ttl_hours=1) is None

def test_timezone_naive_updated_at(cache_mgr):
    # Save a valid signal
    sig = IPSignalData(ip="1.2.3.5", asn=123, source="test", asn_type=ASNType.DATACENTER)
    cache_mgr.save_cached_signal(sig)
    
    # Update with a naive timestamp string
    now_naive_str = datetime.now().isoformat()
    with cache_mgr._get_conn() as conn:
        conn.execute("UPDATE cache SET updated_at = ? WHERE ip = ?", (now_naive_str, "1.2.3.5"))
        
    retrieved = cache_mgr.get_cached_signal("1.2.3.5", "test", ttl_hours=1)
    assert retrieved is not None
    assert retrieved.asn == 123

def test_checked_at_normalization(cache_mgr):
    # 1. Naive checked_at
    naive_dt = datetime.now()
    res = VerdictResult(
        ip="1.2.3.6",
        verdict=Verdict.CLEAN,
        composite_score=0.1,
        reasons=[],
        signals=[],
        checked_at=naive_dt
    )
    cache_mgr.save_history(res)
    history = cache_mgr.get_history("1.2.3.6")
    assert len(history) == 1
    assert history[0]["checked_at"].endswith("+00:00")

    # 2. Non-UTC timezone checked_at
    est = timezone(timedelta(hours=-5))
    aware_dt = datetime.now(est)
    res2 = VerdictResult(
        ip="1.2.3.7",
        verdict=Verdict.CLEAN,
        composite_score=0.1,
        reasons=[],
        signals=[],
        checked_at=aware_dt
    )
    cache_mgr.save_history(res2)
    history2 = cache_mgr.get_history("1.2.3.7")
    assert len(history2) == 1
    assert history2[0]["checked_at"].endswith("+00:00")
    retrieved_dt = datetime.fromisoformat(history2[0]["checked_at"])
    assert abs((retrieved_dt - aware_dt).total_seconds()) < 1.0

def test_sqlite_current_timestamp_fallback(cache_mgr):
    # SQLite CURRENT_TIMESTAMP format is YYYY-MM-DD HH:MM:SS
    with cache_mgr._get_conn() as conn:
        conn.execute(
            """
            INSERT INTO history (ip, verdict, composite_score, reasons, signals, checked_at)
            VALUES (?, ?, ?, ?, ?, '2026-06-26 14:04:07')
            """, ("1.2.3.8", "CLEAN", 0.0, "[]", "[]")
        )
    history = cache_mgr.get_history("1.2.3.8")
    assert len(history) == 1
    assert history[0]["checked_at"] == "2026-06-26T14:04:07+00:00"
