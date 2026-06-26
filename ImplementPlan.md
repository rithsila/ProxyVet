# ProxyVet Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI and FastAPI web application to vet candidate proxy IPs using local databases and external reputation APIs, cache results in SQLite, and track reputation drift over time.

**Architecture:** Core vetting logic is implemented as independent checkers conforming to a base class. A "gate-then-score" engine evaluates results. Entrypoints (CLI and FastAPI) consume the core engine. Caching is handled in SQLite.

**Tech Stack:** Python 3.10+, FastAPI, Typer, SQLite, geoip2, ip2proxy-py, httpx, dnspython, pytest.

## Global Constraints
- Target: Run on self-hosted Linux (VM/LXC).
- Cache TTLs: 7 days for classification (MaxMind, IP2Proxy), 12 hours for reputation/APIs.
- SQLite is the default storage backend.
- Commit frequently (after each task passes tests).
- All dependencies must be defined in `pyproject.toml`.

---

### Task 1: Project Scaffolding & Configuration

**Files:**
- Create: `pyproject.toml`
- Create: `proxyvet/core/config.py`
- Create: `.env.example`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: None
- Produces: `proxyvet.core.config.get_settings` returning settings instance with properties like `maxmind_db_path`, `ip2proxy_db_path`, `abuseipdb_api_key`, `proxycheck_api_key`, `sqlite_db_path`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:
```python
import os
from proxyvet.core.config import get_settings

def test_settings_load():
    os.environ["ABUSEIPDB_API_KEY"] = "test_key_123"
    settings = get_settings()
    assert settings.abuseipdb_api_key == "test_key_123"
    assert settings.sqlite_db_path == "proxyvet.db"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_config.py` (or using `uv run pytest`)
Expected: ModuleNotFoundError for `proxyvet`

- [ ] **Step 3: Create pyproject.toml and source layout**

Create `pyproject.toml`:
```toml
[tool.poetry]
name = "proxyvet"
version = "0.1.0"
description = "Proxy IP quality checker"
authors = ["ProxyVet Developer <developer@proxyvet.local>"]
packages = [{include = "proxyvet"}]

[tool.poetry.dependencies]
python = "^3.10"
fastapi = "^0.100.0"
uvicorn = "^0.22.0"
typer = "^0.9.0"
pydantic = "^2.0.0"
pydantic-settings = "^2.0.0"
httpx = "^0.24.0"
geoip2 = "^4.7.0"
ip2proxy-py = "^4.0.0"
dnspython = "^2.3.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.3.0"

[build-system]
requires = ["poetry-core>=1.0.0"]
build-backend = "poetry.core.masonry.api"
```

Create `.env.example`:
```env
ABUSEIPDB_API_KEY=
PROXYCHECK_API_KEY=
MAXMIND_DB_PATH=data/GeoLite2-ASN.mmdb
IP2PROXY_DB_PATH=data/IP2PROXY-LITE-PX1.BIN
SQLITE_DB_PATH=proxyvet.db
```

Create `proxyvet/__init__.py` and `proxyvet/core/__init__.py` as empty files.
Create `proxyvet/core/config.py`:
```python
from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    abuseipdb_api_key: str = ""
    proxycheck_api_key: str = ""
    maxmind_db_path: str = "data/GeoLite2-ASN.mmdb"
    ip2proxy_db_path: str = "data/IP2PROXY-LITE-PX1.BIN"
    sqlite_db_path: str = "proxyvet.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache()
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_config.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add pyproject.toml .env.example proxyvet/core/config.py tests/test_config.py
git commit -m "feat: initialize project config and dependencies"
```

---

### Task 2: Models & Base Checker Interface

**Files:**
- Create: `proxyvet/core/models.py`
- Create: `proxyvet/core/checkers/base.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: `proxyvet.core.config`
- Produces: `ASNType` Enum, `IPSignalData` Pydantic model, `Verdict` Enum, `VerdictResult` Pydantic model, and `BaseChecker` abstract base class.

- [ ] **Step 1: Write the failing test**

Create `tests/test_models.py`:
```python
from proxyvet.core.models import IPSignalData, ASNType

def test_ip_signal_data_validation():
    data = IPSignalData(
        ip="1.2.3.4",
        asn=1234,
        asn_org="Test ISP",
        asn_type=ASNType.RESIDENTIAL,
        source="test_source"
    )
    assert data.ip == "1.2.3.4"
    assert data.asn_type == "RESIDENTIAL"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_models.py`
Expected: Fail (module not found/import error)

- [ ] **Step 3: Implement schemas and BaseChecker**

Create `proxyvet/core/models.py`:
```python
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from datetime import datetime

class ASNType(str, Enum):
    RESIDENTIAL = "RESIDENTIAL"
    MOBILE = "MOBILE"
    BUSINESS = "BUSINESS"
    DATACENTER = "DATACENTER"
    UNKNOWN = "UNKNOWN"

class IPSignalData(BaseModel):
    ip: str
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    asn_type: ASNType = ASNType.UNKNOWN
    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    abuse_score: Optional[float] = None
    fraud_score: Optional[float] = None
    dnsbl_hits: int = 0
    source: str

class Verdict(str, Enum):
    CLEAN = "CLEAN"
    CAUTION = "CAUTION"
    BURNED = "BURNED"

class VerdictResult(BaseModel):
    ip: str
    verdict: Verdict
    composite_score: float
    reasons: List[str]
    signals: List[IPSignalData]
    checked_at: datetime
    previous_verdict: Optional[Verdict] = None
    previous_score: Optional[float] = None
    drift_detected: bool = False
```

Create `proxyvet/core/checkers/__init__.py` (empty)
Create `proxyvet/core/checkers/base.py`:
```python
from abc import ABC, abstractmethod
from proxyvet.core.models import IPSignalData

class BaseChecker(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def cache_ttl_hours(self) -> int:
        pass

    @abstractmethod
    async def check(self, ip: str) -> IPSignalData:
        pass
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_models.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/core/models.py proxyvet/core/checkers/base.py tests/test_models.py
git commit -m "feat: implement data schemas and base checker interface"
```

---

### Task 3: SQLite Cache & History Database

**Files:**
- Create: `proxyvet/core/cache.py`
- Test: `tests/test_cache.py`

**Interfaces:**
- Consumes: `proxyvet.core.models.IPSignalData`, `proxyvet.core.config.get_settings`
- Produces: `CacheManager` with methods:
  - `init_db()`: Initializes database tables.
  - `get_cached_signal(ip: str, source: str, ttl_hours: int) -> Optional[IPSignalData]`: Retrieves unexpired cache record.
  - `save_cached_signal(signal: IPSignalData)`: Saves signal to cache.
  - `get_history(ip: str) -> List[dict]`: Retrieves past check results.
  - `save_history(result: VerdictResult)`: Appends check result.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cache.py`:
```python
import pytest
from datetime import datetime, timezone
from proxyvet.core.cache import CacheManager
from proxyvet.core.models import IPSignalData, ASNType

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_cache.py`
Expected: FAIL (module/file not found)

- [ ] **Step 3: Implement SQLite CacheManager**

Create `proxyvet/core/cache.py`:
```python
import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from proxyvet.core.models import IPSignalData, VerdictResult

class CacheManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    ip TEXT NOT NULL,
                    source TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    PRIMARY KEY (ip, source)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    composite_score REAL NOT NULL,
                    reasons TEXT NOT NULL,
                    signals TEXT NOT NULL,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def get_cached_signal(self, ip: str, source: str, ttl_hours: int) -> Optional[IPSignalData]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT data, updated_at FROM cache WHERE ip = ? AND source = ?", (ip, source)
            )
            row = cursor.fetchone()
            if not row:
                return None
            data_str, updated_at_str = row
            updated_at = datetime.fromisoformat(updated_at_str)
            if datetime.now(timezone.utc) - updated_at > timedelta(hours=ttl_hours):
                return None
            return IPSignalData.model_validate_json(data_str)

    def save_cached_signal(self, signal: IPSignalData):
        with self._get_conn() as conn:
            data_str = signal.model_dump_json()
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT OR REPLACE INTO cache (ip, source, data, updated_at)
                VALUES (?, ?, ?, ?)
                """, (signal.ip, signal.source, data_str, now)
            )

    def get_history(self, ip: str) -> List[dict]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT verdict, composite_score, reasons, signals, checked_at FROM history WHERE ip = ? ORDER BY checked_at DESC",
                (ip,)
            )
            results = []
            for row in cursor.fetchall():
                results.append({
                    "verdict": row[0],
                    "composite_score": row[1],
                    "reasons": json.loads(row[2]),
                    "signals": json.loads(row[3]),
                    "checked_at": row[4]
                })
            return results

    def save_history(self, result: VerdictResult):
        with self._get_conn() as conn:
            reasons_str = json.dumps(result.reasons)
            signals_str = json.dumps([sig.model_dump() for sig in result.signals])
            conn.execute(
                """
                INSERT INTO history (ip, verdict, composite_score, reasons, signals, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (result.ip, result.verdict.value, result.composite_score, reasons_str, signals_str, result.checked_at.isoformat())
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_cache.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/core/cache.py tests/test_cache.py
git commit -m "feat: implement SQLite caching and history storage"
```

---

### Task 4: Offline Checkers (MaxMind & IP2Proxy)

**Files:**
- Create: `proxyvet/core/checkers/maxmind.py`
- Create: `proxyvet/core/checkers/ip2proxy.py`
- Test: `tests/test_offline_checkers.py`

**Interfaces:**
- Consumes: `proxyvet.core.checkers.base.BaseChecker`
- Produces: `MaxMindChecker` and `IP2ProxyChecker` implementing the abstract interface.

- [ ] **Step 1: Write the failing test**

Create `tests/test_offline_checkers.py`:
```python
import pytest
from unittest.mock import MagicMock, patch
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker

@pytest.mark.asyncio
@patch('geoip2.database.Reader')
async def test_maxmind_checker(mock_reader):
    mock_inst = MagicMock()
    mock_inst.asn.return_value = MagicMock(autonomous_system_number=15169, autonomous_system_organization="Google LLC")
    mock_reader.return_value = mock_inst

    checker = MaxMindChecker(db_path="dummy.mmdb")
    res = await checker.check("8.8.8.8")
    assert res.asn == 15169
    assert res.asn_org == "Google LLC"
    assert res.asn_type == "DATACENTER" # Inferred from "Google"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_offline_checkers.py`
Expected: FAIL (module not found)

- [ ] **Step 3: Implement MaxMind & IP2Proxy Checkers**

Create `proxyvet/core/checkers/maxmind.py`:
```python
import os
import geoip2.database
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData, ASNType

class MaxMindChecker(BaseChecker):
    def __init__(self, db_path: str):
        self.db_path = db_path

    @property
    def name(self) -> str:
        return "maxmind"

    @property
    def cache_ttl_hours(self) -> int:
        return 168  # 7 days

    def _infer_asn_type(self, org: str) -> ASNType:
        org_lower = org.lower()
        dc_keywords = ["hosting", "cloud", "datacenter", "m247", "digitalocean", "ovh", "server", "aws", "google", "linode", "hetzner"]
        mobile_keywords = ["mobile", "wireless", "telecom", "vodafone", "t-mobile", "orange", "verizon", "att", "sprint"]
        if any(kw in org_lower for kw in dc_keywords):
            return ASNType.DATACENTER
        if any(kw in org_lower for kw in mobile_keywords):
            return ASNType.MOBILE
        return ASNType.RESIDENTIAL

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not os.path.exists(self.db_path):
            return result
        try:
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.asn(ip)
                result.asn = response.autonomous_system_number
                result.asn_org = response.autonomous_system_organization
                if result.asn_org:
                    result.asn_type = self._infer_asn_type(result.asn_org)
        except Exception:
            pass
        return result
```

Create `proxyvet/core/checkers/ip2proxy.py`:
```python
import os
import ip2proxy
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class IP2ProxyChecker(BaseChecker):
    def __init__(self, db_path: str):
        self.db_path = db_path

    @property
    def name(self) -> str:
        return "ip2proxy"

    @property
    def cache_ttl_hours(self) -> int:
        return 168  # 7 days

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not os.path.exists(self.db_path):
            return result
        try:
            db = ip2proxy.IP2Proxy()
            db.open(self.db_path)
            res = db.get_all(ip)
            if res:
                is_dc = res.get("usage_type") == "DCH"
                # If usage_type is DCH or proxy type matches common proxy flags
                is_proxy_flag = res.get("is_proxy") in [1, 2, "1", "2"]
                result.is_proxy = is_proxy_flag
                result.is_vpn = res.get("proxy_type") == "VPN"
                result.is_tor = res.get("proxy_type") == "TOR"
                result.is_datacenter = is_dc or res.get("proxy_type") == "DCH"
            db.close()
        except Exception:
            pass
        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_offline_checkers.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/core/checkers/maxmind.py proxyvet/core/checkers/ip2proxy.py tests/test_offline_checkers.py
git commit -m "feat: implement MaxMind and IP2Proxy checkers"
```

---

### Task 5: Hosted APIs & DNSBL Checkers

**Files:**
- Create: `proxyvet/core/checkers/dnsbl.py`
- Create: `proxyvet/core/checkers/abuseipdb.py`
- Create: `proxyvet/core/checkers/proxycheck.py`
- Test: `tests/test_api_checkers.py`

**Interfaces:**
- Consumes: `BaseChecker`
- Produces: `DNSBLChecker`, `AbuseIPDBChecker`, `ProxyCheckChecker`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_api_checkers.py`:
```python
import pytest
from unittest.mock import AsyncMock, patch
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker

@pytest.mark.asyncio
@patch('httpx.AsyncClient.get')
async def test_abuseipdb_checker(mock_get):
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 85,
            "ipAddress": "1.2.3.4"
        }
    }
    mock_get.return_value = mock_resp

    checker = AbuseIPDBChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.abuse_score == 85
    assert res.source == "abuseipdb"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_api_checkers.py`
Expected: FAIL (module not found)

- [ ] **Step 3: Implement DNSBL, AbuseIPDB, and ProxyCheck Checkers**

Create `proxyvet/core/checkers/dnsbl.py`:
```python
import dns.resolver
import asyncio
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class DNSBLChecker(BaseChecker):
    def __init__(self, lists: list[str] = None):
        self.lists = lists or ["zen.spamhaus.org", "dnsbl.sorbs.net"]

    @property
    def name(self) -> str:
        return "dnsbl"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def _query_list(self, reversed_ip: str, bl: str) -> bool:
        query = f"{reversed_ip}.{bl}"
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, dns.resolver.resolve, query, "A")
            return True
        except Exception:
            return False

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        parts = ip.split(".")
        if len(parts) != 4:
            return result
        reversed_ip = ".".join(reversed(parts))
        
        tasks = [self._query_list(reversed_ip, bl) for bl in self.lists]
        hits = await asyncio.gather(*tasks)
        result.dnsbl_hits = sum(1 for hit in hits if hit)
        return result
```

Create `proxyvet/core/checkers/abuseipdb.py`:
```python
import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class AbuseIPDBChecker(BaseChecker):
    def __init__(self, api_key: str):
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not self.api_key:
            return result
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result.abuse_score = float(data.get("abuseConfidenceScore", 0))
        except Exception:
            pass
        return result
```

Create `proxyvet/core/checkers/proxycheck.py`:
```python
import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData, ASNType

class ProxyCheckChecker(BaseChecker):
    def __init__(self, api_key: str):
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "proxycheck"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not self.api_key:
            return result
        url = f"https://proxycheck.io/v2/{ip}"
        params = {"key": self.api_key, "vpn": "1", "asn": "1"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json().get(ip, {})
                    result.is_proxy = data.get("proxy") == "yes"
                    result.is_vpn = data.get("vpn") == "yes"
                    result.asn = data.get("asn")
                    result.asn_org = data.get("provider")
                    
                    type_str = data.get("type", "").lower()
                    if "hosting" in type_str or "business" in type_str:
                        result.asn_type = ASNType.DATACENTER
                    elif "wireless" in type_str or "cellular" in type_str:
                        result.asn_type = ASNType.MOBILE
                    elif "residential" in type_str:
                        result.asn_type = ASNType.RESIDENTIAL
        except Exception:
            pass
        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_api_checkers.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/core/checkers/dnsbl.py proxyvet/core/checkers/abuseipdb.py proxyvet/core/checkers/proxycheck.py tests/test_api_checkers.py
git commit -m "feat: implement DNSBL, AbuseIPDB, and proxycheck.io checkers"
```

---

### Task 6: Verdict Engine

**Files:**
- Create: `proxyvet/core/engine.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: `proxyvet.core.models`, `proxyvet.core.cache`
- Produces: `VerdictEngine` with method:
  - `vet_ip(ip: str, force_refresh: bool = False) -> VerdictResult`: Vets an IP, checking cache first, running active checkers, scoring signals, performing drift detection, caching new entries, and appending to history.

- [ ] **Step 1: Write the failing test**

Create `tests/test_engine.py`:
```python
import pytest
from unittest.mock import AsyncMock
from datetime import datetime, timezone
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.models import Verdict, ASNType, IPSignalData

@pytest.mark.asyncio
async def test_engine_hard_gate_tor():
    # Setup mock config, cache, and checkers
    engine = VerdictEngine(settings=AsyncMock(), cache_mgr=AsyncMock(), checkers=[])
    
    # Mock checker output having Tor exit = True
    sig = IPSignalData(ip="1.1.1.1", is_tor=True, source="test")
    
    verdict_res = engine.evaluate_signals("1.1.1.1", [sig])
    assert verdict_res.verdict == Verdict.BURNED
    assert "Tor exit node detected" in verdict_res.reasons
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_engine.py`
Expected: FAIL (module/engine class not found)

- [ ] **Step 3: Implement the Gate-then-Score Verdict Engine**

Create `proxyvet/core/engine.py`:
```python
import asyncio
from datetime import datetime, timezone
from typing import List
from proxyvet.core.models import Verdict, VerdictResult, IPSignalData, ASNType
from proxyvet.core.cache import CacheManager
from proxyvet.core.config import Settings
from proxyvet.core.checkers.base import BaseChecker

class VerdictEngine:
    def __init__(self, settings: Settings, cache_mgr: CacheManager, checkers: List[BaseChecker]):
        self.settings = settings
        self.cache_mgr = cache_mgr
        self.checkers = checkers

    def evaluate_signals(self, ip: str, signals: List[IPSignalData]) -> VerdictResult:
        reasons = []
        is_burned = False
        
        # 1. Evaluate Hard Gates
        tor_hit = any(sig.is_tor for sig in signals if sig.is_tor is not None)
        if tor_hit:
            is_burned = True
            reasons.append("Tor exit node detected")

        proxy_vpn_sources = [sig.source for sig in signals if sig.is_proxy or sig.is_vpn]
        if len(proxy_vpn_sources) >= 2:
            is_burned = True
            reasons.append(f"Flagged as proxy/VPN by multiple sources: {', '.join(proxy_vpn_sources)}")

        dnsbl_hits = sum(sig.dnsbl_hits for sig in signals if sig.dnsbl_hits > 0)
        if dnsbl_hits >= 1:
            is_burned = True
            reasons.append(f"Listed on {dnsbl_hits} spam blocklist(s)")

        for sig in signals:
            if sig.abuse_score is not None and sig.abuse_score >= 90:
                is_burned = True
                reasons.append(f"Severe abuse score of {sig.abuse_score}% from {sig.source}")

        if is_burned:
            return VerdictResult(
                ip=ip,
                verdict=Verdict.BURNED,
                composite_score=100.0,
                reasons=reasons,
                signals=signals,
                checked_at=datetime.now(timezone.utc)
            )

        # 2. Evaluate Soft Score
        score = 0.0
        asn_types = [sig.asn_type for sig in signals if sig.asn_type != ASNType.UNKNOWN]
        
        if ASNType.DATACENTER in asn_types:
            score += 50.0
            reasons.append("Datacenter ASN detected (+50)")
        elif ASNType.BUSINESS in asn_types:
            score += 15.0
            reasons.append("Business ASN detected (+15)")
        elif ASNType.MOBILE in asn_types:
            score -= 10.0
            reasons.append("Mobile ASN trust bonus (-10)")

        # Single source proxy/VPN flag
        if len(proxy_vpn_sources) == 1:
            score += 30.0
            reasons.append(f"Suspicious: flagged as proxy/VPN by a single source ({proxy_vpn_sources[0]}) (+30)")

        # Abuse score contribution
        abuse_scores = [sig.abuse_score for sig in signals if sig.abuse_score is not None]
        if abuse_scores:
            max_abuse = max(abuse_scores)
            abuse_contrib = 0.4 * max_abuse
            if abuse_contrib > 0:
                score += abuse_contrib
                reasons.append(f"Abuse reputation contribution (+{abuse_contrib:.1f})")

        # Disagreement penalty
        if len(set(asn_types)) > 1:
            score += 10.0
            reasons.append("Source ASN classification mismatch (+10)")

        composite_score = max(0.0, min(100.0, score))
        
        if composite_score >= 60.0:
            verdict = Verdict.BURNED
        elif composite_score > 25.0:
            verdict = Verdict.CAUTION
        else:
            verdict = Verdict.CLEAN

        if not reasons:
            reasons.append("No suspicious flags raised")

        return VerdictResult(
            ip=ip,
            verdict=verdict,
            composite_score=composite_score,
            reasons=reasons,
            signals=signals,
            checked_at=datetime.now(timezone.utc)
        )

    async def vet_ip(self, ip: str, force_refresh: bool = False) -> VerdictResult:
        signals = []
        
        # Step A: Collect Signals (Check cache first unless forced)
        async def get_signal(checker: BaseChecker) -> IPSignalData:
            if not force_refresh:
                cached = self.cache_mgr.get_cached_signal(ip, checker.name, checker.cache_ttl_hours)
                if cached:
                    return cached
            fresh = await checker.check(ip)
            self.cache_mgr.save_cached_signal(fresh)
            return fresh

        tasks = [get_signal(c) for c in self.checkers]
        signals = list(await asyncio.gather(*tasks))

        # Step B: Evaluate Verdict
        result = self.evaluate_signals(ip, signals)

        # Step C: Load History & Check Drift
        history = self.cache_mgr.get_history(ip)
        if history:
            prev = history[0]
            result.previous_verdict = Verdict(prev["verdict"])
            result.previous_score = prev["composite_score"]
            if result.previous_verdict != result.verdict:
                result.drift_detected = True

        # Step D: Save History
        self.cache_mgr.save_history(result)
        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_engine.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/core/engine.py tests/test_engine.py
git commit -m "feat: implement gate-then-score engine and workflow integration"
```

---

### Task 7: Command Line Interface (CLI)

**Files:**
- Create: `proxyvet/cli/main.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `proxyvet.core.engine.VerdictEngine`, `proxyvet.core.config.get_settings`
- Produces: CLI interface exposing commands:
  - `check [IP]`: Vets a single IP address and formats as a table.
  - `batch [FILE]`: Vets multiple IPs in a text file and writes output table or JSON.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli.py`:
```python
from typer.testing import CliRunner
from proxyvet.cli.main import app

runner = CliRunner()

def test_cli_help():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    assert "vet" in res.stdout or "batch" in res.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_cli.py`
Expected: FAIL (module/app not found)

- [ ] **Step 3: Implement Typer CLI**

Create `proxyvet/cli/__init__.py` (empty)
Create `proxyvet/cli/main.py`:
```python
import typer
import asyncio
import os
from typing import Optional
from proxyvet.core.config import get_settings
from proxyvet.core.cache import CacheManager
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker

app = typer.Typer(help="ProxyVet - IP Quality Vetting Tool")

def get_engine() -> VerdictEngine:
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    cache_mgr.init_db()

    checkers = [
        MaxMindChecker(settings.maxmind_db_path),
        IP2ProxyChecker(settings.ip2proxy_db_path),
        DNSBLChecker(),
        AbuseIPDBChecker(settings.abuseipdb_api_key),
        ProxyCheckChecker(settings.proxycheck_api_key)
    ]
    return VerdictEngine(settings, cache_mgr, checkers)

@app.command()
def check(
    ip: str,
    force_refresh: bool = typer.Option(False, "--force", "-f", help="Bypass cache")
):
    """Vet a single IP address."""
    engine = get_engine()
    result = asyncio.run(engine.vet_ip(ip, force_refresh=force_refresh))
    
    typer.echo(f"=== ProxyVet Verdict for {ip} ===")
    typer.echo(f"Verdict:         {result.verdict.value}")
    typer.echo(f"Composite Score: {result.composite_score:.1f}/100.0")
    typer.echo("Reasons:")
    for r in result.reasons:
        typer.echo(f" - {r}")

    if result.drift_detected:
        typer.echo(f"\n[WARNING] Drift detected! Previous: {result.previous_verdict.value} ({result.previous_score:.1f})")

@app.command()
def batch(
    file_path: str = typer.Argument(..., help="Path to file containing IPs (one per line)"),
    force_refresh: bool = typer.Option(False, "--force", "-f", help="Bypass cache")
):
    """Vet a batch of IPs from a file."""
    if not os.path.exists(file_path):
        typer.echo(f"Error: File {file_path} not found.", err=True)
        raise typer.Exit(code=1)

    with open(file_path) as f:
        ips = [line.strip() for line in f if line.strip()]

    engine = get_engine()
    typer.echo(f"Vetting {len(ips)} IPs...")
    
    async def run_batch():
        tasks = [engine.vet_ip(ip, force_refresh=force_refresh) for ip in ips]
        return await asyncio.gather(*tasks)

    results = asyncio.run(run_batch())
    
    typer.echo("\nBatch Results Summary:")
    typer.echo(f"{'IP':<16} | {'Verdict':<8} | {'Score':<5}")
    typer.echo("-" * 35)
    for res in results:
        typer.echo(f"{res.ip:<16} | {res.verdict.value:<8} | {res.composite_score:>5.1f}")

if __name__ == "__main__":
    app()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_cli.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/cli/main.py tests/test_cli.py
git commit -m "feat: implement CLI commands with Typer"
```

---

### Task 8: Web API (FastAPI)

**Files:**
- Create: `proxyvet/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `proxyvet.core.engine.VerdictEngine`, `proxyvet.core.config.get_settings`
- Produces: REST API exposure for single IP check, batch checks, and IP check history.

- [ ] **Step 1: Write the failing test**

Create `tests/test_api.py`:
```python
from fastapi.testclient import TestClient
from proxyvet.api.main import app

client = TestClient(app)

def test_api_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_api.py`
Expected: FAIL (module/app not found)

- [ ] **Step 3: Implement FastAPI Application**

Create `proxyvet/api/__init__.py` (empty)
Create `proxyvet/api/main.py`:
```python
from fastapi import FastAPI, Path, Query, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
from proxyvet.core.config import get_settings
from proxyvet.core.cache import CacheManager
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.models import VerdictResult, Verdict
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker

app = FastAPI(title="ProxyVet API", version="0.1.0")

class BatchVettingRequest(BaseModel):
    ips: List[str]
    force_refresh: bool = False

def get_engine() -> VerdictEngine:
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    cache_mgr.init_db()

    checkers = [
        MaxMindChecker(settings.maxmind_db_path),
        IP2ProxyChecker(settings.ip2proxy_db_path),
        DNSBLChecker(),
        AbuseIPDBChecker(settings.abuseipdb_api_key),
        ProxyCheckChecker(settings.proxycheck_api_key)
    ]
    return VerdictEngine(settings, cache_mgr, checkers)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/api/v1/vet/{ip}", response_model=VerdictResult)
async def vet_ip(
    ip: str = Path(..., regex=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    force_refresh: bool = Query(False)
):
    engine = get_engine()
    try:
        result = await engine.vet_ip(ip, force_refresh=force_refresh)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/vet/batch", response_model=List[VerdictResult])
async def vet_batch(request: BatchVettingRequest):
    engine = get_engine()
    try:
        tasks = [engine.vet_ip(ip, force_refresh=request.force_refresh) for ip in request.ips]
        results = await asyncio.gather(*tasks)
        return list(results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/history/{ip}")
def get_ip_history(ip: str):
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    return cache_mgr.get_history(ip)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_api.py`
Expected: PASS

- [ ] **Step 5: Commit**

Run:
```bash
git add proxyvet/api/main.py tests/test_api.py
git commit -m "feat: implement API endpoints with FastAPI"
```
