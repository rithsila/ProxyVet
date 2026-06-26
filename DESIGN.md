# DESIGN.md — ProxyVet Design Specification

This document details the architectural layout, data models, signal normalization rules, scoring engine, caching system, and Web API spec for the ProxyVet application.

---

## 1. Directory Structure

```text
ProxyVet/
├── .vscode/
│   └── settings.json
├── proxyvet/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── checkers/
│   │   │   ├── __init__.py
│   │   │   ├── base.py
│   │   │   ├── maxmind.py
│   │   │   ├── ip2proxy.py
│   │   │   ├── dnsbl.py
│   │   │   ├── proxycheck.py
│   │   │   ├── abuseipdb.py
│   │   │   └── stopforumspam.py
│   │   ├── models.py        # Pydantic schemas (Normalized IP data, Verdict)
│   │   ├── engine.py        # Gate-then-score verdict logic
│   │   ├── cache.py         # SQLite / SQLAlchemy caching backend
│   │   └── config.py        # Configuration manager (settings & secrets)
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py          # CLI entrypoint
│   └── api/
│       ├── __init__.py
│       └── main.py          # FastAPI web application entrypoint
├── data/                    # Bundled local database files
│   ├── README.md            # Setup guidelines
│   ├── GeoLite2-ASN.mmdb
│   └── IP2PROXY-LITE-PX1.BIN
├── tests/                   # Testing suite
│   ├── conftest.py
│   ├── test_engine.py
│   └── test_checkers.py
├── pyproject.toml           # Poetry/uv packaging config
├── .gitignore
├── README.md
└── PRD.md
```

---

## 2. Technology Stack & Dependencies

- **Language**: Python 3.10+
- **Web API**: FastAPI + Uvicorn
- **CLI Framework**: Typer (or argparse)
- **Database / Caching**: SQLite (using built-in `sqlite3` or `SQLAlchemy`)
- **Key Libraries**:
  - `geoip2`: Official MaxMind GeoIP2 library
  - `ip2proxy-py`: Official IP2Proxy library
  - `pydantic`: For data validation and settings schemas
  - `httpx`: Async HTTP client for hosted APIs (AbuseIPDB, proxycheck.io, StopForumSpam)
  - `dnspython`: For low-latency DNSBL queries

---

## 3. Data Schema & Normalization

All checkers must return data conforming to the `IPSignalData` model.

### 3.1 Pydantic Models

```python
from pydantic import BaseModel, Field
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
    abuse_score: Optional[float] = None  # 0.0 to 100.0
    fraud_score: Optional[float] = None  # 0.0 to 100.0
    dnsbl_hits: int = 0                  # Count of blocklist hits
    source: str                          # Name of the source providing this signal
```

### 3.2 Verdict Output Schema

```python
class Verdict(str, Enum):
    CLEAN = "CLEAN"
    CAUTION = "CAUTION"
    BURNED = "BURNED"

class VerdictResult(BaseModel):
    ip: str
    verdict: Verdict
    composite_score: float               # 0.0 to 100.0
    reasons: List[str]
    signals: List[IPSignalData]
    checked_at: datetime
    previous_verdict: Optional[Verdict] = None
    previous_score: Optional[float] = None
    drift_detected: bool = False
```

---

## 4. Signal Normalization Mapping

| Source | Target Field | Mapping Logic |
|---|---|---|
| **MaxMind GeoLite2 ASN** | `asn`, `asn_org`, `asn_type` | Extracts ASN and organization name. Categorizes `asn_type` as `DATACENTER` if `asn_org` matches hosting keywords, `MOBILE` if it matches mobile carriers, or `RESIDENTIAL` otherwise. |
| **IP2Proxy LITE** | `is_proxy`, `is_vpn`, `is_tor`, `is_datacenter` | Maps boolean flags directly from local `.bin` results. |
| **AbuseIPDB** | `abuse_score` | Maps 1-to-1 to `abuseConfidenceScore` from the JSON payload. |
| **proxycheck.io** | `is_proxy`, `is_vpn`, `asn`, `asn_org`, `asn_type` | Inspects `type` field (e.g., "VPN", "Proxy", "Business") to map boolean flags and ASN categories. |
| **StopForumSpam** | `abuse_score` | Normalizes confidence based on frequency/recency of spam hits. |
| **DNSBLs** | `dnsbl_hits` | Executes parallel reverse-domain queries (e.g., `<reversed-ip>.zen.spamhaus.org`). Increments count for positive responses. |

---

## 5. Gate-then-Score Verdict Engine

### 5.1 Step 1: Hard-Fail Gates
If any of these conditions are met, the IP is instantly marked **`BURNED`** with a composite score of `100.0`, and further scoring is skipped:
1. `is_tor` is `True` on *any* source.
2. `is_proxy` or `is_vpn` is `True` on **$\ge 2$** independent sources.
3. `abuse_score` $\ge 90$ from a verified reputation source (e.g., AbuseIPDB).
4. `dnsbl_hits` $\ge 1$ (Listed on primary DNSBLs like Spamhaus ZEN).
5. `fraud_score` $\ge 80$ (when IPQS is enabled).

### 5.2 Step 2: Soft Score Formula
If no hard-fail gates fire, we compute the score:
$$S_{\text{ASN}} = \begin{cases} 50 & \text{if } \text{ASNType} = \text{DATACENTER} \\ 15 & \text{if } \text{ASNType} = \text{BUSINESS} \\ 0 & \text{if } \text{ASNType} = \text{RESIDENTIAL} \\ -10 & \text{if } \text{ASNType} = \text{MOBILE} \end{cases}$$

$$S_{\text{Flags}} = \begin{cases} 30 & \text{if exactly one source flags } is\_proxy \text{ or } is\_vpn \\ 0 & \text{otherwise} \end{cases}$$

$$S_{\text{Abuse}} = 0.4 \times \max(0, \text{Abuse Scores})$$

$$S_{\text{Disagreement}} = \begin{cases} 10 & \text{if sources disagree on ASN classification or proxy status} \\ 0 & \text{otherwise} \end{cases}$$

$$\text{Composite Score} = \max(0.0, \min(100.0, S_{\text{ASN}} + S_{\text{Flags}} + S_{\text{Abuse}} + S_{\text{Disagreement}}))$$

### 5.3 Step 3: Verdict Bands
- **`CLEAN`**: Composite Score $\le 25.0$
- **`CAUTION`**: $25.0 <$ Composite Score $< 60.0$
- **`BURNED`**: Composite Score $\ge 60.0$

---

## 6. Caching & History (SQLite)

We use SQLite for local storage.

### 6.1 Database Schema
```sql
CREATE TABLE cache (
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    data TEXT NOT NULL,           -- JSON representation of IPSignalData
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (ip, source)
);

CREATE TABLE history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    verdict TEXT NOT NULL,
    composite_score REAL NOT NULL,
    reasons TEXT NOT NULL,        -- JSON array of strings
    signals TEXT NOT NULL,        -- JSON list of IPSignalData
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 6.2 TTL Expiry
- Offline Databases (MaxMind, IP2Proxy): **7 days** (168 hours).
- Hosted APIs (AbuseIPDB, proxycheck.io, StopForumSpam, DNSBL): **12 hours**.

---

## 7. Web API Specification

FastAPI will expose the following endpoints:

### 7.1 GET `/api/v1/vet/{ip}`
Vets a single IP address.
- **Query Params**:
  - `force_refresh` (bool, default `false`): Bypasses the cache and queries external APIs.
- **Response**: `VerdictResult` JSON object.

### 7.2 POST `/api/v1/vet/batch`
Vets multiple IP addresses.
- **Request Body**:
  ```json
  {
    "ips": ["1.1.1.1", "8.8.8.8"],
    "force_refresh": false
  }
  ```
- **Response**: List of `VerdictResult` objects.

### 7.3 GET `/api/v1/history/{ip}`
Returns the check history for a specific IP address to see reputation drift.
- **Response**: List of historical checks sorted by timestamp descending.
