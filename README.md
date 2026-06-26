# ProxyVet

> **Proxy IP quality checker.** Vets candidate proxy IPs across network-classification, anonymizer, and reputation signals to decide whether an IP is safe to front a Facebook business identity.

ProxyVet replaces slow, manual, multi-tab vetting workflows (IPHub, IPQS, VPNAPI, Scamalytics) with a single offline-first command or API call. It enforces quota discipline by running local database checks before hosted APIs, caches results to conserve API keys, and tracks reputation drift over time.

---

## Features

- **Gate-then-Score Engine**: 
  - **Hard-Fail Gates**: Instantly flags IPs as `BURNED` if they are known Tor exits, multi-source proxy/VPNs, blacklisted on DNSBLs, or exceed severe abuse thresholds (>=90%).
  - **Soft scoring**: Computes a composite risk score (0-100) based on ASN type (Datacenter, Mobile Carrier, Business, Residential), single-source warnings, mismatch flags, and abuse scores.
- **Offline-First Checking**: Queries local databases before spending metered API quotas.
- **SQLite Cache & History**: Caches lookup results with per-source TTL (7 days for classifications, 12 hours for reputations) and keeps a full historical record of checks to track reputation drift over time.
- **Dual Interfaces**: 
  - **CLI (Command Line Interface)**: Standard tabular outputs and machine-readable JSON flags.
  - **Web API (FastAPI Service)**: Fast, non-blocking asynchronous REST endpoints for remote tool integration.
- **Strict Validation**: Performs strict IPv4 format validation using Python's `ipaddress` to prevent malformed strings.
- **Concurrency & Thread Safety**: Uses thread locks and asynchronous runners to execute batch processes and SQLite queries safely.

---

## Directory Structure

```text
ProxyVet/
├── proxyvet/
│   ├── core/                # Core business logic (checkers, engine, cache)
│   │   ├── checkers/        # Signal source checkers
│   │   │   ├── base.py      # Abstract checker interface
│   │   │   ├── maxmind.py   # MaxMind GeoLite2 ASN Checker
│   │   │   ├── ip2proxy.py  # IP2Proxy LITE Database Checker
│   │   │   ├── dnsbl.py     # Multi-list DNSBL Resolver
│   │   │   ├── abuseipdb.py # AbuseIPDB check API
│   │   │   ├── proxycheck.py# proxycheck.io check API
│   │   │   └── stopforumspam.py # StopForumSpam check API
│   │   ├── models.py        # Pydantic schemas (Signals, VerdictResult)
│   │   ├── engine.py        # Scorer, hard gates & drift engine
│   │   ├── cache.py         # SQLite connection manager with WAL mode
│   │   └── config.py        # Dotenv settings loader
│   ├── cli/
│   │   └── main.py          # Typer CLI Entrypoint
│   └── api/
│       └── main.py          # FastAPI Server Entrypoint
├── data/                    # Directory for local database binaries
├── tests/                   # Pytest test suite
├── pyproject.toml           # Poetry/Pip project configuration
└── .env                     # Local configuration and API secrets
```

---

## Installation

Ensure you have Python 3.10+ installed.

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/rithsila/ProxyVet.git
   cd ProxyVet
   ```

2. **Activate your Virtual Environment**:
   * Windows:
     ```powershell
     .venv\Scripts\activate
     ```
   * Linux/macOS:
     ```bash
     source .venv/bin/activate
     ```

3. **Install dependencies in editable mode**:
   ```bash
   pip install -e .
   ```
   *This makes the `proxyvet` command globally active in your current shell.*

---

## Configuration & Local Databases

1. **Setup Secrets**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and insert your API keys:
   ```env
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   PROXYCHECK_API_KEY=your_proxycheck_api_key
   MAXMIND_DB_PATH=data/GeoLite2-ASN.mmdb
   IP2PROXY_DB_PATH=data/IP2PROXY-LITE-PX1.BIN
   SQLITE_DB_PATH=proxyvet.db
   ```

2. **Download Local Databases**:
   - **MaxMind GeoLite2 ASN**: Download the free binary `.mmdb` format from MaxMind (requires a free account) and save it as `data/GeoLite2-ASN.mmdb`.
   - **IP2Proxy LITE**: Download the free `PX1` or `PX11` BIN database from IP2Proxy (requires a free account) and save it as `data/IP2PROXY-LITE-PX1.BIN`.

---

## Usage Guide

### 1. Command Line Interface (CLI)

The CLI exposes `check` and `batch` commands.

*   **Vet a single IP address (Tabular table output)**:
    ```bash
    proxyvet check 208.66.73.11
    ```
*   **Vet a single IP and output as JSON**:
    ```bash
    proxyvet check 208.66.73.11 --json
    ```
*   **Bypass SQLite Cache (Force refresh)**:
    ```bash
    proxyvet check 208.66.73.11 --force
    ```
*   **Batch-check multiple IPs from a file**:
    Create a file (e.g., `ips.txt`) containing one IP address per line, then run:
    ```bash
    proxyvet batch ips.txt
    ```
*   **Batch-check and output list as JSON**:
    ```bash
    proxyvet batch ips.txt --json
    ```

---

### 2. Web API (FastAPI)

To run the web service:

```bash
uvicorn proxyvet.api.main:app --reload
```
The server will boot by default on `http://127.0.0.1:8000`.

#### REST Endpoints:

*   **GET `/health`**: Health status endpoint.
*   **GET `/api/v1/vet/{ip}`**: Checks a single IP. Supports `?force_refresh=true` query parameter.
*   **POST `/api/v1/vet/batch`**: Vets a batch of IPs concurrently.
    *   *Payload:* `{"ips": ["8.8.8.8", "1.1.1.1"], "force_refresh": false}`
*   **GET `/api/v1/history/{ip}`**: Returns all historical check results stored in the database for the given IP (useful for checking reputation drift).

---

## Development & Testing

We use `pytest` for the testing suite. To execute all unit and integration tests:

```bash
pytest
```
*Note: Make sure your current terminal is pointing to the root workspace directory so python pathing resolves correctly.*
