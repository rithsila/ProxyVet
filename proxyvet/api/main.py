from fastapi import FastAPI, Path, Query, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import asyncio
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
    ip: str = Path(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
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
