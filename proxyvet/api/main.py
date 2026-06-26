from fastapi import FastAPI, Path, Query, HTTPException
from pydantic import BaseModel, field_validator
from typing import List, Optional
from datetime import datetime, timezone
import asyncio
import httpx
import re
import ipaddress
from contextlib import asynccontextmanager

from proxyvet.core.config import get_settings
from proxyvet.core.cache import CacheManager
from proxyvet.core.engine import VerdictEngine
from proxyvet.core.models import VerdictResult, Verdict
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker
from proxyvet.core.checkers.stopforumspam import StopForumSpamChecker

IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

class BatchVettingRequest(BaseModel):
    ips: List[str]
    force_refresh: bool = False

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, v):
        for ip in v:
            try:
                ipaddress.IPv4Address(ip)
            except ipaddress.AddressValueError:
                raise ValueError(f"Invalid IP address format: {ip}")
        return v

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    client = httpx.AsyncClient(timeout=10.0)
    app.state.http_client = client
    
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    cache_mgr.init_db()
    
    app.state.maxmind_checker = MaxMindChecker(settings.maxmind_db_path)
    app.state.ip2proxy_checker = IP2ProxyChecker(settings.ip2proxy_db_path)
    
    checkers = [
        app.state.maxmind_checker,
        app.state.ip2proxy_checker,
        DNSBLChecker(),
        AbuseIPDBChecker(settings.abuseipdb_api_key, client=client),
        ProxyCheckChecker(settings.proxycheck_api_key, client=client),
        StopForumSpamChecker(client=client)
    ]
    app.state.engine = VerdictEngine(settings, cache_mgr, checkers)
    
    yield
    
    # Shutdown
    try:
        app.state.maxmind_checker.close()
    except Exception:
        pass
    try:
        app.state.ip2proxy_checker.close()
    except Exception:
        pass
    try:
        await client.aclose()
    except Exception:
        pass

app = FastAPI(title="ProxyVet API", version="0.1.0", lifespan=lifespan)

def get_engine() -> VerdictEngine:
    try:
        return app.state.engine
    except AttributeError:
        settings = get_settings()
        cache_mgr = CacheManager(settings.sqlite_db_path)
        checkers = [
            MaxMindChecker(settings.maxmind_db_path),
            IP2ProxyChecker(settings.ip2proxy_db_path),
            DNSBLChecker(),
            AbuseIPDBChecker(settings.abuseipdb_api_key),
            ProxyCheckChecker(settings.proxycheck_api_key),
            StopForumSpamChecker()
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
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
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
def get_ip_history(
    ip: str = Path(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
):
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    settings = get_settings()
    cache_mgr = CacheManager(settings.sqlite_db_path)
    return cache_mgr.get_history(ip)
