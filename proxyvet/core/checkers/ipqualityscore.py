import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class IPQualityScoreChecker(BaseChecker):
    def __init__(self, api_key: str, client: httpx.AsyncClient = None):
        self.api_key = api_key
        self.client = client

    @property
    def name(self) -> str:
        return "ipqualityscore"

    @property
    def cache_ttl_hours(self) -> int:
        return 24

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not self.api_key:
            raise ValueError("API key is missing for ipqualityscore")
            
        url = f"https://ipqualityscore.com/api/json/ip/{self.api_key}/{ip}"
        
        if self.client is not None:
            resp = await self.client.get(url)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                
        resp.raise_for_status()
        data = resp.json()
        
        if not data.get("success"):
            message = data.get("message", "Unknown error")
            raise ValueError(f"IPQualityScore API was unsuccessful: {message}")
            
        result.is_vpn = data.get("vpn")
        result.is_proxy = data.get("proxy")
        result.is_tor = data.get("tor")
        result.is_datacenter = data.get("active_vpn") or data.get("active_tor")
        
        if data.get("fraud_score") is not None:
            try:
                result.abuse_score = float(data.get("fraud_score"))
            except ValueError:
                pass
        
        asn_val = data.get("ASN")
        if asn_val is not None:
            try:
                result.asn = int(asn_val)
            except ValueError:
                pass
                
        result.asn_org = data.get("organization")
        
        return result
