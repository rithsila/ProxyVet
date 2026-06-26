import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class AbuseIPDBChecker(BaseChecker):
    def __init__(self, api_key: str, client: httpx.AsyncClient = None):
        self.api_key = api_key
        self.client = client

    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not self.api_key:
            raise ValueError("API key is missing for abuseipdb")
            
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        
        if self.client is not None:
            resp = await self.client.get(url, headers=headers, params=params)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=headers, params=params)
                
        resp.raise_for_status()
        data = resp.json().get("data", {})
        result.abuse_score = float(data.get("abuseConfidenceScore", 0))
        return result
