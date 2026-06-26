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
