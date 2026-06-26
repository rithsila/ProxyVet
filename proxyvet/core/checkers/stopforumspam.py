import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class StopForumSpamChecker(BaseChecker):
    def __init__(self, client: httpx.AsyncClient = None):
        self.client = client

    @property
    def name(self) -> str:
        return "stopforumspam"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        url = f"https://api.stopforumspam.org/api?ip={ip}&json"
        
        if self.client is not None:
            resp = await self.client.get(url)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
                
        resp.raise_for_status()
        resp_json = resp.json()
        
        # SFS API might return success as a truthy value (e.g. 1 or true)
        if not resp_json.get("success"):
            raise ValueError("StopForumSpam API call was unsuccessful")
            
        ip_data = resp_json.get("ip", {})
        if ip_data.get("appears"):
            result.abuse_score = float(ip_data.get("confidence", 0.0))
        else:
            result.abuse_score = 0.0
            
        return result
