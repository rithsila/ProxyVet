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
