import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData, ASNType

class ProxyCheckChecker(BaseChecker):
    def __init__(self, api_key: str, client: httpx.AsyncClient = None):
        self.api_key = api_key
        self.client = client

    @property
    def name(self) -> str:
        return "proxycheck"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not self.api_key:
            raise ValueError("API key is missing for proxycheck")
            
        url = f"https://proxycheck.io/v2/{ip}"
        params = {"key": self.api_key, "vpn": "1", "asn": "1"}
        
        if self.client is not None:
            resp = await self.client.get(url, params=params)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, params=params)
                
        resp.raise_for_status()
        resp_json = resp.json()
        
        status = resp_json.get("status")
        if status != "ok":
            raise ValueError(f"proxycheck API returned status: {status}")
            
        if ip not in resp_json:
            raise ValueError(f"IP {ip} not found in proxycheck API response")
            
        data = resp_json[ip]
        result.is_proxy = data.get("proxy") == "yes"
        result.is_vpn = data.get("vpn") == "yes"
        asn_val = data.get("asn")
        if asn_val is not None:
            if isinstance(asn_val, str) and asn_val.upper().startswith("AS"):
                try:
                    result.asn = int(asn_val[2:])
                except ValueError:
                    pass
            else:
                try:
                    result.asn = int(asn_val)
                except ValueError:
                    pass
        result.asn_org = data.get("provider")
        
        type_str = data.get("type", "").lower()
        if "hosting" in type_str or "business" in type_str:
            result.asn_type = ASNType.DATACENTER
        elif "wireless" in type_str or "cellular" in type_str:
            result.asn_type = ASNType.MOBILE
        elif "residential" in type_str:
            result.asn_type = ASNType.RESIDENTIAL
        return result
