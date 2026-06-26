import httpx
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData, ASNType

class VPNAPIChecker(BaseChecker):
    def __init__(self, api_key: str, client: httpx.AsyncClient = None):
        self.api_key = api_key
        self.client = client

    @property
    def name(self) -> str:
        return "vpnapi"

    @property
    def cache_ttl_hours(self) -> int:
        return 24

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not self.api_key:
            raise ValueError("API key is missing for vpnapi")
            
        url = f"https://vpnapi.io/api/{ip}"
        params = {"key": self.api_key}
        
        if self.client is not None:
            resp = await self.client.get(url, params=params)
        else:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, params=params)
                
        resp.raise_for_status()
        data = resp.json()
        
        security = data.get("security", {})
        network = data.get("network", {})
        
        result.is_vpn = security.get("vpn")
        result.is_proxy = security.get("proxy")
        result.is_tor = security.get("tor")
        result.is_datacenter = security.get("relay")
        
        asn_val = network.get("asn")
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
                    
        result.asn_org = network.get("org")
        
        if result.asn_org:
            org_lower = result.asn_org.lower()
            if any(x in org_lower for x in ["hosting", "datacenter", "cloud", "server", "ovh", "digitalocean", "linode", "hetzner", "amazon", "google"]):
                result.asn_type = ASNType.DATACENTER
            elif any(x in org_lower for x in ["mobile", "wireless", "cellular"]):
                result.asn_type = ASNType.MOBILE
            elif "business" in org_lower:
                result.asn_type = ASNType.BUSINESS
            
        return result
