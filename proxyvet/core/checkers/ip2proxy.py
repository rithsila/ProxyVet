import os
import IP2Proxy
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class IP2ProxyChecker(BaseChecker):
    def __init__(self, db_path: str):
        self.db_path = db_path

    @property
    def name(self) -> str:
        return "ip2proxy"

    @property
    def cache_ttl_hours(self) -> int:
        return 168  # 7 days

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not os.path.exists(self.db_path):
            return result
        try:
            db = IP2Proxy.IP2Proxy()
            db.open(self.db_path)
            res = db.get_all(ip)
            if res:
                is_dc = res.get("usage_type") == "DCH"
                # If usage_type is DCH or proxy type matches common proxy flags
                is_proxy_flag = res.get("is_proxy") in [1, 2, "1", "2"]
                result.is_proxy = is_proxy_flag
                result.is_vpn = res.get("proxy_type") == "VPN"
                result.is_tor = res.get("proxy_type") == "TOR"
                result.is_datacenter = is_dc or res.get("proxy_type") == "DCH"
            db.close()
        except Exception:
            pass
        return result
