import os
import asyncio
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

    def _run_lookup(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not os.path.exists(self.db_path):
            return result
        db = IP2Proxy.IP2Proxy()
        try:
            db.open(self.db_path)
            res = db.get_all(ip)
            if res:
                is_proxy_val = res.get("is_proxy")
                if is_proxy_val in [1, 2, "1", "2"]:
                    result.is_proxy = True
                elif is_proxy_val in [0, "0"]:
                    result.is_proxy = False

                invalid_vals = {None, "-", "NOT SUPPORTED", "INVALID IP ADDRESS"}

                proxy_type_val = res.get("proxy_type")
                if proxy_type_val not in invalid_vals:
                    result.is_vpn = proxy_type_val == "VPN"
                    result.is_tor = proxy_type_val == "TOR"

                usage_type_val = res.get("usage_type")
                has_usage = usage_type_val not in invalid_vals
                has_proxy_type = proxy_type_val not in invalid_vals
                if has_usage or has_proxy_type:
                    is_dc = (usage_type_val == "DCH") if has_usage else False
                    is_proxy_dc = (proxy_type_val == "DCH") if has_proxy_type else False
                    result.is_datacenter = is_dc or is_proxy_dc
        except Exception:
            pass
        finally:
            db.close()
        return result

    async def check(self, ip: str) -> IPSignalData:
        return await asyncio.to_thread(self._run_lookup, ip)
