import dns.resolver
import asyncio
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData

class DNSBLChecker(BaseChecker):
    def __init__(self, lists: list[str] = None):
        self.lists = lists or ["zen.spamhaus.org", "dnsbl.sorbs.net"]

    @property
    def name(self) -> str:
        return "dnsbl"

    @property
    def cache_ttl_hours(self) -> int:
        return 12  # 12 hours

    async def _query_list(self, reversed_ip: str, bl: str) -> bool:
        query = f"{reversed_ip}.{bl}"
        try:
            loop = asyncio.get_running_loop()
            answers = await loop.run_in_executor(None, dns.resolver.resolve, query, "A")
            for rdata in answers:
                ip_str = str(rdata)
                if ip_str.startswith("127.255.255."):
                    return False
                if ip_str.startswith("127.0.0."):
                    return True
            return False
        except Exception:
            return False

    async def check(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        parts = ip.split(".")
        if len(parts) != 4:
            return result
        reversed_ip = ".".join(reversed(parts))
        
        tasks = [self._query_list(reversed_ip, bl) for bl in self.lists]
        hits = await asyncio.gather(*tasks)
        result.dnsbl_hits = sum(1 for hit in hits if hit)
        return result
