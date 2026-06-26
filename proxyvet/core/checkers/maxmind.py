import os
import asyncio
import geoip2.database
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData, ASNType

class MaxMindChecker(BaseChecker):
    def __init__(self, db_path: str):
        self.db_path = db_path

    @property
    def name(self) -> str:
        return "maxmind"

    @property
    def cache_ttl_hours(self) -> int:
        return 168  # 7 days

    def _infer_asn_type(self, org: str) -> ASNType:
        org_lower = org.lower()
        dc_keywords = ["hosting", "cloud", "datacenter", "m247", "digitalocean", "ovh", "server", "aws", "google", "linode", "hetzner"]
        mobile_keywords = ["mobile", "wireless", "telecom", "vodafone", "t-mobile", "orange", "verizon", "att", "sprint"]
        if any(kw in org_lower for kw in dc_keywords):
            return ASNType.DATACENTER
        if any(kw in org_lower for kw in mobile_keywords):
            return ASNType.MOBILE
        return ASNType.RESIDENTIAL

    def _run_lookup(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        if not os.path.exists(self.db_path):
            return result
        try:
            with geoip2.database.Reader(self.db_path) as reader:
                response = reader.asn(ip)
                result.asn = response.autonomous_system_number
                result.asn_org = response.autonomous_system_organization
                if result.asn_org:
                    result.asn_type = self._infer_asn_type(result.asn_org)
        except Exception:
            pass
        return result

    async def check(self, ip: str) -> IPSignalData:
        return await asyncio.to_thread(self._run_lookup, ip)

