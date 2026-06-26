import os
import asyncio
import threading
import geoip2.database
from proxyvet.core.checkers.base import BaseChecker
from proxyvet.core.models import IPSignalData, ASNType

import geoip2.errors

class MaxMindChecker(BaseChecker):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._reader = None
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return "maxmind"

    @property
    def cache_ttl_hours(self) -> int:
        return 168  # 7 days

    def _infer_asn_type(self, org: str) -> ASNType:
        org_lower = org.lower()
        dc_keywords = ["hosting", "cloud", "datacenter", "m247", "digitalocean", "ovh", "server", "aws", "google", "linode", "hetzner", "godaddy", "secureserver", "thunderbox"]
        mobile_keywords = ["mobile", "wireless", "telecom", "vodafone", "t-mobile", "orange", "verizon", "att", "sprint"]
        if any(kw in org_lower for kw in dc_keywords):
            return ASNType.DATACENTER
        if any(kw in org_lower for kw in mobile_keywords):
            return ASNType.MOBILE
        return ASNType.RESIDENTIAL

    def _get_reader(self) -> geoip2.database.Reader:
        if self._reader is None:
            with self._lock:
                if self._reader is None:
                    if not os.path.exists(self.db_path):
                        raise FileNotFoundError(f"MaxMind database file not found at: {self.db_path}")
                    self._reader = geoip2.database.Reader(self.db_path)
        return self._reader

    def close(self):
        with self._lock:
            if self._reader is not None:
                self._reader.close()
                self._reader = None

    def _run_lookup(self, ip: str) -> IPSignalData:
        result = IPSignalData(ip=ip, source=self.name)
        reader = self._get_reader()
        try:
            response = reader.asn(ip)
            result.asn = response.autonomous_system_number
            result.asn_org = response.autonomous_system_organization
            if result.asn_org:
                result.asn_type = self._infer_asn_type(result.asn_org)
        except geoip2.errors.AddressNotFoundError:
            pass
        return result

    async def check(self, ip: str) -> IPSignalData:
        return await asyncio.to_thread(self._run_lookup, ip)

