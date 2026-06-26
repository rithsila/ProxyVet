from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from datetime import datetime

class ASNType(str, Enum):
    RESIDENTIAL = "RESIDENTIAL"
    MOBILE = "MOBILE"
    BUSINESS = "BUSINESS"
    DATACENTER = "DATACENTER"
    UNKNOWN = "UNKNOWN"

class IPSignalData(BaseModel):
    ip: str
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    asn_type: ASNType = ASNType.UNKNOWN
    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_datacenter: Optional[bool] = None
    abuse_score: Optional[float] = None
    fraud_score: Optional[float] = None
    dnsbl_hits: int = 0
    source: str

class Verdict(str, Enum):
    CLEAN = "CLEAN"
    CAUTION = "CAUTION"
    BURNED = "BURNED"

class VerdictResult(BaseModel):
    ip: str
    verdict: Verdict
    composite_score: float
    reasons: List[str]
    signals: List[IPSignalData]
    checked_at: datetime
    previous_verdict: Optional[Verdict] = None
    previous_score: Optional[float] = None
    drift_detected: bool = False
