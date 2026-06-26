import pytest
from datetime import datetime
from pydantic import ValidationError
from proxyvet.core.models import IPSignalData, ASNType, Verdict, VerdictResult
from proxyvet.core.checkers.base import BaseChecker

def test_ip_signal_data_validation():
    data = IPSignalData(
        ip="1.2.3.4",
        asn=1234,
        asn_org="Test ISP",
        asn_type=ASNType.RESIDENTIAL,
        source="test_source"
    )
    assert data.ip == "1.2.3.4"
    assert data.asn_type == "RESIDENTIAL"
    assert data.dnsbl_hits == 0  # Check default value
    assert data.is_proxy is None

def test_ip_signal_data_missing_required():
    with pytest.raises(ValidationError):
        # Missing required field 'source' and 'ip'
        IPSignalData()

def test_verdict_result_validation():
    signal = IPSignalData(
        ip="1.2.3.4",
        source="test_source"
    )
    now = datetime.now()
    result = VerdictResult(
        ip="1.2.3.4",
        verdict=Verdict.CLEAN,
        composite_score=0.1,
        reasons=["No bad signals found"],
        signals=[signal],
        checked_at=now
    )
    assert result.ip == "1.2.3.4"
    assert result.verdict == Verdict.CLEAN
    assert result.drift_detected is False  # Check default value
    assert result.checked_at == now

def test_base_checker_abstract():
    # Verify BaseChecker cannot be instantiated directly
    with pytest.raises(TypeError):
        BaseChecker()

    # Verify abstract methods/properties enforcement
    class DummyChecker(BaseChecker):
        pass

    with pytest.raises(TypeError):
        DummyChecker()

    # Valid subclass
    class ValidChecker(BaseChecker):
        @property
        def name(self) -> str:
            return "valid_checker"

        @property
        def cache_ttl_hours(self) -> int:
            return 24

        async def check(self, ip: str) -> IPSignalData:
            return IPSignalData(ip=ip, source=self.name)

    checker = ValidChecker()
    assert checker.name == "valid_checker"
    assert checker.cache_ttl_hours == 24
