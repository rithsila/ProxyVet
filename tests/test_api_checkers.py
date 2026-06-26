import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.models import ASNType

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_abuseipdb_checker_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 85,
            "ipAddress": "1.2.3.4"
        }
    }
    mock_get.return_value = mock_resp

    checker = AbuseIPDBChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.abuse_score == 85.0
    assert res.source == "abuseipdb"
    assert res.ip == "1.2.3.4"

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_abuseipdb_checker_non_200(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_get.return_value = mock_resp

    checker = AbuseIPDBChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.abuse_score is None
    assert res.source == "abuseipdb"

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_abuseipdb_checker_exception(mock_get):
    mock_get.side_effect = Exception("Network failure")

    checker = AbuseIPDBChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.abuse_score is None
    assert res.source == "abuseipdb"

@pytest.mark.anyio
async def test_abuseipdb_checker_missing_key():
    checker = AbuseIPDBChecker(api_key="")
    res = await checker.check("1.2.3.4")
    assert res.abuse_score is None
    assert res.source == "abuseipdb"


@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_proxycheck_checker_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "ok",
        "1.2.3.4": {
            "asn": 15169,
            "provider": "Google LLC",
            "vpn": "yes",
            "proxy": "no",
            "type": "Business"
        }
    }
    mock_get.return_value = mock_resp

    checker = ProxyCheckChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.is_proxy is False
    assert res.is_vpn is True
    assert res.asn == 15169
    assert res.asn_org == "Google LLC"
    assert res.asn_type == ASNType.DATACENTER

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_proxycheck_checker_types(mock_get):
    types_mapping = [
        ("Hosting", ASNType.DATACENTER),
        ("business", ASNType.DATACENTER),
        ("wireless", ASNType.MOBILE),
        ("Cellular", ASNType.MOBILE),
        ("Residential", ASNType.RESIDENTIAL),
        ("unknown_type", ASNType.UNKNOWN)
    ]
    for type_str, expected_type in types_mapping:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "1.2.3.4": {
                "type": type_str,
                "proxy": "yes",
                "vpn": "no"
            }
        }
        mock_get.return_value = mock_resp

        checker = ProxyCheckChecker(api_key="mock_key")
        res = await checker.check("1.2.3.4")
        assert res.asn_type == expected_type
        assert res.is_proxy is True
        assert res.is_vpn is False

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_proxycheck_checker_non_200(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_get.return_value = mock_resp

    checker = ProxyCheckChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.is_proxy is None

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_proxycheck_checker_exception(mock_get):
    mock_get.side_effect = Exception("API offline")

    checker = ProxyCheckChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.is_proxy is None

@pytest.mark.anyio
async def test_proxycheck_checker_missing_key():
    checker = ProxyCheckChecker(api_key="")
    res = await checker.check("1.2.3.4")
    assert res.is_proxy is None


@pytest.mark.anyio
@patch('dns.resolver.resolve')
async def test_dnsbl_checker_hits(mock_resolve):
    # Mock dns.resolver.resolve to succeed for zen.spamhaus.org but fail for dnsbl.sorbs.net
    def side_effect(query, rdtype):
        if "zen.spamhaus.org" in query:
            return [MagicMock()]
        raise Exception("NXDOMAIN")

    mock_resolve.side_effect = side_effect

    checker = DNSBLChecker(lists=["zen.spamhaus.org", "dnsbl.sorbs.net"])
    res = await checker.check("1.2.3.4")
    assert res.dnsbl_hits == 1
    assert res.source == "dnsbl"
    assert res.ip == "1.2.3.4"

@pytest.mark.anyio
@patch('dns.resolver.resolve')
async def test_dnsbl_checker_no_hits(mock_resolve):
    mock_resolve.side_effect = Exception("NXDOMAIN")

    checker = DNSBLChecker()
    res = await checker.check("1.2.3.4")
    assert res.dnsbl_hits == 0

@pytest.mark.anyio
async def test_dnsbl_checker_invalid_ip():
    checker = DNSBLChecker()
    res = await checker.check("not-an-ip")
    assert res.dnsbl_hits == 0

    res2 = await checker.check("1.2.3")
    assert res2.dnsbl_hits == 0

    res3 = await checker.check("1.2.3.4.5")
    assert res3.dnsbl_hits == 0
