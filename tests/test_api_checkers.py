import pytest
import httpx
import dns.resolver
from unittest.mock import AsyncMock, patch, MagicMock
from proxyvet.core.checkers.abuseipdb import AbuseIPDBChecker
from proxyvet.core.checkers.proxycheck import ProxyCheckChecker
from proxyvet.core.checkers.dnsbl import DNSBLChecker
from proxyvet.core.checkers.stopforumspam import StopForumSpamChecker
from proxyvet.core.checkers.vpnapi import VPNAPIChecker
from proxyvet.core.checkers.ipqualityscore import IPQualityScoreChecker
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
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("403 Forbidden", request=MagicMock(), response=mock_resp)
    mock_get.return_value = mock_resp

    checker = AbuseIPDBChecker(api_key="mock_key")
    with pytest.raises(httpx.HTTPStatusError):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_abuseipdb_checker_exception(mock_get):
    mock_get.side_effect = Exception("Network failure")

    checker = AbuseIPDBChecker(api_key="mock_key")
    with pytest.raises(Exception, match="Network failure"):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
async def test_abuseipdb_checker_missing_key():
    checker = AbuseIPDBChecker(api_key="")
    with pytest.raises(ValueError, match="API key is missing"):
        await checker.check("1.2.3.4")


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
            "status": "ok",
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
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("500 Internal Server Error", request=MagicMock(), response=mock_resp)
    mock_get.return_value = mock_resp

    checker = ProxyCheckChecker(api_key="mock_key")
    with pytest.raises(httpx.HTTPStatusError):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_proxycheck_checker_exception(mock_get):
    mock_get.side_effect = Exception("API offline")

    checker = ProxyCheckChecker(api_key="mock_key")
    with pytest.raises(Exception, match="API offline"):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
async def test_proxycheck_checker_missing_key():
    checker = ProxyCheckChecker(api_key="")
    with pytest.raises(ValueError, match="API key is missing"):
        await checker.check("1.2.3.4")


@pytest.mark.anyio
@patch('dns.resolver.resolve')
async def test_dnsbl_checker_hits(mock_resolve):
    def side_effect(query, rdtype):
        if "zen.spamhaus.org" in query:
            mock_ans = MagicMock()
            mock_ans.__str__.return_value = "127.0.0.2"
            return [mock_ans]
        raise dns.resolver.NXDOMAIN()

    mock_resolve.side_effect = side_effect

    checker = DNSBLChecker(lists=["zen.spamhaus.org", "dnsbl.sorbs.net"])
    res = await checker.check("1.2.3.4")
    assert res.dnsbl_hits == 1
    assert res.source == "dnsbl"
    assert res.ip == "1.2.3.4"

@pytest.mark.anyio
@patch('dns.resolver.resolve')
async def test_dnsbl_checker_block_refusal(mock_resolve):
    def side_effect(query, rdtype):
        mock_ans = MagicMock()
        mock_ans.__str__.return_value = "127.255.255.2"
        return [mock_ans]

    mock_resolve.side_effect = side_effect
    checker = DNSBLChecker(lists=["zen.spamhaus.org"])
    res = await checker.check("1.2.3.4")
    assert res.dnsbl_hits == 0

@pytest.mark.anyio
@patch('dns.resolver.resolve')
async def test_dnsbl_checker_no_hits(mock_resolve):
    mock_resolve.side_effect = dns.resolver.NXDOMAIN()

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


@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_stopforumspam_success_appears(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": 1,
        "ip": {
            "appears": 1,
            "confidence": 85.5
        }
    }
    mock_get.return_value = mock_resp

    checker = StopForumSpamChecker()
    res = await checker.check("1.2.3.4")
    assert res.abuse_score == 85.5
    assert res.source == "stopforumspam"
    assert res.ip == "1.2.3.4"

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_stopforumspam_success_not_appears(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": 1,
        "ip": {
            "appears": 0,
            "confidence": 0.0
        }
    }
    mock_get.return_value = mock_resp

    checker = StopForumSpamChecker()
    res = await checker.check("1.2.3.4")
    assert res.abuse_score == 0.0
    assert res.source == "stopforumspam"

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_stopforumspam_non_200(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("400 Bad Request", request=MagicMock(), response=mock_resp)
    mock_get.return_value = mock_resp

    checker = StopForumSpamChecker()
    with pytest.raises(httpx.HTTPStatusError):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_stopforumspam_unsuccessful(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": 0
    }
    mock_get.return_value = mock_resp

    checker = StopForumSpamChecker()
    with pytest.raises(ValueError, match="StopForumSpam API call was unsuccessful"):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_vpnapi_checker_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "security": {
            "vpn": True,
            "proxy": False,
            "tor": False,
            "relay": False
        },
        "network": {
            "network": "1.2.3.0/24",
            "autonomous_system_number": "AS15169",
            "asn": "15169",
            "org": "Google LLC"
        }
    }
    mock_get.return_value = mock_resp

    checker = VPNAPIChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.is_vpn is True
    assert res.is_proxy is False
    assert res.is_tor is False
    assert res.is_datacenter is False
    assert res.asn == 15169
    assert res.asn_org == "Google LLC"
    assert res.asn_type == ASNType.DATACENTER
    assert res.source == "vpnapi"

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_vpnapi_checker_non_200(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("403 Forbidden", request=MagicMock(), response=mock_resp)
    mock_get.return_value = mock_resp

    checker = VPNAPIChecker(api_key="mock_key")
    with pytest.raises(httpx.HTTPStatusError):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
async def test_vpnapi_checker_missing_key():
    checker = VPNAPIChecker(api_key="")
    with pytest.raises(ValueError, match="API key is missing"):
        await checker.check("1.2.3.4")


@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_ipqs_checker_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "proxy": True,
        "vpn": False,
        "tor": False,
        "active_vpn": False,
        "active_tor": False,
        "fraud_score": 95,
        "ASN": 12345,
        "organization": "Proxy Provider"
    }
    mock_get.return_value = mock_resp

    checker = IPQualityScoreChecker(api_key="mock_key")
    res = await checker.check("1.2.3.4")
    assert res.is_proxy is True
    assert res.is_vpn is False
    assert res.is_datacenter is False
    assert res.abuse_score == 95.0
    assert res.asn == 12345
    assert res.asn_org == "Proxy Provider"
    assert res.source == "ipqualityscore"

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_ipqs_checker_unsuccessful(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": False,
        "message": "Invalid API Key"
    }
    mock_get.return_value = mock_resp

    checker = IPQualityScoreChecker(api_key="mock_key")
    with pytest.raises(ValueError, match="IPQualityScore API was unsuccessful: Invalid API Key"):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
@patch('httpx.AsyncClient.get')
async def test_ipqs_checker_non_200(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("500 Error", request=MagicMock(), response=mock_resp)
    mock_get.return_value = mock_resp

    checker = IPQualityScoreChecker(api_key="mock_key")
    with pytest.raises(httpx.HTTPStatusError):
        await checker.check("1.2.3.4")

@pytest.mark.anyio
async def test_ipqs_checker_missing_key():
    checker = IPQualityScoreChecker(api_key="")
    with pytest.raises(ValueError, match="API key is missing"):
        await checker.check("1.2.3.4")
