import pytest
from unittest.mock import MagicMock, patch
from proxyvet.core.checkers.maxmind import MaxMindChecker
from proxyvet.core.checkers.ip2proxy import IP2ProxyChecker

@pytest.mark.anyio
@patch('geoip2.database.Reader')
async def test_maxmind_checker(mock_reader):
    mock_inst = MagicMock()
    mock_inst.__enter__.return_value = mock_inst
    mock_inst.asn.return_value = MagicMock(autonomous_system_number=15169, autonomous_system_organization="Google LLC")
    mock_reader.return_value = mock_inst

    # We mock os.path.exists to return True so it enters the try block
    with patch('os.path.exists', return_value=True):
        checker = MaxMindChecker(db_path="dummy.mmdb")
        res = await checker.check("8.8.8.8")
        assert res.asn == 15169
        assert res.asn_org == "Google LLC"
        assert res.asn_type == "DATACENTER" # Inferred from "Google"

@pytest.mark.anyio
@patch('IP2Proxy.IP2Proxy')
async def test_ip2proxy_checker(mock_ip2proxy_class):
    mock_inst = MagicMock()
    mock_inst.get_all.return_value = {
        "usage_type": "DCH",
        "is_proxy": 1,
        "proxy_type": "VPN"
    }
    mock_ip2proxy_class.return_value = mock_inst

    with patch('os.path.exists', return_value=True):
        checker = IP2ProxyChecker(db_path="dummy.bin")
        res = await checker.check("8.8.8.8")
        assert res.is_proxy is True
        assert res.is_vpn is True
        assert res.is_tor is False
        assert res.is_datacenter is True
