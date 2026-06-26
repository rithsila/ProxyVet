import pytest
from unittest.mock import patch, MagicMock
import httpx
from proxyvet.core.alerting import TelegramAlerter

@pytest.mark.anyio
@patch('httpx.AsyncClient.post')
async def test_telegram_alerter_success(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    alerter = TelegramAlerter(bot_token="test_token", chat_id="test_chat")
    await alerter.send_alert("Test message")

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert "bottest_token" in args[0]
    assert kwargs["json"]["chat_id"] == "test_chat"
    assert kwargs["json"]["text"] == "Test message"
    assert kwargs["json"]["parse_mode"] == "HTML"

@pytest.mark.anyio
@patch('httpx.AsyncClient.post')
async def test_telegram_alerter_missing_config(mock_post):
    alerter = TelegramAlerter(bot_token="", chat_id="test_chat")
    await alerter.send_alert("Test message")
    mock_post.assert_not_called()

    alerter2 = TelegramAlerter(bot_token="token", chat_id="")
    await alerter2.send_alert("Test message")
    mock_post.assert_not_called()

@pytest.mark.anyio
@patch('httpx.AsyncClient.post')
async def test_telegram_alerter_http_error(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError("403 Forbidden", request=MagicMock(), response=mock_resp)
    mock_post.return_value = mock_resp

    alerter = TelegramAlerter(bot_token="test_token", chat_id="test_chat")
    with pytest.raises(httpx.HTTPStatusError):
        await alerter.send_alert("Test message")
