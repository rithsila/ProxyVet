import os
from proxyvet.core.config import get_settings

def test_settings_load():
    get_settings.cache_clear()
    os.environ["ABUSEIPDB_API_KEY"] = "test_key_123"
    settings = get_settings()
    assert settings.abuseipdb_api_key == "test_key_123"
    assert settings.sqlite_db_path == "proxyvet.db"
