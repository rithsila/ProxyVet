from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache

class Settings(BaseSettings):
    abuseipdb_api_key: str = ""
    proxycheck_api_key: str = ""
    vpnapi_api_key: str = ""
    ipqualityscore_api_key: str = ""
    maxmind_db_path: str = "data/GeoLite2-ASN.mmdb"
    ip2proxy_db_path: str = "data/IP2PROXY-LITE-PX1.BIN"
    sqlite_db_path: str = "proxyvet.db"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache()
def get_settings() -> Settings:
    return Settings()
