from abc import ABC, abstractmethod
from proxyvet.core.models import IPSignalData

class BaseChecker(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def cache_ttl_hours(self) -> int:
        pass

    @abstractmethod
    async def check(self, ip: str) -> IPSignalData:
        pass
