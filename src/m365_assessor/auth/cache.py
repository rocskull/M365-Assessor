from __future__ import annotations

import logging
from dataclasses import dataclass, field

import keyring
from keyring.errors import KeyringError

logger = logging.getLogger(__name__)


@dataclass
class SecureTokenCacheStore:
    service_name: str = "m365-assessor"
    account_name: str = "msal-cache"
    _memory_cache: str = field(default="", init=False, repr=False)

    def load(self) -> str:
        try:
            return keyring.get_password(self.service_name, self.account_name) or self._memory_cache
        except KeyringError:
            logger.warning("OS keyring unavailable; token cache is memory-only")
            return self._memory_cache

    def save(self, serialized_cache: str) -> None:
        self._memory_cache = serialized_cache
        try:
            keyring.set_password(self.service_name, self.account_name, serialized_cache)
        except KeyringError:
            logger.warning("OS keyring unavailable; token cache was not persisted")

    def clear(self) -> None:
        self._memory_cache = ""
        try:
            keyring.delete_password(self.service_name, self.account_name)
        except KeyringError:
            logger.info("No persistent token cache was available to clear")
