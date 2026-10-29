"""Fernet encryption for stored API keys, with on-disk key bootstrap."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class KeyVault:
    def __init__(self, key_file: Path) -> None:
        self._file = key_file
        self._fernet = Fernet(self._load_or_create())

    def _load_or_create(self) -> bytes:
        env = os.environ.get("MASTER_KEY")
        if env:
            return env.encode()
        if self._file.exists():
            return self._file.read_bytes().strip()
        key = Fernet.generate_key()
        self._file.parent.mkdir(parents=True, exist_ok=True)
        self._file.write_bytes(key)
        self._file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return key

    def encrypt(self, plain: str) -> bytes:
        return self._fernet.encrypt(plain.encode())

    def decrypt(self, blob: bytes) -> str:
        try:
            return self._fernet.decrypt(blob).decode()
        except InvalidToken:
            return ""
