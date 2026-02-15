from __future__ import annotations

from typing import Any, Optional


class DocumentService:
    def __init__(self):
        self._encrypt_api: dict[str, Any] = {}
        self._create_or_load_key = None

    def _get_encrypt_api(self) -> dict[str, Any]:
        if not self._encrypt_api:
            from .encrypt import encrypt_file, decrypt_file, EncryptModeType
            self._encrypt_api = {
                "encrypt_file": encrypt_file,
                "decrypt_file": decrypt_file,
                "EncryptModeType": EncryptModeType,
            }
        return self._encrypt_api

    def get_encrypt_mode_type(self):
        return self._get_encrypt_api()["EncryptModeType"]

    def encrypt_file(self, *args, **kwargs):
        return self._get_encrypt_api()["encrypt_file"](*args, **kwargs)

    def decrypt_file(self, *args, **kwargs):
        return self._get_encrypt_api()["decrypt_file"](*args, **kwargs)

    def create_or_load_key(self, *args, **kwargs):
        if self._create_or_load_key is None:
            from .key import create_or_load_key
            self._create_or_load_key = create_or_load_key
        return self._create_or_load_key(*args, **kwargs)
