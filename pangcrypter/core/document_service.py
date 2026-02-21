from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING, Union

from uuid import UUID

if TYPE_CHECKING:
    from .encrypt import EncryptModeType


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

    def encrypt_file(
        self,
        input_bytes: bytes,
        output_path: str,
        mode: "EncryptModeType",
        uuid: UUID,
        password: Optional[Union[str, bytes, bytearray]] = None,
        usb_key: Optional[bytes] = None,
        content_mode: int = 0x00,
    ) -> None:
        return self._get_encrypt_api()["encrypt_file"](
            input_bytes=input_bytes,
            output_path=output_path,
            mode=mode,
            uuid=uuid,
            password=password,
            usb_key=usb_key,
            content_mode=content_mode,
        )

    def decrypt_file(
        self,
        input_path: str,
        password: Optional[Union[str, bytes, bytearray]] = None,
        usb_key: Optional[bytes] = None,
    ) -> bytes:
        return self._get_encrypt_api()["decrypt_file"](
            input_path=input_path,
            password=password,
            usb_key=usb_key,
        )

    def create_or_load_key(
        self,
        drive_name: str,
        path: str,
        uuid: Optional[UUID] = None,
        create: bool = True,
    ) -> tuple[Optional[bytes], Optional[UUID]]:
        if self._create_or_load_key is None:
            from .key import create_or_load_key
            self._create_or_load_key = create_or_load_key
        return self._create_or_load_key(
            drive_name=drive_name,
            path=path,
            uuid=uuid,
            create=create,
        )
