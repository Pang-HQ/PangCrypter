from __future__ import annotations

from typing import Optional, Protocol, TYPE_CHECKING, Union

from uuid import UUID

if TYPE_CHECKING:
    from .encrypt import EncryptModeType


class EncryptFileFn(Protocol):
    def __call__(
        self,
        input_bytes: bytes,
        output_path: str,
        mode: "EncryptModeType",
        uuid: UUID,
        password: Optional[Union[str, bytes, bytearray]] = None,
        usb_key: Optional[bytes] = None,
        content_mode: int = 0x00,
    ) -> None: ...


class DecryptFileFn(Protocol):
    def __call__(
        self,
        input_path: str,
        password: Optional[Union[str, bytes, bytearray]] = None,
        usb_key: Optional[bytes] = None,
    ) -> bytes: ...


class CreateOrLoadKeyFn(Protocol):
    def __call__(
        self,
        drive_name: str,
        path: str,
        uuid: Optional[UUID] = None,
        create: bool = True,
    ) -> tuple[Optional[bytes], Optional[UUID]]: ...


class DocumentService:
    def __init__(self):
        self._encrypt_file: Optional[EncryptFileFn] = None
        self._decrypt_file: Optional[DecryptFileFn] = None
        self._encrypt_mode_type: Optional[type["EncryptModeType"]] = None
        self._create_or_load_key: Optional[CreateOrLoadKeyFn] = None

    def _ensure_encrypt_api(self) -> None:
        if self._encrypt_file is not None and self._decrypt_file is not None and self._encrypt_mode_type is not None:
            return
        from .encrypt import EncryptModeType, decrypt_file, encrypt_file

        self._encrypt_file = encrypt_file
        self._decrypt_file = decrypt_file
        self._encrypt_mode_type = EncryptModeType

    def get_encrypt_mode_type(self) -> type["EncryptModeType"]:
        self._ensure_encrypt_api()
        assert self._encrypt_mode_type is not None
        return self._encrypt_mode_type

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
        self._ensure_encrypt_api()
        assert self._encrypt_file is not None
        return self._encrypt_file(
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
        self._ensure_encrypt_api()
        assert self._decrypt_file is not None
        return self._decrypt_file(
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
