from __future__ import annotations


def mode_uses_password(mode, EncryptModeType) -> bool:
    return mode in [EncryptModeType.MODE_PASSWORD_ONLY, EncryptModeType.MODE_PASSWORD_PLUS_KEY]


def mode_uses_usb(mode, EncryptModeType) -> bool:
    return mode in [EncryptModeType.MODE_PASSWORD_PLUS_KEY, EncryptModeType.MODE_KEY_ONLY]
