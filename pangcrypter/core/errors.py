class ValidationError(Exception):
    """Input validation failure."""


class CryptographyError(Exception):
    """Cryptography-related failure."""


class USBKeyError(Exception):
    """USB key operation failure."""


class DecryptionAuthError(ValueError):
    """Auth/tag decryption failure."""
