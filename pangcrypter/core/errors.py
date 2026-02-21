class ValidationError(Exception):
    """Input validation failure."""


class CryptographyError(Exception):
    """Cryptography-related failure."""


class USBKeyError(Exception):
    """USB key operation failure."""


try:
    from nacl.exceptions import CryptoError as NaClCryptoError
except (ImportError, OSError, RuntimeError, ValueError):
    class NaClCryptoError(Exception):
        """Fallback CryptoError type when PyNaCl is unavailable."""


class DecryptionAuthError(NaClCryptoError, ValueError):
    """Auth/tag decryption failure compatible with both CryptoError and ValueError handlers."""
