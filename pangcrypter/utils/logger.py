import logging
import os
from pathlib import Path
from typing import Optional


def _default_log_dir() -> Path:
    if os.name == "nt":
        base = os.getenv("APPDATA") or str(Path.home())
        return Path(base) / "PangCrypter" / "logs"
    if os.name == "darwin":
        return Path.home() / "Library" / "Application Support" / "PangCrypter" / "logs"
    return Path.home() / ".local" / "share" / "pangcrypter" / "logs"


def configure_logging(debug: bool, log_dir: Optional[Path] = None) -> logging.Logger:
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    if not debug:
        logger.addHandler(logging.NullHandler())
        return logger

    target_dir = log_dir or _default_log_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    log_file = target_dir / "pangcrypter.log"

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger