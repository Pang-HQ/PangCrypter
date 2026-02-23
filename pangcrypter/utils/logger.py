import logging
import os
import platform
from pathlib import Path
from typing import Optional


_DEFERRED_FILE_LOGGING: dict[str, object] = {
    "logger": None,
    "formatter": None,
    "log_file": None,
}


def _default_log_dir() -> Path:
    if os.name == "nt":
        base = os.getenv("APPDATA") or str(Path.home())
        return Path(base) / "PangCrypter" / "logs"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "PangCrypter" / "logs"
    return Path.home() / ".local" / "share" / "pangcrypter" / "logs"


def configure_logging(debug: bool, log_dir: Optional[Path] = None, defer_file_logging: bool = False) -> logging.Logger:
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if debug else logging.WARNING)

    target_dir = log_dir or _default_log_dir()
    log_file = target_dir / "pangcrypter.log"
    log_dir_ready = True

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir_ready = False

    if not debug:
        if not log_dir_ready:
            logger.addHandler(logging.NullHandler())
            return logger
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.WARNING)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    if defer_file_logging:
        _DEFERRED_FILE_LOGGING["logger"] = logger
        _DEFERRED_FILE_LOGGING["formatter"] = formatter
        _DEFERRED_FILE_LOGGING["log_file"] = log_file if log_dir_ready else None
        return logger

    if not log_dir_ready:
        return logger

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def enable_deferred_file_logging() -> None:
    logger = _DEFERRED_FILE_LOGGING.get("logger")
    formatter = _DEFERRED_FILE_LOGGING.get("formatter")
    log_file = _DEFERRED_FILE_LOGGING.get("log_file")
    if not isinstance(logger, logging.Logger) or not isinstance(formatter, logging.Formatter) or not isinstance(log_file, Path):
        return

    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            return

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)