import logging

from pangcrypter.utils.logger import configure_logging


def test_configure_logging_non_debug_writes_warning_file(tmp_path):
    logger = configure_logging(False, log_dir=tmp_path)
    logger.warning("warning-from-test")

    log_file = tmp_path / "pangcrypter.log"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "warning-from-test" in content

    # keep root logger clean for other tests
    logging.getLogger().handlers.clear()
