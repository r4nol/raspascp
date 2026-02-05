import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path


_DEFAULT_SKIP_KEYS = {
    "args",
    "msg",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
}


class JsonLogFormatter(logging.Formatter):
    """Simple JSON formatter for app logs."""

    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key in _DEFAULT_SKIP_KEYS:
                continue
            if key in log_record:
                continue
            try:
                json.dumps(value)
                log_record[key] = value
            except TypeError:
                log_record[key] = str(value)

        return json.dumps(log_record)


class SecurityJSONFormatter(logging.Formatter):
    """JSON formatter for security events (SIEM-friendly)."""

    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
        }

        if hasattr(record, "security_event"):
            log_data.update(record.security_event)
        else:
            log_data["message"] = record.getMessage()

        for key, value in record.__dict__.items():
            if key in _DEFAULT_SKIP_KEYS or key in log_data:
                continue
            try:
                json.dumps(value)
                log_data[key] = value
            except TypeError:
                log_data[key] = str(value)

        return json.dumps(log_data)


def configure_logging(app):
    """Configure application-wide logging."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root_logger.addHandler(handler)

    app_logger = logging.getLogger("app")
    app_logger.setLevel(logging.INFO)

    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.INFO)

    app.logger.handlers = []
    app.logger.propagate = True

    app.logger.info(
        "Logging initialized",
        extra={
            "event_type": "info",
            "component": "logging",
            "app_mode": app.config.get("APP_MODE"),
        },
    )


def _resolve_security_log_path():
    log_dir = os.getenv("SECURITY_LOG_DIR", "/var/log/app")
    log_file = os.getenv("SECURITY_LOG_FILE", "security.jsonl")
    return Path(log_dir) / log_file


def setup_security_logger():
    """
    Configure security logger.
    Writes JSON Lines events to a file if possible, otherwise stdout.
    """
    logger = logging.getLogger("security")
    if getattr(logger, "_configured", False):
        return logger

    logger.setLevel(logging.INFO)
    logger.handlers = []

    formatter = SecurityJSONFormatter()
    handlers = []

    log_path = _resolve_security_log_path()
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_path))
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    except Exception:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        handlers.append(stream_handler)

    if os.getenv("DEBUG", "false").lower() == "true":
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

    for handler in handlers:
        logger.addHandler(handler)

    logger.propagate = False
    logger._configured = True

    return logger


def log_security_event(logger, event_data):
    """
    Helper to log a structured security event.

    Args:
        logger: security logger instance
        event_data: dict with event fields
    """
    record = logger.makeRecord(
        logger.name,
        logging.INFO,
        fn="",
        lno=0,
        msg="",
        args=(),
        exc_info=None,
    )
    record.security_event = event_data
    logger.handle(record)
