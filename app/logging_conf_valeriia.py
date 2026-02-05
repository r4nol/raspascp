import logging
import json
import sys
from datetime import datetime


class JsonLogFormatter(logging.Formatter):
    """
    Simple JSON formatter for SIEM-friendly logs.
    """

    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge structured fields from `extra`
        for key, value in record.__dict__.items():
            if key in (
                "args", "msg", "levelname", "levelno",
                "pathname", "filename", "module",
                "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created",
                "msecs", "relativeCreated", "thread",
                "threadName", "processName", "process"
            ):
                continue

            # Do not overwrite base fields
            if key not in log_record:
                try:
                    json.dumps(value)
                    log_record[key] = value
                except TypeError:
                    log_record[key] = str(value)

        return json.dumps(log_record)


def configure_logging(app):
    """
    Configure application-wide logging.
    """

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove default handlers (important for gunicorn / reloads)
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())

    root_logger.addHandler(handler)

    # --- App logger ---
    app_logger = logging.getLogger("app")
    app_logger.setLevel(logging.INFO)

    # --- Security logger ---
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.INFO)

    app.logger.handlers = []
    app.logger.propagate = True

    app.logger.info(
        "Logging initialized",
        extra={
            "event_type": "info",
            "component": "logging",
            "app_mode": app.config.get("APP_MODE")
        }
    )
