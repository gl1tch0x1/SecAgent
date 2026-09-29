"""Comprehensive logging and error handling system for SecAgents."""

import logging
import json
import traceback
import sys
from datetime import datetime, timezone
from typing import Any, Dict
from pathlib import Path
from enum import Enum


class LogLevel(str, Enum):
    """Logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class JSONFormatter(logging.Formatter):
    """JSON logging formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            log_obj["exception_type"] = record.exc_info[0].__name__

        # Add extra fields
        if hasattr(record, "extra"):
            log_obj.update(record.extra)

        return json.dumps(log_obj)


class SecAgentsLogger:
    """Centralized logging for SecAgents."""

    _instance = None
    _loggers: Dict[str, logging.Logger] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)

        # Configure root logger
        self._configure_root_logger()

    def _configure_root_logger(self):
        """Configure root logger with handlers."""
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)

        # Console handler (INFO level)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            "[%(asctime)s] %(name)s - %(levelname)s - %(message)s"
        )
        console_handler.setFormatter(console_formatter)
        root.addHandler(console_handler)

        # File handler (DEBUG level, JSON)
        file_handler = logging.FileHandler(
            self.log_dir / f"secagents-{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter())
        root.addHandler(file_handler)

        # Error file handler
        error_handler = logging.FileHandler(
            self.log_dir / f"secagents-errors-{datetime.now().strftime('%Y%m%d')}.log"
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(JSONFormatter())
        root.addHandler(error_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """Get or create logger by name."""
        if name not in self._loggers:
            self._loggers[name] = logging.getLogger(name)
        return self._loggers[name]


class SecAgentsException(Exception):
    """Base exception for SecAgents."""

    def __init__(self, message: str, code: str = "GENERIC_ERROR", **context):
        self.message = message
        self.code = code
        self.context = context
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dict."""
        return {
            "error": self.code,
            "message": self.message,
            "context": self.context,
        }


class ValidationError(SecAgentsException):
    """Validation error."""

    def __init__(self, message: str, **context):
        super().__init__(message, "VALIDATION_ERROR", **context)


class AuthenticationError(SecAgentsException):
    """Authentication error."""

    def __init__(self, message: str, **context):
        super().__init__(message, "AUTH_ERROR", **context)


class AuthorizationError(SecAgentsException):
    """Authorization error."""

    def __init__(self, message: str, **context):
        super().__init__(message, "AUTHZ_ERROR", **context)


class SecAgentTimeoutError(SecAgentsException):
    """Timeout error."""

    def __init__(self, message: str, timeout_sec: float = None, **context):
        super().__init__(message, "TIMEOUT_ERROR", timeout_seconds=timeout_sec, **context)


# Alias to avoid shadowing builtin TimeoutError
TimeoutErrorAlias = SecAgentTimeoutError


class ConfigurationError(SecAgentsException):
    """Configuration error."""

    def __init__(self, message: str, **context):
        super().__init__(message, "CONFIG_ERROR", **context)


class ToolError(SecAgentsException):
    """External tool error."""

    def __init__(self, message: str, tool_name: str = None, **context):
        super().__init__(message, "TOOL_ERROR", tool_name=tool_name, **context)


class CircuitBreakerError(SecAgentsException):
    """Circuit breaker error."""

    def __init__(self, message: str, **context):
        super().__init__(message, "CIRCUIT_BREAKER_ERROR", **context)


def setup_logging(level: LogLevel = LogLevel.INFO):
    """Initialize logging system."""
    logger = SecAgentsLogger()
    root = logging.getLogger()
    root.setLevel(level.value)
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get logger by name."""
    logger_singleton = SecAgentsLogger()
    return logger_singleton.get_logger(name)


def log_exception(logger: logging.Logger, exc: Exception, message: str = None):
    """Log exception with full traceback."""
    if message:
        logger.error(message)

    logger.error(f"Exception: {type(exc).__name__}: {str(exc)}")
    logger.debug(traceback.format_exc())

    if isinstance(exc, SecAgentsException):
        logger.error(f"Context: {exc.to_dict()}")


# Global logger
_logger = get_logger("secagents.core")

__all__ = [
    "LogLevel",
    "JSONFormatter",
    "SecAgentsLogger",
    "SecAgentsException",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "SecAgentTimeoutError",
    "ConfigurationError",
    "ToolError",
    "CircuitBreakerError",
    "setup_logging",
    "get_logger",
    "log_exception",
]
