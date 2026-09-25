"""Structured logging and lightweight observability helpers for SecAgent."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from contextlib import contextmanager
from typing import Any, Iterator


def configure_logging(level: str = "INFO", json_output: bool = False) -> logging.Logger:
    """Configure a consistent application logger with optional JSON output."""
    logger = logging.getLogger("secagents")
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    handler = logging.StreamHandler()
    if json_output:
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


class JsonFormatter(logging.Formatter):
    """Simple JSON formatter for structured logs."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "event"):
            payload["event"] = record.event
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        return json.dumps(payload, sort_keys=True)


class MetricsCollector:
    """Lightweight in-memory metrics tracker for CLI and runtime operations."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._timings: dict[str, list[float]] = defaultdict(list)

    def increment(self, name: str, value: int = 1) -> None:
        self._counters[name] += value

    def record_duration(self, name: str, duration_ms: float) -> None:
        self._timings[name].append(duration_ms)

    @contextmanager
    def timed(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            self.record_duration(name, (time.perf_counter() - start) * 1000)

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "timings": {key: {"count": len(values), "avg_ms": sum(values) / len(values) if values else 0.0} for key, values in self._timings.items()},
        }
