"""Native C/C++ Engine Python CFFI/ctypes Bridge."""

from __future__ import annotations

import ctypes
import re
import sys
from pathlib import Path
from typing import Any, Optional


class SecAgentProbeResult(ctypes.Structure):
    _fields_ = [
        ("open", ctypes.c_int),
        ("port", ctypes.c_int),
        ("latency_ms", ctypes.c_double),
    ]


class NativeCore:
    """Python bridge to compiled C/C++ foundational core engine (secagent_core)."""

    def __init__(self) -> None:
        self._lib: Optional[ctypes.CDLL] = None
        self._load_library()

    def _load_library(self) -> None:
        possible_names = ["secagent_core.dll", "libsecagent_core.so", "libsecagent_core.dylib"]
        search_dirs = [
            Path(__file__).parent.parent.parent.parent / "cpp-core" / "build",
            Path(__file__).parent.parent.parent.parent / "cpp-core" / "build" / "Debug",
            Path(__file__).parent.parent.parent.parent / "cpp-core" / "build" / "Release",
            Path(sys.prefix) / "lib",
            Path("/usr/local/lib"),
        ]

        for d in search_dirs:
            for name in possible_names:
                lib_path = d / name
                if lib_path.exists():
                    try:
                        self._lib = ctypes.CDLL(str(lib_path))
                        self._setup_prototypes()
                        return
                    except Exception:
                        continue

    def _setup_prototypes(self) -> None:
        if not self._lib:
            return
        self._lib.secagent_match_signature.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        self._lib.secagent_match_signature.restype = ctypes.c_int

        self._lib.secagent_probe_port.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        self._lib.secagent_probe_port.restype = SecAgentProbeResult

    @property
    def is_available(self) -> bool:
        """Return True if native C++ shared library is loaded."""
        return self._lib is not None

    def match_signature(self, buffer: str, pattern: str) -> bool:
        """High-speed signature scanning via native C++ matcher (fallback to Python re)."""
        if self._lib:
            res = self._lib.secagent_match_signature(
                buffer.encode("utf-8"), pattern.encode("utf-8")
            )
            return res == 1

        # Fallback pure-Python regex implementation
        try:
            return bool(re.search(pattern, buffer, re.IGNORECASE))
        except Exception:
            return pattern in buffer

    def probe_port(self, host: str, port: int, timeout_ms: int = 1000) -> dict[str, Any]:
        """Probe socket port via native C++ prober (fallback to socket)."""
        if self._lib:
            res = self._lib.secagent_probe_port(host.encode("utf-8"), port, timeout_ms)
            return {
                "open": bool(res.open),
                "port": res.port,
                "latency_ms": round(res.latency_ms, 2),
                "engine": "cpp-core",
            }

        # Fallback pure-Python socket probe
        import socket
        import time

        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_ms / 1000.0)
        is_open = s.connect_ex((host, port)) == 0
        s.close()
        latency = round((time.time() - start) * 1000.0, 2)
        return {"open": is_open, "port": port, "latency_ms": latency, "engine": "python-fallback"}


# Singleton instance
native_engine = NativeCore()
