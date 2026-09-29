"""Module 11: Vault — secure .env management and key validation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import httpx

# ANSI colors
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"


class KeyStatus(str, Enum):
    VALID = "valid"  # 🟢 tested OK
    PRESENT = "present"  # 🟡 found, not fully validated
    MISSING = "missing"  # 🔴 absent
    INVALID = "invalid"  # 🔴 tested failed


@dataclass
class KeyReport:
    name: str
    status: KeyStatus
    masked: str
    message: str = ""


def mask_secret(value: str, visible: int = 4) -> str:
    """Mask API key for logs: sk-ant...8f9g"""
    if not value or len(value) <= visible * 2:
        return "***"
    return f"{value[:visible]}...{value[-visible:]}"


# Provider detection by key prefix
KEY_PREFIX_MAP: list[tuple[str, str]] = [
    ("sk-ant-", "anthropic"),
    ("sk-proj-", "openai"),
    ("sk-or-", "openrouter"),
    ("sk-", "openai"),
    ("gsk_", "groq"),
    ("AIza", "google"),
    ("xai-", "xai"),
]


def detect_provider_from_key(api_key: str) -> str:
    for prefix, provider in KEY_PREFIX_MAP:
        if api_key.startswith(prefix):
            return provider
    return "openai_compatible"


@dataclass
class Vault:
    """Load, validate, and report on all configured API keys."""

    env_path: Path = field(default_factory=lambda: Path(".env"))
    reports: list[KeyReport] = field(default_factory=list)

    def load(self) -> None:
        """Load .env into os.environ without overwriting existing vars."""
        if not self.env_path.exists():
            return
        for line in self.env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value

    def _collect_llm_keys(self) -> list[tuple[str, str]]:
        keys: list[tuple[str, str]] = []
        bulk = os.environ.get("LLM_API_KEYS", "")
        if bulk:
            for i, k in enumerate(bulk.split(",")):
                k = k.strip()
                if k:
                    keys.append((f"LLM_API_KEYS[{i}]", k))
        for env_name in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GROQ_API_KEY",
            "DEEPSEEK_API_KEY",
            "GEMINI_API_KEY",
            "OPENROUTER_API_KEY",
            "XAI_API_KEY",
            "SECAGENT_LLM_API_KEY",
        ):
            val = os.environ.get(env_name, "").strip()
            if val:
                keys.append((env_name, val))
        return keys

    async def _probe_key(self, name: str, api_key: str) -> KeyReport:
        named_providers = {
            "OPENAI_API_KEY": "openai",
            "ANTHROPIC_API_KEY": "anthropic",
            "DEEPSEEK_API_KEY": "deepseek",
            "GEMINI_API_KEY": "google",
            "GROQ_API_KEY": "groq",
            "OPENROUTER_API_KEY": "openrouter",
            "SECAGENT_LLM_API_KEY": "custom",
        }
        provider = named_providers.get(name, detect_provider_from_key(api_key))
        masked = mask_secret(api_key)
        if provider == "custom":
            return KeyReport(name, KeyStatus.PRESENT, masked, "Custom endpoint not probed")
        try:
            ok, msg = await self._cheap_validation(provider, api_key)
            if ok:
                return KeyReport(name, KeyStatus.VALID, masked, msg)
            return KeyReport(name, KeyStatus.INVALID, masked, msg)
        except Exception as e:
            return KeyReport(name, KeyStatus.PRESENT, masked, str(e)[:80])

    async def _cheap_validation(self, provider: str, api_key: str) -> tuple[bool, str]:
        """Minimal API call to verify key works."""
        async with httpx.AsyncClient(timeout=15) as client:
            if provider == "openai" or provider == "openai_compatible":
                resp = await client.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if resp.status_code == 200:
                    return True, "OpenAI models list OK"
                if resp.status_code == 401:
                    return False, "Invalid OpenAI key"
                return False, f"OpenAI validation failed ({resp.status_code})"

            if provider == "anthropic":
                resp = await client.get(
                    "https://api.anthropic.com/v1/models",
                    headers={
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                )
                return resp.status_code == 200, f"Anthropic models {resp.status_code}"

            if provider == "deepseek":
                resp = await client.get(
                    "https://api.deepseek.com/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                return resp.status_code == 200, f"DeepSeek models {resp.status_code}"

            if provider == "groq":
                resp = await client.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                return resp.status_code == 200, f"Groq {resp.status_code}"

            if provider == "google":
                resp = await client.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    headers={"x-goog-api-key": api_key},
                )
                return resp.status_code == 200, f"Gemini {resp.status_code}"

            # OpenAI-compatible fallback
            base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            resp = await client.get(
                f"{base.rstrip('/')}/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            return resp.status_code in (200, 401), f"Compatible endpoint {resp.status_code}"

    async def validate_all(self) -> list[KeyReport]:
        self.load()
        self.reports = []

        for name, key in self._collect_llm_keys():
            self.reports.append(await self._probe_key(name, key))

        for env_name, probe in (
            ("SHODAN_API_KEY", self._probe_shodan),
            ("CHAOS_API_KEY", self._probe_chaos),
        ):
            val = os.environ.get(env_name, "").strip()
            if not val:
                self.reports.append(KeyReport(env_name, KeyStatus.MISSING, "", "Not configured"))
            else:
                self.reports.append(await probe(env_name, val))

        return self.reports

    async def _probe_shodan(self, name: str, key: str) -> KeyReport:
        masked = mask_secret(key)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://api.shodan.io/api-info?key={key}")
                if resp.status_code == 200:
                    return KeyReport(name, KeyStatus.VALID, masked, "Shodan API OK")
                if resp.status_code == 401:
                    return KeyReport(name, KeyStatus.INVALID, masked, "Invalid Shodan key")
                return KeyReport(name, KeyStatus.PRESENT, masked, f"Shodan {resp.status_code}")
        except (httpx.HTTPError, OSError) as e:
            return KeyReport(name, KeyStatus.PRESENT, masked, f"Shodan probe error: {str(e)[:50]}")

    async def _probe_chaos(self, name: str, key: str) -> KeyReport:
        masked = mask_secret(key)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://dns.projectdiscovery.io/dns/example.com/subdomains",
                    headers={"Authorization": key},
                )
                if resp.status_code in (200, 404):
                    return KeyReport(name, KeyStatus.VALID, masked, "Chaos API reachable")
                if resp.status_code == 401:
                    return KeyReport(name, KeyStatus.INVALID, masked, "Invalid Chaos key")
                return KeyReport(name, KeyStatus.PRESENT, masked, f"Chaos {resp.status_code}")
        except (httpx.HTTPError, OSError) as e:
            return KeyReport(name, KeyStatus.PRESENT, masked, f"Chaos probe error: {str(e)[:50]}")

    def print_status(self, use_color: bool = True) -> None:
        icon = {
            KeyStatus.VALID: ("🟢", GREEN),
            KeyStatus.PRESENT: ("🟡", YELLOW),
            KeyStatus.MISSING: ("🔴", RED),
            KeyStatus.INVALID: ("🔴", RED),
        }
        print("\n  The Vault — API Key Status")
        print("  " + "─" * 50)
        for r in self.reports:
            sym, col = icon.get(r.status, ("⚪", ""))
            line = f"  {sym} {r.name}: {r.masked or '(empty)'} — {r.message or r.status.value}"
            if use_color and col:
                print(f"{col}{line}{RESET}")
            else:
                print(line)

    def any_llm_available(self) -> bool:
        if os.environ.get("SECAGENT_LLM_PROVIDER") == "ollama" and os.environ.get("OLLAMA_HOST"):
            return True
        return any(
            r.status in (KeyStatus.VALID, KeyStatus.PRESENT)
            for r in self.reports
            if r.name
            in {
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "DEEPSEEK_API_KEY",
                "GEMINI_API_KEY",
                "GROQ_API_KEY",
                "OPENROUTER_API_KEY",
                "XAI_API_KEY",
                "SECAGENT_LLM_API_KEY",
            }
            or r.name.startswith("LLM_API_KEYS[")
        )
