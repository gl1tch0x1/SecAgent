"""Module 2: Omni-LLM — provider-aware client with explicit routing."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

import httpx

from secagents.vault.env_loader import detect_provider_from_key, mask_secret
from secagents.infra.rate_limiting import get_rate_limiter


@dataclass
class LLMMessage:
    role: str
    content: str


@dataclass
class LLMResponse:
    content: str
    provider: str
    model: str
    tokens_used: int = 0


DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "openai_compatible": "gpt-4o-mini",
    "anthropic": "claude-sonnet-5",
    "deepseek": "deepseek-flash",
    "groq": "llama-3.1-70b-versatile",
    "google": "gemini-3.8-flash",
    "openrouter": "openai/gpt-4o-mini",
    "xai": "grok-beta",
    "ollama": "llama3.2:3b",
}


@dataclass
class ProviderConfig:
    name: str
    api_key: str
    base_url: str | None = None
    model: str | None = None
    endpoint: str | None = None
    display_name: str | None = None


class OmniLLM:
    """
    Universal LLM client with an explicit primary provider and optional fallback keys.
    Legacy bulk keys still use prefix detection when no named key identifies them.
    """

    def __init__(self, providers: list[ProviderConfig] | None = None):
        self.providers = providers or self._discover_providers()
        self._client = httpx.AsyncClient(timeout=120)

    def _discover_providers(self) -> list[ProviderConfig]:
        configs: list[ProviderConfig] = []
        named_keys = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
            "google": "GEMINI_API_KEY",
            "groq": "GROQ_API_KEY",
            "openrouter": "OPENROUTER_API_KEY",
            "xai": "XAI_API_KEY",
        }
        selected = os.environ.get("SECAGENT_LLM_PROVIDER", "").strip().lower()
        configured_model = os.environ.get("SECAGENT_LLM_MODEL", "").strip() or None
        if selected:
            if selected == "ollama":
                configs.append(
                    ProviderConfig(
                        name="ollama",
                        api_key=os.environ.get("SECAGENT_LLM_API_KEY", "").strip(),
                        base_url=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
                        model=configured_model or os.environ.get("OLLAMA_MODEL") or None,
                    )
                )
            elif selected == "custom":
                endpoint = os.environ.get("SECAGENT_LLM_ENDPOINT", "").strip()
                key = os.environ.get("SECAGENT_LLM_API_KEY", "").strip()
                if not key or not configured_model or not endpoint:
                    raise ValueError("Custom LLM needs API key, model ID, and endpoint")
                try:
                    parsed = urlsplit(endpoint)
                    port = parsed.port
                except ValueError as exc:
                    raise ValueError("Custom LLM endpoint URL is invalid") from exc
                if parsed.username or parsed.password:
                    raise ValueError("Custom LLM endpoint cannot contain credentials")
                if port is not None and not 1 <= port <= 65535:
                    raise ValueError("Custom LLM endpoint port is invalid")
                if parsed.scheme != "https" and not (
                    parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                ):
                    raise ValueError("Custom LLM endpoint must use HTTPS or local loopback HTTP")
                if (
                    not parsed.hostname
                    or not parsed.path.strip("/")
                    or parsed.query
                    or parsed.fragment
                ):
                    raise ValueError(
                        "Custom LLM endpoint must be a full route without query or fragment"
                    )
                configs.append(
                    ProviderConfig(
                        name="custom",
                        api_key=key,
                        model=configured_model,
                        endpoint=endpoint,
                        display_name=os.environ.get("SECAGENT_LLM_NAME", "").strip() or "custom",
                    )
                )
            elif selected in named_keys:
                key = os.environ.get(named_keys[selected], "").strip()
                if not key:
                    raise ValueError(
                        f"{named_keys[selected]} is missing for the selected LLM provider"
                    )
                configs.append(ProviderConfig(name=selected, api_key=key, model=configured_model))
            else:
                raise ValueError(f"Unsupported SECAGENT_LLM_PROVIDER: {selected}")

        bulk = os.environ.get("LLM_API_KEYS", "")
        for name, env in named_keys.items():
            key = os.environ.get(env, "").strip()
            if key and not any(p.name == name and p.api_key == key for p in configs):
                configs.append(ProviderConfig(name=name, api_key=key))
        for key in (item.strip() for item in bulk.split(",")):
            if key and not any(p.api_key == key for p in configs):
                configs.append(ProviderConfig(name=detect_provider_from_key(key), api_key=key))
        # Local Ollama fallback — only if OLLAMA_HOST is explicitly set
        if not configs:
            ollama_host = os.environ.get("OLLAMA_HOST", "").strip()
            if ollama_host:
                configs.append(
                    ProviderConfig(name="ollama", api_key="ollama", base_url=ollama_host)
                )
        return configs

    async def complete(
        self,
        messages: list[LLMMessage],
        provider: str | None = None,
        model: str | None = None,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        cfg = self._select_provider(provider)
        if not cfg:
            raise RuntimeError(
                "No LLM provider configured. Run the installer LLM setup or configure .env"
            )

        await get_rate_limiter().check(cfg.name)
        model = model or cfg.model or DEFAULT_MODELS.get(cfg.name, "gpt-4o-mini")

        if cfg.name == "anthropic":
            return await self._anthropic(cfg, messages, model, max_tokens)
        if cfg.name == "google":
            return await self._gemini(cfg, messages, model, max_tokens)
        if cfg.name == "ollama":
            return await self._ollama(cfg, messages, model, max_tokens)
        if cfg.name == "groq":
            return await self._openai_compatible(
                cfg, messages, model, max_tokens, "https://api.groq.com/openai/v1"
            )
        if cfg.name == "openrouter":
            return await self._openai_compatible(
                cfg, messages, model, max_tokens, "https://openrouter.ai/api/v1"
            )
        if cfg.name == "deepseek":
            return await self._openai_compatible(
                cfg, messages, model, max_tokens, "https://api.deepseek.com"
            )
        if cfg.name == "xai":
            return await self._openai_compatible(
                cfg, messages, model, max_tokens, "https://api.x.ai/v1"
            )
        base = cfg.base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        return await self._openai_compatible(cfg, messages, model, max_tokens, base)

    def _select_provider(self, name: str | None) -> ProviderConfig | None:
        if not self.providers:
            return None
        if name:
            for p in self.providers:
                if p.name == name or p.display_name == name:
                    return p
            raise ValueError(f"LLM provider is not configured: {name}")
        return self.providers[0]

    async def _openai_compatible(
        self,
        cfg: ProviderConfig,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int,
        base_url: str,
    ) -> LLMResponse:
        url = cfg.endpoint or f"{base_url.rstrip('/')}/chat/completions"
        token_field = (
            "max_completion_tokens"
            if cfg.name == "openai" and urlsplit(url).hostname == "api.openai.com"
            else "max_tokens"
        )
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            token_field: max_tokens,
        }
        resp = await self._client.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {cfg.api_key}"},
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return LLMResponse(
            content=content,
            provider=cfg.display_name or cfg.name,
            model=model,
            tokens_used=usage.get("total_tokens", 0),
        )

    async def _anthropic(
        self,
        cfg: ProviderConfig,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int,
    ) -> LLMResponse:
        system = ""
        msgs = []
        for m in messages:
            if m.role == "system":
                system = m.content
            else:
                msgs.append({"role": m.role, "content": m.content})
        body: dict = {"model": model, "max_tokens": max_tokens, "messages": msgs}
        if system:
            body["system"] = system
        resp = await self._client.post(
            "https://api.anthropic.com/v1/messages",
            json=body,
            headers={
                "x-api-key": cfg.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["content"][0]["text"]
        return LLMResponse(content=content, provider="anthropic", model=model)

    async def _gemini(
        self,
        cfg: ProviderConfig,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int,
    ) -> LLMResponse:
        system = "\n".join(m.content for m in messages if m.role == "system")
        contents = [
            {"role": "model" if m.role == "assistant" else "user", "parts": [{"text": m.content}]}
            for m in messages
            if m.role != "system"
        ]
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{quote(model, safe='-._')}:generateContent"
        )
        body: dict = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": max_tokens},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        resp = await self._client.post(
            url,
            json=body,
            headers={"x-goog-api-key": cfg.api_key},
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["candidates"][0]["content"]["parts"][0]["text"]
        return LLMResponse(content=content, provider="google", model=model)

    async def _ollama(
        self,
        cfg: ProviderConfig,
        messages: list[LLMMessage],
        model: str,
        max_tokens: int,
    ) -> LLMResponse:
        base = (cfg.base_url or "http://localhost:11434").rstrip("/")
        resp = await self._client.post(
            f"{base}/api/chat",
            json={
                "model": model,
                "messages": [{"role": m.role, "content": m.content} for m in messages],
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            headers={"Authorization": f"Bearer {cfg.api_key}"} if cfg.api_key else None,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data.get("message", {}).get("content", "")
        return LLMResponse(content=content, provider="ollama", model=model)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> OmniLLM:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.aclose()

    def masked_providers(self) -> list[str]:
        return [f"{p.name}:{mask_secret(p.api_key)}" for p in self.providers]
