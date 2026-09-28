"""Scope-checked request templates imported from API definitions and HAR traffic."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urljoin

import yaml

from secagents.infra.scope import enforce_scope

READ_METHODS = frozenset({"GET", "HEAD"})
HTTP_METHODS = READ_METHODS | {"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
MAX_IMPORT_BYTES = 5_000_000


@dataclass(frozen=True)
class RequestTemplate:
    method: str
    url: str
    source: str
    body: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _load(path: Path) -> dict:
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("API import exceeds the 5 MB limit")
    raw = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw) if path.suffix.lower() in {".yaml", ".yml"} else json.loads(raw)
    if not isinstance(doc, dict):
        raise ValueError("API import must be an object")
    return doc


def import_openapi(path: Path, base_url: str) -> list[RequestTemplate]:
    """Read bounded OpenAPI paths without inventing methods or sending traffic."""
    enforce_scope(base_url)
    doc = _load(path)
    if not (doc.get("openapi") or doc.get("swagger")):
        raise ValueError("Expected an OpenAPI or Swagger document")
    templates = []
    paths = doc.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")
    for route, operations in paths.items():
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or not isinstance(operations, dict)
        ):
            continue
        if "{" in route or "}" in route:
            continue  # Path parameters need operator-supplied concrete values.
        url = urljoin(base_url, route)
        enforce_scope(url)
        for method, operation in operations.items():
            method = method.upper()
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            example = (
                operation.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("example")
            )
            body = json.dumps(example) if example is not None else ""
            templates.append(RequestTemplate(method, url, "openapi", body))
    return templates[:2000]


def import_har(path: Path) -> list[RequestTemplate]:
    """Import captured request method, URL and body; omit captured credentials."""
    doc = _load(path)
    templates = []
    for entry in doc.get("log", {}).get("entries", [])[:2000]:
        request = entry.get("request", {})
        method = str(request.get("method", "")).upper()
        url = request.get("url", "")
        if method not in HTTP_METHODS or not isinstance(url, str):
            continue
        enforce_scope(url)
        body = str(request.get("postData", {}).get("text", ""))
        templates.append(RequestTemplate(method, url, "har", body))
    return templates
