"""Minimal MCP server exposing a `mask_pii` tool.

This server provides a single tool to redact or hash email addresses and phone
numbers before text is sent to an LLM.  It relies only on regular expressions so
it can run even when the full masking engine or the `mcp` package are
unavailable.
"""

from __future__ import annotations

import hashlib
import re
from typing import Literal

try:  # pragma: no cover - optional dependency
    from mcp.server.fastapi import FastAPI
except Exception:  # pragma: no cover - library might be missing
    FastAPI = None  # type: ignore

EMAIL_RE = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){1,2}\d{4}\b")


def _hash(value: str) -> str:
    """Return a deterministic hash for the provided value."""
    return "hash_" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def mask_pii(text: str, mode: Literal["redact", "hash"] = "redact") -> str:
    """Mask e‑mails and phone numbers in ``text``.

    Parameters
    ----------
    text:
        Input string potentially containing PII.
    mode:
        ``"redact"`` to replace matches with a token (``[EMAIL]``/``[PHONE]``),
        or ``"hash"`` to substitute with a deterministic hash.
    """

    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        if mode == "hash":
            return _hash(value)
        return "[EMAIL]" if "@" in value else "[PHONE]"

    text = EMAIL_RE.sub(repl, text)
    text = PHONE_RE.sub(repl, text)
    return text


if FastAPI:
    app = FastAPI("PII Masking MCP Server")

    @app.tool()
    async def mask_pii_tool(
        text: str, mode: Literal["redact", "hash"] = "redact"
    ) -> str:
        """Expose ``mask_pii`` as an MCP tool."""
        return mask_pii(text, mode)

else:  # pragma: no cover - executed only when FastAPI is missing
    app = None  # type: ignore
