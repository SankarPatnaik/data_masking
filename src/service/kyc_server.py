"""KYC-oriented MCP server exposing basic compliance tools.

This module adds simple helpers for Know Your Customer (KYC) workflows.  The
functions operate on small in-memory data stores so the server can be exercised
without external dependencies.  The utilities are exposed as MCP tools when the
optional ``mcp.server.fastapi`` package is available.
"""

from __future__ import annotations

from typing import List

try:  # pragma: no cover - optional dependency
    from mcp.server.fastapi import FastAPI
except Exception:  # pragma: no cover - library might be missing
    FastAPI = None  # type: ignore

from .mcp_server import mask_pii

# ---------------------------------------------------------------------------
# In-memory data stores
# ---------------------------------------------------------------------------
# Map of entity id -> list of UBO identifiers (email/phone for demo purposes)
UBO_DATA = {
    "acme_corp": ["alice@example.com", "+1-555-0100"],
    "globex": ["bob@example.com"],
}

# Map of entity id -> entity type used for policy lookup
ENTITY_TYPES = {
    "acme_corp": "company",
    "bob": "individual",
}

# Policy: required document types per entity type
REQUIRED_DOCS = {
    "company": ["registration", "director_id"],
    "individual": ["id", "proof_of_address"],
}

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def extract_ubos(entity_id: str, mask: bool = True) -> List[str]:
    """Return UBO identifiers for ``entity_id``.

    When ``mask`` is ``True`` the identifiers are passed through
    :func:`mask_pii` so that e-mails and phone numbers are redacted or hashed
    according to the existing policy rules.
    """

    ubos = UBO_DATA.get(entity_id, [])
    if mask:
        return [mask_pii(ubo) for ubo in ubos]
    return ubos


def classify_document(text: str) -> str:
    """Classify ``text`` into a simple document category.

    The classifier is intentionally naive and relies on keyword matching in
    order to keep the example self-contained.
    """

    lower = text.lower()
    if "passport" in lower:
        return "passport"
    if "utility bill" in lower or "bank statement" in lower:
        return "proof_of_address"
    if "certificate" in lower or "registration" in lower:
        return "registration"
    return "unknown"


def validate_required_docs(entity_id: str, provided_docs: List[str]) -> bool:
    """Validate ``provided_docs`` against policy for ``entity_id``.

    Looks up the entity type in :data:`ENTITY_TYPES` and verifies that all
    documents listed in :data:`REQUIRED_DOCS` for that type are present in
    ``provided_docs``.
    """

    entity_type = ENTITY_TYPES.get(entity_id)
    if not entity_type:
        return False
    required = set(REQUIRED_DOCS.get(entity_type, []))
    return required.issubset(set(provided_docs))


# ---------------------------------------------------------------------------
# MCP tool exposure
# ---------------------------------------------------------------------------
if FastAPI:  # pragma: no cover - depends on optional dependency
    app = FastAPI("KYC MCP Server")

    @app.tool()
    async def extract_ubos_tool(entity_id: str) -> List[str]:
        return extract_ubos(entity_id)

    @app.tool()
    async def classify_document_tool(text: str) -> str:
        return classify_document(text)

    @app.tool()
    async def validate_required_docs_tool(entity_id: str, provided_docs: List[str]) -> bool:
        return validate_required_docs(entity_id, provided_docs)
else:  # pragma: no cover - executed only when FastAPI is missing
    app = None  # type: ignore
