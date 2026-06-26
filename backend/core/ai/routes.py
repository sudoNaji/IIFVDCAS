"""
IIFVDCAS AI API routes — Phase 3-7 AI features.

All endpoints read the AI provider config from request headers:
  X-AI-Provider : nvidia_nim | openai | anthropic | gemini | ollama
  X-AI-Key      : <api_key>
  X-AI-Model    : <model_name>   (optional, uses sensible defaults)
  X-AI-Base-URL : <base_url>     (optional, for NIM and Ollama)
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .providers import get_provider, DEFAULTS
from .prompts import (
    explain_cve_messages,
    vex_justification_messages,
    compliance_writeup_messages,
    compliance_executive_summary_messages,
    explain_finding_messages,
    chat_messages,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/ai", tags=["AI"])


# ─── Helper: extract provider from headers ────────────────────────────────────
def _provider_from_headers(
    x_ai_provider: str | None,
    x_ai_key: str | None,
    x_ai_model: str | None,
    x_ai_base_url: str | None,
):
    if not x_ai_provider:
        raise HTTPException(
            status_code=400,
            detail="Missing X-AI-Provider header. "
                   "Configure your AI provider in the AI Settings page.",
        )
    try:
        return get_provider(
            provider_name=x_ai_provider,
            api_key=x_ai_key or "",
            model=x_ai_model or None,
            base_url=x_ai_base_url or None,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


def _call(provider, messages, max_tokens=600) -> str:
    try:
        return provider.complete(messages, max_tokens=max_tokens)
    except Exception as e:
        msg = str(e)
        logger.error("[AI] completion error: %s", msg)
        # Surface helpful error messages
        if "401" in msg or "authentication" in msg.lower() or "api_key" in msg.lower():
            raise HTTPException(
                status_code=401,
                detail="AI provider rejected the API key. Check your key in AI Settings.",
            )
        if "model" in msg.lower() and "not found" in msg.lower():
            raise HTTPException(
                status_code=400,
                detail=f"Model not found. Check the model name in AI Settings. ({msg})",
            )
        raise HTTPException(status_code=502, detail=f"AI provider error: {msg}")


# ─── Models ───────────────────────────────────────────────────────────────────
class ExplainCveRequest(BaseModel):
    cve_id: str
    description: Optional[str] = ""
    firmware_context: Optional[Dict[str, Any]] = {}


class VexJustificationRequest(BaseModel):
    triage_finding: Dict[str, Any]
    firmware_context: Optional[Dict[str, Any]] = {}


class ComplianceWriteupRequest(BaseModel):
    control: Dict[str, Any]
    firmware_context: Optional[Dict[str, Any]] = {}


class ComplianceExecSummaryRequest(BaseModel):
    summary: Dict[str, Any]
    failed_controls: Optional[List[Dict[str, Any]]] = []
    firmware_context: Optional[Dict[str, Any]] = {}


class ExplainFindingRequest(BaseModel):
    finding: Dict[str, Any]
    firmware_context: Optional[Dict[str, Any]] = {}


class ChatRequest(BaseModel):
    message: str
    scan_context: Optional[Dict[str, Any]] = {}
    history: Optional[List[Dict[str, str]]] = []


class TestRequest(BaseModel):
    pass


# ─── Endpoints ────────────────────────────────────────────────────────────────
@router.get("/providers")
async def list_providers():
    """Return the list of supported providers with their default models."""
    return {
        "providers": [
            {
                "id":        "nvidia_nim",
                "label":     "NVIDIA NIM",
                "model":     DEFAULTS["nvidia_nim"]["model"],
                "base_url":  DEFAULTS["nvidia_nim"]["base_url"],
                "needs_key": True,
                "needs_base_url": True,
            },
            {
                "id":        "openai",
                "label":     "OpenAI",
                "model":     DEFAULTS["openai"]["model"],
                "base_url":  None,
                "needs_key": True,
                "needs_base_url": False,
            },
            {
                "id":        "anthropic",
                "label":     "Anthropic (Claude)",
                "model":     DEFAULTS["anthropic"]["model"],
                "base_url":  None,
                "needs_key": True,
                "needs_base_url": False,
            },
            {
                "id":        "gemini",
                "label":     "Google Gemini",
                "model":     DEFAULTS["gemini"]["model"],
                "base_url":  None,
                "needs_key": True,
                "needs_base_url": False,
            },
            {
                "id":        "ollama",
                "label":     "Ollama (Local)",
                "model":     DEFAULTS["ollama"]["model"],
                "base_url":  DEFAULTS["ollama"]["base_url"],
                "needs_key": False,
                "needs_base_url": True,
            },
        ]
    }


@router.post("/test")
async def test_connection(
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """Test that the configured provider responds correctly."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    reply = _call(
        provider,
        [{"role": "user", "content": "Reply with exactly: IIFVDCAS OK"}],
        max_tokens=20,
    )
    return {"status": "ok", "reply": reply, "provider": x_ai_provider, "model": x_ai_model}


@router.post("/explain-cve")
async def explain_cve(
    body: ExplainCveRequest,
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """Generate a plain-English explanation of a CVE in firmware context (Phase 5)."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    msgs = explain_cve_messages(
        cve_id=body.cve_id,
        description=body.description or "",
        firmware_context=body.firmware_context or {},
    )
    explanation = _call(provider, msgs, max_tokens=500)
    return {"cve_id": body.cve_id, "explanation": explanation}


@router.post("/vex-justification")
async def vex_justification(
    body: VexJustificationRequest,
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """Generate a CycloneDX-compliant VEX justification paragraph (Phase 6)."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    msgs = vex_justification_messages(
        triage_finding=body.triage_finding,
        firmware_context=body.firmware_context or {},
    )
    justification = _call(provider, msgs, max_tokens=400)
    return {
        "cve_id":        body.triage_finding.get("cve_id"),
        "justification": justification,
    }


@router.post("/compliance-writeup")
async def compliance_writeup(
    body: ComplianceWriteupRequest,
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """Generate a formal non-conformance statement for a FAIL control (Phase 7)."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    msgs = compliance_writeup_messages(
        control=body.control,
        firmware_context=body.firmware_context or {},
    )
    writeup = _call(provider, msgs, max_tokens=600)
    return {
        "control_id": body.control.get("control_id"),
        "standard":   body.control.get("standard"),
        "writeup":    writeup,
    }


@router.post("/compliance-exec-summary")
async def compliance_exec_summary(
    body: ComplianceExecSummaryRequest,
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """Generate an executive summary paragraph for the full compliance report (Phase 7)."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    msgs = compliance_executive_summary_messages(
        summary=body.summary,
        failed_controls=body.failed_controls or [],
        firmware_context=body.firmware_context or {},
    )
    text = _call(provider, msgs, max_tokens=500)
    return {"executive_summary": text}


@router.post("/explain-finding")
async def explain_finding(
    body: ExplainFindingRequest,
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """Explain a static analysis finding in plain English (Phase 3)."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    msgs = explain_finding_messages(
        finding=body.finding,
        firmware_context=body.firmware_context or {},
    )
    explanation = _call(provider, msgs, max_tokens=300)
    return {"explanation": explanation}


@router.post("/chat")
async def chat(
    body: ChatRequest,
    x_ai_provider: Optional[str] = Header(default=None),
    x_ai_key:      Optional[str] = Header(default=None),
    x_ai_model:    Optional[str] = Header(default=None),
    x_ai_base_url: Optional[str] = Header(default=None),
):
    """AI security assistant with full scan context (cross-cutting)."""
    provider = _provider_from_headers(x_ai_provider, x_ai_key, x_ai_model, x_ai_base_url)
    msgs = chat_messages(
        user_message=body.message,
        scan_context=body.scan_context or {},
        history=body.history or [],
    )
    reply = _call(provider, msgs, max_tokens=600)
    return {"reply": reply}
