"""Optional AI synthesis for Svikruti reports."""

from __future__ import annotations

import json
import os
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from svikruti.models import ScanResult


DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
GEMINI_GENERATE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def generate_ai_insights(
    result: ScanResult,
    provider: str = "openai",
    model: str | None = None,
    api_key: str | None = None,
    timeout: int = 45,
) -> Dict[str, Any]:
    """Generate evidence-grounded AI commentary.

    The scanner is private/offline by default. This function sends a compact
    evidence packet only when an API key is explicitly available.
    """

    if provider == "gemini":
        return _generate_gemini_insights(result, model=model, api_key=api_key, timeout=timeout)
    if provider != "openai":
        return {"status": "unsupported_provider", "provider": provider, "message": f"Unsupported AI provider: {provider}"}

    token = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY")
    selected_model = model or os.environ.get("SVIKRUTI_AI_MODEL") or DEFAULT_OPENAI_MODEL
    if not token:
        return {
            "status": "not_configured",
            "provider": provider,
            "model": selected_model,
            "message": "Set OPENAI_API_KEY and rerun with --ai to generate AI commentary.",
        }

    packet = _compact_packet(result)
    payload = {
        "model": selected_model,
        "input": [
            {
                "role": "developer",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "You are Svikruti AI, an evidence-grounded privacy operations assistant for Indian DPDPA readiness. "
                            "Use only the supplied scanner evidence. Do not certify compliance. Do not invent laws, facts, vendors, "
                            "or file references. Return strict JSON only."
                        ),
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": (
                            "Create a concise AI co-pilot output with keys: executive_brief, launch_risk, "
                            "top_priorities, control_commentary, buyer_summary, notice_patch, fix_pack_improvements, caveats. "
                            "top_priorities must be an array of objects with title, why, owner, evidence. "
                            "control_commentary must be an array of objects with control, status, comment. "
                            "Evidence packet:\n"
                            + json.dumps(packet, ensure_ascii=True)
                        ),
                    }
                ],
            },
        ],
    }

    try:
        request = Request(
            OPENAI_RESPONSES_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "SvikrutiPrivacyOps/0.4",
            },
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        return {
            "status": "error",
            "provider": provider,
            "model": selected_model,
            "message": f"OpenAI request failed with HTTP {exc.code}: {detail}",
        }
    except URLError as exc:
        return {
            "status": "error",
            "provider": provider,
            "model": selected_model,
            "message": f"OpenAI request failed: {exc}",
        }

    try:
        parsed = json.loads(body)
        text = _extract_response_text(parsed)
        insights = json.loads(_strip_json_fence(text))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return {
            "status": "parse_error",
            "provider": provider,
            "model": selected_model,
            "message": f"AI response could not be parsed as JSON: {exc}",
            "raw": body[:2000],
        }

    if not isinstance(insights, dict):
        return {
            "status": "parse_error",
            "provider": provider,
            "model": selected_model,
            "message": "AI response JSON was not an object.",
        }

    insights["status"] = "generated"
    insights["provider"] = provider
    insights["model"] = selected_model
    return insights


def _generate_gemini_insights(
    result: ScanResult,
    model: str | None = None,
    api_key: str | None = None,
    timeout: int = 45,
) -> Dict[str, Any]:
    token = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY")
    selected_model = model or os.environ.get("SVIKRUTI_AI_MODEL") or DEFAULT_GEMINI_MODEL
    if not token:
        return {
            "status": "not_configured",
            "provider": "gemini",
            "model": selected_model,
            "message": "Set GEMINI_API_KEY and rerun with --ai --ai-provider gemini to generate AI commentary.",
        }

    packet = _compact_packet(result)
    system_instruction = (
        "You are Svikruti AI, an evidence-grounded privacy operations assistant for Indian DPDPA readiness. "
        "Use only the supplied scanner evidence. Do not certify compliance. Do not invent laws, facts, vendors, "
        "or file references. Return strict JSON only."
    )
    user_text = (
        "Create a concise AI co-pilot output with keys: executive_brief, launch_risk, "
        "top_priorities, control_commentary, buyer_summary, notice_patch, fix_pack_improvements, caveats. "
        "top_priorities must be an array of objects with title, why, owner, evidence. "
        "control_commentary must be an array of objects with control, status, comment. "
        "Evidence packet:\n" + json.dumps(packet, ensure_ascii=True)
    )
    payload = {
        "system_instruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"parts": [{"text": user_text}]}],
        "generationConfig": {"responseMimeType": "application/json"},
    }
    url = GEMINI_GENERATE_URL.format(model=selected_model)

    try:
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "x-goog-api-key": token,
                "Content-Type": "application/json",
                "User-Agent": "SvikrutiPrivacyOps/0.4",
            },
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        return {
            "status": "error",
            "provider": "gemini",
            "model": selected_model,
            "message": f"Gemini request failed with HTTP {exc.code}: {detail}",
        }
    except URLError as exc:
        return {
            "status": "error",
            "provider": "gemini",
            "model": selected_model,
            "message": f"Gemini request failed: {exc}",
        }

    try:
        parsed = json.loads(body)
        text = _extract_gemini_text(parsed)
        insights = json.loads(_strip_json_fence(text))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return {
            "status": "parse_error",
            "provider": "gemini",
            "model": selected_model,
            "message": f"Gemini response could not be parsed as JSON: {exc}",
            "raw": body[:2000],
        }

    if not isinstance(insights, dict):
        return {"status": "parse_error", "provider": "gemini", "model": selected_model, "message": "Gemini response JSON was not an object."}

    insights["status"] = "generated"
    insights["provider"] = "gemini"
    insights["model"] = selected_model
    return insights


def _compact_packet(result: ScanResult) -> Dict[str, Any]:
    return {
        "summary": result.summary.to_dict(),
        "notice_gaps": result.notice_gaps[:12],
        "data_flows": result.evidence_graph.data_flows[:10],
        "proof_pack": result.evidence_graph.proof_pack[:12],
        "ropa_starter": result.ropa_starter[:10],
        "top_evidence": [
            {
                "kind": item.kind,
                "label": item.label,
                "severity": item.severity,
                "file": item.file,
                "line": item.line,
                "category": item.category,
                "detail": item.detail,
                "recommendation": item.recommendation,
                "metadata": item.metadata,
            }
            for item in result.evidence[:80]
        ],
        "scope": {"repo_path": result.repo_path, "url": result.url},
    }


def _extract_response_text(response: Dict[str, Any]) -> str:
    if isinstance(response.get("output_text"), str):
        return response["output_text"]
    chunks: list[str] = []
    for output in response.get("output", []):
        for content in output.get("content", []):
            if content.get("type") in {"output_text", "text"} and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    if not chunks:
        raise KeyError("No output text found in OpenAI response.")
    return "\n".join(chunks)


def _extract_gemini_text(response: Dict[str, Any]) -> str:
    candidates = response.get("candidates", [])
    if not candidates:
        raise KeyError("No Gemini candidates found.")
    parts = candidates[0].get("content", {}).get("parts", [])
    chunks = [part.get("text", "") for part in parts if isinstance(part.get("text"), str)]
    if not chunks:
        raise KeyError("No Gemini text parts found.")
    return "\n".join(chunks)


def _strip_json_fence(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned
