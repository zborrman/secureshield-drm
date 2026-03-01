"""
LLM Council — AI enrichment layer over the statistical anomaly detectors.

Mirrors the 3-stage flow from karpathy/llm-council (vendor/llm-council):

  Stage 1 — First Opinions
    All COUNCIL_MODELS are queried in parallel with the anomaly evidence.
    Each model independently assesses severity, confidence, and root cause.

  Stage 2 — Peer Review (anonymized)
    Each model reviews the other models' Stage 1 assessments without
    knowing which model produced which response (Response A, B, C ...).
    Prevents sycophancy / brand bias.

  Stage 3 — Chairman Synthesis
    CHAIRMAN_MODEL reads all Stage 1 opinions + Stage 2 critiques and
    produces the final structured verdict (severity, actions, summary).

OpenRouter (https://openrouter.ai) is used as the unified API gateway so
any mix of GPT, Claude, Gemini, Mistral, etc. can sit on the council.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

import config

_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# ─── Stage 1 prompt ────────────────────────────────────────────────────────────

_S1_SYSTEM = """\
You are a cybersecurity analyst reviewing a DRM license anomaly finding.
Respond ONLY with a valid JSON object — no prose, no markdown fences.
Required schema:
{
  "severity_assessment": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": <integer 0-100>,
  "root_cause_hypothesis": "<string>",
  "false_positive_likelihood": <integer 0-100>,
  "immediate_actions": ["<action>", ...],
  "reasoning": "<string>"
}"""

_S1_USER = """\
Anomaly finding:
  type            : {anomaly_type}
  rule-based score: {score}/100
  rule-based sev  : {severity}
  evidence        : {evidence}
  recommendation  : {recommendation}
  invoice         : {invoice_id}
  detected at     : {detected_at}

Is the rule-based severity accurate? Provide your independent assessment."""

# ─── Stage 2 prompt ────────────────────────────────────────────────────────────

_S2_SYSTEM = """\
You are a senior cybersecurity analyst peer-reviewing anomaly assessments.
Respond ONLY with a valid JSON object — no prose, no markdown fences.
Required schema:
{
  "agreement_score": <integer 0-100>,
  "disagreements": ["<point>", ...],
  "refined_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "additional_insights": "<string>"
}"""

_S2_USER = """\
Original anomaly:
{anomaly_summary}

Anonymized peer assessments (do NOT assume which model wrote which):
{peer_assessments}

Critique these assessments. Do you agree with their conclusions?
What important points, if any, were missed?"""

# ─── Stage 3 (Chairman) prompt ─────────────────────────────────────────────────

_S3_SYSTEM = """\
You are the Chairman of a security analyst council.
Respond ONLY with a valid JSON object — no prose, no markdown fences.
Required schema:
{
  "final_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "final_confidence": <integer 0-100>,
  "consensus_root_cause": "<string>",
  "priority_rank": <integer 1-10>,
  "immediate_actions": ["<action>", ...],
  "council_summary": "<string>"
}"""

_S3_USER = """\
Anomaly: {anomaly_summary}

Full council deliberation:
{full_deliberation}

Synthesize a final, authoritative verdict from the council."""


# ─── OpenRouter helpers (mirrors vendor/llm-council/backend/openrouter.py) ─────

def _build_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
        "HTTP-Referer": "https://github.com/secureshield-drm",
        "Content-Type": "application/json",
    }


async def _query_model(
    client: httpx.AsyncClient,
    model: str,
    system: str,
    user: str,
) -> dict[str, Any] | None:
    """Call a single OpenRouter model; return parsed JSON or None on failure."""
    try:
        resp = await client.post(
            _OPENROUTER_URL,
            headers=_build_headers(),
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0.3,
                "response_format": {"type": "json_object"},
            },
            timeout=45.0,
        )
        resp.raise_for_status()
        raw = resp.json()["choices"][0]["message"]["content"]
        return json.loads(raw)
    except Exception:
        return None


async def _query_parallel(
    client: httpx.AsyncClient,
    models: list[str],
    system: str,
    user: str,
) -> list[dict[str, Any]]:
    """Query all council models in parallel; filter out failures."""
    results = await asyncio.gather(
        *[_query_model(client, m, system, user) for m in models]
    )
    return [r for r in results if r is not None]


# ─── Public API ────────────────────────────────────────────────────────────────

async def run_council(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Run the 3-stage LLM Council on a single anomaly finding.

    Args:
        finding: A finding dict as returned by anomaly_service.run_anomaly_analysis().

    Returns:
        The original finding dict extended with a ``council_verdict`` key.

    Raises:
        RuntimeError: If OPENROUTER_API_KEY is not configured.
        RuntimeError: If all council models fail in Stage 1.
    """
    if not config.OPENROUTER_API_KEY:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured. "
            "Set it in your environment to enable AI anomaly enrichment."
        )

    anomaly_summary = (
        f"type={finding['type']}, score={finding['score']}/100, "
        f"severity={finding['severity']}, invoice={finding.get('invoice_id', 'N/A')}"
    )

    s1_user = _S1_USER.format(
        anomaly_type=finding["type"],
        score=finding["score"],
        severity=finding["severity"],
        evidence=json.dumps(finding.get("evidence", {}), indent=2),
        recommendation=finding.get("recommendation", ""),
        invoice_id=finding.get("invoice_id", "N/A"),
        detected_at=finding.get("detected_at", "N/A"),
    )

    async with httpx.AsyncClient() as client:
        # ── Stage 1: parallel first opinions ───────────────────────────────────
        opinions = await _query_parallel(client, config.COUNCIL_MODELS, _S1_SYSTEM, s1_user)
        if not opinions:
            raise RuntimeError("All council models failed to respond in Stage 1.")

        # ── Stage 2: anonymized peer review (mirrors llm-council label scheme) ─
        labels = [chr(65 + i) for i in range(len(opinions))]   # A, B, C, …
        peer_text = "\n\n".join(
            f"Response {lbl}:\n{json.dumps(op, indent=2)}"
            for lbl, op in zip(labels, opinions)
        )
        s2_user = _S2_USER.format(
            anomaly_summary=anomaly_summary,
            peer_assessments=peer_text,
        )
        reviews = await _query_parallel(client, config.COUNCIL_MODELS, _S2_SYSTEM, s2_user)

        # ── Stage 3: Chairman synthesis ─────────────────────────────────────────
        deliberation = json.dumps(
            {"stage1_opinions": opinions, "stage2_reviews": reviews}, indent=2
        )
        s3_user = _S3_USER.format(
            anomaly_summary=anomaly_summary,
            full_deliberation=deliberation,
        )
        verdict = await _query_model(
            client, config.CHAIRMAN_MODEL, _S3_SYSTEM, s3_user
        )

    if verdict is None:
        # Graceful degradation: return statistical finding unchanged
        verdict = {
            "final_severity": finding["severity"],
            "final_confidence": 0,
            "consensus_root_cause": "Chairman model unavailable.",
            "priority_rank": 5,
            "immediate_actions": [],
            "council_summary": "Council synthesis failed — falling back to rule-based result.",
        }

    return {
        **finding,
        "council_verdict": {
            **verdict,
            "stage1_opinions": opinions,
            "stage2_reviews": reviews,
            "models_used": config.COUNCIL_MODELS,
            "chairman": config.CHAIRMAN_MODEL,
        },
    }
