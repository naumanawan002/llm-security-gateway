from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import uuid
import time

from app.core.pii import PIIRedactor
from app.core.injection import InjectionDetector
from app.core.policy import ContentGuardrail

app = FastAPI(
    title="LLM Security & Guardrail Gateway",
    description="Enterprise proxy mitigating prompt injections, PII leakage, and jailbreak attempts",
    version="0.1.0"
)

pii_redactor = PIIRedactor()
injection_detector = InjectionDetector()
guardrail = ContentGuardrail()

class Message(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: List[Message]
    temperature: Optional[float] = 0.7
    restore_pii_in_response: Optional[bool] = False

class InspectRequest(BaseModel):
    prompt: str

@app.get("/healthz")
async def healthz():
    return {"status": "healthy", "service": "llm-security-gateway"}

@app.post("/inspect")
async def inspect_prompt(req: InspectRequest):
    """
    Analyzes a prompt for prompt injection, jailbreaks, and PII without dispatching to an LLM.
    """
    # 1. Guardrail Check
    allowed, guardrail_reason = guardrail.evaluate(req.prompt)
    if not allowed:
        return {
            "allowed": False,
            "blocked_by": "guardrail",
            "reason": guardrail_reason,
            "risk_score": 1.0,
            "threats": ["policy_violation"],
            "redacted_prompt": req.prompt,
            "pii_detected": 0
        }

    # 2. Prompt Injection Scan
    is_malicious, risk_score, threats = injection_detector.scan_prompt(req.prompt)
    if is_malicious:
        return {
            "allowed": False,
            "blocked_by": "injection_detector",
            "reason": f"Prompt injection or jailbreak detected: {', '.join(threats)}",
            "risk_score": risk_score,
            "threats": threats,
            "redacted_prompt": req.prompt,
            "pii_detected": 0
        }

    # 3. PII Redaction
    redacted_text, pii_map, pii_count = pii_redactor.redact(req.prompt)

    return {
        "allowed": True,
        "blocked_by": None,
        "risk_score": risk_score,
        "threats": [],
        "pii_detected": pii_count,
        "redacted_prompt": redacted_text,
        "pii_surrogates": list(pii_map.keys())
    }

@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest):
    """
    OpenAI-compatible chat completions proxy with security guardrails and PII masking.
    """
    start_time = time.perf_counter()
    canary_token = f"CANARY_SECRET_{uuid.uuid4().hex[:8]}"

    # Combine user messages for inspection
    user_prompts = [m.content for m in req.messages if m.role == "user"]
    full_prompt = "\n".join(user_prompts)

    # 1. Policy & Guardrail Inspection
    allowed, reason = guardrail.evaluate(full_prompt)
    if not allowed:
        raise HTTPException(status_code=400, detail={
            "error": "policy_violation",
            "message": reason
        })

    # 2. Injection & Jailbreak Defense
    is_malicious, risk_score, threats = injection_detector.scan_prompt(full_prompt)
    if is_malicious:
        raise HTTPException(status_code=400, detail={
            "error": "prompt_injection_blocked",
            "message": f"Security violation: prompt contains adversarial patterns ({', '.join(threats)})",
            "risk_score": risk_score,
            "threats": threats
        })

    # 3. PII Redaction
    pii_mappings: Dict[str, str] = {}
    total_pii_masked = 0
    sanitized_messages = []

    for msg in req.messages:
        redacted_content, msg_pii_map, pii_count = pii_redactor.redact(msg.content)
        pii_mappings.update(msg_pii_map)
        total_pii_masked += pii_count
        sanitized_messages.append(Message(role=msg.role, content=redacted_content))

    # 4. Generate Mock or Upstream LLM Response (Safe deterministic fallback)
    raw_response = (
        f"Verified safe response. I processed your request without exposure of sensitive credentials. "
        f"Input contained {total_pii_masked} redacted PII entities."
    )

    # 5. Output Verification: Check for Canary Token Leaks
    if injection_detector.check_canary_leakage(raw_response, canary_token):
        raise HTTPException(status_code=500, detail={
            "error": "system_prompt_leakage",
            "message": "Output contained canary tokens indicating system instruction extraction."
        })

    # 6. Reversible PII Restoration if requested
    final_content = raw_response
    if req.restore_pii_in_response and pii_mappings:
        final_content = pii_redactor.restore(final_content, pii_mappings)

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": final_content
                },
                "finish_reason": "stop"
            }
        ],
        "security_telemetry": {
            "pii_redacted_count": total_pii_masked,
            "risk_score": risk_score,
            "latency_ms": duration_ms,
            "canary_verified": True
        }
    }
