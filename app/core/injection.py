import re
import base64
from typing import Tuple, List

class InjectionDetector:
    """
    Analyzes inbound prompts for prompt injection, jailbreaks, system prompt overrides,
    and out-of-band delimiter attacks.
    """
    INJECTION_PATTERNS = [
        # Instruction Overrides
        (re.compile(r'\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|rules|prompts|directives)\b', re.I), "system_instruction_override", 0.95),
        (re.compile(r'\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(DAN|unfiltered|jailbroken|developer\s+mode|chaosgpt|evil|unrestricted)\b', re.I), "jailbreak_persona_adoption", 0.90),
        (re.compile(r'\b(output|print|reveal|show|display|leak)\s+(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+rules)\b', re.I), "system_prompt_extraction", 0.85),
        
        # Delimiter & Format Injections
        (re.compile(r'(\[INST\]\s*<<SYS>>|<\|im_start\|>system|###\s*System:|```system)', re.I), "delimiter_hijack", 0.95),
        (re.compile(r'(\bstop\s+being\s+helpful\b|\bdo\s+anything\s+now\b|\bmaximum\s+jailbreak\b)', re.I), "classic_jailbreak", 0.85),
    ]

    def scan_prompt(self, prompt: str) -> Tuple[bool, float, List[str]]:
        """
        Scans a prompt and returns: (is_malicious, risk_score, detected_threats)
        """
        threats: List[str] = []
        max_score = 0.0

        # 1. Regex Pattern Matching
        for pattern, threat_name, weight in self.INJECTION_PATTERNS:
            if pattern.search(prompt):
                threats.append(threat_name)
                max_score = max(max_score, weight)

        # 2. Obfuscation check (e.g. Base64 encoded payload)
        obfuscated_threat = self._check_base64_payloads(prompt)
        if obfuscated_threat:
            threats.append("obfuscated_base64_injection")
            max_score = max(max_score, 0.90)

        # Risk threshold: >= 0.70 is blocked
        is_malicious = max_score >= 0.70
        return is_malicious, round(max_score, 2), threats

    def check_canary_leakage(self, llm_output: str, canary_token: str) -> bool:
        """
        Returns True if the system canary token leaked into the generated output.
        """
        if not canary_token:
            return False
        return canary_token in llm_output

    def _check_base64_payloads(self, text: str) -> bool:
        # Detect base64 strings longer than 20 chars
        b64_candidates = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for cand in b64_candidates:
            try:
                decoded = base64.b64decode(cand).decode('utf-8', errors='ignore')
                for pattern, _, _ in self.INJECTION_PATTERNS:
                    if pattern.search(decoded):
                        return True
            except Exception:
                continue
        return False
