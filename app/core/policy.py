import re
from typing import Tuple, List

class ContentGuardrail:
    """
    Enforces organizational policies, token budgets, and banned topical content.
    """
    BANNED_TOPIC_PATTERNS = [
        (re.compile(r'\b(write|create|generate)\s+(a\s+)?(ransomware|keylogger|trojan|zero-day\s+exploit)\b', re.I), "malware_generation"),
        (re.compile(r'\b(how\s+to\s+build|synthesize)\s+(a\s+)?(bomb|nerve\s+agent|bioweapon)\b', re.I), "dangerous_substances"),
    ]

    def __init__(self, max_prompt_chars: int = 10000):
        self.max_prompt_chars = max_prompt_chars

    def evaluate(self, prompt: str) -> Tuple[bool, str]:
        """
        Validates content limits and safety boundaries.
        Returns: (allowed, reason)
        """
        if len(prompt) > self.max_prompt_chars:
            return False, f"Prompt exceeds maximum allowed character quota ({len(prompt)} > {self.max_prompt_chars})"

        for pattern, topic in self.BANNED_TOPIC_PATTERNS:
            if pattern.search(prompt):
                return False, f"Content policy violation: prompt violates safety policy on {topic}"

        return True, "permitted"
