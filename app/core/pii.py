import re
from typing import Tuple, Dict

class PIIRedactor:
    """
    Detects, masks, and reversibly tokenizes sensitive Personally Identifiable Information (PII)
    and secrets before prompts are sent to external LLM providers.
    """
    PATTERNS = {
        "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "PHONE": re.compile(r'\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b'),
        "CREDIT_CARD": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
        "API_KEY": re.compile(r'\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b'),
    }

    def redact(self, text: str) -> Tuple[str, Dict[str, str], int]:
        """
        Replaces detected PII entities with reversible cryptographic surrogate tokens.
        Returns: (sanitized_text, token_mapping, total_entities_redacted)
        """
        mapping: Dict[str, str] = {}
        redacted_text = text
        count = 0

        for entity_type, pattern in self.PATTERNS.items():
            matches = list(pattern.finditer(redacted_text))
            for idx, match in enumerate(matches):
                val = match.group(0)
                # Luhn check validation for credit cards to reduce false positives
                if entity_type == "CREDIT_CARD" and not self._luhn_check(val):
                    continue

                token = f"<PII:{entity_type}_{count+1}>"
                mapping[token] = val
                redacted_text = redacted_text.replace(val, token, 1)
                count += 1

        return redacted_text, mapping, count

    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        """
        Restores original values from surrogate tokens upon response return.
        """
        restored = text
        for token, original in mapping.items():
            restored = restored.replace(token, original)
        return restored

    def _luhn_check(self, card_num: str) -> bool:
        digits = [int(c) for c in card_num if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse = digits[::-1]
        for idx, d in enumerate(reverse):
            if idx % 2 == 1:
                doubled = d * 2
                total += doubled - 9 if doubled > 9 else doubled
            else:
                total += d
        return total % 10 == 0
