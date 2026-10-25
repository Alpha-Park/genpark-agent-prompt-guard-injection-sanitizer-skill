import sys, re
sys.stdout.reconfigure(encoding='utf-8')

class PromptGuardInjectionSanitizerClient:
    """
    Zero-trust LLM input sanitization and heuristic prompt firewall.
    Detects direct prompt injections, jailbreak tokens, system override attempts,
    and returns threat telemetry and sanitized text payloads.
    """
    INJECTION_PATTERNS = [
        (r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)", "INSTRUCTION_OVERRIDE"),
        (r"(?i)system\s*:\s*you\s+are\s+now", "SYSTEM_ROLE_IMPERSONATION"),
        (r"(?i)disregard\s+all\s+guidelines", "SAFETY_BYPASS"),
        (r"(?i)jailbreak", "EXPLICIT_JAILBREAK"),
        (r"(?i)<script[\s>]", "XSS_SCRIPT_TAG"),
        (r"(?i)drop\s+table\b", "SQL_INJECTION"),
        (r"(?i)override\s+system\s+prompt", "SYSTEM_OVERRIDE"),
        (r"(?i)you\s+must\s+now\s+act\s+as", "ROLEPLAY_HIJACKING"),
        (r"(?i)DAN\s+mode\b", "DO_ANYTHING_NOW_EXPLOIT")
    ]

    def sanitize(self, text):
        detected_threats = []
        cleaned_text = text

        for pattern, threat_type in self.INJECTION_PATTERNS:
            matches = re.findall(pattern, cleaned_text)
            if matches:
                detected_threats.append({
                    "threat_type": threat_type,
                    "matched_pattern": pattern,
                    "match_count": len(matches)
                })
                cleaned_text = re.sub(pattern, "[BLOCKED_PROMPT_INJECTION]", cleaned_text)

        is_safe = (len(detected_threats) == 0)
        risk_score = min(1.0, len(detected_threats) * 0.35)

        return {
            "status": "success",
            "is_safe": is_safe,
            "risk_score": round(risk_score, 2),
            "threats_count": len(detected_threats),
            "threats": detected_threats,
            "original_length": len(text),
            "sanitized_length": len(cleaned_text),
            "sanitized_text": cleaned_text
        }
