import os
import json
import re

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

class GuardrailProxy:
    def __init__(self, config_path=CONFIG_PATH):
        self.config_path = config_path
        self.reload()

    def reload(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "enabled": False,
                "block_thought_injection": True,
                "block_sql_keywords": True,
                "mask_sensitive_output": True,
                "blocked_patterns": []
            }

    def inspect_input(self, user_input: str):
        """
        Validates input against active guardrail policies.
        Returns: (is_allowed: bool, reason: str)
        """
        self.reload()
        if not self.config.get("enabled", False):
            # Guardrails disabled: pass through
            return True, "Guardrails inactive"

        blocked_patterns = self.config.get("blocked_patterns", [])
        for pattern in blocked_patterns:
            if re.search(re.escape(pattern), user_input, re.IGNORECASE):
                return False, f"SECURITY ALERT: Blocked adversarial pattern detected: '{pattern}'"

        return True, "Input passed inspection"

    def inspect_output(self, agent_output: str):
        """
        Sanitizes or masks confidential information in agent response.
        """
        self.reload()
        if not self.config.get("enabled", False):
            return agent_output

        if self.config.get("mask_sensitive_output", False):
            # Mask potential passwords or secrets
            sanitized = re.sub(r'("password":\s*")[^"]+(")', r'\1[REDACTED_BY_GUARDRAIL]\2', agent_output)
            sanitized = re.sub(r'(FLAG:[a-zA-Z0-9_\-]+)', r'[FLAG_MASKED_BY_GUARDRAIL]', sanitized)
            return sanitized

        return agent_output

# Global singleton
guardrail = GuardrailProxy()
