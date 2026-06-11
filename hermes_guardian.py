"""
hermes_guardian.py — Cerverus Swarm: Local Guardian
===================================================
The Hermes Agent acts as a secure proxy between the local swarm
and external LLM providers (e.g., OpenRouter).

Responsibilities:
  1. Initialize `camel-ai` agents
  2. Sanitize outgoing prompts (strip API keys, secrets via exact match AND regex)
  3. Dispatch tasks and return sanitized responses
  4. Log sanitization events for audit trail (pattern type only, never the value)
"""

import os
import re
from typing import List, Tuple

# Setup environment variables for camel-ai's underlying OpenAI client to use OpenRouter
os.environ["OPENAI_API_KEY"] = os.getenv("OPENROUTER_API_KEY", "")
os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"

# Import camel-ai after setting env vars
from camel.agents import ChatAgent
from camel.messages import BaseMessage
from camel.models import OpenAIModel


# ── Regex Patterns for Common Secret Types ──────────────────────────
# Each tuple is (pattern_name, compiled_regex).
# pattern_name is logged on match; the actual matched value is NEVER logged.

SENSITIVE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # OpenRouter API keys (sk-or-v1-<64 hex chars>)
    ("OpenRouter API Key",
     re.compile(r"sk-or-v1-[a-f0-9]{64}")),

    # OpenAI-style API keys (sk-<48+ alphanumeric chars>)
    ("OpenAI API Key",
     re.compile(r"sk-[a-zA-Z0-9]{20,}")),

    # AWS Access Key IDs (AKIA<16 uppercase alphanum>)
    ("AWS Access Key ID",
     re.compile(r"AKIA[0-9A-Z]{16}")),

    # AWS Secret Access Keys (40 char base64-ish)
    ("AWS Secret Access Key",
     re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),

    # SSH / PEM Private Keys
    ("Private Key Block",
     re.compile(r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----")),

    # JSON Web Tokens (three base64url segments separated by dots)
    ("JWT Token",
     re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")),

    # Generic API key patterns (key=<long hex/alphanum string>)
    ("Generic API Key Assignment",
     re.compile(r"""(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']?[a-zA-Z0-9_\-]{20,}["']?""", re.IGNORECASE)),

    # IPv4 addresses (optional — useful for preventing internal network leakage)
    ("IPv4 Address",
     re.compile(r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")),

    # Common password-in-config patterns
    ("Password in Config",
     re.compile(r"""(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']""", re.IGNORECASE)),
]


class HermesGuardian:
    def __init__(self):
        self.sensitive_strings: List[str] = self._load_sensitive_strings()
        self.model_id = os.getenv("OPENROUTER_MODEL_ID", "nvidia/nemotron-3-super-120b-a12b:free")
        self.sanitization_log: List[dict] = []  # Audit trail for the current session

        print("  Hermes Guardian initialized.")
        print(f"   Loaded {len(self.sensitive_strings)} sensitive strings for sanitization.")
        print(f"   Loaded {len(SENSITIVE_PATTERNS)} regex patterns for advanced detection.")

    def _load_sensitive_strings(self) -> List[str]:
        """
        Build a list of exact strings that should never leave the local machine.
        Reads all environment variables that look like secrets.
        """
        secrets = []

        # Primary: OpenRouter API key
        api_key = os.getenv("OPENROUTER_API_KEY")
        if api_key and api_key != "your_openrouter_api_key_here":
            secrets.append(api_key)

        # Also scan .env file for any other secret-looking values
        env_path = os.path.join(os.getcwd(), ".env")
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, _, value = line.partition("=")
                            value = value.strip().strip("\"'")
                            # Only add values that look like actual secrets (long enough)
                            if len(value) >= 16 and value not in secrets:
                                secrets.append(value)
            except OSError:
                pass

        # Sort longest first to avoid partial matches
        return sorted(secrets, key=len, reverse=True)

    def sanitize(self, text: str) -> str:
        """
        Two-pass sanitization:
          1. Exact match — replace known secret strings from .env
          2. Regex match — detect common secret patterns (AWS, JWT, SSH, etc.)
        """
        if not text:
            return text

        sanitized = text

        # ── Pass 1: Exact string replacement ────────────────────────
        for secret in self.sensitive_strings:
            if secret in sanitized:
                sanitized = sanitized.replace(secret, "[REDACTED]")
                self._log_event("exact_match", "Environment Variable")

        # ── Pass 2: Regex pattern replacement ───────────────────────
        for pattern_name, pattern in SENSITIVE_PATTERNS:
            match = pattern.search(sanitized)
            if match:
                sanitized = pattern.sub("[REDACTED]", sanitized)
                self._log_event("regex_match", pattern_name)

        if sanitized != text:
            redaction_count = sanitized.count("[REDACTED]") - text.count("[REDACTED]")
            print(f"  Hermes intercepted and redacted {redaction_count} sensitive item(s).")

        return sanitized

    def _log_event(self, match_type: str, pattern_name: str):
        """
        Record a sanitization event for the audit trail.
        NEVER logs the actual matched value — only the pattern type.
        """
        from datetime import datetime, timezone
        self.sanitization_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "match_type": match_type,
            "pattern": pattern_name,
        })

    def get_sanitization_report(self) -> List[dict]:
        """Return the audit trail of all sanitization events this session."""
        return self.sanitization_log.copy()

    def create_agent(self, role_name: str, system_prompt: str) -> ChatAgent:
        """Create a camel-ai ChatAgent configured for OpenRouter."""

        model = OpenAIModel(model_type=self.model_id, model_config_dict={})

        sys_msg = BaseMessage.make_assistant_message(role_name=role_name, content=system_prompt)

        agent = ChatAgent(
            system_message=sys_msg,
            model=model,
        )
        return agent

    def dispatch(self, agent: ChatAgent, user_prompt: str, agent_name: str) -> str:
        """Sanitize input, run the camel-ai agent, and sanitize output."""
        print(f"\n{'='*60}")
        print(f" >>> {agent_name} task dispatched via Hermes...")
        print(f"{'='*60}")

        # 1. Sanitize outgoing prompt
        safe_prompt = self.sanitize(user_prompt)

        # 2. Prepare the camel message
        user_msg = BaseMessage.make_user_message(role_name="User", content=safe_prompt)

        # 3. Execute
        try:
            response = agent.step(user_msg)

            # Handle case where response.msgs is None or empty
            if response.msgs is None or len(response.msgs) == 0:
                # Fallback: try response.msg (singular) which some camel-ai versions use
                if hasattr(response, 'msg') and response.msg is not None:
                    result_text = response.msg.content
                else:
                    result_text = "No response generated by the agent."
                    print(f"  {agent_name} returned an empty response.")
            else:
                result_text = response.msgs[0].content

            # 4. Sanitize incoming response (just in case the LLM echoed something)
            safe_result = self.sanitize(result_text)

            print(f"  {agent_name} completed ({len(safe_result)} chars)")
            return safe_result

        except Exception as e:
            print(f" Hermes failed to execute {agent_name}: {e}")
            return f"ERROR: {e}"
