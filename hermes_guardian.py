"""
hermes_guardian.py — Cerverus Swarm: Local Guardian
===================================================
The Hermes Agent acts as a secure proxy between the local swarm
and external LLM providers (e.g., OpenRouter).

Responsibilities:
  1. Initialize `camel-ai` agents
  2. Sanitize outgoing prompts (strip API keys, secrets)
  3. Dispatch tasks and return sanitized responses
"""

import os
import re
from typing import List

# Setup environment variables for camel-ai's underlying OpenAI client to use OpenRouter
os.environ["OPENAI_API_KEY"] = os.getenv("OPENROUTER_API_KEY", "")
os.environ["OPENAI_BASE_URL"] = "https://openrouter.ai/api/v1"

# Import camel-ai after setting env vars
from camel.agents import ChatAgent
from camel.messages import BaseMessage
from camel.models import OpenAIModel


class HermesGuardian:
    def __init__(self):
        self.sensitive_strings: List[str] = self._load_sensitive_strings()
        self.model_id = os.getenv("OPENROUTER_MODEL_ID", "nvidia/nemotron-3-super-120b-a12b:free")
        
        print("🛡️  Hermes Guardian initialized.")
        print(f"   Loaded {len(self.sensitive_strings)} sensitive strings for sanitization.")

    def _load_sensitive_strings(self) -> List[str]:
        """
        Build a list of strings that should never leave the local machine.
        """
        secrets = []
        api_key = os.getenv("OPENROUTER_API_KEY")
        if api_key and api_key != "your_openrouter_api_key_here":
            secrets.append(api_key)
            
        # Add any hardcoded regex patterns we want to catch (e.g., typical password shapes)
        # For Phase 3, we stick to exact matches from environment variables
        return sorted(secrets, key=len, reverse=True)  # Sort longest first to avoid partial matches

    def sanitize(self, text: str) -> str:
        """Replace any sensitive string with [REDACTED]."""
        if not text:
            return text
            
        sanitized = text
        for secret in self.sensitive_strings:
            sanitized = sanitized.replace(secret, "[REDACTED]")
            
        if sanitized != text:
            print("🛡️  Hermes intercepted and redacted sensitive data.")
            
        return sanitized

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
        print(f"🛡️ >>> {agent_name} task dispatched via Hermes...")
        print(f"{'='*60}")
        
        # 1. Sanitize outgoing prompt
        safe_prompt = self.sanitize(user_prompt)
        
        # 2. Prepare the camel message
        user_msg = BaseMessage.make_user_message(role_name="User", content=safe_prompt)
        
        # 3. Execute
        try:
            response = agent.step(user_msg)
            result_text = response.msgs[0].content
            
            # 4. Sanitize incoming response (just in case the LLM echoed something)
            safe_result = self.sanitize(result_text)
            
            print(f"🛡️  {agent_name} completed ({len(safe_result)} chars)")
            return safe_result
            
        except Exception as e:
            print(f"❌ Hermes failed to execute {agent_name}: {e}")
            return f"ERROR: {e}"
