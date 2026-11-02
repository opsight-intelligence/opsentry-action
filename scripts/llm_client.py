"""
Configurable LLM Client for CI Agents.
Supports AWS Bedrock, Anthropic API, OpenAI-compatible APIs, and local models.
Provider is selected via the LLM_PROVIDER environment variable.
"""

import json
import os
import urllib.request
import urllib.error
from dataclasses import dataclass


@dataclass
class LLMResponse:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    provider: str = ""


class LLMClient:
    """Unified LLM client supporting multiple providers."""

    def __init__(self):
        self.provider = os.environ.get("LLM_PROVIDER", "bedrock").lower()
        self._validate_config()

    def _validate_config(self):
        """Check that required environment variables are set for the chosen provider."""
        required = {
            "bedrock": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
            "anthropic": ["ANTHROPIC_API_KEY"],
            "openai": ["OPENAI_API_KEY"],
            "local": ["LOCAL_MODEL_URL"],
        }
        missing = [var for var in required.get(self.provider, []) if not os.environ.get(var)]
        if missing:
            raise EnvironmentError(
                f"LLM_PROVIDER={self.provider} requires: {', '.join(missing)}. "
                f"Set these in your .env file."
            )

    def complete(self, prompt: str, system: str = "", max_tokens: int = 1024, temperature: float = 0.0) -> LLMResponse:
        """Send a completion request to the configured LLM provider."""
        if self.provider == "bedrock":
            return self._bedrock_complete(prompt, system, max_tokens, temperature)
        elif self.provider == "anthropic":
            return self._anthropic_complete(prompt, system, max_tokens, temperature)
        elif self.provider == "openai":
            return self._openai_complete(prompt, system, max_tokens, temperature)
        elif self.provider == "local":
            return self._openai_complete(prompt, system, max_tokens, temperature, local=True)
        else:
            raise ValueError(f"Unknown LLM_PROVIDER: {self.provider}. Use: bedrock, anthropic, openai, local")

    def _bedrock_complete(self, prompt: str, system: str, max_tokens: int, temperature: float) -> LLMResponse:
        """Call AWS Bedrock with Claude."""
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required for Bedrock. Install with: pip install boto3")

        model_id = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-sonnet-4-20250514-v1:0")
        region = os.environ.get("AWS_REGION", "us-east-1")

        client = boto3.client("bedrock-runtime", region_name=region)

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system

        response = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )

        result = json.loads(response["body"].read())
        text = result.get("content", [{}])[0].get("text", "")
        usage = result.get("usage", {})

        return LLMResponse(
            text=text,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            model=model_id,
            provider="bedrock",
        )

    def _anthropic_complete(self, prompt: str, system: str, max_tokens: int, temperature: float) -> LLMResponse:
        """Call the Anthropic API directly."""
        api_key = os.environ["ANTHROPIC_API_KEY"]
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

        body = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system

        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))

        text = result.get("content", [{}])[0].get("text", "")
        usage = result.get("usage", {})

        return LLMResponse(
            text=text,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            model=model,
            provider="anthropic",
        )

    def _openai_complete(self, prompt: str, system: str, max_tokens: int, temperature: float, local: bool = False) -> LLMResponse:
        """Call an OpenAI-compatible API (works with OpenAI, LM Studio, Ollama, etc.)."""
        if local:
            api_key = os.environ.get("OPENAI_API_KEY", "not-needed")
            base_url = os.environ.get("LOCAL_MODEL_URL", "http://localhost:11434/v1")
            model = os.environ.get("LOCAL_MODEL_NAME", "llama3")
        else:
            api_key = os.environ["OPENAI_API_KEY"]
            base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
            model = os.environ.get("OPENAI_MODEL", "gpt-4o")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }

        data = json.dumps(body).encode("utf-8")
        url = f"{base_url.rstrip('/')}/chat/completions"
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )

        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))

        text = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = result.get("usage", {})

        return LLMResponse(
            text=text,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            model=model,
            provider="local" if local else "openai",
        )


def get_client() -> LLMClient:
    """Factory function to create an LLM client from environment variables."""
    return LLMClient()


if __name__ == "__main__":
    client = get_client()
    print(f"LLM Provider: {client.provider}")
    response = client.complete("Say hello in one sentence.", max_tokens=50)
    print(f"Response: {response.text}")
    print(f"Tokens: {response.input_tokens} in / {response.output_tokens} out")
