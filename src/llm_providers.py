"""Pluggable, read-only LLM adapters for the verified SOC pipeline.

Providers receive only compact, pre-collected evidence dossiers. They never
receive Wazuh credentials, raw API access, or authority to execute a response.
Their output is validated by the application before it can appear in a report.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Any
from urllib.request import Request, urlopen

try:
    from .assessment_prompt import assessment_prompt
    from .evidence_interpretation import interpretation_prompt
    from .qa_review import qa_prompt
    from .triage_planner import triage_prompt
    from .llm_usage import ModelPricing
except ImportError:
    from assessment_prompt import assessment_prompt
    from evidence_interpretation import interpretation_prompt
    from qa_review import qa_prompt
    from triage_planner import triage_prompt
    from llm_usage import ModelPricing


class ProviderError(RuntimeError):
    pass


class ModelProvider:
    provider_name = "unknown"

    def __init__(self, model: str, max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.pricing = pricing
        self.last_usage: dict[str, int] | None = None

    def assess(self, case: Any) -> str:
        """Return strict assessment JSON. Providers remain unable to access tools."""
        return self.assess_prompt(assessment_prompt(case))

    def review(self, case: Any, assessment: Any) -> str:
        """Return a strict QA review. Providers remain unable to access tools."""
        return self.review_prompt(qa_prompt(case, assessment))

    def assess_prompt(self, prompt: str) -> str:
        """Send one already-built assessment prompt, exactly as audited."""
        raise ProviderError(f"{type(self).__name__} does not implement prompt assessment")

    def review_prompt(self, prompt: str) -> str:
        """Send one already-built QA prompt, exactly as audited."""
        raise ProviderError(f"{type(self).__name__} does not implement prompt review")

    def interpret(self, case: Any) -> str:
        """Return a bounded explanation of already observed facts."""
        raise ProviderError(f"{type(self).__name__} does not implement evidence interpretation")

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        """Return one reference-only triage decision."""
        raise ProviderError(f"{type(self).__name__} does not implement triage planning")


class JsonHttpProvider(ModelProvider):
    def _post(self, url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        request = Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers}, method="POST")
        try:
            with urlopen(request, timeout=int(os.getenv("LLM_TIMEOUT_SECONDS", "180"))) as response:
                return json.loads(response.read().decode())
        except Exception as exc:
            raise ProviderError(f"provider request failed: {exc}") from exc


class OllamaProvider(JsonHttpProvider):
    provider_name = "ollama"

    def __init__(self, model: str, base_url: str = "http://localhost:11434", max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        super().__init__(model, max_output_tokens, pricing)
        self.base_url = base_url.rstrip("/")

    def assess_prompt(self, prompt: str) -> str:
        # The compact dossier uses short option IDs.  Plain JSON is more
        # reliable across local model templates than a deeply nested schema;
        # AssessmentPipeline resolves and verifies every selected ID.
        return self._generate(prompt, response_format="json")

    def review_prompt(self, prompt: str) -> str:
        return self._generate(prompt, response_format="json")

    def interpret(self, case: Any) -> str:
        return self._generate(interpretation_prompt(case), response_format="json")

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        return self._generate(triage_prompt(seed_card, ledger), response_format="json")

    def _generate(self, prompt: str, response_format: str | dict[str, Any]) -> str:
        payload = self._post(f"{self.base_url}/api/generate", {}, {
            "model": self.model, "prompt": prompt, "stream": False, "format": response_format,
            "options": {
                "temperature": 0,
                "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "4096")),
                "num_predict": self.max_output_tokens or int(os.getenv("OLLAMA_MAX_TOKENS", "800")),
            },
        })
        return _require_text(payload.get("response"), "Ollama")


class OpenAIProvider(JsonHttpProvider):
    """Responses API adapter. Set OPENAI_API_KEY and LLM_MODEL."""
    provider_name = "openai"

    def __init__(self, model: str, api_key: str, max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        super().__init__(model, max_output_tokens, pricing)
        self.api_key = api_key

    def assess_prompt(self, prompt: str) -> str:
        return self._generate(prompt)

    def review_prompt(self, prompt: str) -> str:
        return self._generate(prompt)

    def interpret(self, case: Any) -> str:
        return self._generate(interpretation_prompt(case))

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        return self._generate(triage_prompt(seed_card, ledger))

    def _generate(self, prompt: str) -> str:
        payload = self._post("https://api.openai.com/v1/responses", {"Authorization": f"Bearer {self.api_key}"}, {"model": self.model, "input": prompt, "text": {"format": {"type": "json_object"}}})
        if isinstance(payload.get("output_text"), str):
            return payload["output_text"]
        for item in payload.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    return _require_text(content.get("text"), "OpenAI")
        raise ProviderError("OpenAI response did not contain output text")


class AnthropicProvider(JsonHttpProvider):
    provider_name = "anthropic"

    def __init__(self, model: str, api_key: str, max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        super().__init__(model, max_output_tokens or 350, pricing)
        self.api_key = api_key

    def assess_prompt(self, prompt: str) -> str:
        return self._generate(prompt)

    def review_prompt(self, prompt: str) -> str:
        return self._generate(prompt)

    def interpret(self, case: Any) -> str:
        return self._generate(interpretation_prompt(case))

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        return self._generate(triage_prompt(seed_card, ledger))

    def _generate(self, prompt: str) -> str:
        body: dict[str, Any] = {"model": self.model, "max_tokens": self.max_output_tokens, "messages": [{"role": "user", "content": prompt}]}
        # Claude Sonnet 5 rejects non-default sampling parameters when its
        # adaptive thinking behavior is enabled. Earlier Claude models retain
        # temperature=0 for repeatable JSON selection behavior.
        if self.model != "claude-sonnet-5":
            body["temperature"] = 0
        payload = self._post("https://api.anthropic.com/v1/messages", {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}, body)
        usage = payload.get("usage", {})
        if isinstance(usage, dict) and isinstance(usage.get("input_tokens"), int) and isinstance(usage.get("output_tokens"), int):
            self.last_usage = {"input_tokens": usage["input_tokens"], "output_tokens": usage["output_tokens"]}
        text = next((item.get("text") for item in payload.get("content", []) if item.get("type") == "text"), None)
        if isinstance(text, str) and text.strip():
            return text
        stop_reason = payload.get("stop_reason")
        content_types = [item.get("type") for item in payload.get("content", []) if isinstance(item, dict)]
        raise ProviderError(f"Anthropic returned no text (stop_reason={stop_reason!r}, content_types={content_types!r})")


class GeminiProvider(JsonHttpProvider):
    provider_name = "gemini"

    def __init__(self, model: str, api_key: str, max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        super().__init__(model, max_output_tokens, pricing)
        self.api_key = api_key

    def assess_prompt(self, prompt: str) -> str:
        return self._generate(prompt)

    def review_prompt(self, prompt: str) -> str:
        return self._generate(prompt)

    def interpret(self, case: Any) -> str:
        return self._generate(interpretation_prompt(case))

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        return self._generate(triage_prompt(seed_card, ledger))

    def _generate(self, prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        config: dict[str, Any] = {"temperature": 0, "responseMimeType": "application/json"}
        if self.max_output_tokens:
            config["maxOutputTokens"] = self.max_output_tokens
        payload = self._post(url, {}, {"contents": [{"role": "user", "parts": [{"text": prompt}]}], "generationConfig": config})
        try:
            return _require_text(payload["candidates"][0]["content"]["parts"][0]["text"], "Gemini")
        except (IndexError, KeyError) as exc:
            raise ProviderError("Gemini response did not contain text") from exc


class CliProvider(ModelProvider):
    """Optional local CLI adapter. Command is allowlisted to Claude or Gemini CLI."""
    def __init__(self, command: str, max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        self.command = shlex.split(command, posix=False)
        if not self.command or _cli_name(self.command[0]) not in {"claude", "gemini"}:
            raise ProviderError("LLM_CLI_COMMAND must start with claude or gemini")
        super().__init__(_cli_name(self.command[0]), max_output_tokens, pricing)

    def assess_prompt(self, prompt: str) -> str:
        return self._run(prompt)

    def review_prompt(self, prompt: str) -> str:
        return self._run(prompt)

    def interpret(self, case: Any) -> str:
        return self._run(interpretation_prompt(case))

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        return self._run(triage_prompt(seed_card, ledger))

    def _run(self, prompt: str) -> str:
        try:
            completed = subprocess.run(self.command, input=prompt, text=True, capture_output=True, timeout=180, check=True)
            return _require_text(completed.stdout.strip(), "CLI provider")
        except (OSError, subprocess.SubprocessError) as exc:
            raise ProviderError(f"CLI provider failed: {exc}") from exc


class GeminiCliProvider(ModelProvider):
    """Read-only Gemini CLI adapter using its non-interactive JSON output."""
    def __init__(self, command: str, max_output_tokens: int | None = None, pricing: ModelPricing | None = None):
        self.command = shlex.split(command, posix=False)
        if not self.command or _cli_name(self.command[0]) != "gemini":
            raise ProviderError("LLM_CLI_COMMAND must start with gemini")
        super().__init__(_cli_name(self.command[0]), max_output_tokens, pricing)

    def assess_prompt(self, prompt: str) -> str:
        return self._run(prompt)

    def review_prompt(self, prompt: str) -> str:
        return self._run(prompt)

    def interpret(self, case: Any) -> str:
        return self._run(interpretation_prompt(case))

    def plan(self, seed_card: dict[str, Any], ledger: dict[str, Any]) -> str:
        return self._run(triage_prompt(seed_card, ledger))

    def _run(self, prompt: str) -> str:
        command = list(self.command)
        if "--skip-trust" not in command:
            command.append("--skip-trust")
        command.extend(["--output-format", "json", "--prompt", prompt])
        try:
            completed = subprocess.run(command, text=True, capture_output=True, timeout=180, check=True)
            payload = json.loads(completed.stdout)
            return _require_text(payload.get("response"), "Gemini CLI")
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Gemini CLI provider failed: {exc}") from exc


def provider_from_env() -> ModelProvider:
    provider = os.getenv("LLM_PROVIDER", "ollama").lower()
    model = os.getenv("LLM_MODEL", "llama3.2")
    return _provider_from_settings(provider, model, os.getenv("LLM_CLI_COMMAND"), _stage_output_limit("LLM", 800), _stage_pricing("LLM"))


def qa_provider_from_env() -> ModelProvider:
    """Build a separately configurable critic provider.

    Leaving QA_PROVIDER unset retains the existing provider for local testing;
    production should set it to a different provider/model for independence.
    """
    provider = os.getenv("QA_PROVIDER", os.getenv("LLM_PROVIDER", "ollama")).lower()
    model = os.getenv("QA_MODEL", os.getenv("LLM_MODEL", "llama3.2"))
    command = os.getenv("QA_LLM_CLI_COMMAND", os.getenv("LLM_CLI_COMMAND"))
    return _provider_from_settings(provider, model, command, _stage_output_limit("QA", 200), _stage_pricing("QA"))


def _provider_from_settings(provider: str, model: str, cli_command: str | None, max_output_tokens: int, pricing: ModelPricing | None) -> ModelProvider:
    if provider == "ollama":
        return OllamaProvider(model, os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"), max_output_tokens, pricing)
    if provider == "openai":
        return OpenAIProvider(model, _required_env("OPENAI_API_KEY"), max_output_tokens, pricing)
    if provider == "anthropic":
        return AnthropicProvider(model, _required_env("ANTHROPIC_API_KEY"), max_output_tokens, pricing)
    if provider == "gemini":
        return GeminiProvider(model, _required_env("GEMINI_API_KEY"), max_output_tokens, pricing)
    if provider == "claude_cli":
        return CliProvider(cli_command or _required_env("QA_LLM_CLI_COMMAND"), max_output_tokens, pricing)
    if provider == "gemini_cli":
        return GeminiCliProvider(cli_command or _required_env("QA_LLM_CLI_COMMAND"), max_output_tokens, pricing)
    raise ProviderError(f"unsupported LLM_PROVIDER: {provider}")


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ProviderError(f"{name} is required for this provider")
    return value


def _stage_output_limit(prefix: str, default: int) -> int:
    raw = os.getenv(f"{prefix}_MAX_OUTPUT_TOKENS", str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ProviderError(f"{prefix}_MAX_OUTPUT_TOKENS must be an integer") from exc
    if not 32 <= value <= 4_000:
        raise ProviderError(f"{prefix}_MAX_OUTPUT_TOKENS must be from 32 to 4000")
    return value


def _stage_pricing(prefix: str) -> ModelPricing | None:
    try:
        from .llm_usage import pricing_from_env
    except ImportError:
        from llm_usage import pricing_from_env
    try:
        return pricing_from_env(prefix)
    except ValueError as exc:
        raise ProviderError(str(exc)) from exc


def _require_text(value: Any, provider: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProviderError(f"{provider} returned no text")
    return value.strip()


def _cli_name(command: str) -> str:
    """Normalise Windows npm shims (for example gemini.cmd) and executables."""
    return os.path.splitext(os.path.basename(command))[0].lower()
