import os
import unittest
from unittest.mock import patch

from src.llm_providers import AnthropicProvider, CliProvider, GeminiCliProvider, OllamaProvider, ProviderError, provider_from_env, qa_provider_from_env
from src.llm_usage import ModelPricing


class ProviderTests(unittest.TestCase):
    def test_cli_provider_rejects_non_allowlisted_executable(self):
        with self.assertRaises(ProviderError):
            CliProvider("powershell -Command anything")

    def test_gemini_cli_provider_rejects_a_non_gemini_command(self):
        with self.assertRaises(ProviderError):
            GeminiCliProvider("claude -p")

    def test_factory_defaults_to_ollama(self):
        previous = os.environ.pop("LLM_PROVIDER", None)
        try:
            self.assertEqual(type(provider_from_env()).__name__, "OllamaProvider")
        finally:
            if previous:
                os.environ["LLM_PROVIDER"] = previous

    def test_qa_factory_can_use_a_separate_provider(self):
        previous_provider, previous_model = os.environ.get("QA_PROVIDER"), os.environ.get("QA_MODEL")
        os.environ["QA_PROVIDER"], os.environ["QA_MODEL"] = "ollama", "qa-model"
        try:
            provider = qa_provider_from_env()
            self.assertEqual(provider.model, "qa-model")
        finally:
            if previous_provider is None:
                os.environ.pop("QA_PROVIDER", None)
            else:
                os.environ["QA_PROVIDER"] = previous_provider
            if previous_model is None:
                os.environ.pop("QA_MODEL", None)
            else:
                os.environ["QA_MODEL"] = previous_model

    def test_ollama_request_uses_bounded_context_and_output(self):
        provider = OllamaProvider("llama3.2")
        captured = {}
        def fake_post(url, headers, body):
            captured.update(body)
            return {"response": '{"verdict":"inconclusive"}'}
        provider._post = fake_post  # type: ignore[method-assign]
        provider._generate("test", "json")
        self.assertEqual(captured["options"]["num_ctx"], 4096)
        self.assertEqual(captured["options"]["num_predict"], 800)
        self.assertEqual(captured["format"], "json")

    def test_ollama_assessment_prompt_is_sent_unchanged(self):
        provider = OllamaProvider("llama3.2")
        captured = {}
        provider._post = lambda url, headers, body: (captured.update(body) or {"response": "{}"})  # type: ignore[method-assign]
        provider.assess_prompt("exact audited prompt")
        self.assertEqual(captured["prompt"], "exact audited prompt")

    def test_http_provider_serializes_a_request_payload(self):
        """Protect the actual network path, not only the mocked generator."""
        captured = {}

        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return b'{"response":"ok"}'

        def fake_urlopen(request, timeout):
            captured["body"] = request.data.decode("utf-8")
            captured["timeout"] = timeout
            return Response()

        provider = OllamaProvider("llama3.2")
        with patch("src.llm_providers.urlopen", fake_urlopen):
            result = provider._post("http://example.invalid", {}, {"check": "value"})
        self.assertEqual(result["response"], "ok")
        self.assertEqual(captured["body"], '{"check": "value"}')

    def test_anthropic_records_actual_usage_and_honors_output_cap(self):
        provider = AnthropicProvider("claude-test", "not-a-real-key", max_output_tokens=350, pricing=ModelPricing(2, 10))
        captured = {}
        def fake_post(url, headers, body):
            captured.update(body)
            return {"content": [{"type": "text", "text": "{}"}], "usage": {"input_tokens": 123, "output_tokens": 45}}
        provider._post = fake_post  # type: ignore[method-assign]
        self.assertEqual(provider._generate("test"), "{}")
        self.assertEqual(captured["max_tokens"], 350)
        self.assertEqual(provider.last_usage, {"input_tokens": 123, "output_tokens": 45})

    def test_sonnet_five_omits_non_default_temperature(self):
        provider = AnthropicProvider("claude-sonnet-5", "not-a-real-key")
        captured = {}
        provider._post = lambda url, headers, body: (captured.update(body) or {"content": [{"type": "text", "text": "{}"}], "usage": {"input_tokens": 1, "output_tokens": 1}})  # type: ignore[method-assign]
        provider._generate("test")
        self.assertNotIn("temperature", captured)

if __name__ == "__main__":
    unittest.main()
