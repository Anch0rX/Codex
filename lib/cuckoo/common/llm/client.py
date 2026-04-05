"""HTTP client for OpenAI-compatible LLM endpoint."""

from __future__ import annotations

import json
import logging
import ssl
from typing import Any, Dict, Optional
from urllib import error, request

LOGGER = logging.getLogger(__name__)


class LLMClient:
    """OpenAI-compatible chat completion client with graceful failures."""

    def __init__(self, provider: str, endpoint: str, api_key: str, model: str, timeout: int = 120, verify_tls: bool = True):
        self.provider = provider
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.verify_tls = verify_tls

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.verify_tls:
            return None
        return ssl._create_unverified_context()

    def _post_json(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(self.endpoint, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.api_key:
            req.add_header("Authorization", "Bearer %s" % self.api_key)

        with request.urlopen(req, timeout=self.timeout, context=self._ssl_context()) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)

    def chat_completion(self, system_prompt: str, user_prompt: str, temperature: float = 0.0, max_tokens: int = 2200) -> Dict[str, Any]:
        """Call remote provider and return either content or structured error."""
        if self.provider != "openai_compatible":
            return {"ok": False, "error": "unsupported_provider", "details": self.provider}

        payload = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
        }

        try:
            body = self._post_json(payload)
        except TimeoutError:
            LOGGER.warning("LLM request timeout provider=%s", self.provider)
            return {"ok": False, "error": "timeout"}
        except error.HTTPError as exc:
            LOGGER.warning("LLM HTTP failure provider=%s code=%s", self.provider, exc.code)
            return {"ok": False, "error": "http_error", "details": str(exc.code)}
        except error.URLError as exc:
            LOGGER.warning("LLM endpoint unreachable provider=%s", self.provider)
            return {"ok": False, "error": "connection_error", "details": str(exc.reason)}
        except ValueError:
            LOGGER.warning("LLM returned invalid JSON provider=%s", self.provider)
            return {"ok": False, "error": "invalid_response"}
        except OSError as exc:
            LOGGER.warning("LLM request OS error provider=%s", self.provider)
            return {"ok": False, "error": "io_error", "details": str(exc)}

        choices = body.get("choices", []) if isinstance(body, dict) else []
        if not isinstance(choices, list) or not choices:
            return {"ok": False, "error": "empty_response"}
        content = ((choices[0] or {}).get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            return {"ok": False, "error": "empty_content"}
        return {"ok": True, "content": content}
