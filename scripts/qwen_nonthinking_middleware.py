"""Enforce the local pilot's thinking mode before vLLM renders or parses."""

from __future__ import annotations

import json
import logging
import os
from typing import Any


class NonThinkingMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app
        self.enabled = False
        self.sampling: dict[str, Any] = {}

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") not in ("/v1/messages", "/v1/messages/count_tokens")
        ):
            await self.app(scope, receive, send)
            return
        chunks = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        raw = b"".join(chunks)
        try:
            body = json.loads(raw)
            original = {
                "thinking": body.get("thinking"),
                "output_config": body.get("output_config"),
            }
            body["thinking"] = {"type": "adaptive" if self.enabled else "disabled"}
            body["chat_template_kwargs"] = {
                **(body.get("chat_template_kwargs") or {}),
                "enable_thinking": self.enabled,
            }
            if scope["path"] == "/v1/messages":
                for key in ("temperature", "top_p", "top_k"):
                    if key in self.sampling:
                        body[key] = self.sampling[key]
            raw = json.dumps(body).encode()
            logging.getLogger("vllm").info(
                "Pilot thinking=%s sampling=%s enforced; incoming=%s",
                self.enabled,
                self.sampling,
                original,
            )
        except (ValueError, TypeError, AttributeError):
            pass
        scope = dict(scope)
        scope["headers"] = [
            (k, v) for k, v in scope["headers"] if k.lower() != b"content-length"
        ] + [(b"content-length", str(len(raw)).encode())]
        delivered = False

        async def rewritten_receive() -> Any:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        await self.app(scope, rewritten_receive, send)


class QwenPilotMiddleware(NonThinkingMiddleware):
    def __init__(self, app: Any) -> None:
        super().__init__(app)
        policy = json.loads(os.environ["QWEN_PILOT_POLICY"])
        if policy["thinking"] not in ("enabled", "disabled"):
            raise ValueError("invalid pilot thinking policy")
        self.enabled = policy["thinking"] == "enabled"
        self.sampling = policy["sampling"]
