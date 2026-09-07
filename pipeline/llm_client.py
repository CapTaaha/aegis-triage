"""Provider-agnostic LLM client used by the discovery and triage pipeline."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Optional


def _post_json(url: str, payload: dict, headers: Optional[dict] = None) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def generate(prompt: str, system: Optional[str] = None, provider: Optional[str] = None) -> str:
    selected = (provider or os.getenv("AEGIS_LLM_PROVIDER", "mock")).lower()
    system_prompt = system or "You are a cautious application-security reviewer. Return valid JSON only."

    if selected == "mock":
        return json.dumps({"provider": "mock", "message": "Deterministic heuristic analysis used."})

    if selected == "ollama":
        base_url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
        model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
        result = _post_json(
            f"{base_url}/api/generate",
            {"model": model, "system": system_prompt, "prompt": prompt, "stream": False},
        )
        return result["response"]

    if selected == "groq":
        api_key = os.environ["GROQ_API_KEY"]
        model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        result = _post_json(
            "https://api.groq.com/openai/v1/chat/completions",
            {"model": model, "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}], "response_format": {"type": "json_object"}},
            {"Authorization": f"Bearer {api_key}"},
        )
        return result["choices"][0]["message"]["content"]

    if selected == "gemini":
        api_key = os.environ["GEMINI_API_KEY"]
        model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        result = _post_json(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
            {"systemInstruction": {"parts": [{"text": system_prompt}]}, "contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"responseMimeType": "application/json"}},
        )
        return result["candidates"][0]["content"]["parts"][0]["text"]

    raise ValueError(f"Unsupported LLM provider: {selected}")
