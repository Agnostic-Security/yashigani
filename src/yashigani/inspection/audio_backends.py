"""
Yashigani Inspection — audio transcription backends (T4b, 5.0).

Concrete backends for A6-audio. A backend implements transcribe(data, fmt)->str
and is wrapped by AudioTranscriber. Ollama (whisper-class models exposed via the
local ollama server) is the default local-only path, consistent with the
"detection never leaves the estate" posture.

Live-stack note: the exact ollama transcription endpoint/model depends on the
installed whisper model; the request/parse shape here follows the documented
ollama audio API. The bytes→base64 packaging + response parse are unit-testable;
the live call is verified on the rig.
"""
from __future__ import annotations

import base64
import logging

logger = logging.getLogger(__name__)


class OllamaTranscriber:
    """Transcribe audio via a local ollama whisper-class model. Local-only —
    audio never egresses. Raises on any failure so AudioTranscriber fails
    closed (audio is never passed uninspected)."""

    def __init__(
        self,
        base_url: str = "http://ollama:11434",
        model: str = "whisper",
        timeout: float = 60.0,
    ) -> None:
        self._base_url = base_url
        self._model = model
        self._timeout = timeout

    def transcribe(self, data: bytes, fmt: str) -> str:
        from yashigani.inspection._ollama_transport import ollama_post_json
        payload = {
            "model": self._model,
            "audio": base64.b64encode(data).decode("ascii"),
            "format": fmt,
            "stream": False,
        }
        resp = ollama_post_json(
            self._base_url, "/api/transcribe", payload, timeout=self._timeout,
        )
        return parse_transcription(resp)


def parse_transcription(resp) -> str:
    """Pure parse of a transcription response → transcript text. Testable.
    Accepts the common shapes ({'text': ...} / {'transcript': ...} /
    {'response': ...}); anything else → ''."""
    if not isinstance(resp, dict):
        return ""
    for key in ("text", "transcript", "response"):
        val = resp.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""
