"""
Yashigani Inspection — audio transcription backends (T4b, 5.0).

Concrete backend for A6-audio. A backend implements transcribe(data, fmt)->str
and is wrapped by AudioTranscriber.

HONESTY NOTE: Ollama does not expose a native audio-transcription endpoint, so
there is no "ollama transcribe" to call. Instead this is an OpenAI-compatible
transcription client (POST multipart to <base>/v1/audio/transcriptions), which
is what local whisper servers (whisper.cpp `server`, faster-whisper, LocalAI,
speaches, etc.) implement. Point YASHIGANI_AUDIO_TRANSCRIBE_URL at a LOCAL such
server so audio never egresses. The multipart packaging + response parse are
unit-tested; the live call is verified on the rig against the chosen server.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# audio fmt → a sensible upload filename (some servers key on the extension).
_FMT_EXT = {"wav": "wav", "mp3": "mp3", "m4a": "m4a", "ogg": "ogg",
            "flac": "flac", "webm": "webm", "mpeg": "mp3", "mp4": "m4a"}


class OpenAITranscriptionBackend:
    """Transcribe audio via an OpenAI-compatible /v1/audio/transcriptions
    endpoint on a LOCAL whisper server. Raises on any failure so
    AudioTranscriber fails closed (audio is never passed uninspected)."""

    def __init__(
        self,
        base_url: str = "http://whisper:8000",
        model: str = "whisper-1",
        timeout: float = 60.0,
        api_key: str = "",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._api_key = api_key

    def transcribe(self, data: bytes, fmt: str) -> str:
        import httpx

        ext = _FMT_EXT.get((fmt or "wav").lower(), "wav")
        files = {"file": (f"audio.{ext}", data, f"audio/{ext}")}
        payload = {"model": self._model, "response_format": "json"}
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        url = f"{self._base_url}/v1/audio/transcriptions"
        resp = httpx.post(
            url, files=files, data=payload, headers=headers, timeout=self._timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"transcription server returned {resp.status_code}: {resp.text[:200]}")
        return parse_transcription(resp.json())


def parse_transcription(resp) -> str:
    """Pure parse of a transcription response → transcript text. Testable.
    OpenAI shape is {'text': ...}; also accepts {'transcript'|'response': ...}."""
    if not isinstance(resp, dict):
        return ""
    for key in ("text", "transcript", "response"):
        val = resp.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""
