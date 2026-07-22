"""
Yashigani Inspection — audio transcription for reuse of the text controls (A6-audio, 5.0).

Register decision (Tiago 2026-07-14): voice input is transcribed to text, then
the EXISTING injection / PII / secret / sensitivity pipeline runs on the
transcript — no new inspection logic, the cheapest expansion of the coverage
claim to voice.

Fail-closed contract: if a request carries audio but transcription is
unavailable or errors, the audio must NOT pass uninspected. The caller blocks
(the honest "we don't ship un-inspected audio" posture) rather than forwarding
opaque audio to the model.

This module is backend-agnostic: `AudioTranscriber` wraps any object exposing
`transcribe(data: bytes, fmt: str) -> str` (e.g. a local whisper/ollama
endpoint). The concrete backend + its wiring is a live-stack concern; the
block-when-absent gate and the transcript-fold logic are here and fully tested.
"""
from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)

# OpenAI-compatible audio content block:
#   {"type": "input_audio", "input_audio": {"data": "<base64>", "format": "wav"}}
_AUDIO_BLOCK_TYPE = "input_audio"
_MAX_AUDIO_BYTES = 25 * 1024 * 1024  # 25 MB — matches common transcription limits


class TranscriptionUnavailableError(Exception):
    """Transcription could not run — the caller MUST fail closed (block)."""


class TranscriptionBackend(Protocol):
    def transcribe(self, data: bytes, fmt: str) -> str: ...


@dataclass
class AudioBlock:
    data_b64: str
    fmt: str

    def decode(self) -> bytes:
        try:
            raw = base64.b64decode(self.data_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise TranscriptionUnavailableError(f"invalid base64 audio: {exc}") from exc
        if not raw:
            raise TranscriptionUnavailableError("empty audio payload")
        if len(raw) > _MAX_AUDIO_BYTES:
            raise TranscriptionUnavailableError(
                f"audio exceeds {_MAX_AUDIO_BYTES} bytes")
        return raw


@dataclass
class ExtractResult:
    blocks: list[AudioBlock] = field(default_factory=list)

    @property
    def has_audio(self) -> bool:
        return bool(self.blocks)


def extract_audio_blocks(raw_content: Any) -> ExtractResult:
    """Pull input_audio blocks out of a message's *original* list-form content.

    Accepts the list form only (a plain string never carries audio). Unknown
    block shapes are ignored — only well-formed input_audio blocks are returned.
    """
    result = ExtractResult()
    if not isinstance(raw_content, list):
        return result
    for block in raw_content:
        if not isinstance(block, dict):
            continue
        if block.get("type") != _AUDIO_BLOCK_TYPE:
            continue
        audio = block.get("input_audio") or {}
        data = audio.get("data")
        fmt = (audio.get("format") or "wav").lower()
        if isinstance(data, str) and data:
            result.blocks.append(AudioBlock(data_b64=data, fmt=fmt))
    return result


class AudioTranscriber:
    """Transcribes audio blocks to text. `configured` is False when no backend
    is wired — callers use that to fail closed on audio rather than pass it
    uninspected."""

    def __init__(self, backend: Optional[TranscriptionBackend] = None) -> None:
        self._backend = backend

    @property
    def configured(self) -> bool:
        return self._backend is not None

    def transcribe_blocks(self, blocks: list[AudioBlock]) -> str:
        """Transcribe every block and join the transcripts. Raises
        TranscriptionUnavailableError on any failure (fail-closed)."""
        if self._backend is None:
            raise TranscriptionUnavailableError("no transcription backend configured")
        parts: list[str] = []
        for i, block in enumerate(blocks):
            raw = block.decode()
            try:
                text = self._backend.transcribe(raw, block.fmt)
            except Exception as exc:  # noqa: BLE001 — normalize to fail-closed
                raise TranscriptionUnavailableError(
                    f"transcription backend failed on block {i}: {exc}") from exc
            if text:
                parts.append(text.strip())
        transcript = "\n".join(p for p in parts if p)
        logger.info(
            "A6-audio: transcribed %d audio block(s) → %d transcript chars",
            len(blocks), len(transcript),
        )
        return transcript
