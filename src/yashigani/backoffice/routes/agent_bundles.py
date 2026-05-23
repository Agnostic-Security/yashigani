"""
Yashigani Backoffice — Optional agent bundle registry (v0.8.0).

Last updated: 2026-05-02T09:00:00+01:00

These routes expose metadata about the third-party agent containers that users
can opt-in to at install time.  No bundle is installed or removed via this API
— that is handled by the installer / Helm values.  The API exists so the
backoffice UI can display bundle status and show the disclaimer banner.

Routes:
  GET /admin/agent-bundles            — list all bundles with metadata
  GET /admin/agent-bundles/disclaimer — the standard disclaimer text
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from yashigani.backoffice.middleware import AdminSession

router = APIRouter()

# ---------------------------------------------------------------------------
# Disclaimer text — single source of truth; displayed at install time,
# in the backoffice banner, and in the docs callout box.
# ---------------------------------------------------------------------------

_DISCLAIMER = (
    "These third-party agent containers are provided AS IS by Agnostic Security "
    "as a courtesy integration. Image digests are pinned to upstream-tagged releases "
    "and updated as part of the Yashigani release cycle. "
    "All support, bug reports, and feature requests must be directed to the "
    "upstream maintainers — Agnostic Security provides no warranty and accepts "
    "no support obligation for these integrations."
)

# ---------------------------------------------------------------------------
# Static bundle catalogue — updated with each Yashigani release when digests
# are pinned.  The `image` field should match docker/docker-compose.yml.
# ---------------------------------------------------------------------------

_BUNDLES: list[dict] = [
    {
        "id": "langflow",
        "name": "Langflow",
        "description": "Visual multi-agent workflow builder by DataStax. Best for: custom AI pipelines, chaining steps, API integrations, reusable automation workflows.",
        "best_for": ["Multi-step workflows", "API chaining", "Data pipelines", "Automation"],
        "example_prompts": [
            "Summarise this document and translate the summary to Portuguese",
            "Check the weather API, then draft an email based on the forecast",
            "Extract key points, classify sentiment, create a report",
        ],
        "upstream_url": "https://github.com/langflow-ai/langflow",
        "license": "MIT",
        "stack": "Python",
        "image": "langflowai/langflow:1.9.0",
        "integration": "OpenAI-compat API → Yashigani Gateway → LLM providers",
        "compose_profile": "langflow",
        "helm_key": "agentBundles.langflow.enabled",
        "size_warning": None,
    },
    {
        "id": "letta",
        "name": "Letta",
        "description": "Stateful agent with persistent memory (formerly MemGPT). Best for: long-running projects, personal assistant tasks, research that builds over time.",
        "best_for": ["Persistent memory", "Long-running projects", "Personal assistant", "Research"],
        "example_prompts": [
            "Remember that our Q2 budget is 50K and the deadline is June 30th",
            "What did we discuss about the security audit last time?",
            "I prefer bullet points over paragraphs — remember that for all future responses",
        ],
        "upstream_url": "https://github.com/letta-ai/letta",
        "license": "Apache-2.0",
        "stack": "Python",
        "image": "letta/letta:0.16.7",
        "integration": "REST API → Yashigani Gateway → LLM providers",
        "compose_profile": "letta",
        "helm_key": "agentBundles.letta.enabled",
        "size_warning": None,
    },
    # Goose removed — ACP protocol too slow on CPU (~300s per request).
    # CrewAI removed — enterprise-only feature (no public Docker image available).
    {
        "id": "openclaw",
        "name": "OpenClaw",
        "description": (
            "Connected AI agent with 30+ messaging channel integrations and web access. "
            "Best for: web search, code execution, file management, Slack/Teams/email integration."
        ),
        "best_for": ["Web search", "Code execution", "File management", "Messaging channels"],
        "example_prompts": [
            "Search the web for the latest OWASP Top 10 changes and summarise them",
            "Write a Python script that parses a CSV and finds duplicates",
            "Draft a Slack message announcing the new security policy",
        ],
        "upstream_url": "https://openclaw.ai",
        "license": "MIT",
        "stack": "Node.js 24",
        "image": "ghcr.io/openclaw/openclaw:2026.3.1",
        "integration": "OpenClaw Gateway (:18789) → Yashigani Gateway → LLM providers",
        "compose_profile": "openclaw",
        "helm_key": "agentBundles.openclaw.enabled",
        "size_warning": (
            "Node.js 24 image is approximately 800 MB — significantly larger than "
            "the Python agent images (~200 MB). Ensure sufficient disk space."
        ),
    },
]


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class AgentBundleResponse(BaseModel):
    id: str
    name: str
    description: str
    upstream_url: str
    license: str
    stack: str
    image: str
    integration: str
    compose_profile: str
    helm_key: str
    size_warning: Optional[str]


class AgentBundleListResponse(BaseModel):
    bundles: list[AgentBundleResponse]
    disclaimer: str


class DisclaimerResponse(BaseModel):
    disclaimer: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", response_model=AgentBundleListResponse)
async def list_agent_bundles(session: AdminSession):
    """Return all available optional agent bundles with their metadata and disclaimer."""
    return AgentBundleListResponse(
        bundles=[AgentBundleResponse(**b) for b in _BUNDLES],
        disclaimer=_DISCLAIMER,
    )


@router.get("/disclaimer", response_model=DisclaimerResponse)
async def get_disclaimer(session: AdminSession):
    """Return the standard third-party agent bundle disclaimer for use in UI banners."""
    return DisclaimerResponse(disclaimer=_DISCLAIMER)
