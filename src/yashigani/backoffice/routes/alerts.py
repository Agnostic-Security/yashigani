"""
Yashigani Backoffice — Alert sink configuration + custom alert rules (v2.25.5).

Last updated: 2026-06-13T00:00:00+01:00

Routes:
  GET  /admin/alerts/config                   — current sink configuration (URLs masked)
  PUT  /admin/alerts/config                   — update sink configuration
  POST /admin/alerts/test/{sink}              — send a test alert to a specific sink

R17 — Budget threshold alert (default 85%, enabled by default):
  GET  /admin/alerts/budget-threshold         — get current budget alert threshold config
  PUT  /admin/alerts/budget-threshold         — update budget alert threshold config

R18 — Custom alert CRUD:
  GET  /admin/alerts/custom                   — list all custom alert rules
  POST /admin/alerts/custom                   — create a custom alert rule
  GET  /admin/alerts/custom/{alert_id}        — get a single custom alert rule
  PUT  /admin/alerts/custom/{alert_id}        — update a custom alert rule
  DELETE /admin/alerts/custom/{alert_id}      — delete a custom alert rule
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Path, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models — sink config
# ---------------------------------------------------------------------------

class AlertConfigRequest(BaseModel):
    slack_webhook_url: str = Field(
        default="",
        description="Slack incoming webhook URL. Empty = disabled.",
    )
    teams_webhook_url: str = Field(
        default="",
        description="Microsoft Teams incoming webhook URL. Empty = disabled.",
    )
    pagerduty_routing_key: str = Field(
        default="",
        description="PagerDuty Events API v2 routing key. Empty = disabled.",
    )
    # Alert trigger config
    alert_on_credential_exfil: bool = True
    alert_on_anomaly_threshold: bool = True
    license_expiry_warning_days: int = Field(default=14, ge=1, le=90)
    license_limit_warning_pct: int = Field(default=90, ge=50, le=99)


# ---------------------------------------------------------------------------
# R17 — Budget threshold alert models
# ---------------------------------------------------------------------------

class BudgetThresholdAlertConfig(BaseModel):
    """
    R17: Alert when token budget used >= threshold_pct of the limit.

    Defaults: enabled=True, threshold_pct=85.
    This replaces exhaustion-only alerting: operators are warned before the
    budget runs out, not only when it is exhausted.
    """
    enabled: bool = Field(
        default=True,
        description="Enable budget-threshold alerts. Default: True.",
    )
    threshold_pct: int = Field(
        default=85,
        ge=1,
        le=99,
        description=(
            "Alert when budget used >= this percentage. "
            "Default 85 (fire at 85% used, not 100%)."
        ),
    )


# ---------------------------------------------------------------------------
# R18 — Custom alert rule models
# ---------------------------------------------------------------------------

_ALLOWED_CHANNELS = frozenset({"slack", "teams", "pagerduty", "webhook"})
_ALLOWED_TRIGGER_TYPES = frozenset({
    "budget_threshold",       # used_pct >= threshold
    "budget_exhausted",       # used == 100%
    "anomaly_score",          # anomaly score >= threshold
    "policy_violation",       # OPA policy fires > N times per interval
    "login_failure_rate",     # admin login failures >= threshold per interval
    "user_session_anomaly",   # unusual session pattern
    "custom",                 # operator-defined free-form condition
})


class CustomAlertCondition(BaseModel):
    """Condition for a custom alert rule."""
    field: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Metric or event field to evaluate (e.g. 'budget_used_pct', "
            "'anomaly_score', 'login_failures_per_hour')."
        ),
    )
    operator: str = Field(
        pattern=r"^(gte|gt|lte|lt|eq|neq)$",
        description="Comparison operator: gte, gt, lte, lt, eq, neq.",
    )
    threshold: float = Field(
        description="Numeric threshold value.",
    )


class CustomAlertChannel(BaseModel):
    """Delivery channel for a custom alert."""
    type: str = Field(
        pattern=r"^(slack|teams|pagerduty|webhook)$",
        description="Delivery channel type.",
    )
    webhook_url: Optional[str] = Field(
        default=None,
        description=(
            "Override webhook URL for this rule. If omitted, uses the globally "
            "configured sink URL. Required when type='webhook'."
        ),
    )


class CreateCustomAlertRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    trigger_type: str = Field(
        pattern=r"^(budget_threshold|budget_exhausted|anomaly_score|policy_violation|login_failure_rate|user_session_anomaly|custom)$",
    )
    condition: CustomAlertCondition
    channels: list[CustomAlertChannel] = Field(
        default_factory=list,
        description="Delivery channels. Uses globally configured sinks when empty.",
    )
    enabled: bool = Field(default=True)
    cooldown_minutes: int = Field(
        default=60,
        ge=1,
        le=10080,  # max 1 week
        description="Minimum interval (minutes) between consecutive firings of this rule.",
    )


class UpdateCustomAlertRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    trigger_type: Optional[str] = Field(
        default=None,
        pattern=r"^(budget_threshold|budget_exhausted|anomaly_score|policy_violation|login_failure_rate|user_session_anomaly|custom)$",
    )
    condition: Optional[CustomAlertCondition] = None
    channels: Optional[list[CustomAlertChannel]] = None
    enabled: Optional[bool] = None
    cooldown_minutes: Optional[int] = Field(default=None, ge=1, le=10080)


class CustomAlertRule(BaseModel):
    """Stored custom alert rule (includes server-assigned fields)."""
    id: str
    name: str
    description: str
    trigger_type: str
    condition: CustomAlertCondition
    channels: list[CustomAlertChannel]
    enabled: bool
    cooldown_minutes: int


# ---------------------------------------------------------------------------
# In-process store for custom alerts and budget threshold config.
# Backed by backoffice_state attributes; survives the request lifecycle.
# ---------------------------------------------------------------------------

_BUDGET_THRESHOLD_KEY = "budget_threshold_alert_config"
_CUSTOM_ALERTS_KEY = "custom_alert_rules"


def _get_budget_threshold_config() -> BudgetThresholdAlertConfig:
    """Return current budget threshold alert config. Defaults to enabled/85%."""
    stored = getattr(backoffice_state, _BUDGET_THRESHOLD_KEY, None)
    if stored is None:
        return BudgetThresholdAlertConfig()
    return stored


def _set_budget_threshold_config(cfg: BudgetThresholdAlertConfig) -> None:
    setattr(backoffice_state, _BUDGET_THRESHOLD_KEY, cfg)


def _get_custom_alerts() -> dict[str, CustomAlertRule]:
    """Return {id: CustomAlertRule} dict from backoffice_state."""
    stored = getattr(backoffice_state, _CUSTOM_ALERTS_KEY, None)
    if stored is None:
        stored = {}
        setattr(backoffice_state, _CUSTOM_ALERTS_KEY, stored)
    return stored


# ---------------------------------------------------------------------------
# Helpers — sink config
# ---------------------------------------------------------------------------

def _mask(value: str) -> str:
    """Mask a secret URL/key for display — show only last 6 chars."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return "***" + value[-6:]


def _rebuild_dispatcher(config: AlertConfigRequest) -> None:
    """Rebuild the AlertDispatcher from the new configuration."""
    from yashigani.alerts import AlertDispatcher, configure_dispatcher
    from yashigani.alerts.slack_sink import SlackSink
    from yashigani.alerts.teams_sink import TeamsSink
    from yashigani.alerts.pagerduty_sink import PagerDutySink

    dispatcher = AlertDispatcher()
    if config.slack_webhook_url:
        dispatcher.add_sink(SlackSink(webhook_url=config.slack_webhook_url))
    if config.teams_webhook_url:
        dispatcher.add_sink(TeamsSink(webhook_url=config.teams_webhook_url))
    if config.pagerduty_routing_key:
        dispatcher.add_sink(PagerDutySink(routing_key=config.pagerduty_routing_key))
    configure_dispatcher(dispatcher)

    # Persist config to backoffice state so it survives the request
    backoffice_state.alert_config = config


# ---------------------------------------------------------------------------
# Routes — sink config (existing, unchanged)
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_alert_config(session: AdminSession):
    """Return current alert sink configuration. URLs and keys are masked."""
    config = getattr(backoffice_state, "alert_config", None)
    if config is None:
        return {
            "configured": False,
            "sinks": [],
        }
    sinks = []
    if config.slack_webhook_url:
        sinks.append({"type": "slack", "masked_url": _mask(config.slack_webhook_url)})
    if config.teams_webhook_url:
        sinks.append({"type": "teams", "masked_url": _mask(config.teams_webhook_url)})
    if config.pagerduty_routing_key:
        sinks.append({"type": "pagerduty", "masked_key": _mask(config.pagerduty_routing_key)})
    return {
        "configured": bool(sinks),
        "sinks": sinks,
        "alert_on_credential_exfil": config.alert_on_credential_exfil,
        "alert_on_anomaly_threshold": config.alert_on_anomaly_threshold,
        "license_expiry_warning_days": config.license_expiry_warning_days,
        "license_limit_warning_pct": config.license_limit_warning_pct,
    }


@router.put("/config")
async def update_alert_config(
    body: AlertConfigRequest,
    session: AdminSession,
):
    """Update alert sink configuration and rebuild the dispatcher.

    V232-CSCAN-01b: URL guard is applied inside _rebuild_dispatcher() via the
    SlackSink/TeamsSink constructors. A WebhookUrlForbidden exception is caught
    here and converted to HTTP 400 so the malicious URL is never persisted.
    """
    from yashigani.alerts._url_guard import WebhookUrlForbidden
    try:
        _rebuild_dispatcher(body)
    except WebhookUrlForbidden as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "webhook_url_forbidden", "reason": exc.reason},
        ) from exc

    from yashigani.audit.schema import ConfigChangedEvent
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="alert_sinks",
                previous_value="(previous)",
                new_value=(
                    f"slack={'set' if body.slack_webhook_url else 'disabled'}, "
                    f"teams={'set' if body.teams_webhook_url else 'disabled'}, "
                    f"pagerduty={'set' if body.pagerduty_routing_key else 'disabled'}"
                ),
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for alert config: %s", exc)

    return {"status": "ok", "sinks_configured": sum([
        bool(body.slack_webhook_url),
        bool(body.teams_webhook_url),
        bool(body.pagerduty_routing_key),
    ])}


@router.post("/test/{sink_type}")
async def test_alert_sink(
    session: AdminSession,
    sink_type: str = Path(pattern="^(slack|teams|pagerduty)$"),
):
    """Send a test alert to a specific configured sink."""
    config = getattr(backoffice_state, "alert_config", None)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "no_alert_config", "message": "No alert sinks configured yet."},
        )

    if sink_type == "slack":
        if not config.slack_webhook_url:
            raise HTTPException(status_code=404, detail={"error": "slack_not_configured"})
        from yashigani.alerts.slack_sink import SlackSink
        ok = await SlackSink(config.slack_webhook_url).test()
    elif sink_type == "teams":
        if not config.teams_webhook_url:
            raise HTTPException(status_code=404, detail={"error": "teams_not_configured"})
        from yashigani.alerts.teams_sink import TeamsSink
        ok = await TeamsSink(config.teams_webhook_url).test()
    else:  # pagerduty
        if not config.pagerduty_routing_key:
            raise HTTPException(status_code=404, detail={"error": "pagerduty_not_configured"})
        from yashigani.alerts.pagerduty_sink import PagerDutySink
        ok = await PagerDutySink(config.pagerduty_routing_key).test()

    if not ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "delivery_failed", "sink": sink_type},
        )
    return {"status": "delivered", "sink": sink_type}


# ---------------------------------------------------------------------------
# R17 — Budget threshold alert config
# ---------------------------------------------------------------------------

@router.get(
    "/budget-threshold",
    summary="R17: Get budget threshold alert configuration",
    tags=["alerts"],
)
async def get_budget_threshold_alert(session: AdminSession):
    """
    GET /admin/alerts/budget-threshold

    Returns the current budget-threshold alert configuration.

    Default: enabled=true, threshold_pct=85.
    An alert fires when any identity's token budget usage reaches or exceeds
    threshold_pct of their allocated limit — before exhaustion.
    """
    cfg = _get_budget_threshold_config()
    return {
        "enabled": cfg.enabled,
        "threshold_pct": cfg.threshold_pct,
        "description": (
            f"Alert fires when budget used >= {cfg.threshold_pct}% of the limit."
        ),
    }


@router.put(
    "/budget-threshold",
    summary="R17: Update budget threshold alert configuration",
    tags=["alerts"],
)
async def update_budget_threshold_alert(
    body: BudgetThresholdAlertConfig,
    session: AdminSession,
):
    """
    PUT /admin/alerts/budget-threshold

    Update the budget-threshold alert configuration.

    Persists to backoffice_state. The budget enforcer polls this config
    when evaluating per-identity usage thresholds.
    """
    old_cfg = _get_budget_threshold_config()
    _set_budget_threshold_config(body)

    if backoffice_state.audit_writer is not None:
        try:
            from yashigani.audit.schema import ConfigChangedEvent
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="budget_threshold_alert",
                previous_value=f"enabled={old_cfg.enabled},threshold_pct={old_cfg.threshold_pct}",
                new_value=f"enabled={body.enabled},threshold_pct={body.threshold_pct}",
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for budget threshold: %s", exc)

    return {
        "status": "ok",
        "enabled": body.enabled,
        "threshold_pct": body.threshold_pct,
    }


# ---------------------------------------------------------------------------
# R18 — Custom alert rules CRUD
# ---------------------------------------------------------------------------

@router.get(
    "/custom",
    summary="R18: List all custom alert rules",
    tags=["alerts"],
)
async def list_custom_alerts(session: AdminSession):
    """
    GET /admin/alerts/custom

    Returns all admin-defined custom alert rules.
    """
    rules = _get_custom_alerts()
    return {
        "count": len(rules),
        "custom_alerts": [r.model_dump() for r in rules.values()],
    }


@router.post(
    "/custom",
    status_code=status.HTTP_201_CREATED,
    summary="R18: Create a custom alert rule",
    tags=["alerts"],
)
async def create_custom_alert(
    body: CreateCustomAlertRequest,
    session: AdminSession,
):
    """
    POST /admin/alerts/custom

    Create a new admin-defined alert rule. Returns the created rule including
    the server-assigned ID.

    Trigger types: budget_threshold, budget_exhausted, anomaly_score,
    policy_violation, login_failure_rate, user_session_anomaly, custom.

    Channels: slack, teams, pagerduty, webhook. If channels is empty the
    globally configured sinks are used at fire time.
    """
    alert_id = str(uuid.uuid4())
    rule = CustomAlertRule(
        id=alert_id,
        name=body.name,
        description=body.description,
        trigger_type=body.trigger_type,
        condition=body.condition,
        channels=body.channels,
        enabled=body.enabled,
        cooldown_minutes=body.cooldown_minutes,
    )
    rules = _get_custom_alerts()
    rules[alert_id] = rule

    if backoffice_state.audit_writer is not None:
        try:
            from yashigani.audit.schema import ConfigChangedEvent
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="custom_alert_created",
                previous_value="",
                new_value=f"id={alert_id},name={body.name},trigger={body.trigger_type}",
            ))
        except Exception as exc:
            logger.error("Failed to write audit for custom alert create: %s", exc)

    return rule.model_dump()


@router.get(
    "/custom/{alert_id}",
    summary="R18: Get a single custom alert rule",
    tags=["alerts"],
)
async def get_custom_alert(
    alert_id: str,
    session: AdminSession,
):
    """
    GET /admin/alerts/custom/{alert_id}

    Returns the specified custom alert rule.
    """
    rules = _get_custom_alerts()
    rule = rules.get(alert_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "custom_alert_not_found", "id": alert_id},
        )
    return rule.model_dump()


@router.put(
    "/custom/{alert_id}",
    summary="R18: Update a custom alert rule",
    tags=["alerts"],
)
async def update_custom_alert(
    alert_id: str,
    body: UpdateCustomAlertRequest,
    session: AdminSession,
):
    """
    PUT /admin/alerts/custom/{alert_id}

    Update one or more fields of an existing custom alert rule.
    Only provided fields are updated (partial update semantics).
    """
    rules = _get_custom_alerts()
    rule = rules.get(alert_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "custom_alert_not_found", "id": alert_id},
        )

    changes = []
    data = rule.model_dump()

    if body.name is not None:
        data["name"] = body.name
        changes.append("name")
    if body.description is not None:
        data["description"] = body.description
        changes.append("description")
    if body.trigger_type is not None:
        data["trigger_type"] = body.trigger_type
        changes.append("trigger_type")
    if body.condition is not None:
        data["condition"] = body.condition.model_dump()
        changes.append("condition")
    if body.channels is not None:
        data["channels"] = [c.model_dump() for c in body.channels]
        changes.append("channels")
    if body.enabled is not None:
        data["enabled"] = body.enabled
        changes.append("enabled")
    if body.cooldown_minutes is not None:
        data["cooldown_minutes"] = body.cooldown_minutes
        changes.append("cooldown_minutes")

    updated_rule = CustomAlertRule(**data)
    rules[alert_id] = updated_rule

    if backoffice_state.audit_writer is not None:
        try:
            from yashigani.audit.schema import ConfigChangedEvent
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="custom_alert_updated",
                previous_value="",
                new_value=f"id={alert_id},changed={','.join(changes)}",
            ))
        except Exception as exc:
            logger.error("Failed to write audit for custom alert update: %s", exc)

    return updated_rule.model_dump()


@router.delete(
    "/custom/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="R18: Delete a custom alert rule",
    tags=["alerts"],
)
async def delete_custom_alert(
    alert_id: str,
    session: AdminSession,
):
    """
    DELETE /admin/alerts/custom/{alert_id}

    Permanently removes the specified custom alert rule.
    """
    rules = _get_custom_alerts()
    if alert_id not in rules:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "custom_alert_not_found", "id": alert_id},
        )
    del rules[alert_id]

    if backoffice_state.audit_writer is not None:
        try:
            from yashigani.audit.schema import ConfigChangedEvent
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="custom_alert_deleted",
                previous_value=alert_id,
                new_value="",
            ))
        except Exception as exc:
            logger.error("Failed to write audit for custom alert delete: %s", exc)
