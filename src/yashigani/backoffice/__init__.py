"""Yashigani Backoffice — Admin control plane."""
from yashigani.backoffice.state import backoffice_state, BackofficeState

__all__ = ["create_backoffice_app", "backoffice_state", "BackofficeState"]


def __getattr__(name: str):
    # Lazy re-export (PEP 562). Importing ``app`` eagerly here dragged the full
    # backoffice FastAPI app — and its module-level Prometheus metric
    # registration (yashigani_backoffice_requests_*) — into every process that
    # only needs ``backoffice.state`` (the gateway reaches it via
    # licensing.verifier and the credential-exfil alert path). When app.py was
    # re-executed after a partial import, that produced
    # "Duplicated timeseries in CollectorRegistry" on every exfil detection.
    # Deferring the import keeps ``from yashigani.backoffice import
    # create_backoffice_app`` working without that side effect.
    if name == "create_backoffice_app":
        from yashigani.backoffice.app import create_backoffice_app

        return create_backoffice_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
