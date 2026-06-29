"""
Unit tests — license /activate endpoint JSON body (4.0 fixup).

Verifies that:
  1. activate_license accepts ActivateRequest (JSON body), not Form/File.
  2. The ActivateRequest model is importable and has license_content field.
  3. The endpoint function 'body' parameter is annotated ActivateRequest.
  4. No Form / File / UploadFile are imported into license.py.
  5. StepUp dependency is still applied to session.

Note: license.py uses ``from __future__ import annotations`` so parameter
annotations are strings at runtime. We check the string annotation value.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import inspect

import pytest


class TestActivateLicenseJsonBody:
    """activate_license must accept JSON body, not multipart form."""

    def test_activate_request_model_importable(self):
        from yashigani.backoffice.routes.license import ActivateRequest
        req = ActivateRequest(license_content="some-key")
        assert req.license_content == "some-key"

    def test_activate_request_optional_content(self):
        from yashigani.backoffice.routes.license import ActivateRequest
        req = ActivateRequest()
        assert req.license_content is None

    def test_activate_endpoint_has_body_parameter(self):
        """activate_license must have a 'body' parameter (JSON body)."""
        from yashigani.backoffice.routes.license import activate_license

        sig = inspect.signature(activate_license)
        assert "body" in sig.parameters, (
            "activate_license must accept 'body: ActivateRequest'"
        )

    def test_activate_endpoint_body_annotation_is_activate_request_string(self):
        """The 'body' parameter annotation must be 'ActivateRequest' (string form)."""
        from yashigani.backoffice.routes.license import activate_license

        sig = inspect.signature(activate_license)
        body_param = sig.parameters["body"]
        ann = body_param.annotation
        # PEP 563: annotation is stored as string
        assert ann in ("ActivateRequest", "yashigani.backoffice.routes.license.ActivateRequest"), (
            f"body annotation must be ActivateRequest, got: {ann!r}"
        )

    def test_activate_endpoint_has_no_form_file_params(self):
        """No license_content or license_file top-level parameters (old Form/File params)."""
        from yashigani.backoffice.routes.license import activate_license

        sig = inspect.signature(activate_license)
        param_names = list(sig.parameters.keys())

        for forbidden in ("license_content", "license_file"):
            assert forbidden not in param_names, (
                f"activate_license must not have top-level param '{forbidden}'; "
                "those were Form/File params and have been replaced by 'body: ActivateRequest'"
            )

    def test_activate_endpoint_no_form_import(self):
        """Form / File / UploadFile must not be importable from license.py namespace."""
        import yashigani.backoffice.routes.license as lic_mod

        for name in ("Form", "File", "UploadFile"):
            assert not hasattr(lic_mod, name), (
                f"license.py must not import fastapi.{name} "
                "(endpoint was converted to JSON body)"
            )

    def test_stepup_dep_still_applied(self):
        """require_stepup_admin_session must still be on activate_license session param."""
        from yashigani.backoffice.routes.license import activate_license
        from yashigani.backoffice.middleware import require_stepup_admin_session

        sig = inspect.signature(activate_license)
        session_param = sig.parameters.get("session")
        assert session_param is not None

        default = session_param.default
        assert default is not inspect.Parameter.empty, (
            "session parameter must have a Depends() default"
        )
        assert default.dependency is require_stepup_admin_session, (
            "activate_license must still require step-up admin session"
        )
