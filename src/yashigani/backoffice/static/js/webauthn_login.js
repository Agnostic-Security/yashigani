// Yashigani — WebAuthn / FIDO2 login flow (external JS, CSP-compliant).
// Strict CSP: no inline scripts, no eval, no unsafe-inline.
// Handles the hardware-key authentication path on the admin login page.
//
// ASVS V2.8: challenge single-use enforced server-side.
// Cross-origin attestation: rejected server-side via expected_origin check.
//
// Last updated: 2026-05-07

(function () {
    'use strict';

    // -----------------------------------------------------------------
    // DOM helpers
    // -----------------------------------------------------------------

    function showMsg(type, text) {
        var b = document.getElementById('msg-box');
        if (!b) return;
        b.className = 'msg ' + type + ' visible';
        b.textContent = text;
    }

    function clearMsg() {
        var b = document.getElementById('msg-box');
        if (!b) return;
        b.className = 'msg';
        b.textContent = '';
    }

    function parseError(data) {
        if (!data) return 'Request failed';
        if (typeof data === 'string') return data;
        if (data.detail) {
            if (typeof data.detail === 'string') return data.detail;
            if (data.detail.error) return data.detail.error.replace(/_/g, ' ');
            if (Array.isArray(data.detail)) {
                return data.detail.map(function (d) { return d.msg; }).join(', ');
            }
        }
        return JSON.stringify(data);
    }

    // -----------------------------------------------------------------
    // base64url helpers (WebAuthn uses base64url without padding)
    // -----------------------------------------------------------------

    function base64urlToBuffer(b64url) {
        var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) { b64 += '='; }
        var binary = atob(b64);
        var buf = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            buf[i] = binary.charCodeAt(i);
        }
        return buf.buffer;
    }

    function bufferToBase64url(buf) {
        var bytes = new Uint8Array(buf);
        var binary = '';
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    // -----------------------------------------------------------------
    // Decode PublicKeyCredentialRequestOptions from server JSON
    // (server returns base64url strings; Web API needs ArrayBuffers)
    // -----------------------------------------------------------------

    function decodeAuthOptions(optionsJson) {
        // optionsJson may be a JSON string or already an object
        var opts = (typeof optionsJson === 'string') ? JSON.parse(optionsJson) : optionsJson;
        opts.challenge = base64urlToBuffer(opts.challenge);
        if (opts.allowCredentials) {
            opts.allowCredentials = opts.allowCredentials.map(function (cred) {
                return {
                    type: cred.type,
                    id: base64urlToBuffer(cred.id),
                    transports: cred.transports || [],
                };
            });
        }
        return opts;
    }

    // -----------------------------------------------------------------
    // Serialise PublicKeyCredential assertion for the server
    // -----------------------------------------------------------------

    function serialiseAssertion(credential) {
        var response = credential.response;
        return {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: bufferToBase64url(response.authenticatorData),
                clientDataJSON: bufferToBase64url(response.clientDataJSON),
                signature: bufferToBase64url(response.signature),
                userHandle: response.userHandle
                    ? bufferToBase64url(response.userHandle)
                    : null,
            },
        };
    }

    // -----------------------------------------------------------------
    // Main WebAuthn login flow
    // -----------------------------------------------------------------

    async function doWebAuthnLogin(username, btn) {
        clearMsg();
        btn.disabled = true;
        btn.textContent = 'Waiting for security key…';

        try {
            // Step 1: get challenge from server
            var startResp = await fetch('/api/v1/admin/webauthn/login/start', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username }),
            });

            if (!startResp.ok) {
                var errData = await startResp.json().catch(function () { return {}; });
                showMsg('error', parseError(errData) || 'No security key registered for this account.');
                return;
            }

            var startData = await startResp.json();
            var userId = startData.user_id;
            var authOptions = decodeAuthOptions(startData.options);

            // Step 2: invoke browser WebAuthn API — prompts for key touch
            var credential;
            try {
                credential = await navigator.credentials.get({ publicKey: authOptions });
            } catch (e) {
                // User cancelled, key not present, etc.
                showMsg('error', 'Security key authentication cancelled or failed: ' + e.message);
                return;
            }

            if (!credential) {
                showMsg('error', 'No credential returned from security key.');
                return;
            }

            // Step 3: send assertion to server
            var assertion = serialiseAssertion(credential);
            var finishResp = await fetch('/api/v1/admin/webauthn/login/finish', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, credential_response: assertion }),
            });

            if (finishResp.ok) {
                // Session cookie set by server — redirect to dashboard
                var params = new URLSearchParams(window.location.search);
                var next = params.get('next');
                window.location.href = safeNext(next) || '/admin/';
            } else {
                var finishErr = await finishResp.json().catch(function () { return {}; });
                showMsg('error', 'Security key authentication failed. ' + parseError(finishErr));
            }
        } catch (err) {
            showMsg('error', 'Connection error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Sign in with Security Key';
        }
    }

    // -----------------------------------------------------------------
    // safeNext — identical to login.js (open-redirect guard)
    // ASVS V5.1.5, OWASP A01:2021, CWE-601
    // -----------------------------------------------------------------

    function safeNext(rawNext) {
        if (!rawNext) return '/';
        if (!/^\/[^/\\]/.test(rawNext)) return '/';
        try {
            var parsed = new URL(rawNext, window.location.origin);
            if (parsed.origin !== window.location.origin) return '/';
            if (parsed.protocol !== window.location.protocol) return '/';
            return parsed.pathname + parsed.search + parsed.hash;
        } catch (e) {
            return '/';
        }
    }

    // -----------------------------------------------------------------
    // Availability check — hide the WebAuthn option if not supported
    // -----------------------------------------------------------------

    function isWebAuthnSupported() {
        return !!(window.PublicKeyCredential &&
            typeof navigator.credentials !== 'undefined' &&
            typeof navigator.credentials.get === 'function');
    }

    // -----------------------------------------------------------------
    // Initialise on DOMContentLoaded
    // -----------------------------------------------------------------

    document.addEventListener('DOMContentLoaded', function () {
        var waSection = document.getElementById('webauthn-section');
        if (!waSection) return;

        if (!isWebAuthnSupported()) {
            waSection.style.display = 'none';
            return;
        }

        var waBtn = document.getElementById('webauthn-login-btn');
        if (!waBtn) return;

        waBtn.addEventListener('click', function () {
            var usernameField = document.getElementById('username');
            var username = usernameField ? usernameField.value.trim() : '';
            if (!username) {
                showMsg('error', 'Enter your username before using a security key.');
                if (usernameField) usernameField.focus();
                return;
            }
            doWebAuthnLogin(username, waBtn);
        });
    });

}());
