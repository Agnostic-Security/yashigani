// Last updated: 2026-06-12 (Phase 1: role-based redirect via server-supplied redirect_to)
document.addEventListener('DOMContentLoaded', function() {
    var savedPassword = '';

    /**
     * safeNext — validate a `next` redirect parameter before using it.
     *
     * V232-CSCAN-01d: the old guard (startsWith('/') && !startsWith('//'))
     * admitted `/\attacker.com` because the backslash passes both checks, but
     * browsers normalise `/\…` → `//…` in location.assign(), producing an
     * off-origin redirect.
     *
     * This function closes that bypass with two independent layers:
     *   1. Regex: must start with exactly one `/` followed by a char that is
     *      neither `/` nor `\` (blocks `//`, `/\`, `///`, `/\\`, etc.)
     *   2. URL parse: construct a URL against the current origin; reject if
     *      the parsed origin differs, if the protocol differs, or if parse
     *      throws (malformed input).
     *
     * Returns the sanitised path+search+hash on-origin string, or '/' if
     * the input fails either check (including falsy/empty input).
     *
     * Call-site contract (BUG-LOGIN-REDIRECT-01 — v2.23.3): callers that need
     * a different default when there is NO next param (e.g. '/admin/') must
     * guard the call themselves:
     *   window.location.href = (next && safeNext(next)) || '/admin/';
     * This keeps safeNext's return contract uniform: always '/' on rejection,
     * always the validated path on acceptance.
     *
     * ASVS V5.1.5, OWASP A01:2021, CWE-601.
     */
    function safeNext(rawNext) {
        if (!rawNext) return '/';
        // Layer 1: reject anything that doesn't start with a single forward-slash
        // followed by a non-slash, non-backslash char.
        if (!/^\/[^/\\]/.test(rawNext)) return '/';
        // Layer 2: parse against current origin; reject if origin or protocol differs.
        try {
            var parsed = new URL(rawNext, window.location.origin);
            if (parsed.origin !== window.location.origin) return '/';
            if (parsed.protocol !== window.location.protocol) return '/';
            return parsed.pathname + parsed.search + parsed.hash;
        } catch (e) {
            return '/';
        }
    }

    function showMsg(type, text) {
        var b = document.getElementById('msg-box');
        b.className = 'msg ' + type + ' visible';
        b.textContent = text;
    }
    function clearMsg() {
        var b = document.getElementById('msg-box');
        b.className = 'msg';
        b.textContent = '';
    }
    function parseError(data) {
        if (!data.detail) return 'Request failed';
        if (typeof data.detail === 'string') return data.detail;
        if (data.detail.error) return data.detail.error;
        if (Array.isArray(data.detail)) return data.detail.map(function(d){ return d.msg; }).join(', ');
        return JSON.stringify(data.detail);
    }

    // Step 1: Login
    document.getElementById('login-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMsg();
        var btn = document.getElementById('login-btn');
        btn.disabled = true;
        btn.textContent = 'Authenticating...';

        try {
            var resp = await fetch('/auth/login', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    totp_code: document.getElementById('totp_code').value
                })
            });
            var data = await resp.json();
            if (resp.ok) {
                if (data.force_password_change) {
                    savedPassword = document.getElementById('password').value;
                    document.getElementById('login-form').className = 'hidden';
                    document.getElementById('pw-form').className = '';
                    document.getElementById('page-subtitle').textContent = 'Set a new password to continue';
                    showMsg('info', 'First login — you must change your password before continuing.');
                } else {
                    var params = new URLSearchParams(window.location.search);
                    var next = params.get('next');
                    // Phase 1 (2.25.5-auth-ingress) — role-based redirect.
                    // data.redirect_to comes from the server: "/admin/" for admin,
                    // "/app/webui" for user.  If the URL carried a ?next= (set by
                    // Caddy when a protected path bounced to /login), honour it;
                    // otherwise use the server-supplied role destination.
                    // Defence-in-depth: JS safeNext guard runs first; server-side
                    // /auth/post-login-redirect is the trust-boundary enforcement
                    // point (drift audit finding #6 — ASVS V5.1.5 / CWE-601).
                    var serverDefault = (data.redirect_to && safeNext(data.redirect_to)) || '/';
                    var clientValidated = (next && safeNext(next)) || serverDefault;
                    window.location.href = '/auth/post-login-redirect?next=' + encodeURIComponent(clientValidated);
                }
            } else {
                showMsg('error', parseError(data));
            }
        } catch (err) {
            showMsg('error', 'Connection error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Sign In';
        }
    });

    // Step 2: Password Change
    document.getElementById('pw-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMsg();
        var newPw = document.getElementById('new_password').value;
        var confirmPw = document.getElementById('confirm_password').value;

        if (newPw.length < 36) { showMsg('error', 'Password must be at least 36 characters.'); return; }
        if (newPw !== confirmPw) { showMsg('error', 'Passwords do not match.'); return; }

        var btn = document.getElementById('pw-btn');
        btn.disabled = true;
        btn.textContent = 'Changing...';

        try {
            var resp = await fetch('/auth/password/change', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    current_password: savedPassword,
                    new_password: newPw
                })
            });
            var data = await resp.json();
            if (resp.ok) {
                document.getElementById('pw-form').className = 'hidden';
                showMsg('success', 'Password changed. Please sign in with your new password.');
                document.getElementById('page-subtitle').textContent = 'Admin Control Plane';
                document.getElementById('login-form').className = '';
                document.getElementById('password').value = '';
                document.getElementById('totp_code').value = '';
                document.getElementById('username').focus();
            } else {
                showMsg('error', parseError(data));
            }
        } catch (err) {
            showMsg('error', 'Connection error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Change Password';
        }
    });
});
