// Yashigani Backoffice — HIBP API key admin panel
// v2.23.3 (#59) — CSP-compliant external JS (no inline scripts)
// Last updated: 2026-05-07T01:00:00+01:00
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml, _stepupQueue)
// Loaded as: <script src="/static/js/hibp.js" defer></script>

/* global api, apiMutate, escapeHtml */

// ---------------------------------------------------------------------------
// HIBP key status panel
// ---------------------------------------------------------------------------

async function loadHibpStatus() {
    var container = document.getElementById('hibp-status-container');
    if (!container) { return; }
    container.innerHTML = '<span class="loading">Loading…</span>';

    var data = await api('/api/v1/admin/auth/hibp/status');
    if (!data) {
        container.innerHTML = '<span style="color:#ef4444">Failed to load HIBP key status.</span>';
        _hibpSetButtons(false);
        return;
    }

    var source = data.source || 'none';
    var sourceLabel = {
        'admin_panel': 'Admin panel',
        'env_var': 'Environment variable',
        'none': 'Not configured'
    }[source] || escapeHtml(source);

    var html = '';
    if (data.configured) {
        var maskedVal = data.masked_value ? escapeHtml(data.masked_value) : '(set)';
        var updatedAt = data.updated_at ? escapeHtml(data.updated_at) : '';
        var updatedBy = data.updated_by ? escapeHtml(data.updated_by) : '';
        html += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">'
            + '<span class="badge badge-green">Configured</span>'
            + '<span style="font-size:0.85rem;color:#334155;">Source: <strong>' + sourceLabel + '</strong></span>'
            + '</div>';
        html += '<div style="font-size:0.8rem;color:#64748b;">'
            + 'Key: <code style="background:#f1f5f9;padding:2px 6px;border-radius:3px;">' + maskedVal + '</code>';
        if (updatedAt) {
            html += ' &mdash; set ' + updatedAt;
        }
        if (updatedBy && updatedBy !== '__system_init__') {
            html += ' by <strong>' + updatedBy + '</strong>';
        }
        html += '</div>';
    } else {
        html += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">'
            + '<span class="badge badge-yellow">Not configured</span>'
            + '<span style="font-size:0.8rem;color:#64748b;">Using anonymous k-Anonymity requests (free tier).</span>'
            + '</div>';
    }

    container.innerHTML = html;
    _hibpSetButtons(data.configured, source);
}

function _hibpSetButtons(configured, source) {
    var btnClear = document.getElementById('hibp-btn-clear');
    if (btnClear) {
        // Only enable clear if admin-panel has a key (env var source can't be cleared here)
        btnClear.disabled = !(configured && source === 'admin_panel');
    }
}

// ---------------------------------------------------------------------------
// Save key
// ---------------------------------------------------------------------------

async function saveHibpKey() {
    var input = document.getElementById('hibp-key-input');
    var result = document.getElementById('hibp-key-result');
    if (!input || !result) { return; }

    var keyVal = (input.value || '').trim();
    if (!keyVal) {
        result.style.color = '#ef4444';
        result.textContent = 'Enter an API key. Use the Clear button to remove an existing key.';
        return;
    }
    if (keyVal.length < 8 || keyVal.length > 128) {
        result.style.color = '#ef4444';
        result.textContent = 'Key must be 8–128 characters.';
        return;
    }
    if (!/^[A-Za-z0-9\-]+$/.test(keyVal)) {
        result.style.color = '#ef4444';
        result.textContent = 'Key must contain only alphanumeric characters and hyphens.';
        return;
    }

    result.style.color = '#64748b';
    result.textContent = 'Saving…';

    var resp = await apiMutate('/api/v1/admin/auth/hibp/key', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: keyVal })
    });

    // Clear the input regardless of outcome (key is sensitive)
    input.value = '';

    if (!resp) {
        result.style.color = '#ef4444';
        result.textContent = 'Network error. Check step-up TOTP or try again.';
        return;
    }
    if (resp.status === 422) {
        var body = await resp.json().catch(function() { return {}; });
        var msg = (body && body.detail && body.detail.message) ? body.detail.message : 'Invalid key format.';
        result.style.color = '#ef4444';
        result.textContent = msg;
        return;
    }
    if (!resp.ok) {
        result.style.color = '#ef4444';
        result.textContent = 'Error ' + resp.status + ' — see server logs.';
        return;
    }

    result.style.color = '#16a34a';
    result.textContent = 'HIBP API key saved.';
    await loadHibpStatus();
}

// ---------------------------------------------------------------------------
// Clear key
// ---------------------------------------------------------------------------

async function clearHibpKey() {
    var result = document.getElementById('hibp-key-result');
    if (!result) { return; }

    result.style.color = '#64748b';
    result.textContent = 'Clearing…';

    var resp = await apiMutate('/api/v1/admin/auth/hibp/key', {
        method: 'DELETE'
    });

    if (!resp) {
        result.style.color = '#ef4444';
        result.textContent = 'Network error. Check step-up TOTP or try again.';
        return;
    }
    if (!resp.ok) {
        result.style.color = '#ef4444';
        result.textContent = 'Error ' + resp.status + ' — see server logs.';
        return;
    }

    result.style.color = '#334155';
    result.textContent = 'HIBP API key cleared. Falling back to env var or anonymous.';
    await loadHibpStatus();
}

// ---------------------------------------------------------------------------
// Test connection probe
// ---------------------------------------------------------------------------

async function testHibpConnection() {
    var probeResult = document.getElementById('hibp-probe-result');
    if (!probeResult) { return; }

    probeResult.style.color = '#64748b';
    probeResult.textContent = 'Probing…';

    // Fetch status — confirms key resolution is working
    var status = await api('/api/v1/admin/auth/hibp/status');
    if (!status) {
        probeResult.style.color = '#ef4444';
        probeResult.textContent = 'Could not reach admin API. Check network and authentication.';
        return;
    }

    var srcLabel = {
        'admin_panel': 'Admin panel key',
        'env_var': 'Env var key',
        'none': 'No key (anonymous)'
    }[status.source] || status.source;

    probeResult.style.color = '#334155';
    probeResult.textContent = 'Admin API: OK. Key source: ' + srcLabel
        + (status.masked_value ? ' (' + status.masked_value + ')' : '')
        + '. Note: live connectivity to api.pwnedpasswords.com is not tested here'
        + '— a probe call would consume rate-limit quota.';
}

// ---------------------------------------------------------------------------
// Wire up buttons after DOM ready
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function() {
    var btnSave = document.getElementById('hibp-btn-save');
    if (btnSave) {
        btnSave.addEventListener('click', saveHibpKey);
    }
    var btnClear = document.getElementById('hibp-btn-clear');
    if (btnClear) {
        btnClear.addEventListener('click', clearHibpKey);
    }
    var btnTest = document.getElementById('hibp-btn-test');
    if (btnTest) {
        btnTest.addEventListener('click', testHibpConnection);
    }
    // Allow Enter in key input to trigger save
    var keyInput = document.getElementById('hibp-key-input');
    if (keyInput) {
        keyInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { saveHibpKey(); }
        });
    }
});

// Expose so showPage() in dashboard.js can call it
// (registered via: if (name === 'settings') loadSettings() which also calls loadHibpStatus)
window.loadHibpStatus = loadHibpStatus;
