// LAURA-V400-R2-001 — Data-Protection dual-admin maker-checker admin page.
// Loaded deferred; exposes window.loadDpPage() for showPage('data-protection').
//
// V1.2.1: All user-controlled strings rendered via escapeHtml() (XSS prevention).
// All fetch calls use credentials:'same-origin' + step-up interceptor.
// Last updated: 2026-07-02T00:00:00+00:00

(function() {

// ---------------------------------------------------------------------------
// Control labels (human-readable)
// ---------------------------------------------------------------------------

var CONTROL_LABELS = {
    'pii_config':       'PII Scanning Mode',
    'pii_cloud_bypass': 'PII Cloud Bypass',
    'doc_enforcement':  'Document Enforcement',
};

function controlLabel(c) {
    return CONTROL_LABELS[c] || escapeHtml(c);
}

function stateStr(s) {
    if (!s) return '—';
    if (s.mode !== undefined) return 'mode=' + escapeHtml(String(s.mode));
    if (s.enabled !== undefined) return s.enabled ? 'enabled' : 'disabled';
    return escapeHtml(JSON.stringify(s));
}

function fmtTs(ts) {
    if (!ts) return '—';
    try { return new Date(ts * 1000).toLocaleString(); }
    catch(e) { return String(ts); }
}

// ---------------------------------------------------------------------------
// Status panel
// ---------------------------------------------------------------------------

async function loadDpStatus() {
    var el = document.getElementById('dp-status-result');
    if (!el) return;
    el.innerHTML = '<span class="loading">Loading&hellip;</span>';
    var data = await api('/admin/data-protection/status');
    if (!data) { el.innerHTML = '<span class="badge badge-red">Error loading status</span>'; return; }

    var rows = [
        { key: 'pii_config',       label: 'PII Scanning Mode',   state: data.pii_config },
        { key: 'pii_cloud_bypass', label: 'PII Cloud Bypass',    state: data.pii_cloud_bypass },
        { key: 'doc_enforcement',  label: 'Document Enforcement', state: data.doc_enforcement },
    ];
    var html = '<table><thead><tr><th>Control</th><th>State</th><th>Protection</th></tr></thead><tbody>';
    rows.forEach(function(r) {
        var st = r.state || {};
        var weakened = st.weakened;
        var badge = weakened
            ? '<span class="badge badge-red">&#9888; WEAKENED</span>'
            : '<span class="badge badge-green">Enforcing</span>';
        var desc = stateStr(st);
        html += '<tr><td>' + escapeHtml(r.label) + '</td><td><code>' + desc + '</code></td><td>' + badge + '</td></tr>';
    });
    html += '</tbody></table>';
    if (data.any_weakened) {
        html += '<p class="txt-warn"><strong>&#9888; One or more data-protection controls are in a weakened state.</strong></p>';
    }
    el.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Pending requests panel
// ---------------------------------------------------------------------------

async function loadDpPending() {
    var tbody = document.getElementById('dp-pending-tbody');
    var result = document.getElementById('dp-pending-result');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="7" class="empty">Loading&hellip;</td></tr>';

    var data = await api('/admin/data-protection/weaken-requests');
    if (!data || !data.pending) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">Error loading pending requests.</td></tr>';
        return;
    }
    var rows = data.pending;
    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No pending weaken requests.</td></tr>';
        return;
    }

    var html = '';
    rows.forEach(function(r) {
        html += '<tr>'
            + '<td>' + controlLabel(r.control) + '</td>'
            + '<td><code>' + escapeHtml(r.requester_id) + '</code></td>'
            + '<td><code>' + stateStr(r.from_state) + '</code></td>'
            + '<td><code>' + stateStr(r.to_state) + '</code></td>'
            + '<td>' + fmtTs(r.requested_at) + '</td>'
            + '<td>' + fmtTs(r.expires_at) + '</td>'
            + '<td class="env-actions">'
            + '<button class="btn-sm-save" onclick="dpApprove(' + JSON.stringify(escapeHtml(r.request_id)) + ')">Approve (TOTP)</button>'
            + ' '
            + '<button class="btn-sm-danger" onclick="dpReject(' + JSON.stringify(escapeHtml(r.request_id)) + ')">Reject (TOTP)</button>'
            + '</td>'
            + '</tr>';
    });
    tbody.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Approve / reject
// ---------------------------------------------------------------------------

window.dpApprove = async function(requestId) {
    var result = document.getElementById('dp-decision-result');
    if (result) result.innerHTML = '<span class="loading">Processing&hellip;</span>';
    var r = await fetch('/admin/data-protection/weaken-requests/' + encodeURIComponent(requestId) + '/approve', {
        method: 'POST',
        credentials: 'same-origin',
    });
    await handleDpDecisionResponse(r, 'approved', result);
};

window.dpReject = async function(requestId) {
    var result = document.getElementById('dp-decision-result');
    if (result) result.innerHTML = '<span class="loading">Processing&hellip;</span>';
    var r = await fetch('/admin/data-protection/weaken-requests/' + encodeURIComponent(requestId) + '/reject', {
        method: 'POST',
        credentials: 'same-origin',
    });
    await handleDpDecisionResponse(r, 'rejected', result);
};

async function handleDpDecisionResponse(r, action, resultEl) {
    if (r.status === 401) {
        // Step-up interceptor: the global fetch interceptor in dashboard.js
        // will catch step_up_required and prompt for TOTP, then retry.
        // For non-intercepted paths, show a hint.
        if (typeof window._handleStepUpResponse === 'function') {
            await window._handleStepUpResponse(r);
        } else {
            if (resultEl) resultEl.innerHTML = '<span class="badge badge-red">Step-up required — verify TOTP first.</span>';
        }
        return;
    }
    var json = {};
    try { json = await r.json(); } catch(e) {}
    if (r.ok) {
        if (resultEl) resultEl.innerHTML = '<span class="badge badge-green">' +
            (action === 'approved' ? 'Approved and applied.' : 'Rejected. No change applied.') +
            '</span>';
        loadDpPage();  // refresh
        if (typeof loadDpProtectionStatus === 'function') loadDpProtectionStatus();
    } else {
        var msg = (json.detail && (json.detail.message || json.detail.error)) || ('Error ' + r.status);
        if (resultEl) resultEl.innerHTML = '<span class="badge badge-red">' + escapeHtml(String(msg)) + '</span>';
    }
}

// ---------------------------------------------------------------------------
// Page loader (exported to window)
// ---------------------------------------------------------------------------

window.loadDpPage = async function() {
    await Promise.all([loadDpStatus(), loadDpPending()]);
};

// ---------------------------------------------------------------------------
// data-action dispatcher (dpRefresh)
// ---------------------------------------------------------------------------

document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    if (action === 'dpRefresh') {
        e.preventDefault();
        window.loadDpPage();
    }
});

})();
