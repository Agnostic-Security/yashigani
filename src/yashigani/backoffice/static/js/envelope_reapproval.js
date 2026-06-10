// Yashigani Backoffice — MCP capability-envelope RE-APPROVAL admin panel (3.0)
// Thin consumer of /admin/mcp/envelopes/* — the operator-facing surface for the
// imported-MCP capability-envelope pin (YSG-RISK-060).
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml, the step-up modal)
// Loaded as: <script src="/static/js/envelope_reapproval.js" defer></script>
//
// SECURITY — attacker-controlled content escaping (CWE-79):
//   Tool keys (provenance_id::tool_name) and every diff `detail` string come
//   from an UNTRUSTED upstream MCP's tools/list — this is the XSS surface the
//   whole feature exists to police, so a malicious tool name like
//   `<img src=x onerror=...>` MUST render inert.  EVERY value rendered into
//   innerHTML below passes through escapeHtml().  No value from the server is
//   ever interpolated raw.
//
//   No secret, handle, or map material is ever returned by these endpoints, so
//   nothing sensitive reaches the DOM — the panel renders only the public,
//   typed capability dimensions + the diff details.
//
// Step-up: approve/reject go through apiMutate(), which transparently catches
// the 401 `step_up_required` from the server-side privileged-mutation gate,
// shows the shared TOTP modal, and retries — no bespoke step-up code here.
//
// Last updated: 2026-06-10

/* global api, apiMutate, escapeHtml */

// The provenance_id of the entry currently open in the diff panel.
var _envSelected = null;

var ENV_SEVERITY_BADGE = { high: 'badge-red', med: 'badge-amber', low: 'badge-blue' };
var ENV_REASON_LABEL = {
    expanding: 'Capability expansion',
    uncertain: 'Sidecar uncertain (fail-closed)'
};

// ---------------------------------------------------------------------------
// Load: the pending queue
// ---------------------------------------------------------------------------

async function loadEnvelopes() {
    _envHideDiff();
    var tbody = document.getElementById('env-pending-tbody');
    var resultEl = document.getElementById('env-pending-result');
    if (!tbody) { return; }
    tbody.innerHTML = '<tr><td colspan="7" class="empty">Loading…</td></tr>';
    if (resultEl) { resultEl.innerHTML = ''; }

    var data = await api('/admin/mcp/envelopes/pending');
    if (!data || !data.pending) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">Failed to load pending re-approvals.</td></tr>';
        return;
    }
    if (!data.pending.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No pending re-approvals — every imported MCP is within its approved envelope.</td></tr>';
        return;
    }
    var html = '';
    data.pending.forEach(function (p) {
        var reasonBadge = (p.triage_class === 'expanding') ? 'badge-red' : 'badge-amber';
        var reasonText = ENV_REASON_LABEL[p.triage_class] || p.triage_class;
        var prov = p.provenance_id || '';
        var when = p.blocked_at ? new Date(p.blocked_at * 1000).toISOString().slice(0, 19).replace('T', ' ') : '—';
        html += '<tr>'
            + '<td>' + escapeHtml(p.server_id) + '</td>'
            + '<td><code>' + escapeHtml(prov.slice(0, 12)) + '…</code></td>'
            + '<td><span class="badge ' + reasonBadge + '">' + escapeHtml(reasonText) + '</span></td>'
            + '<td>' + escapeHtml(String(p.candidate_tool_count)) + '</td>'
            + '<td><code>' + escapeHtml(p.candidate_egress_posture) + '</code></td>'
            + '<td>' + escapeHtml(when) + '</td>'
            // data-prov carries the (server-supplied, untrusted) id — we escape it
            // for the attribute AND only ever use it via encodeURIComponent in fetch.
            + '<td><button class="btn-sm-save" data-action="envReview" data-prov="' + escapeHtml(prov) + '">Review</button></td>'
            + '</tr>';
    });
    tbody.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Review: the field-level diff vs ORIGINAL baseline (+ vs prior)
// ---------------------------------------------------------------------------

async function envReview(provenanceId) {
    _envSelected = provenanceId;
    var emptyEl = document.getElementById('env-diff-empty');
    var bodyEl = document.getElementById('env-diff-body');
    var decEl = document.getElementById('env-decision-result');
    if (decEl) { decEl.innerHTML = ''; }
    if (emptyEl) { emptyEl.className = ''; emptyEl.textContent = 'Loading change review…'; }
    if (bodyEl) { bodyEl.className = 'env-hidden'; }

    var data = await api('/admin/mcp/envelopes/pending/' + encodeURIComponent(provenanceId));
    if (!data) {
        if (emptyEl) { emptyEl.className = ''; emptyEl.innerHTML = '<span class="badge badge-red">Could not load the diff (the entry may have been resolved). Refresh the queue.</span>'; }
        return;
    }
    _envRenderDiff(data);
}

function _envRenderDiff(data) {
    var emptyEl = document.getElementById('env-diff-empty');
    var bodyEl = document.getElementById('env-diff-body');
    if (emptyEl) { emptyEl.className = 'env-hidden'; }
    if (bodyEl) { bodyEl.className = ''; }

    // Headline — the legible "tried to expand from X to Y" story.
    var head = document.getElementById('env-diff-headline');
    if (head) {
        var reasonText = ENV_REASON_LABEL[data.triage_class] || data.triage_class;
        var s = '<div class="env-headline-box">'
            + '<span class="badge badge-red">BLOCKED</span> '
            + '<strong>' + escapeHtml(data.server_id) + '</strong> '
            + '<span class="txt-note">(' + escapeHtml(reasonText) + ')</span><br>';
        var origTools = (data.original && data.original.tool_count) || 0;
        var candTools = (data.candidate && data.candidate.tool_count) || 0;
        s += 'Originally approved: <strong>' + escapeHtml(String(origTools)) + '</strong> tool(s), egress <code>'
            + escapeHtml((data.original || {}).egress_posture || 'NONE') + '</code>. '
            + 'Now requesting: <strong>' + escapeHtml(String(candTools)) + '</strong> tool(s), egress <code>'
            + escapeHtml((data.candidate || {}).egress_posture || 'NONE') + '</code>.';
        if (data.egress_change) {
            s += '<br><span class="badge badge-red">Egress posture change</span> '
                + '<code>' + escapeHtml(data.egress_from) + '</code> &rarr; <code>' + escapeHtml(data.egress_to) + '</code> '
                + '<span class="txt-note">(this MCP wants to reach further than it was approved for)</span>';
        }
        s += '</div>';
        head.innerHTML = s;
    }

    _envFillFindings('env-vsorig-tbody', data.vs_original, 'No capability expansion vs the original — within the approved envelope.');
    _envFillFindings('env-vsprior-tbody', data.vs_prior, 'No change vs the immediately-prior approved version.');
}

function _envFillFindings(tbodyId, findings, emptyMsg) {
    var tbody = document.getElementById(tbodyId);
    if (!tbody) { return; }
    findings = findings || [];
    if (!findings.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">' + escapeHtml(emptyMsg) + '</td></tr>';
        return;
    }
    var html = '';
    findings.forEach(function (f) {
        // dimension label + every string is attacker-influenced → escapeHtml.
        var sevBadge = ENV_SEVERITY_BADGE[f.severity] || 'badge-p4';
        var tool = f.tool_key ? ('<code>' + escapeHtml(f.tool_key) + '</code>') : '<span class="txt-note">—</span>';
        html += '<tr>'
            + '<td><span class="badge ' + sevBadge + '">' + escapeHtml(f.label || f.dimension) + '</span></td>'
            + '<td>' + tool + '</td>'
            + '<td>' + escapeHtml(f.detail) + '</td>'
            + '</tr>';
    });
    tbody.innerHTML = html;
}

function _envHideDiff() {
    _envSelected = null;
    var emptyEl = document.getElementById('env-diff-empty');
    var bodyEl = document.getElementById('env-diff-body');
    if (emptyEl) { emptyEl.className = ''; emptyEl.textContent = 'Select a pending re-approval above to review the field-level diff.'; }
    if (bodyEl) { bodyEl.className = 'env-hidden'; }
}

// ---------------------------------------------------------------------------
// Approve / Reject — both step-up gated server-side (apiMutate triggers modal)
// ---------------------------------------------------------------------------

async function envApprove() {
    if (!_envSelected) { return; }
    if (!confirm('Re-approve this tool-surface change? This re-pins a NEW baseline and clears the block. Requires TOTP step-up.')) { return; }
    await _envDecision('approve', 'Re-approved — new baseline pinned, block cleared.');
}

async function envReject() {
    if (!_envSelected) { return; }
    if (!confirm('Keep this MCP BLOCKED? The mutation is rejected and the MCP stays gated until an explicit re-approval. Requires TOTP step-up.')) { return; }
    await _envDecision('reject', 'Rejected — the MCP stays blocked.');
}

async function _envDecision(action, okMsg) {
    var prov = _envSelected;
    var decEl = document.getElementById('env-decision-result');
    if (decEl) { decEl.innerHTML = '<span class="loading">Submitting…</span>'; }

    // apiMutate() catches the server's 401 step_up_required, shows the TOTP modal,
    // and retries — so the REAL privileged-mutation gate is enforced server-side.
    var resp = await apiMutate(
        '/admin/mcp/envelopes/pending/' + encodeURIComponent(prov) + '/' + action,
        { method: 'POST' }
    ).catch(function () { return null; });

    if (!resp) {
        if (decEl) { decEl.innerHTML = '<span class="badge badge-red">Network error or step-up cancelled.</span>'; }
        return;
    }
    if (!resp.ok) {
        var err = await resp.json().catch(function () { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message)) ? (err.detail.error || err.detail.message) : ('HTTP ' + resp.status);
        if (resp.status === 403) { msg = 'Forbidden — operator (admin) privilege required.'; }
        if (decEl) { decEl.innerHTML = '<span class="badge badge-red">' + escapeHtml(msg) + '</span>'; }
        return;
    }
    if (decEl) { decEl.innerHTML = '<span class="badge badge-green">' + escapeHtml(okMsg) + '</span>'; }
    _envHideDiff();
    loadEnvelopes();
}

// ---------------------------------------------------------------------------
// Self-register action handlers (CSP-safe — no inline handlers)
// ---------------------------------------------------------------------------

document.addEventListener('click', function (e) {
    var actionEl = e.target.closest ? e.target.closest('[data-action]') : null;
    if (!actionEl) { return; }
    switch (actionEl.getAttribute('data-action')) {
        case 'envRefresh':
            loadEnvelopes();
            break;
        case 'envReview':
            envReview(actionEl.getAttribute('data-prov'));
            break;
        case 'envApprove':
            envApprove();
            break;
        case 'envReject':
            envReject();
            break;
        default:
            break;
    }
});

// Expose for showPage() in dashboard.js
window.loadEnvelopes = loadEnvelopes;
