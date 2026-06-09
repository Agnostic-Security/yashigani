// Yashigani Backoffice — Document Enforcement admin panel (v2.26)
// Thin consumer of /admin/documents/* — the document-content OPA enforcement
// surface (plan: opa_document_enforcement_plan_*.md).
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml)
// Loaded as: <script src="/static/js/documents.js" defer></script>
//
// SECURITY — attacker-controlled content escaping:
//   Match `instance` and `location` come from DOCUMENT CONTENT, which is
//   attacker-controlled.  EVERY such value rendered into innerHTML below passes
//   through escapeHtml() (CWE-79).  The masked instance is already masked
//   server-side, but we escape anyway — defence in depth and the location/
//   data_class strings are equally attacker-influenced.
//
// Last updated: 2026-06-09

/* global api, apiMutate, escapeHtml */

// ---------------------------------------------------------------------------
// Load: status cards + format catalogue + policy table
// ---------------------------------------------------------------------------

async function loadDocuments() {
    await Promise.all([_docLoadStatus(), _docLoadPolicies()]);
}

async function _docLoadStatus() {
    var cards = document.getElementById('doc-status-cards');
    var fmtBody = document.getElementById('doc-formats-tbody');
    var parkBody = document.getElementById('doc-parked-tbody');
    if (!cards) { return; }

    var data = await api('/admin/documents/status');
    if (!data) {
        cards.innerHTML = '<div class="card"><span class="badge badge-red">Failed to load status</span></div>';
        return;
    }

    var flagBadge = data.enabled
        ? '<span class="badge badge-green">ENABLED</span>'
        : '<span class="badge badge-p4">DISABLED (dark)</span>';
    cards.innerHTML =
        '<div class="card"><div class="card-label">Feature flag</div>' + flagBadge + '</div>'
        + '<div class="card"><div class="card-label">Max document bytes</div><div class="card-value">' + escapeHtml(String(data.max_document_bytes)) + '</div></div>'
        + '<div class="card"><div class="card-label">Max segments</div><div class="card-value">' + escapeHtml(String(data.max_segments)) + '</div></div>'
        + '<div class="card"><div class="card-label">Supported formats</div><div class="card-value">' + escapeHtml(String((data.supported_formats || []).length)) + '</div></div>';

    if (fmtBody) {
        var fh = '';
        (data.supported_formats || []).forEach(function (f) {
            fh += '<tr><td><code>' + escapeHtml(f.ext) + '</code></td><td>' + escapeHtml(f.family) + '</td><td>' + escapeHtml(f.label) + '</td></tr>';
        });
        fmtBody.innerHTML = fh || '<tr><td colspan="3" class="empty">None</td></tr>';
    }
    if (parkBody) {
        var ph = '';
        (data.parked_formats || []).forEach(function (f) {
            ph += '<tr><td><code>' + escapeHtml(f.ext) + '</code></td><td>' + escapeHtml(f.family) + '</td><td><span class="badge badge-amber">' + escapeHtml(f.reason) + '</span></td></tr>';
        });
        parkBody.innerHTML = ph || '<tr><td colspan="3" class="empty">None</td></tr>';
    }
}

async function _docLoadPolicies() {
    var tbody = document.getElementById('doc-policies-tbody');
    if (!tbody) { return; }
    tbody.innerHTML = '<tr><td colspan="8" class="empty">Loading…</td></tr>';

    var data = await api('/admin/documents/policies');
    if (!data || !data.policies) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty">Failed to load policies.</td></tr>';
        return;
    }
    if (!data.policies.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty">No policies configured.</td></tr>';
        return;
    }
    var html = '';
    data.policies.forEach(function (p) {
        var actionBadge = {
            'LOG': 'badge-blue', 'REDACT': 'badge-amber',
            'PSEUDONYMIZE': 'badge-green', 'BLOCK': 'badge-red'
        }[p.action] || 'badge-p4';
        html += '<tr>'
            + '<td>' + escapeHtml(p.data_class) + '</td>'
            + '<td><code>' + escapeHtml(p.format) + '</code></td>'
            + '<td>' + escapeHtml(p.route) + '</td>'
            + '<td><span class="badge ' + actionBadge + '">' + escapeHtml(p.action) + '</span></td>'
            + '<td>' + escapeHtml(String(p.pseudonymize_mode || '—')) + '</td>'
            + '<td>' + (p.small_set_escalation ? 'on' : 'off') + '</td>'
            + '<td>' + escapeHtml(p.description) + '</td>'
            + '<td><button class="btn-sm-danger" data-action="docDeletePolicy" data-policy-id="' + escapeHtml(p.id) + '">Delete</button></td>'
            + '</tr>';
    });
    tbody.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Policy mutation (step-up gated server-side)
// ---------------------------------------------------------------------------

async function docAddPolicy() {
    var resultEl = document.getElementById('doc-policy-result');
    var body = {
        data_class: document.getElementById('doc-pol-class').value,
        format: document.getElementById('doc-pol-format').value,
        route: document.getElementById('doc-pol-route').value,
        action: document.getElementById('doc-pol-action').value,
        pseudonymize_mode: document.getElementById('doc-pol-mode').value,
        small_set_escalation: document.getElementById('doc-pol-escalate').value === 'true',
        description: document.getElementById('doc-pol-desc').value.trim()
    };
    if (!body.description) {
        resultEl.innerHTML = '<span class="badge badge-red">Description is required.</span>';
        return;
    }
    resultEl.innerHTML = '<span class="loading">Saving…</span>';
    var resp = await apiMutate('/admin/documents/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    }).catch(function () { return null; });
    if (!resp) { resultEl.innerHTML = '<span class="badge badge-red">Network error or step-up cancelled.</span>'; return; }
    if (!resp.ok) {
        var err = await resp.json().catch(function () { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message)) ? (err.detail.error || err.detail.message) : ('HTTP ' + resp.status);
        resultEl.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(msg) + '</span>';
        return;
    }
    resultEl.innerHTML = '<span class="badge badge-green">Policy added.</span>';
    document.getElementById('doc-pol-desc').value = '';
    _docLoadPolicies();
}

async function docDeletePolicy(policyId) {
    if (!confirm('Delete this document-enforcement policy? Requires TOTP step-up.')) { return; }
    var resp = await apiMutate('/admin/documents/policies/' + encodeURIComponent(policyId), {
        method: 'DELETE'
    }).catch(function () { return null; });
    if (!resp || !resp.ok) {
        var resultEl = document.getElementById('doc-policy-result');
        if (resultEl) { resultEl.innerHTML = '<span class="badge badge-red">Delete failed or step-up cancelled.</span>'; }
        return;
    }
    _docLoadPolicies();
}

// ---------------------------------------------------------------------------
// Inspect a sample document + render the verdict viewer
// ---------------------------------------------------------------------------

async function docInspect() {
    var resultEl = document.getElementById('doc-insp-result');
    var body = {
        content: document.getElementById('doc-insp-content').value,
        filename: document.getElementById('doc-insp-name').value.trim() || 'sample.txt',
        declared_mime: 'text/plain',
        requested_action: document.getElementById('doc-insp-action').value,
        pseudonymize_mode: document.getElementById('doc-insp-mode').value,
        detokenize_rbac_role: document.getElementById('doc-insp-role').value.trim() || 'doc-pseudonymize-reverser'
    };
    if (!body.content) { resultEl.innerHTML = '<span class="badge badge-red">Paste some content first.</span>'; return; }
    resultEl.innerHTML = '<span class="loading">Inspecting…</span>';

    var resp = await apiMutate('/admin/documents/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    }).catch(function () { return null; });
    if (!resp) { resultEl.innerHTML = '<span class="badge badge-red">Network error.</span>'; return; }
    if (!resp.ok) {
        var err = await resp.json().catch(function () { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message)) ? (err.detail.error || err.detail.message) : ('HTTP ' + resp.status);
        resultEl.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(msg) + '</span>';
        return;
    }
    var data = await resp.json();
    resultEl.innerHTML = '<span class="badge badge-green">Inspected — request id <code>' + escapeHtml(data.summary.request_id) + '</code></span>';
    // Pre-fill the table-retrieval request id for convenience.
    var ridInput = document.getElementById('doc-table-rid');
    if (ridInput) { ridInput.value = data.summary.request_id; }
    _docRenderVerdict(data);
}

function _docRenderVerdict(data) {
    var summary = data.summary || {};
    var matches = data.matches || [];

    var dispBadge = {
        'LOG': 'badge-blue', 'REDACT': 'badge-amber',
        'PSEUDONYMIZE': 'badge-green', 'BLOCK': 'badge-red'
    }[summary.disposition] || 'badge-p4';

    var sumEl = document.getElementById('doc-verdict-summary');
    if (sumEl) {
        var s = '<span class="badge ' + dispBadge + '">' + escapeHtml(summary.disposition || '—') + '</span> ';
        s += 'format <code>' + escapeHtml(summary.detected_format || '—') + '</code> · ';
        s += 'extraction ' + (summary.extraction_complete ? 'complete' : '<strong>incomplete (fail-closed)</strong>') + ' · ';
        s += escapeHtml(String(summary.match_count || 0)) + ' match(es)';
        if (summary.has_correspondence_table) {
            s += ' · <span class="badge badge-green">mode-A table available</span> (role <code>' + escapeHtml(summary.detokenize_rbac_role || '—') + '</code>)';
        }
        if (summary.block_reason) {
            s += '<br><span class="doc-block-reason">Reason: ' + escapeHtml(summary.block_reason) + '</span>';
        }
        sumEl.innerHTML = s;
    }

    // Layman alert surface for BLOCK/HOLD (unified user-alert contract).
    var alertEl = document.getElementById('doc-user-alert');
    if (alertEl) {
        if (data.user_alert) {
            alertEl.innerHTML = '<div class="doc-alert-box">'
                + '<strong>Security alert (' + escapeHtml(data.user_alert.code) + ')</strong><br>'
                + escapeHtml(data.user_alert.user_message)
                + '<br><span class="doc-alert-pol">policy: ' + escapeHtml(data.user_alert.policy_id) + '</span>'
                + '</div>';
        } else {
            alertEl.innerHTML = '';
        }
    }

    var tbody = document.getElementById('doc-matches-tbody');
    if (!tbody) { return; }
    if (!matches.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No matches found.</td></tr>';
        return;
    }
    var html = '';
    matches.forEach(function (m) {
        // EVERY value below is attacker-controlled document content → escapeHtml.
        var hiddenFlag = m.hidden
            ? ' <span class="badge badge-red">' + escapeHtml(m.segment_kind) + '</span>'
            : '';
        html += '<tr' + (m.hidden ? ' class="doc-row-hidden"' : '') + '>'
            + '<td>' + escapeHtml(m.data_class) + (m.qi ? ' <span class="badge badge-amber">QI</span>' : '') + '</td>'
            + '<td>' + (m.qi ? 'yes' : 'no') + '</td>'
            + '<td><code>' + escapeHtml(m.instance) + '</code></td>'
            + '<td><code>' + escapeHtml(m.location) + '</code></td>'
            + '<td>' + escapeHtml(m.segment_kind || 'BODY') + hiddenFlag + '</td>'
            + '</tr>';
    });
    tbody.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Correspondence-table retrieval (mode A) — RBAC gated server-side
// ---------------------------------------------------------------------------

async function docRetrieveTable() {
    var rid = document.getElementById('doc-table-rid').value.trim();
    var resultEl = document.getElementById('doc-table-result');
    var tbl = document.getElementById('doc-table-table');
    var tbody = document.getElementById('doc-table-tbody');
    if (!rid) { resultEl.innerHTML = '<span class="badge badge-red">Enter a document request id.</span>'; return; }
    if (tbl) { tbl.className = 'doc-hidden'; }
    if (tbody) { tbody.innerHTML = ''; }
    resultEl.innerHTML = '<span class="loading">Retrieving…</span>';

    // Raw fetch (not api()) so we can discriminate the RBAC 403 path explicitly
    // — the gate must be VISIBLE to the operator, not swallowed as a generic error.
    var raw = await fetch('/admin/documents/results/' + encodeURIComponent(rid) + '/table', { credentials: 'same-origin' }).catch(function () { return null; });
    if (!raw) { resultEl.innerHTML = '<span class="badge badge-red">Network error.</span>'; return; }
    if (raw.status === 403) {
        var ferr = await raw.json().catch(function () { return {}; });
        var role = (ferr.detail && ferr.detail.required_role) ? ferr.detail.required_role : '';
        resultEl.innerHTML = '<span class="badge badge-red">Forbidden — you are not in the detokenize role'
            + (role ? ' (<code>' + escapeHtml(role) + '</code>)' : '') + '. Table NOT shown.</span>';
        return;
    }
    if (raw.status === 404) { resultEl.innerHTML = '<span class="badge badge-amber">No correspondence table for that document.</span>'; return; }
    if (!raw.ok) { resultEl.innerHTML = '<span class="badge badge-red">HTTP ' + raw.status + '</span>'; return; }

    var data = await raw.json();
    resultEl.innerHTML = '<span class="badge badge-green">Authorised — ' + escapeHtml(String((data.rows || []).length)) + ' row(s). This table is the re-identification key; keep it secure.</span>';
    if (tbody) {
        var html = '';
        (data.rows || []).forEach(function (r) {
            // token + original are attacker-influenced document content → escape.
            html += '<tr><td><code>' + escapeHtml(r.token) + '</code></td><td>' + escapeHtml(r.original) + '</td></tr>';
        });
        tbody.innerHTML = html;
    }
    if (tbl) { tbl.className = ''; }
}

function docDownloadTable() {
    var rid = document.getElementById('doc-table-rid').value.trim();
    if (!rid) {
        var resultEl = document.getElementById('doc-table-result');
        if (resultEl) { resultEl.innerHTML = '<span class="badge badge-red">Enter a document request id.</span>'; }
        return;
    }
    // The download endpoint enforces the same RBAC gate; a 403 yields a JSON
    // error body instead of a file (browser shows it).  Open in same tab.
    window.location.href = '/admin/documents/results/' + encodeURIComponent(rid) + '/table.csv';
}

// ---------------------------------------------------------------------------
// Show/hide the add-policy form (mirrors dashboard.js toggleForm)
// ---------------------------------------------------------------------------

function docToggleForm(formId) {
    var el = document.getElementById(formId);
    if (!el) { return; }
    el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}

// ---------------------------------------------------------------------------
// Self-register action handlers (CSP-safe — no inline handlers)
// ---------------------------------------------------------------------------

document.addEventListener('click', function (e) {
    var actionEl = e.target.closest ? e.target.closest('[data-action]') : null;
    if (!actionEl) { return; }
    var action = actionEl.getAttribute('data-action');
    switch (action) {
        case 'docToggleForm':
            docToggleForm(actionEl.getAttribute('data-form-id'));
            break;
        case 'docAddPolicy':
            docAddPolicy();
            break;
        case 'docDeletePolicy':
            docDeletePolicy(actionEl.getAttribute('data-policy-id'));
            break;
        case 'docInspect':
            docInspect();
            break;
        case 'docRetrieveTable':
            docRetrieveTable();
            break;
        case 'docDownloadTable':
            docDownloadTable();
            break;
        default:
            break;
    }
});

// Expose for showPage() in dashboard.js
window.loadDocuments = loadDocuments;
