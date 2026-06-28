// Yashigani Backoffice — Capability Policy admin panel
// 3.0 — Admin-configurable browser Permissions-Policy (RBAC-scoped)
// Last updated: 2026-06-27T00:00:00+00:00
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml, fillSelect)
// Loaded as: <script src="/static/js/capability-policy.js" defer></script>

/* global api, apiMutate, escapeHtml, fillSelect */

var CAP_NAMES = ['camera', 'microphone', 'geolocation', 'display-capture', 'fullscreen'];
var CAP_LABELS = {
    'camera':          'Camera',
    'microphone':      'Microphone',
    'geolocation':     'Geolocation',
    'display-capture': 'Display Capture',
    'fullscreen':      'Fullscreen'
};
var CAP_MAX_ORIGINS = 10;
var _capScopeType = 'org';
var _capScopeId   = '';

// Convert capability name to a safe element id segment (display-capture → display_capture)
function _capId(cap) { return cap.replace(/-/g, '_'); }

// ---------------------------------------------------------------------------
// Scope picker visibility
// ---------------------------------------------------------------------------
function _capUpdateScopeVisibility() {
    var typeEl = document.getElementById('cap-scope-type');
    if (!typeEl) return;
    var t = typeEl.value;
    var gp = document.getElementById('cap-group-picker');
    var up = document.getElementById('cap-user-picker');
    if (gp) { if (t === 'group') gp.classList.remove('is-hidden'); else gp.classList.add('is-hidden'); }
    if (up) { if (t === 'user')  up.classList.remove('is-hidden'); else up.classList.add('is-hidden'); }
}

// ---------------------------------------------------------------------------
// Load groups into the group picker
// ---------------------------------------------------------------------------
async function _capLoadGroups() {
    var data = await api('/admin/rbac/groups');
    var groups = (data && data.groups) ? data.groups : [];
    fillSelect('cap-group-id', groups.map(function(g) {
        return { value: g.id, label: (g.display_name || g.id) + ' (' + g.id + ')' };
    }), [{ value: '', label: groups.length ? 'Select a group…' : 'No groups configured' }]);
}

// ---------------------------------------------------------------------------
// Main entry — called by showPage() when the Permissions Policy page opens
// ---------------------------------------------------------------------------
async function loadCapabilityPolicy() {
    await _capLoadGroups();
    _capUpdateScopeVisibility();
    // Auto-load org scope on every visit
    _capScopeType = 'org';
    _capScopeId   = '';
    var typeEl = document.getElementById('cap-scope-type');
    if (typeEl) typeEl.value = 'org';
    await _capFetchAndRender();
}

// ---------------------------------------------------------------------------
// Load button handler — reads the scope picker then fetches
// ---------------------------------------------------------------------------
async function capPolLoad() {
    var typeEl = document.getElementById('cap-scope-type');
    if (!typeEl) return;
    _capScopeType = typeEl.value;

    if (_capScopeType === 'group') {
        var gEl = document.getElementById('cap-group-id');
        _capScopeId = gEl ? (gEl.value || '').trim() : '';
        if (!_capScopeId) { _capSetResult('<span class="badge badge-red">Select a group first.</span>'); return; }
    } else if (_capScopeType === 'user') {
        var uEl = document.getElementById('cap-user-email');
        _capScopeId = uEl ? (uEl.value || '').trim() : '';
        if (!_capScopeId) { _capSetResult('<span class="badge badge-red">Enter a user email first.</span>'); return; }
    } else {
        _capScopeId = '';
    }

    await _capFetchAndRender();
}

// ---------------------------------------------------------------------------
// Fetch current scope policy and render the rows
// ---------------------------------------------------------------------------
async function _capFetchAndRender() {
    _capSetResult('<span class="loading">Loading…</span>');

    var data      = null;
    var policyKey = 'org';

    if (_capScopeType === 'org') {
        data = await api('/admin/api/capability-policy');
        policyKey = 'org';
    } else if (_capScopeType === 'group') {
        data = await api('/admin/api/capability-policy/groups/' + encodeURIComponent(_capScopeId));
        policyKey = 'overrides';
    } else {
        data = await api('/admin/api/capability-policy/users/' + encodeURIComponent(_capScopeId));
        policyKey = 'overrides';
    }

    _capSetResult('');

    var policy = (data && data[policyKey]) ? data[policyKey] : {};
    _capRenderRows(policy);

    // Update the scope label in the panel header
    var labelEl = document.getElementById('cap-pol-scope-label');
    if (labelEl) {
        if (_capScopeType === 'org')        labelEl.textContent = 'Organisation (default)';
        else if (_capScopeType === 'group') labelEl.textContent = 'Group: ' + _capScopeId;
        else                                labelEl.textContent = 'User: ' + _capScopeId;
    }

    // Show / hide "inherits from parent" note for group / user overrides
    var noteEl = document.getElementById('cap-pol-partial-note');
    if (noteEl) {
        if (_capScopeType !== 'org') noteEl.classList.remove('is-hidden');
        else noteEl.classList.add('is-hidden');
    }

    // Delete / reset button (revealed once a scope is loaded)
    var delBtn = document.getElementById('cap-pol-delete-btn');
    if (delBtn) {
        delBtn.classList.remove('is-hidden');
        delBtn.textContent = (_capScopeType === 'org')
            ? 'Reset org to baseline'
            : 'Delete ' + _capScopeType + ' override';
    }
}

// ---------------------------------------------------------------------------
// Render the 5-row capability settings table
// ---------------------------------------------------------------------------
function _capRenderRows(policy) {
    var container = document.getElementById('cap-pol-rows');
    if (!container) return;

    var isPartial = (_capScopeType !== 'org');
    var html = '<table class="cap-pol-table">'
        + '<thead><tr>'
        + '<th class="cap-th-name">Capability</th>'
        + '<th class="cap-th-value">Setting</th>'
        + '<th>Allowed Origins (https:// only, max ' + CAP_MAX_ORIGINS + ')</th>'
        + '</tr></thead><tbody>';

    CAP_NAMES.forEach(function(cap) {
        var cid     = _capId(cap);
        var setting = policy[cap] || null;
        var value   = setting ? setting.value : (isPartial ? '' : 'self');
        var origins = (setting && setting.allow_list) ? setting.allow_list : [];

        // Build <option> elements
        var opts = '';
        if (isPartial) {
            opts += '<option value=""' + (!value ? ' selected' : '') + '>— inherit from parent</option>';
        }
        opts += '<option value="off"'        + (value === 'off'        ? ' selected' : '') + '>off (blocked everywhere)</option>';
        opts += '<option value="self"'       + (value === 'self'       ? ' selected' : '') + '>self (same-origin only)</option>';
        opts += '<option value="allow_list"' + (value === 'allow_list' ? ' selected' : '') + '>allow-list (explicit origins)</option>';

        // Build existing origin chips
        var chipsHtml = '';
        origins.forEach(function(o) { chipsHtml += _capChipHtml(cap, o); });

        var origHidden = (value !== 'allow_list') ? ' is-hidden' : '';

        html += '<tr>'
            + '<td class="cap-name-cell"><strong>' + escapeHtml(CAP_LABELS[cap] || cap) + '</strong></td>'
            + '<td>'
            +   '<select id="cap-val-' + cid + '" class="fi-sm cap-val-sel" data-cap="' + escapeHtml(cap) + '">'
            +   opts
            +   '</select>'
            + '</td>'
            + '<td>'
            +   '<div id="cap-origins-' + cid + '" class="cap-origins-area' + origHidden + '">'
            +     '<div id="cap-chips-' + cid + '" class="cap-chips">' + chipsHtml + '</div>'
            +     '<div class="cap-origin-add">'
            +       '<input id="cap-origin-input-' + cid + '" type="url" placeholder="https://example.com" class="fi w-250" maxlength="253">'
            +       '<button class="btn-allowlist-add" data-action="capPolAddOrigin" data-cap="' + escapeHtml(cap) + '">Add</button>'
            +     '</div>'
            +     '<span id="cap-origin-err-' + cid + '" class="cap-origin-err"></span>'
            +   '</div>'
            + '</td>'
            + '</tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

function _capChipHtml(cap, origin) {
    return '<span class="cap-origin-chip">'
        + escapeHtml(origin)
        + ' <button class="chip-x" data-action="capPolRemoveOrigin"'
        +   ' data-cap="' + escapeHtml(cap) + '"'
        +   ' data-origin="' + escapeHtml(origin) + '"'
        +   ' title="Remove origin">✕</button>'
        + '</span>';
}

// ---------------------------------------------------------------------------
// Origin validation
// ---------------------------------------------------------------------------
function _capValidateOrigin(s) {
    s = (s || '').trim();
    if (!s || s.indexOf('*') !== -1) return false;
    if (s.indexOf('https://') !== 0) return false;
    try {
        var url = new URL(s);
        if (url.protocol !== 'https:') return false;
        // pathname must be '/' (no trailing path component)
        if (url.pathname !== '/') return false;
        // no query string, fragment, or credentials
        if (url.search || url.hash || url.username || url.password) return false;
        return true;
    } catch (e) {
        return false;
    }
}

function _capNormalizeOrigin(s) {
    s = (s || '').trim();
    try {
        var url = new URL(s);
        return url.protocol + '//' + url.host;
    } catch (e) {
        return s;
    }
}

// ---------------------------------------------------------------------------
// Read origin list from the chip elements for a given capability
// ---------------------------------------------------------------------------
function _capGetOrigins(cap) {
    var cid     = _capId(cap);
    var chipsEl = document.getElementById('cap-chips-' + cid);
    if (!chipsEl) return [];
    var origins = [];
    // Safe: cap is from our own CAP_NAMES constant (lowercase letters + single hyphen only)
    chipsEl.querySelectorAll('[data-action="capPolRemoveOrigin"][data-cap="' + cap + '"]').forEach(function(btn) {
        var o = btn.getAttribute('data-origin');
        if (o) origins.push(o);
    });
    return origins;
}

// ---------------------------------------------------------------------------
// Add an origin chip
// ---------------------------------------------------------------------------
function capPolAddOrigin(cap) {
    var cid     = _capId(cap);
    var inputEl = document.getElementById('cap-origin-input-' + cid);
    var errEl   = document.getElementById('cap-origin-err-' + cid);
    var chipsEl = document.getElementById('cap-chips-' + cid);
    if (!inputEl || !chipsEl) return;

    if (errEl) errEl.textContent = '';

    var raw    = (inputEl.value || '').trim();
    var origin = _capNormalizeOrigin(raw);

    if (!_capValidateOrigin(origin)) {
        if (errEl) errEl.textContent = 'Must be https://hostname[:port] — no path, no wildcard.';
        return;
    }

    var existing = _capGetOrigins(cap);
    if (existing.indexOf(origin) !== -1) {
        if (errEl) errEl.textContent = 'Origin already in the list.';
        return;
    }
    if (existing.length >= CAP_MAX_ORIGINS) {
        if (errEl) errEl.textContent = 'Maximum ' + CAP_MAX_ORIGINS + ' origins per capability.';
        return;
    }

    // Use <template> so the HTML is parsed safely (no document.write, no innerHTML on a live node)
    var tmpl = document.createElement('template');
    tmpl.innerHTML = _capChipHtml(cap, origin);
    chipsEl.appendChild(tmpl.content.firstChild);
    inputEl.value = '';
}

// ---------------------------------------------------------------------------
// Remove an origin chip
// ---------------------------------------------------------------------------
function capPolRemoveOrigin(cap, origin) {
    var cid     = _capId(cap);
    var chipsEl = document.getElementById('cap-chips-' + cid);
    if (!chipsEl) return;
    chipsEl.querySelectorAll('[data-action="capPolRemoveOrigin"]').forEach(function(btn) {
        if (btn.getAttribute('data-cap') === cap && btn.getAttribute('data-origin') === origin) {
            var chip = btn.closest('.cap-origin-chip');
            if (chip) chip.remove();
        }
    });
}

// ---------------------------------------------------------------------------
// Collect policy object from DOM state
// ---------------------------------------------------------------------------
function _capCollectPolicy() {
    var policy  = {};
    var partial = (_capScopeType !== 'org');
    CAP_NAMES.forEach(function(cap) {
        var cid   = _capId(cap);
        var valEl = document.getElementById('cap-val-' + cid);
        if (!valEl) return;
        var value = valEl.value;
        if (partial && value === '') return;   // empty = inherit (do not include in partial override)
        policy[cap] = {
            value:      value,
            allow_list: (value === 'allow_list') ? _capGetOrigins(cap) : []
        };
    });
    return policy;
}

// ---------------------------------------------------------------------------
// Save (PUT)
// ---------------------------------------------------------------------------
async function capPolSave() {
    _capSetResult('<span class="loading">Saving…</span>');
    var policy = _capCollectPolicy();

    if (_capScopeType === 'org' && Object.keys(policy).length < CAP_NAMES.length) {
        _capSetResult('<span class="badge badge-red">All ' + CAP_NAMES.length + ' capabilities must be set for the org policy.</span>');
        return;
    }
    if (_capScopeType !== 'org' && Object.keys(policy).length === 0) {
        _capSetResult('<span class="badge badge-red">Set at least one capability to save an override.</span>');
        return;
    }

    var url;
    if (_capScopeType === 'org')        url = '/admin/api/capability-policy';
    else if (_capScopeType === 'group') url = '/admin/api/capability-policy/groups/' + encodeURIComponent(_capScopeId);
    else                                url = '/admin/api/capability-policy/users/'  + encodeURIComponent(_capScopeId);

    var resp = await apiMutate(url, {
        method:  'PUT',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(policy)
    }).catch(function() { return null; });

    if (!resp) {
        _capSetResult('<span class="badge badge-red">Network error or request cancelled.</span>');
        return;
    }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message))
            ? (err.detail.error || err.detail.message)
            : ('HTTP ' + resp.status);
        _capSetResult('<span class="badge badge-red">Error: ' + escapeHtml(msg) + '</span>');
        return;
    }

    _capSetResult('<span class="badge badge-green">Saved.</span>');
    await _capFetchAndRender();   // reload to show canonical server state
}

// ---------------------------------------------------------------------------
// Delete / Reset
// ---------------------------------------------------------------------------
async function capPolDelete() {
    var scopeLabel = (_capScopeType === 'org')
        ? 'the org policy (will fall back to the immutable baseline)'
        : 'the ' + _capScopeType + ' override';
    if (!confirm('Delete / reset ' + scopeLabel + '?')) return;

    var url;
    // Org reset goes via the addressable /orgs/{id} endpoint (DEFAULT_ORG_ID = 'default')
    if (_capScopeType === 'group')     url = '/admin/api/capability-policy/groups/' + encodeURIComponent(_capScopeId);
    else if (_capScopeType === 'user') url = '/admin/api/capability-policy/users/'  + encodeURIComponent(_capScopeId);
    else                               url = '/admin/api/capability-policy/orgs/default';

    _capSetResult('<span class="loading">Deleting…</span>');

    var resp = await apiMutate(url, { method: 'DELETE' }).catch(function() { return null; });

    if (!resp) { _capSetResult('<span class="badge badge-red">Network error.</span>'); return; }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message))
            ? (err.detail.error || err.detail.message)
            : ('HTTP ' + resp.status);
        _capSetResult('<span class="badge badge-red">Error: ' + escapeHtml(msg) + '</span>');
        return;
    }

    _capSetResult('<span class="badge badge-green">Override removed.</span>');
    await _capFetchAndRender();
}

// ---------------------------------------------------------------------------
// Effective policy preview (GET /effective?user=...)
// ---------------------------------------------------------------------------
async function capPolEffective() {
    var emailEl  = document.getElementById('cap-eff-user');
    var resultEl = document.getElementById('cap-eff-result');
    var tableEl  = document.getElementById('cap-eff-table');
    var tbodyEl  = document.getElementById('cap-eff-tbody');
    if (!emailEl) return;

    var email = (emailEl.value || '').trim();
    if (!email) {
        if (resultEl) resultEl.innerHTML = '<span class="badge badge-red">Enter a user email.</span>';
        return;
    }

    if (resultEl) resultEl.innerHTML = '<span class="loading">Resolving…</span>';
    if (tableEl)  tableEl.classList.add('is-hidden');

    var data = await api('/admin/api/capability-policy/effective?user=' + encodeURIComponent(email));

    if (!data) {
        if (resultEl) resultEl.innerHTML = '<span class="badge badge-red">Failed to load effective policy.</span>';
        return;
    }

    if (resultEl) {
        resultEl.innerHTML = '<span class="badge badge-green">Resolved for '
            + escapeHtml(data.user || email)
            + ' (org: ' + escapeHtml(data.org_id || 'default') + ')</span>';
    }

    var effective = data.effective || {};
    var html = '';
    CAP_NAMES.forEach(function(cap) {
        var setting = effective[cap];
        var value   = setting ? setting.value : '—';
        var origins = (setting && setting.allow_list && setting.allow_list.length)
            ? setting.allow_list.map(function(o) { return escapeHtml(o); }).join('<br>')
            : '<span class="txt-muted-sm">—</span>';

        var badge = ({
            'off':        '<span class="badge badge-red">off</span>',
            'self':       '<span class="badge badge-green">self</span>',
            'allow_list': '<span class="badge badge-blue">allow-list</span>'
        })[value] || escapeHtml(value);

        html += '<tr>'
            + '<td class="cap-name-cell">' + escapeHtml(CAP_LABELS[cap] || cap) + '</td>'
            + '<td>' + badge + '</td>'
            + '<td class="cap-origins-display">' + origins + '</td>'
            + '</tr>';
    });

    if (tbodyEl) tbodyEl.innerHTML = html || '<tr><td colspan="3" class="empty">No effective policy resolved.</td></tr>';
    if (tableEl) tableEl.classList.remove('is-hidden');
}

// ---------------------------------------------------------------------------
// Update the save-result span
// ---------------------------------------------------------------------------
function _capSetResult(html) {
    var el = document.getElementById('cap-pol-result');
    if (el) el.innerHTML = html;
}

// ---------------------------------------------------------------------------
// DOM-ready: wire the scope-type select change event
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    var scopeTypeEl = document.getElementById('cap-scope-type');
    if (scopeTypeEl) scopeTypeEl.addEventListener('change', _capUpdateScopeVisibility);
});

// Global change delegation: show / hide allow-list area when value select changes.
// Scoped to .cap-val-sel so no interference with other selects on the page.
document.addEventListener('change', function(e) {
    if (!e.target || !e.target.classList || !e.target.classList.contains('cap-val-sel')) return;
    var cap = e.target.getAttribute('data-cap');
    if (!cap) return;
    var origArea = document.getElementById('cap-origins-' + _capId(cap));
    if (!origArea) return;
    if (e.target.value === 'allow_list') origArea.classList.remove('is-hidden');
    else origArea.classList.add('is-hidden');
});

// Expose for the showPage() hook in dashboard.js
window.loadCapabilityPolicy = loadCapabilityPolicy;
