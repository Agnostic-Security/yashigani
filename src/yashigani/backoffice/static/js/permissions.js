// Yashigani Backoffice — Unified Resource Permission Grant admin panel
// 3.1 Phase 8 — WebUI consuming /admin/api/permissions
// Last updated: 2026-06-28T00:00:00+00:00
//
// Manages grants for blast-radius resource types:
//   mcp_server | external_api | cloud_model | agent
// browser_capability is managed by capability-policy.js (separate page).
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml, fillSelect, errMsg)
// Loaded as: <script src="/static/js/permissions.js" defer></script>

/* global api, apiMutate, escapeHtml, fillSelect, errMsg */

var _PERM_RT_LIST = ['mcp_server', 'external_api', 'cloud_model', 'agent'];
var _PERM_RT_LABELS = {
    'mcp_server':   'MCP Server',
    'external_api': 'External API',
    'cloud_model':  'Cloud Model',
    'agent':        'Agent',
};

var _permScopeType      = 'org';
var _permScopeId        = 'default';
var _permResourceType   = 'mcp_server';
var _permPendingApprove = null;   // {rt, rid} while approve form is open

// ---------------------------------------------------------------------------
// Scope picker visibility
// ---------------------------------------------------------------------------
function _permUpdateScopeVisibility() {
    var typeEl = document.getElementById('perm-scope-type');
    if (!typeEl) return;
    var t = typeEl.value;
    var gp = document.getElementById('perm-group-picker');
    var up = document.getElementById('perm-user-picker');
    var ap = document.getElementById('perm-agent-picker');
    if (gp) { if (t === 'group') gp.classList.remove('is-hidden'); else gp.classList.add('is-hidden'); }
    if (up) { if (t === 'user')  up.classList.remove('is-hidden'); else up.classList.add('is-hidden'); }
    if (ap) { if (t === 'agent') ap.classList.remove('is-hidden'); else ap.classList.add('is-hidden'); }
}

// ---------------------------------------------------------------------------
// Load groups into the group picker
// ---------------------------------------------------------------------------
async function _permLoadGroups() {
    var data = await api('/admin/rbac/groups');
    var groups = (data && data.groups) ? data.groups : [];
    fillSelect('perm-group-id', groups.map(function(g) {
        return { value: g.id, label: (g.display_name || g.id) + ' (' + g.id + ')' };
    }), [{ value: '', label: groups.length ? 'Select a group…' : 'No groups configured' }]);
}

// ---------------------------------------------------------------------------
// Entry point — called by showPage() when the Permissions page opens
// ---------------------------------------------------------------------------
async function loadPermissions() {
    await _permLoadGroups();
    _permUpdateScopeVisibility();
    _permScopeType    = 'org';
    _permScopeId      = 'default';
    _permResourceType = 'mcp_server';
    var typeEl = document.getElementById('perm-scope-type');
    if (typeEl) typeEl.value = 'org';
    var rtEl = document.getElementById('perm-resource-type');
    if (rtEl) rtEl.value = 'mcp_server';
    // Sync OPA row hidden state with initial resource type
    _permUpdateGrantFormOpa();
    await _permFetchAndRender();
    await loadDeclarations();
}

// ---------------------------------------------------------------------------
// Load button handler — reads scope + resource_type pickers then fetches
// ---------------------------------------------------------------------------
async function permLoad() {
    var typeEl = document.getElementById('perm-scope-type');
    if (!typeEl) return;
    _permScopeType = typeEl.value;

    if (_permScopeType === 'group') {
        var gEl = document.getElementById('perm-group-id');
        _permScopeId = gEl ? (gEl.value || '').trim() : '';
        if (!_permScopeId) { _permSetResult('<span class="badge badge-red">Select a group first.</span>'); return; }
    } else if (_permScopeType === 'user') {
        var uEl = document.getElementById('perm-user-email');
        _permScopeId = uEl ? (uEl.value || '').trim() : '';
        if (!_permScopeId) { _permSetResult('<span class="badge badge-red">Enter a user email first.</span>'); return; }
    } else if (_permScopeType === 'agent') {
        var aEl = document.getElementById('perm-agent-id');
        _permScopeId = aEl ? (aEl.value || '').trim() : '';
        if (!_permScopeId) { _permSetResult('<span class="badge badge-red">Enter an agent ID first.</span>'); return; }
    } else {
        // org
        _permScopeId = 'default';
    }

    var rtEl = document.getElementById('perm-resource-type');
    if (rtEl) _permResourceType = rtEl.value;
    // Re-evaluate OPA row visibility after resource type may have changed
    _permUpdateGrantFormOpa();

    await _permFetchAndRender();
}

// ---------------------------------------------------------------------------
// Fetch grants and render
// ---------------------------------------------------------------------------
async function _permFetchAndRender() {
    var container = document.getElementById('perm-grants-container');
    if (!container) return;
    container.innerHTML = '<span class="loading">Loading…</span>';

    var url = '/admin/api/permissions/grants/'
        + encodeURIComponent(_permScopeType) + '/'
        + encodeURIComponent(_permScopeId)   + '/'
        + encodeURIComponent(_permResourceType);

    var data = await api(url);

    // Update scope label in panel header
    var labelEl = document.getElementById('perm-scope-label');
    if (labelEl) {
        var rtLabel   = _PERM_RT_LABELS[_permResourceType] || _permResourceType;
        var scopePart = _permScopeType === 'org'   ? 'Organisation'
                      : _permScopeType === 'group' ? 'Group: ' + _permScopeId
                      : _permScopeType === 'user'  ? 'User: ' + _permScopeId
                      :                              'Agent: ' + _permScopeId;
        labelEl.textContent = rtLabel + ' — ' + scopePart;
    }

    if (!data) {
        container.innerHTML = '<p class="txt-note">Could not load grants (permission store may not be ready).</p>';
        return;
    }

    _permRenderGrants(data.grants || []);
}

// ---------------------------------------------------------------------------
// Render grants table
// ---------------------------------------------------------------------------
function _permRenderGrants(grants) {
    var container = document.getElementById('perm-grants-container');
    if (!container) return;

    if (!grants.length) {
        container.innerHTML = '<p class="empty">No grants for this scope and resource type.</p>';
        return;
    }

    var html = '<table class="perm-table">'
        + '<thead><tr>'
        + '<th>Resource ID</th>'
        + '<th>Grant</th>'
        + '<th>OPA Policy Ref</th>'
        + '<th>Actions</th>'
        + '</tr></thead><tbody>';

    grants.forEach(function(g) {
        var allowBadge = g.allow
            ? '<span class="badge badge-green">allow</span>'
            : '<span class="badge badge-red">deny</span>';
        var opaRef = g.opa_policy_ref
            ? '<code class="perm-code">' + escapeHtml(g.opa_policy_ref) + '</code>'
            : '<span class="txt-muted-sm">—</span>';
        html += '<tr>'
            + '<td class="td-mono">' + escapeHtml(g.resource_id) + '</td>'
            + '<td>' + allowBadge + '</td>'
            + '<td>' + opaRef + '</td>'
            + '<td>'
            + '<button class="btn-tbl btn-tbl--blue" data-action="permGrantEdit"'
            +   ' data-rid="' + escapeHtml(g.resource_id) + '"'
            +   ' data-allow="' + (g.allow ? '1' : '0') + '"'
            +   ' data-opa="' + escapeHtml(g.opa_policy_ref || '') + '">Edit</button>'
            + ' <button class="btn-tbl btn-tbl--red btn-tbl--ml" data-action="permDeleteGrant"'
            +   ' data-rid="' + escapeHtml(g.resource_id) + '">Delete</button>'
            + '</td>'
            + '</tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Grant form — OPA policy ref row visibility
// cloud_model + allow=true only
// ---------------------------------------------------------------------------
function _permUpdateGrantFormOpa() {
    var allowEl = document.getElementById('perm-grant-allow');
    var opaRow  = document.getElementById('perm-grant-opa-row');
    if (!opaRow) return;
    var show = (_permResourceType === 'cloud_model') && (allowEl ? allowEl.checked : false);
    if (show) opaRow.classList.remove('is-hidden');
    else      opaRow.classList.add('is-hidden');
}

// ---------------------------------------------------------------------------
// Open grant form in add or edit mode
// Called with '' / true / '' for "Add" and with real values for "Edit".
// ---------------------------------------------------------------------------
function permGrantEdit(resourceId, allow, opaPolicyRef) {
    var ridEl   = document.getElementById('perm-grant-rid');
    var allowEl = document.getElementById('perm-grant-allow');
    var opaEl   = document.getElementById('perm-grant-opa');
    var resEl   = document.getElementById('perm-grant-result');
    var titleEl = document.getElementById('perm-grant-form-title');

    var rid = (resourceId || '').trim();
    if (ridEl)   ridEl.value    = rid;
    if (allowEl) allowEl.checked = (allow === '1' || allow === true || allow === 'true');
    if (opaEl)   opaEl.value    = opaPolicyRef || '';
    if (resEl)   resEl.innerHTML = '';
    if (titleEl) titleEl.textContent = rid ? 'Edit grant: ' + rid : 'Add grant';

    _permUpdateGrantFormOpa();

    var formEl = document.getElementById('perm-grant-form');
    if (formEl) formEl.classList.add('is-open');
}

function permGrantEditCancel() {
    var formEl = document.getElementById('perm-grant-form');
    if (formEl) formEl.classList.remove('is-open');
}

// ---------------------------------------------------------------------------
// Save grant (PUT /grants/{scope}/{scope_id}/{rt}/{rid})
// Step-up handled transparently by apiMutate.
// ---------------------------------------------------------------------------
async function permSaveGrant() {
    var ridEl   = document.getElementById('perm-grant-rid');
    var allowEl = document.getElementById('perm-grant-allow');
    var opaEl   = document.getElementById('perm-grant-opa');
    var resEl   = document.getElementById('perm-grant-result');
    if (!ridEl || !allowEl) return;

    var resourceId = (ridEl.value || '').trim();
    var allow      = allowEl.checked;
    var opa        = (opaEl && opaEl.value) ? opaEl.value.trim() : null;

    if (!resourceId) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Resource ID is required.</span>';
        return;
    }

    // INV-2 client-side guard: cloud_model + allow=true requires opa_policy_ref.
    // The server enforces this too (422); we mirror it here for instant feedback.
    if (_permResourceType === 'cloud_model' && allow && !opa) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">OPA policy ref is required for cloud_model with allow=on (INV-2).</span>';
        return;
    }

    if (resEl) resEl.innerHTML = '<span class="loading">Saving…</span>';

    var url = '/admin/api/permissions/grants/'
        + encodeURIComponent(_permScopeType) + '/'
        + encodeURIComponent(_permScopeId)   + '/'
        + encodeURIComponent(_permResourceType) + '/'
        + encodeURIComponent(resourceId);

    var body = { allow: allow };
    if (opa) body.opa_policy_ref = opa;

    var resp = await apiMutate(url, {
        method:  'PUT',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
    }).catch(function() { return null; });

    if (!resp) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Network error or request cancelled.</span>';
        return;
    }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(errMsg(err, resp.status)) + '</span>';
        return;
    }

    if (resEl) resEl.innerHTML = '<span class="badge badge-green">Saved.</span>';
    permGrantEditCancel();
    await _permFetchAndRender();
}

// ---------------------------------------------------------------------------
// Delete grant (DELETE /grants/{scope}/{scope_id}/{rt}/{rid})
// Step-up handled transparently by apiMutate.
// ---------------------------------------------------------------------------
async function permDeleteGrant(resourceId) {
    if (!resourceId) return;
    if (!confirm('Delete grant for "' + resourceId + '"? This removes the explicit permission entry.')) return;

    var url = '/admin/api/permissions/grants/'
        + encodeURIComponent(_permScopeType) + '/'
        + encodeURIComponent(_permScopeId)   + '/'
        + encodeURIComponent(_permResourceType) + '/'
        + encodeURIComponent(resourceId);

    _permSetResult('<span class="loading">Deleting…</span>');

    var resp = await apiMutate(url, { method: 'DELETE' }).catch(function() { return null; });

    if (!resp) { _permSetResult('<span class="badge badge-red">Network error.</span>'); return; }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        _permSetResult('<span class="badge badge-red">Error: ' + escapeHtml(errMsg(err, resp.status)) + '</span>');
        return;
    }

    _permSetResult('<span class="badge badge-green">Deleted.</span>');
    await _permFetchAndRender();
}

// ---------------------------------------------------------------------------
// Effective permission preview (GET /effective)
// ---------------------------------------------------------------------------
async function permEffective() {
    var rtEl     = document.getElementById('perm-eff-rt');
    var ridEl    = document.getElementById('perm-eff-rid');
    var orgEl    = document.getElementById('perm-eff-org');
    var emailEl  = document.getElementById('perm-eff-user');
    var groupsEl = document.getElementById('perm-eff-groups');
    var resEl    = document.getElementById('perm-eff-result');
    var pathEl   = document.getElementById('perm-eff-path');
    if (!rtEl || !ridEl) return;

    var rt  = rtEl.value;
    var rid = (ridEl.value || '').trim();
    if (!rid) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Enter a resource ID.</span>';
        return;
    }

    if (resEl)  resEl.innerHTML = '<span class="loading">Resolving…</span>';
    if (pathEl) pathEl.classList.add('is-hidden');

    var orgId  = (orgEl && orgEl.value) ? orgEl.value.trim() : 'default';
    var email  = emailEl  ? (emailEl.value  || '').trim() : '';
    var groups = groupsEl ? (groupsEl.value || '').trim() : '';

    var qs = '?resource_type=' + encodeURIComponent(rt)
           + '&resource_id='   + encodeURIComponent(rid)
           + '&org_id='        + encodeURIComponent(orgId || 'default');
    if (email)  qs += '&user_email=' + encodeURIComponent(email);
    if (groups) qs += '&group_ids='  + encodeURIComponent(groups);

    var data = await api('/admin/api/permissions/effective' + qs);

    if (!data) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Failed to resolve (permission store may not be ready).</span>';
        return;
    }

    var effectiveBadge = data.effective_allow
        ? '<span class="badge badge-green">ALLOW</span>'
        : '<span class="badge badge-red">DENY</span>';

    if (resEl) resEl.innerHTML = effectiveBadge
        + ' &nbsp;<strong>' + escapeHtml(_PERM_RT_LABELS[rt] || rt) + '</strong>'
        + ' / <code class="perm-code">' + escapeHtml(rid) + '</code>'
        + ' &nbsp;<span class="txt-muted-sm">(org: ' + escapeHtml(data.org_id || 'default') + ')</span>';

    if (pathEl) {
        var path    = data.resolution_path || {};
        var orgG    = path.org_grant;
        var userG   = path.user_grant;
        var groupGs = path.group_grants || [];

        function _grantSummary(g) {
            if (!g) return '<span class="txt-muted-sm">no explicit grant — deny by default</span>';
            var badge = g.allow
                ? '<span class="badge badge-green">allow</span>'
                : '<span class="badge badge-red">deny</span>';
            return badge + (g.opa_policy_ref
                ? ' <code class="perm-code">' + escapeHtml(g.opa_policy_ref) + '</code>'
                : '');
        }

        var pathHtml = '<div class="perm-eff-path">';
        pathHtml += '<div class="perm-eff-path-row">'
            + '<span class="perm-eff-path-lbl">Org grant</span>'
            + '<span>' + _grantSummary(orgG) + '</span></div>';

        groupGs.forEach(function(gg) {
            pathHtml += '<div class="perm-eff-path-row">'
                + '<span class="perm-eff-path-lbl">Group: ' + escapeHtml(gg.group_id) + '</span>'
                + '<span>' + _grantSummary(gg) + '</span></div>';
        });

        if (email) {
            pathHtml += '<div class="perm-eff-path-row">'
                + '<span class="perm-eff-path-lbl">User grant</span>'
                + '<span>' + _grantSummary(userG) + '</span></div>';
        }

        pathHtml += '<div class="perm-eff-path-row perm-eff-path-row--result">'
            + '<span class="perm-eff-path-lbl">Effective</span>'
            + '<span>' + effectiveBadge + '</span></div>';
        pathHtml += '</div>';

        pathEl.innerHTML = pathHtml;
        pathEl.classList.remove('is-hidden');
    }
}

// ---------------------------------------------------------------------------
// Declarations — list pending (GET /declarations)
// ---------------------------------------------------------------------------
async function loadDeclarations() {
    var container = document.getElementById('perm-decl-container');
    if (!container) return;
    container.innerHTML = '<span class="loading">Loading…</span>';

    var data = await api('/admin/api/permissions/declarations');

    if (!data) {
        container.innerHTML = '<p class="txt-note">Could not load declarations.</p>';
        return;
    }

    _permRenderDeclarations(data.pending || []);
}

function _permRenderDeclarations(pending) {
    var container = document.getElementById('perm-decl-container');
    if (!container) return;

    if (!pending.length) {
        container.innerHTML = '<p class="empty">No pending declarations.</p>';
        return;
    }

    var html = '<table class="perm-table">'
        + '<thead><tr>'
        + '<th>Resource Type</th>'
        + '<th>Resource ID</th>'
        + '<th>Declared By</th>'
        + '<th>Justification</th>'
        + '<th>Org Grant</th>'
        + '<th>Actions</th>'
        + '</tr></thead><tbody>';

    pending.forEach(function(d) {
        var rtLabel  = _PERM_RT_LABELS[d.resource_type] || d.resource_type;
        var orgBadge = d.org_grant_exists
            ? '<span class="badge badge-green">Exists</span>'
            : '<span class="badge badge-red">None</span>';
        html += '<tr>'
            + '<td><span class="badge badge-blue">' + escapeHtml(rtLabel) + '</span></td>'
            + '<td class="td-mono">' + escapeHtml(d.resource_id) + '</td>'
            + '<td class="td-xs">'  + escapeHtml(d.declared_by || '—') + '</td>'
            + '<td class="td-xs perm-decl-just">' + escapeHtml(d.justification || '—') + '</td>'
            + '<td>' + orgBadge + '</td>'
            + '<td>'
            + '<button class="btn-tbl btn-tbl--green" data-action="permApproveClick"'
            +   ' data-rt="' + escapeHtml(d.resource_type) + '"'
            +   ' data-rid="' + escapeHtml(d.resource_id) + '">Approve</button>'
            + ' <button class="btn-tbl btn-tbl--red btn-tbl--ml" data-action="permRejectDeclaration"'
            +   ' data-rt="' + escapeHtml(d.resource_type) + '"'
            +   ' data-rid="' + escapeHtml(d.resource_id) + '">Reject</button>'
            + '</td>'
            + '</tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Approve declaration — open inline confirm form
// EU AI Act Art.14: AI recommends; human (admin) decides here.
// ---------------------------------------------------------------------------
function _permUpdateApproveFormOpa() {
    var allowEl = document.getElementById('perm-decl-approve-allow');
    var opaRow  = document.getElementById('perm-decl-approve-opa-row');
    if (!allowEl || !opaRow) return;
    var isCloud = _permPendingApprove && _permPendingApprove.rt === 'cloud_model';
    var show    = isCloud && allowEl.checked;
    if (show) opaRow.classList.remove('is-hidden');
    else      opaRow.classList.add('is-hidden');
}

function permApproveClick(rt, rid) {
    _permPendingApprove = { rt: rt, rid: rid };

    var labelEl = document.getElementById('perm-decl-approve-label');
    if (labelEl) labelEl.textContent = (_PERM_RT_LABELS[rt] || rt) + ': ' + rid;

    var opaEl   = document.getElementById('perm-decl-approve-opa');
    var allowEl = document.getElementById('perm-decl-approve-allow');
    var resEl   = document.getElementById('perm-decl-approve-result');
    if (opaEl)   opaEl.value    = '';
    if (allowEl) allowEl.checked = true;
    if (resEl)   resEl.innerHTML = '';

    _permUpdateApproveFormOpa();

    var formEl = document.getElementById('perm-decl-approve-form');
    if (formEl) formEl.classList.add('is-open');
}

function permApproveCancelClick() {
    _permPendingApprove = null;
    var formEl = document.getElementById('perm-decl-approve-form');
    if (formEl) formEl.classList.remove('is-open');
}

// Execute the approval — POST /declarations/{rt}/{rid}/approve
// Step-up handled transparently by apiMutate.
async function permApproveDeclaration() {
    if (!_permPendingApprove) return;
    var rt  = _permPendingApprove.rt;
    var rid = _permPendingApprove.rid;

    var allowEl = document.getElementById('perm-decl-approve-allow');
    var opaEl   = document.getElementById('perm-decl-approve-opa');
    var resEl   = document.getElementById('perm-decl-approve-result');

    var allow = allowEl ? allowEl.checked : true;
    var opa   = (opaEl && opaEl.value) ? opaEl.value.trim() : null;

    // INV-2 client-side guard
    if (rt === 'cloud_model' && allow && !opa) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">OPA policy ref is required for cloud_model allow=on (INV-2).</span>';
        return;
    }

    if (resEl) resEl.innerHTML = '<span class="loading">Approving…</span>';

    var url = '/admin/api/permissions/declarations/'
        + encodeURIComponent(rt) + '/'
        + encodeURIComponent(rid) + '/approve';

    var body = { allow: allow };
    if (opa) body.opa_policy_ref = opa;

    var resp = await apiMutate(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
    }).catch(function() { return null; });

    if (!resp) {
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Network error or request cancelled.</span>';
        return;
    }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        if (resEl) resEl.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(errMsg(err, resp.status)) + '</span>';
        return;
    }

    if (resEl) resEl.innerHTML = '<span class="badge badge-green">Approved. Org-level grant created.</span>';
    _permPendingApprove = null;
    var formEl = document.getElementById('perm-decl-approve-form');
    if (formEl) formEl.classList.remove('is-open');

    await loadDeclarations();
    // Refresh grants table if the approved resource_type matches current view
    if (rt === _permResourceType) await _permFetchAndRender();
}

// ---------------------------------------------------------------------------
// Reject declaration (DELETE /declarations/{rt}/{rid})
// Step-up handled transparently by apiMutate.
// ---------------------------------------------------------------------------
async function permRejectDeclaration(rt, rid) {
    if (!rt || !rid) return;
    var label = (_PERM_RT_LABELS[rt] || rt) + ' / ' + rid;
    if (!confirm('Reject declaration for "' + label + '"?\nNo grant will be created.')) return;

    _permSetDeclResult('<span class="loading">Rejecting…</span>');

    var url = '/admin/api/permissions/declarations/'
        + encodeURIComponent(rt) + '/'
        + encodeURIComponent(rid);

    var resp = await apiMutate(url, { method: 'DELETE' }).catch(function() { return null; });

    if (!resp) { _permSetDeclResult('<span class="badge badge-red">Network error.</span>'); return; }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        _permSetDeclResult('<span class="badge badge-red">Error: ' + escapeHtml(errMsg(err, resp.status)) + '</span>');
        return;
    }

    _permSetDeclResult('<span class="badge badge-green">Declaration rejected.</span>');
    await loadDeclarations();
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------
function _permSetResult(html) {
    var el = document.getElementById('perm-grants-result');
    if (el) el.innerHTML = html;
}

function _permSetDeclResult(html) {
    var el = document.getElementById('perm-decl-result');
    if (el) el.innerHTML = html;
}

// ---------------------------------------------------------------------------
// DOM-ready: wire scope-type change event
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    var scopeTypeEl = document.getElementById('perm-scope-type');
    if (scopeTypeEl) scopeTypeEl.addEventListener('change', _permUpdateScopeVisibility);
});

// Global change delegation: OPA row + grant form visibility updates.
document.addEventListener('change', function(e) {
    if (!e.target) return;
    var id = e.target.id;
    if (id === 'perm-grant-allow') {
        // Toggle OPA ref row in add/edit grant form
        _permUpdateGrantFormOpa();
    } else if (id === 'perm-decl-approve-allow') {
        // Toggle OPA ref row in approve form
        _permUpdateApproveFormOpa();
    } else if (id === 'perm-resource-type') {
        // Resource type changed in scope picker
        _permResourceType = e.target.value;
        _permUpdateGrantFormOpa();
    }
});

// Expose for the showPage() hook in dashboard.js
window.loadPermissions   = loadPermissions;
window.loadDeclarations  = loadDeclarations;
