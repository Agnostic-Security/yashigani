// last-updated: 2026-06-13T00:00:00+01:00 (2.25.5-uifix: R7 remove onboarding; B3 budget dropdowns; R3 alias layout)
// V1.2.1 — HTML output encoding helper (CWE-79 stored XSS prevention).
// Every user-controlled value rendered into innerHTML MUST pass through
// escapeHtml().  Stage B audit (§4.1) identified 10 sinks; all are fixed below.
var HTML_ESCAPES = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) { return HTML_ESCAPES[c]; });
}

// 2.25.5 — populate a <select> from a list of {value,label} (or strings),
// preserving the current selection if it still exists. `leading` is an optional
// array of {value,label} prepended (e.g. an explicit "All" wildcard option).
// All values are escaped — built via DOM, never innerHTML — CSP-safe, no styles.
function fillSelect(id, items, leading) {
    var sel = document.getElementById(id);
    if (!sel) return;
    var prev = sel.value;
    var opts = (leading || []).concat(items || []);
    sel.replaceChildren();
    opts.forEach(function(it) {
        var value = (typeof it === 'string') ? it : it.value;
        var label = (typeof it === 'string') ? it : (it.label != null ? it.label : it.value);
        var o = document.createElement('option');
        o.value = (value == null ? '' : String(value));
        o.textContent = (label == null ? '' : String(label));
        sel.appendChild(o);
    });
    // Restore prior selection if still present.
    if (prev) {
        for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === prev) { sel.value = prev; break; }
        }
    }
}

// Navigation
function showPage(name, triggerEl) {
    document.querySelectorAll('.page').forEach(function(p) { p.className = 'page'; });
    document.getElementById('page-' + name).className = 'page active';
    document.querySelectorAll('.nav-links button').forEach(function(b) { b.className = ''; });
    // Highlight the matching nav button by data-param — works whether triggered
    // from the nav itself or programmatically.
    var navBtn = (triggerEl && triggerEl.tagName === 'BUTTON' && triggerEl.closest && triggerEl.closest('.nav-links'))
        ? triggerEl
        : document.querySelector('.nav-links button[data-param="' + name + '"]');
    if (navBtn) navBtn.className = 'active';
    // Load data for the page
    if (name === 'dashboard') loadDashboard();
    if (name === 'agents') loadAgents();
    if (name === 'accounts') loadAccounts();
    if (name === 'budgets') loadBudgets();
    if (name === 'models') { loadModels(); loadCloudOverride(); }
    if (name === 'sensitivity') loadSensitivity();
    if (name === 'policies') loadPolicies();
    if (name === 'audit') loadAuditFacets();  // R19/R20 — populate verdict + source-type filters
    if (name === 'settings') loadSettings();
    if (name === 'backup') loadBackup();
    // PKI panel — loadPkiStatus is defined in pki.js (loaded defer).
    // window.loadPkiStatus guard prevents ReferenceError if pki.js not yet parsed.
    // Bug fix: v2.23.3 — showPage('pki') was missing the loadPkiStatus() call.
    if (name === 'pki' && typeof window.loadPkiStatus === 'function') window.loadPkiStatus();
    // Runtime settings panel — loadRuntimeSettings is defined in runtime-settings.js (loaded defer).
    if (name === 'runtime-settings' && typeof window.loadRuntimeSettings === 'function') window.loadRuntimeSettings();
    if (name === 'policies') loadBindings();  // #16 — load bindings alongside policies
    if (name === 'rbac') loadGroups();        // RBAC group management (parity with /admin/rbac API)
}

// ---------------------------------------------------------------------------
// Policies (OPA) — read-only viewer of the Rego modules loaded in OPA.
// Example modules are IMMUTABLE templates; editable client copies + activation
// + ingress/egress enforcement are phased features (opa_policy_management_design).
// ---------------------------------------------------------------------------
async function loadPolicies() {
    var container = document.getElementById('policies-container');
    if (!container) return;
    container.innerHTML = '<span class="loading">Loading…</span>';
    var data = await api('/admin/policies');
    if (!data || !data.policies) {
        container.innerHTML = '<p class="error">Could not load policies from the policy service.</p>';
        return;
    }
    var catLabel = { example: 'Templates (immutable examples)', core: 'Core gateway policies', test: 'Test policies' };
    var catBadge = {
        example: '<span class="badge badge-amber">template</span>',
        core: '<span class="badge badge-green">core</span>',
        test: '<span class="badge badge-slate">test</span>'
    };
    var groups = {};
    data.policies.forEach(function(p) { (groups[p.category] = groups[p.category] || []).push(p); });
    var html = '';
    ['example', 'core', 'test'].forEach(function(cat) {
        var list = groups[cat];
        if (!list || !list.length) return;
        html += '<h3 class="h3-section">' + escapeHtml(catLabel[cat] || cat) + '</h3>';
        html += '<table><thead><tr><th>Name</th><th>Package</th><th></th><th></th></tr></thead><tbody>';
        list.forEach(function(p) {
            html += '<tr>'
                + '<td class="td-mono">' + escapeHtml(p.name) + '</td>'
                + '<td class="td-pkg">' + escapeHtml(p.package || '—') + '</td>'
                + '<td>' + (catBadge[p.category] || '') + '</td>'
                + '<td><button class="btn btn-sm" data-action="policyView" data-id="' + escapeHtml(p.id) + '" data-cat="' + escapeHtml(p.category) + '">View</button></td>'
                + '</tr>';
        });
        html += '</tbody></table>';
    });
    container.innerHTML = html + '<p class="txt-note txt-mt8">' +
        escapeHtml(String(data.count)) + ' policy modules loaded in OPA (' + escapeHtml(data.opa_url || '') + ').</p>';
}

async function viewPolicy(id, cat) {
    var panel = document.getElementById('policy-view-panel');
    var ta = document.getElementById('policy-view-src');
    var title = document.getElementById('policy-view-title');
    var badge = document.getElementById('policy-view-badge');
    if (!panel || !ta) return;
    title.textContent = id;
    badge.innerHTML = (cat === 'example')
        ? '<span class="badge badge-template">immutable template</span>'
        : (cat === 'client' ? '<span class="badge badge-green">client copy</span>' : '');
    // Reset to view (read-only) state each time.
    ta.readOnly = true;
    var sa = document.getElementById('policy-saveas'); if (sa) sa.classList.remove('is-open');
    var ec = document.querySelector('#policy-edit-controls [data-action="policyEditCopy"]'); if (ec) ec.classList.remove('is-hidden');
    var res = document.getElementById('policy-save-result'); if (res) res.innerHTML = '';
    var nm = document.getElementById('policy-copy-name');
    if (nm) nm.value = (id.split('/').pop().replace(/\.rego$/, '') + '_copy').toLowerCase().replace(/[^a-z0-9_]/g, '');
    ta.value = 'Loading…';
    panel.classList.remove('is-hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    // {policy_id:path} — keep the slashes, encode each segment
    var encoded = id.split('/').map(encodeURIComponent).join('/');
    var data = await api('/admin/policies/' + encoded);
    ta.value = (data && typeof data.raw === 'string' && data.raw) ? data.raw : 'Could not load policy source.';
}

// Turn the read-only viewer into an editable "copy" (templates are immutable —
// we edit a copy and save it under a new clients.<name>).
function policyEditCopy() {
    var ta = document.getElementById('policy-view-src');
    var sa = document.getElementById('policy-saveas');
    var ec = document.querySelector('#policy-edit-controls [data-action="policyEditCopy"]');
    if (ta) { ta.readOnly = false; ta.focus(); }
    if (sa) sa.classList.add('is-open');
    if (ec) ec.classList.add('is-hidden');
}

async function policySaveCopy() {
    var ta = document.getElementById('policy-view-src');
    var nm = document.getElementById('policy-copy-name');
    var res = document.getElementById('policy-save-result');
    if (!ta || !nm || !res) return;
    var name = (nm.value || '').trim().toLowerCase();
    if (!/^[a-z][a-z0-9_]{1,40}$/.test(name)) {
        res.innerHTML = '<span class="badge badge-red">Error</span> name: lowercase, start with a letter (a-z0-9_)';
        return;
    }
    res.innerHTML = '<span class="loading">Saving…</span>';
    var resp = await apiMutate('/admin/policies/save', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, rego: ta.value })
    });
    if (!resp) { res.innerHTML = '<span class="badge badge-red">Error</span> request cancelled'; return; }
    var data = await resp.json().catch(function() { return {}; });
    if (resp.ok && data.status === 'ok') {
        res.innerHTML = '<span class="badge badge-green">Saved</span> clients.' + escapeHtml(name) + ' — loaded into OPA';
        loadPolicies();
    } else {
        res.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(data, resp.status));
    }
}

function closePolicyView() {
    var panel = document.getElementById('policy-view-panel');
    if (panel) panel.classList.add('is-hidden');
}

// Open the editor pre-loaded with an AI draft, in edit mode, ready to save.
function viewPolicyDraft(name, rego) {
    var panel = document.getElementById('policy-view-panel');
    var ta = document.getElementById('policy-view-src');
    var title = document.getElementById('policy-view-title');
    var badge = document.getElementById('policy-view-badge');
    var nm = document.getElementById('policy-copy-name');
    if (!panel || !ta) return;
    title.textContent = 'AI draft: clients.' + name;
    badge.innerHTML = '<span class="badge badge-violet">AI draft — review before saving</span>';
    ta.value = rego;
    ta.readOnly = false;
    if (nm) nm.value = name;
    var sa = document.getElementById('policy-saveas'); if (sa) sa.classList.add('is-open');
    var ec = document.querySelector('#policy-edit-controls [data-action="policyEditCopy"]'); if (ec) ec.classList.add('is-hidden');
    var sr = document.getElementById('policy-save-result'); if (sr) sr.innerHTML = '';
    panel.classList.remove('is-hidden');
    panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function generatePolicy() {
    var promptEl = document.getElementById('policy-gen-prompt');
    var nmEl = document.getElementById('policy-gen-name');
    var res = document.getElementById('policy-gen-result');
    if (!promptEl || !res) return;
    var p = (promptEl.value || '').trim();
    if (p.length < 4) { res.innerHTML = '<span class="badge badge-red">Error</span> describe the policy first'; return; }
    var name = ((nmEl && nmEl.value) || 'generated').trim().toLowerCase().replace(/[^a-z0-9_]/g, '') || 'generated';
    res.innerHTML = '<span class="loading">Asking the internal LLM… (can take ~20–60s)</span>';
    var resp = await apiMutate('/admin/policies/generate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: p, name: name })
    });
    if (!resp) { res.innerHTML = '<span class="badge badge-red">Error</span> request failed'; return; }
    var d = await resp.json().catch(function() { return {}; });
    if (resp.ok && d.status === 'ok' && d.rego) {
        res.innerHTML = '<span class="badge badge-green">Drafted</span> review &amp; save below (model: ' + escapeHtml(d.model || '') + ')';
        viewPolicyDraft(d.name || name, d.rego);
    } else {
        res.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(d, resp.status));
    }
}

// ── #16 client-policy bindings (parity with the /admin/policies/bind* API) ──
// R11(a): populate the "Policy name" dropdown from the policies loaded in OPA.
// Only client policies (clients/<name>) are bindable, so prefer those; fall back
// to all names if no client policies exist yet.
async function loadBindablePolicies() {
    var data = await api('/admin/policies');
    var pols = (data && data.policies) ? data.policies : [];
    // A bindable client policy has package clients.<name>; its name is <name>.
    var clientPols = pols.filter(function(p) {
        return (p.package && p.package.indexOf('clients') === 0) ||
               (p.id && (p.id.indexOf('clients/') === 0 || p.id.indexOf('/clients/') >= 0));
    });
    var src = clientPols.length ? clientPols : pols;
    var opts = src.map(function(p) { return { value: p.name, label: p.name }; });
    fillSelect('bind-policy-name', opts, [{ value: '', label: opts.length ? 'Select a policy…' : 'No bindable policies' }]);
}

// R11(b): populate the "Subject ID" dropdown for the selected subject kind, with
// an explicit "All (wildcard)" option instead of an implicit blank.
async function loadBindSubjects() {
    var kindSel = document.getElementById('bind-scope-kind');
    if (!kindSel) return;
    var kind = kindSel.value;
    var leading = [{ value: '*', label: 'All (wildcard)' }];
    var items = [];
    if (kind === 'agent') {
        var agents = await api('/admin/agents');
        items = (agents || []).map(function(a) { return { value: a.agent_id, label: a.name + ' (' + a.agent_id + ')' }; });
    } else if (kind === 'human') {
        var t = await api('/admin/models/allocation-targets?target_type=user');
        items = (t && t.targets) ? t.targets : [];
    }
    // service / api_client / mcp_server: no enumerable registry surfaced here —
    // wildcard "All" plus free identifiers are handled by the explicit All option.
    fillSelect('bind-scope-id', items, leading);
}

async function loadBindings() {
    var c = document.getElementById('bindings-container');
    if (!c) return;
    // R11: refresh the policy + subject dropdowns alongside the bindings table.
    loadBindablePolicies();
    loadBindSubjects();
    c.innerHTML = '<span class="loading">Loading…</span>';
    var data = await api('/admin/policies/bindings');
    if (!data || !data.bindings) { c.innerHTML = '<p class="txt-note">No bindings (or failed to load).</p>'; return; }
    if (data.bindings.length === 0) { c.innerHTML = '<p class="txt-note">No client-policy bindings yet.</p>'; return; }
    var html = '<table><thead><tr><th>Policy</th><th>Scope</th><th>Direction</th><th>Enabled</th><th></th></tr></thead><tbody>';
    data.bindings.forEach(function(b) {
        var scope = escapeHtml(b.scope_kind) + ':' + escapeHtml(b.scope_id || '*');
        html += '<tr>'
            + '<td class="td-mono">' + escapeHtml(b.policy_name) + '</td>'
            + '<td class="td-mono">' + scope + '</td>'
            + '<td>' + escapeHtml(b.direction) + '</td>'
            + '<td>' + (b.enabled ? 'yes' : 'no') + '</td>'
            + '<td><button class="btn btn-sm btn-sm-danger" data-action="unbindBinding" data-binding-id="' + escapeHtml(b.id) + '">Remove</button></td>'
            + '</tr>';
    });
    c.innerHTML = html + '</tbody></table>';
}

async function bindPolicy() {
    var name = (document.getElementById('bind-policy-name').value || '').trim();
    var kind = document.getElementById('bind-scope-kind').value;
    var sid = (document.getElementById('bind-scope-id').value || '').trim();
    // R11: explicit "All" wildcard is the "*" option — the backend stores an
    // empty scope_id as the wildcard, so normalise "*" -> "".
    if (sid === '*') sid = '';
    var dir = document.getElementById('bind-direction').value;
    if (!name) { alert('Select a client policy to bind.'); return; }
    var resp = await apiMutate('/admin/policies/bind', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy_name: name, scope_kind: kind, scope_id: sid, direction: dir })
    });
    if (!resp) return;
    var d = await resp.json().catch(function() { return {}; });
    if (resp.ok && d.status === 'ok') {
        document.getElementById('bind-policy-name').value = '';
        document.getElementById('bind-scope-id').value = '';
        loadBindings();
    } else {
        alert('Bind failed: ' + errMsg(d, resp.status));
    }
}

async function unbindBinding(id) {
    if (!id || !confirm('Remove this client-policy binding?')) return;
    var resp = await apiMutate('/admin/policies/bind/' + encodeURIComponent(id), { method: 'DELETE' });
    if (!resp) return;
    if (resp.ok) { loadBindings(); return; }
    var d = await resp.json().catch(function() { return {}; });
    alert('Remove failed: ' + errMsg(d, resp.status));
}

// ── RBAC group management (parity with the /admin/rbac API) ──────────────────
// All mutating calls go through apiMutate() so the step-up TOTP modal is handled
// transparently; GETs go through api(). The selected group for member management
// is tracked in _rbacSelectedGroup.
var _rbacSelectedGroup = null;  // {id, display_name} of the group whose members are shown

function _rbacResourcesSummary(resources) {
    if (!resources || !resources.length) return '<span class="txt-muted-sm">none</span>';
    return resources.map(function(r) {
        return escapeHtml((r.method || '*') + ' ' + (r.path_glob || ''));
    }).join('<br>');
}

async function loadGroups() {
    var tbody = document.getElementById('rbac-groups-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="5" class="empty">Loading...</td></tr>';
    var data = await api('/admin/rbac/groups');
    if (!data || !data.groups) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">Could not load RBAC groups.</td></tr>';
        return;
    }
    if (data.groups.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No groups yet. Use "+ Create group" above.</td></tr>';
        return;
    }
    var html = '';
    data.groups.forEach(function(g) {
        html += '<tr>'
            + '<td class="txt-xs cred-code">' + escapeHtml(g.id) + '</td>'
            + '<td>' + escapeHtml(g.display_name) + '</td>'
            + '<td>' + (g.members ? g.members.length : 0) + '</td>'
            + '<td class="txt-xs">' + _rbacResourcesSummary(g.allowed_resources) + '</td>'
            + '<td>'
            + '<button class="btn btn-sm btn-sm-primary" data-action="rbacManageMembers" data-group-id="' + escapeHtml(g.id) + '" data-group-name="' + escapeHtml(g.display_name) + '">Members</button> '
            + '<button class="btn btn-sm btn-sm-danger" data-action="deleteGroup" data-group-id="' + escapeHtml(g.id) + '" data-group-name="' + escapeHtml(g.display_name) + '">Delete</button>'
            + '</td>'
            + '</tr>';
    });
    tbody.innerHTML = html;
    // If a members panel is open for a group that still exists, refresh it; else close.
    if (_rbacSelectedGroup) {
        var still = data.groups.filter(function(g) { return g.id === _rbacSelectedGroup.id; });
        if (still.length) { _rbacRenderMembers(still[0]); }
        else { rbacMembersClose(); }
    }
}

function rbacAddResourceRow() {
    var rows = document.getElementById('rbac-resource-rows');
    if (!rows) return;
    var div = document.createElement('div');
    div.className = 'form-row rbac-resource-row';
    div.innerHTML =
        '<div><label class="lbl">Method</label><br><select class="fi rbac-res-method">'
        + '<option value="*">*</option><option value="GET">GET</option><option value="POST">POST</option>'
        + '<option value="PUT">PUT</option><option value="DELETE">DELETE</option></select></div>'
        + '<div><label class="lbl">Path glob</label><br><input type="text" placeholder="/mcp/**" class="fi w-250 rbac-res-path"></div>';
    rows.appendChild(div);
}

function _rbacCollectResources() {
    var out = [];
    document.querySelectorAll('#rbac-resource-rows .rbac-resource-row').forEach(function(row) {
        var method = row.querySelector('.rbac-res-method');
        var path = row.querySelector('.rbac-res-path');
        var pv = path ? (path.value || '').trim() : '';
        if (!pv) return;  // blank path → skip the row
        out.push({ method: method ? method.value : '*', path_glob: pv });
    });
    return out;
}

async function createGroup() {
    var res = document.getElementById('rbac-create-result');
    var name = (document.getElementById('rbac-group-name').value || '').trim();
    if (!name) { if (res) res.innerHTML = '<span class="badge badge-red">Enter a display name.</span>'; return; }
    var resources = _rbacCollectResources();
    var resp = await apiMutate('/admin/rbac/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ display_name: name, allowed_resources: resources })
    });
    if (!resp) return;
    var d = await resp.json().catch(function() { return {}; });
    if (resp.ok) {
        if (res) res.innerHTML = '<span class="badge badge-green">Group created.</span>';
        document.getElementById('rbac-group-name').value = '';
        // Reset resource rows to a single blank row.
        var rows = document.getElementById('rbac-resource-rows');
        if (rows) {
            rows.innerHTML = '';
            rbacAddResourceRow();
        }
        loadGroups();
    } else {
        if (res) res.innerHTML = '<span class="badge badge-red">Create failed: ' + escapeHtml(errMsg(d, resp.status)) + '</span>';
    }
}

async function deleteGroup(id, name) {
    if (!id) return;
    if (!confirm('Delete group "' + (name || id) + '"? This removes all its members and resource grants.')) return;
    var resp = await apiMutate('/admin/rbac/groups/' + encodeURIComponent(id), { method: 'DELETE' });
    if (!resp) return;
    if (resp.ok) { loadGroups(); return; }
    var d = await resp.json().catch(function() { return {}; });
    alert('Delete failed: ' + errMsg(d, resp.status));
}

function rbacManageMembers(id, name) {
    _rbacSelectedGroup = { id: id, display_name: name };
    var panel = document.getElementById('rbac-members-panel');
    if (panel) panel.className = 'panel';
    var title = document.getElementById('rbac-members-title');
    if (title) title.textContent = 'Members — ' + name;
    var input = document.getElementById('rbac-member-email');
    if (input) input.value = '';
    // Fetch the fresh group so the member list reflects current state.
    _rbacRefreshSelected();
}

async function _rbacRefreshSelected() {
    if (!_rbacSelectedGroup) return;
    var g = await api('/admin/rbac/groups/' + encodeURIComponent(_rbacSelectedGroup.id));
    if (!g || !g.id) {
        var c = document.getElementById('rbac-members-container');
        if (c) c.innerHTML = '<p class="txt-note">Group not found (it may have been deleted).</p>';
        return;
    }
    _rbacRenderMembers(g);
}

function _rbacRenderMembers(group) {
    var c = document.getElementById('rbac-members-container');
    if (!c) return;
    var members = group.members || [];
    if (members.length === 0) {
        c.innerHTML = '<p class="txt-note">No members yet. Add one above.</p>';
        return;
    }
    var html = '<table><thead><tr><th>Email</th><th>Actions</th></tr></thead><tbody>';
    members.forEach(function(m) {
        html += '<tr><td>' + escapeHtml(m) + '</td>'
            + '<td><button class="btn btn-sm btn-sm-danger" data-action="removeRbacMember" data-group-id="'
            + escapeHtml(group.id) + '" data-member-email="' + escapeHtml(m) + '">Remove</button></td></tr>';
    });
    c.innerHTML = html + '</tbody></table>';
}

function rbacMembersClose() {
    _rbacSelectedGroup = null;
    var panel = document.getElementById('rbac-members-panel');
    if (panel) panel.className = 'panel is-hidden';
}

async function addRbacMember(id) {
    var gid = id || (_rbacSelectedGroup && _rbacSelectedGroup.id);
    if (!gid) return;
    var input = document.getElementById('rbac-member-email');
    var email = input ? (input.value || '').trim() : '';
    if (!email) { alert('Enter a member email.'); return; }
    var resp = await apiMutate('/admin/rbac/groups/' + encodeURIComponent(gid) + '/members', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
    });
    if (!resp) return;
    var d = await resp.json().catch(function() { return {}; });
    if (resp.ok) {
        if (input) input.value = '';
        _rbacRefreshSelected();
        loadGroups();  // refresh member counts in the table
    } else {
        alert('Add member failed: ' + errMsg(d, resp.status));
    }
}

async function removeRbacMember(id, email) {
    if (!id || !email) return;
    if (!confirm('Remove ' + email + ' from this group?')) return;
    var resp = await apiMutate(
        '/admin/rbac/groups/' + encodeURIComponent(id) + '/members/' + encodeURIComponent(email),
        { method: 'DELETE' }
    );
    if (!resp) return;
    if (resp.ok) { _rbacRefreshSelected(); loadGroups(); return; }
    var d = await resp.json().catch(function() { return {}; });
    alert('Remove member failed: ' + errMsg(d, resp.status));
}

async function rbacForcePush() {
    var res = document.getElementById('rbac-push-result');
    if (res) res.textContent = 'Pushing…';
    var resp = await apiMutate('/admin/rbac/policy/push', { method: 'POST' });
    if (!resp) { if (res) res.textContent = ''; return; }
    var d = await resp.json().catch(function() { return {}; });
    if (resp.ok && d.pushed) {
        if (res) res.textContent = 'Pushed: ' + (d.groups_count || 0) + ' group(s), ' + (d.users_count || 0) + ' user mapping(s).';
    } else {
        if (res) res.textContent = 'Push failed: ' + errMsg(d, resp.status);
    }
}

async function api(path) {
    try {
        var controller = new AbortController();
        var timeout = setTimeout(function() { controller.abort(); }, 10000);
        var resp = await fetch(path, { credentials: 'same-origin', signal: controller.signal });
        clearTimeout(timeout);
        if (resp.status === 401) { window.location.href = '/admin/login'; return null; }
        if (!resp.ok) { console.error('API error: ' + path + ' → ' + resp.status); return null; }
        return await resp.json();
    } catch (err) {
        if (err.name === 'AbortError') { console.error('API timeout: ' + path); }
        else { console.error('API fetch failed: ' + path + ' — ' + err.message); }
        return null;
    }
}

// ---------------------------------------------------------------------------
// V6.8.4 Step-up TOTP interceptor + Phase 1 auth-UX (B4 fix)
//
// apiMutate() wraps high-value fetch calls.
//
// 401 handling:
//   - detail.error === "step_up_required": show TOTP step-up modal + retry.
//   - detail.error === "session_expired_or_invalid": explicit re-login prompt,
//     NOT a silent redirect (B4 fix — prevents confusing mid-action bounces).
//   - Generic 401: redirect to /admin/login with a clear re-auth message.
//
// 403 handling (B4 fix — Phase 1 / 2.25.5-auth-ingress):
//   - Previously: apiMutate returned the resp and callers checked resp.ok, but
//     403 was not handled specially — the caller rendered it as a generic error.
//     The *real* B4 bounce happened because the OWUI/catch-all Caddy route saw
//     a 403 from /auth/verify (admin session on data plane) and redirected to
//     /admin/ — which *looked* like a login bounce.  The fix is on the Caddy
//     side (route the 403 to an explicit error page, not a login redirect) plus
//     here: surfacing the 403 body as a readable error instead of null.
//   - detail.error present: return the resp so the caller can render errMsg().
//   - This ensures a non-admin user hitting an admin-only action gets a clean
//     "Not authorized" message, not a silent bounce or blank response.
//
// Usage: var resp = await apiMutate(path, options);
// Returns the final Response object (or null on abort/network error).
// ---------------------------------------------------------------------------

var _stepupQueue = null;  // Pending {resolve, reject, path, options} while modal is open

async function apiMutate(path, options) {
    options = Object.assign({ credentials: 'same-origin' }, options || {});
    try {
        var resp = await fetch(path, options);
        if (resp.status === 401) {
            var body = null;
            try { body = await resp.clone().json(); } catch(e) {}
            if (body && body.detail && body.detail.error === 'step_up_required') {
                // Show step-up modal; resolve/reject from the modal confirm handler.
                return new Promise(function(resolve, reject) {
                    _stepupQueue = { resolve: resolve, reject: reject, path: path, options: options };
                    _showStepUpModal();
                });
            }
            if (body && body.detail && body.detail.error === 'session_expired_or_invalid') {
                // B4 fix: session expired mid-action — explicit prompt, not silent bounce.
                // Show a message so the admin knows what happened, then redirect.
                _showAuthzError('Your session has expired. Please sign in again.', '/admin/login');
                return null;
            }
            // Generic 401 — session gone or unauthenticated; redirect to login.
            window.location.href = '/admin/login';
            return null;
        }
        if (resp.status === 403) {
            // B4 fix: return the response so the caller can render errMsg() rather
            // than silently returning null.  Callers already check resp.ok and render
            // the error; returning null here caused a "Request failed" message instead
            // of the actual authorization error from the server.
            return resp;
        }
        return resp;
    } catch(err) {
        console.error('apiMutate failed: ' + path + ' — ' + err.message);
        return null;
    }
}

// _showAuthzError — display a clear authorization/session error to the admin.
// Used by the B4 fix to surface session-expiry + 403 errors gracefully.
// msg: human-readable message; redirectTo: optional URL to navigate to after a delay.
function _showAuthzError(msg, redirectTo) {
    // Try to show in a visible location on the page.
    var banner = document.getElementById('msg-box') || document.getElementById('status-msg');
    if (banner) {
        banner.className = (banner.className || '') + ' msg error visible';
        banner.textContent = msg;
    } else {
        // Fallback: browser alert (last resort).
        alert(msg);
    }
    if (redirectTo) {
        setTimeout(function() { window.location.href = redirectTo; }, 2500);
    }
}

// errMsg() extracts a human-readable string from a parsed JSON error body.
// FastAPI `detail` may be a string, an object ({error,message}), or a Pydantic
// validation list — never render an object directly or it shows "[object Object]".
function errMsg(err, status) {
    var d = err && err.detail;
    if (d === undefined || d === null) return 'HTTP ' + status;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) {
        return d.map(function(x) { return (x && (x.msg || x.message)) || JSON.stringify(x); }).join('; ');
    }
    if (typeof d === 'object') return d.message || d.error || JSON.stringify(d);
    return String(d);
}

function _showStepUpModal() {
    var modal = document.getElementById('stepup-modal');
    if (!modal) return;
    document.getElementById('stepup-code').value = '';
    document.getElementById('stepup-error').textContent = '';
    modal.classList.add('is-open');
    document.getElementById('stepup-code').focus();
}

function _hideStepUpModal() {
    var modal = document.getElementById('stepup-modal');
    if (modal) modal.classList.remove('is-open');
    _stepupQueue = null;
}

async function submitStepUp() {
    var code = (document.getElementById('stepup-code').value || '').trim();
    var errEl = document.getElementById('stepup-error');
    if (!/^\d{6}$/.test(code)) {
        errEl.textContent = 'Enter a 6-digit TOTP code.';
        return;
    }
    errEl.textContent = '';
    document.getElementById('stepup-submit').disabled = true;
    try {
        var r = await fetch('/auth/stepup', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ totp_code: code })
        });
        if (r.ok) {
            // Step-up accepted — retry the original request
            var pending = _stepupQueue;
            _hideStepUpModal();
            if (pending) {
                var retry = await fetch(pending.path, pending.options);
                pending.resolve(retry);
            }
        } else {
            var err = await r.json().catch(function() { return {}; });
            if (r.status === 429) {
                errEl.textContent = 'Too many failed attempts. Please log out and log in again.';
            } else {
                errEl.textContent = 'Invalid code. Try again.';
            }
            document.getElementById('stepup-submit').disabled = false;
        }
    } catch(e) {
        errEl.textContent = 'Network error. Try again.';
        document.getElementById('stepup-submit').disabled = false;
    }
}

function cancelStepUp() {
    if (_stepupQueue) {
        _stepupQueue.reject(new Error('step_up_cancelled'));
    }
    _hideStepUpModal();
}

// Allow Enter key in the TOTP input to submit
document.addEventListener('DOMContentLoaded', function() {
    var codeEl = document.getElementById('stepup-code');
    if (codeEl) {
        codeEl.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { e.preventDefault(); submitStepUp(); }
        });
    }
});

// Dashboard
async function loadDashboard() {
    var data = await api('/dashboard/health');
    var container = document.getElementById('health-cards');
    if (data && data.components) {
        var html = '';
        for (var name in data.components) {
            var comp = data.components[name];
            var status = comp.status || 'unknown';
            var badge = status === 'ok' ? 'badge-green' : status === 'degraded' ? 'badge-yellow' : 'badge-red';
            html += '<div class="card"><div class="card-label">' + name + '</div><span class="badge ' + badge + '">' + status + '</span></div>';
        }
        container.innerHTML = html;
    } else {
        container.innerHTML = '<div class="card"><span class="badge badge-red">Error loading health data</span></div>';
    }

    // Accounts count
    var accounts = await api('/admin/accounts');
    if (accounts && accounts.accounts) {
        document.getElementById('stat-accounts').textContent = accounts.accounts.length;
    }

    // Agents count
    var agents = await api('/admin/agents');
    if (agents) {
        document.getElementById('stat-agents').textContent = Array.isArray(agents) ? agents.length : 0;
    }

    // License
    document.getElementById('stat-license').textContent = 'Community';
}

// Agents
async function loadAgents() {
    var agents = await api('/admin/agents');
    var tbody = document.getElementById('agents-tbody');
    if (agents && agents.length > 0) {
        var html = '';
        for (var i = 0; i < agents.length; i++) {
            var a = agents[i];
            var statusBadge = a.status === 'active' ? 'badge-green' : 'badge-red';
            // R6: Edit button — carries the editable agent fields (groups/caller-groups
            // are arrays; join with commas for the text inputs).
            var aGroups = (a.groups || []).join(',');
            var aCaller = (a.allowed_caller_groups || []).join(',');
            var actions = '<button data-action="editAgent"'
                + ' data-agent-id="' + escapeHtml(a.agent_id) + '"'
                + ' data-agent-name="' + escapeHtml(a.name) + '"'
                + ' data-agent-url="' + escapeHtml(a.upstream_url || '') + '"'
                + ' data-agent-groups="' + escapeHtml(aGroups) + '"'
                + ' data-agent-caller-groups="' + escapeHtml(aCaller) + '"'
                + ' class="btn-tbl btn-tbl--blue">Edit</button>';
            actions += ' <button data-action="rotateAgentToken" data-agent-id="' + escapeHtml(a.agent_id) + '" data-agent-name="' + escapeHtml(a.name) + '" class="btn-tbl btn-tbl--blue btn-tbl--ml">Rotate Token</button>';
            if (a.status === 'active') {
                actions += ' <button data-action="deactivateAgent" data-agent-id="' + escapeHtml(a.agent_id) + '" class="btn-tbl btn-tbl--red btn-tbl--ml">Deactivate</button>';
            }
            html += '<tr><td>' + escapeHtml(a.name) + '</td><td class="td-mono-xs">' + escapeHtml(a.agent_id) + '</td><td class="td-xs">' + escapeHtml(a.upstream_url) + '</td><td><span class="badge ' + statusBadge + '">' + escapeHtml(a.status) + '</span></td><td class="td-xs">' + escapeHtml(a.last_seen_at || 'Never') + '</td><td>' + actions + '</td></tr>';
        }
        tbody.innerHTML = html;
    } else {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No agents registered</td></tr>';
    }
}

async function registerAgent() {
    var name = document.getElementById('agent-name').value.trim();
    var url = document.getElementById('agent-url').value.trim();
    var protocol = document.getElementById('agent-protocol').value;
    var groups = document.getElementById('agent-groups').value.trim().split(',').filter(Boolean);
    var callerGroups = document.getElementById('agent-caller-groups').value.trim().split(',').filter(Boolean);
    var cidrs = document.getElementById('agent-cidrs').value.trim().split(',').filter(Boolean);
    var result = document.getElementById('register-agent-result');
    if (!name || !url) { result.textContent = 'Name and URL are required.'; return; }
    result.innerHTML = '<span class="loading">Registering...</span>';
    var body = { name: name, upstream_url: url, protocol: protocol };
    if (groups.length) body.groups = groups;
    if (callerGroups.length) body.allowed_caller_groups = callerGroups;
    if (cidrs.length) body.allowed_cidrs = cidrs;
    var resp = await apiMutate('/admin/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) {
        var data = await resp.json();
        result.innerHTML = '<span class="badge badge-green">Registered</span>';
        document.getElementById('agent-name').value = '';
        document.getElementById('agent-url').value = '';
        document.getElementById('agent-token-name').textContent = name;
        document.getElementById('agent-token-value').textContent = data.token;
        document.getElementById('agent-token-panel').classList.add('is-open');
        loadAgents();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status));
    }
}

async function rotateAgentToken(agentId, name) {
    if (!confirm('Rotate token for "' + name + '"? The old token will stop working immediately.')) return;
    var resp = await apiMutate('/admin/agents/' + agentId + '/token/rotate', {
        method: 'POST'
    }).catch(function() { return null; });
    if (resp && resp.ok) {
        var data = await resp.json();
        document.getElementById('agent-token-name').textContent = name;
        document.getElementById('agent-token-value').textContent = data.token;
        document.getElementById('agent-token-panel').classList.add('is-open');
    } else if (resp) {
        alert('Token rotation failed: ' + resp.status);
    }
}

async function deactivateAgent(agentId) {
    if (!confirm('Deactivate this agent? It will no longer accept requests.')) return;
    var resp = await apiMutate('/admin/agents/' + agentId, {
        method: 'DELETE'
    }).catch(function() { return null; });
    if (resp && (resp.ok || resp.status === 204)) { loadAgents(); }
    else if (resp) { alert('Deactivation failed: ' + resp.status); }
}

// ── R6: edit an agent (name / url / groups / caller-groups) via PUT ─────────
function editAgent(agentId, name, url, groups, callerGroups) {
    document.getElementById('edit-agent-id').value = agentId;
    document.getElementById('edit-agent-name').value = name || '';
    document.getElementById('edit-agent-url').value = url || '';
    document.getElementById('edit-agent-groups').value = groups || '';
    document.getElementById('edit-agent-caller-groups').value = callerGroups || '';
    document.getElementById('edit-agent-result').textContent = '';
    document.getElementById('edit-agent-form').classList.add('is-open');
}

function cancelEditAgent() {
    document.getElementById('edit-agent-form').classList.remove('is-open');
}

async function saveEditAgent() {
    var agentId = document.getElementById('edit-agent-id').value;
    var name = document.getElementById('edit-agent-name').value.trim();
    var url = document.getElementById('edit-agent-url').value.trim();
    var groups = document.getElementById('edit-agent-groups').value.trim().split(',').map(function(s){return s.trim();}).filter(Boolean);
    var callerGroups = document.getElementById('edit-agent-caller-groups').value.trim().split(',').map(function(s){return s.trim();}).filter(Boolean);
    var result = document.getElementById('edit-agent-result');
    // Only send changed/non-empty fields — AgentUpdateRequest fields are all optional.
    var body = {};
    if (name) body.name = name;
    if (url) body.upstream_url = url;
    body.groups = groups;
    body.allowed_caller_groups = callerGroups;
    var resp = await apiMutate('/admin/agents/' + encodeURIComponent(agentId), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) {
        result.innerHTML = '<span class="badge badge-green">Saved</span>';
        document.getElementById('edit-agent-form').classList.remove('is-open');
        loadAgents();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status));
    }
}

// Accounts
async function loadAccounts() {
    // Admin accounts
    var data = await api('/admin/accounts');
    var tbody = document.getElementById('accounts-tbody');
    if (data && data.accounts && data.accounts.length > 0) {
        var html = '';
        for (var i = 0; i < data.accounts.length; i++) {
            var acc = data.accounts[i];
            var statusBadge = acc.disabled ? 'badge-red' : 'badge-green';
            var statusText = acc.disabled ? 'Disabled' : 'Active';
            var pwBadge = acc.force_password_change ? 'badge-yellow' : 'badge-green';
            var pwText = acc.force_password_change ? 'Change required' : 'OK';
            var totpBadge = acc.force_totp_provision ? 'badge-yellow' : 'badge-green';
            var totpText = acc.force_totp_provision ? 'Not provisioned' : 'Active';
            var toggleBtn = acc.disabled
                ? '<button data-action="toggleAccount" data-account-type="admin" data-username="' + escapeHtml(acc.username) + '" data-toggle-action="enable" class="btn-tbl btn-tbl--green">Enable</button>'
                : '<button data-action="toggleAccount" data-account-type="admin" data-username="' + escapeHtml(acc.username) + '" data-toggle-action="disable" class="btn-tbl btn-tbl--amber">Disable</button>';
            var deleteBtn = '<button data-action="deleteAccount" data-account-type="admin" data-username="' + escapeHtml(acc.username) + '" class="btn-tbl btn-tbl--red btn-tbl--ml">Delete</button>';
            // R5: Edit button — carries username/email/status for the inline edit form.
            var editBtn = '<button data-action="editAccount" data-account-type="admin" data-username="' + escapeHtml(acc.username) + '" data-email="' + escapeHtml(acc.email || '') + '" data-disabled="' + (acc.disabled ? '1' : '0') + '" class="btn-tbl btn-tbl--blue btn-tbl--ml">Edit</button>';
            html += '<tr><td><strong>' + escapeHtml(acc.username) + '</strong></td><td class="td-xs">' + escapeHtml(acc.email || '—') + '</td><td><span class="badge ' + statusBadge + '">' + statusText + '</span></td><td><span class="badge ' + pwBadge + '">' + pwText + '</span></td><td><span class="badge ' + totpBadge + '">' + totpText + '</span></td><td>' + editBtn + toggleBtn + deleteBtn + '</td></tr>';
        }
        tbody.innerHTML = html;
    } else {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No admin accounts found</td></tr>';
    }

    // User accounts
    var users = await api('/admin/users');
    var utbody = document.getElementById('users-tbody');
    if (users && users.users && users.users.length > 0) {
        var html = '';
        for (var i = 0; i < users.users.length; i++) {
            var u = users.users[i];
            var sb = u.disabled ? 'badge-red' : 'badge-green';
            var st = u.disabled ? 'Disabled' : 'Active';
            var pb = u.force_password_change ? 'badge-yellow' : 'badge-green';
            var pt = u.force_password_change ? 'Change required' : 'OK';
            var tb = u.force_totp_provision ? 'badge-yellow' : 'badge-green';
            var tt = u.force_totp_provision ? 'Not provisioned' : 'Active';
            var toggleBtn = u.disabled
                ? '<button data-action="toggleAccount" data-account-type="user" data-username="' + escapeHtml(u.username) + '" data-toggle-action="enable" class="btn-tbl btn-tbl--green">Enable</button>'
                : '<button data-action="toggleAccount" data-account-type="user" data-username="' + escapeHtml(u.username) + '" data-toggle-action="disable" class="btn-tbl btn-tbl--amber">Disable</button>';
            var deleteBtn = '<button data-action="deleteAccount" data-account-type="user" data-username="' + escapeHtml(u.username) + '" class="btn-tbl btn-tbl--red btn-tbl--ml">Delete</button>';
            // R5: Edit button — carries username/email/status for the inline edit form.
            var editBtn = '<button data-action="editAccount" data-account-type="user" data-username="' + escapeHtml(u.username) + '" data-email="' + escapeHtml(u.email || '') + '" data-disabled="' + (u.disabled ? '1' : '0') + '" class="btn-tbl btn-tbl--blue btn-tbl--ml">Edit</button>';
            html += '<tr><td><strong>' + escapeHtml(u.username) + '</strong></td><td class="td-xs">' + escapeHtml(u.email || '—') + '</td><td><span class="badge ' + sb + '">' + st + '</span></td><td><span class="badge ' + pb + '">' + pt + '</span></td><td><span class="badge ' + tb + '">' + tt + '</span></td><td>' + editBtn + toggleBtn + deleteBtn + '</td></tr>';
        }
        utbody.innerHTML = html;
    } else {
        utbody.innerHTML = '<tr><td colspan="6" class="empty">No user accounts — click + Add User to create one</td></tr>';
    }
}

function toggleForm(id) {
    var el = document.getElementById(id);
    // Strict-CSP: toggle the `is-open` modifier instead of writing element.style.
    // Base `.form-panel` is display:none; `.is-open` reveals it.
    el.classList.toggle('is-open');
}

function showCredentials(username, password, totpSecret, totpUri) {
    document.getElementById('cred-username').textContent = username;
    document.getElementById('cred-password').textContent = password;
    document.getElementById('cred-totp').textContent = totpSecret || 'Provisioned at first login';
    document.getElementById('cred-totp-uri').textContent = totpUri || 'Generated at first login';
    document.getElementById('credentials-panel').classList.add('is-open');
}

function generatePassword() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
    var pwd = '';
    for (var i = 0; i < 36; i++) pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    return pwd;
}

async function createAdmin() {
    var email = document.getElementById('new-admin-email').value.trim();
    var result = document.getElementById('create-admin-result');
    if (!email) { result.textContent = 'Email is required.'; return; }
    result.innerHTML = '<span class="loading">Creating...</span>';
    var resp = await fetch('/admin/accounts', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: email })
    });
    if (resp.ok) {
        var data = await resp.json();
        result.innerHTML = '<span class="badge badge-green">Created</span>';
        document.getElementById('new-admin-email').value = '';
        showCredentials(email, data.temporary_password, data.totp_secret, data.totp_uri);
        loadAccounts();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(err.detail ? (err.detail.error || JSON.stringify(err.detail)) : resp.status);
    }
}

async function createUser() {
    var username = document.getElementById('new-user-name').value.trim();
    var result = document.getElementById('create-user-result');
    if (!username) { result.textContent = 'Username is required.'; return; }
    result.innerHTML = '<span class="loading">Creating...</span>';
    var resp = await fetch('/admin/users', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
    });
    if (resp.ok) {
        var data = await resp.json();
        result.innerHTML = '<span class="badge badge-green">Created</span>';
        document.getElementById('new-user-name').value = '';
        showCredentials(username, data.temporary_password, data.totp_secret, data.totp_uri);
        loadAccounts();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(err.detail ? (err.detail.error || JSON.stringify(err.detail)) : resp.status);
    }
}

async function toggleAccount(type, username, action) {
    var path = type === 'admin' ? '/admin/accounts/' : '/admin/users/';
    var fetchFn = (action === 'disable') ? apiMutate : fetch;
    var opts = { method: 'POST', credentials: 'same-origin' };
    var resp = await fetchFn(path + encodeURIComponent(username) + '/' + action, opts)
        .catch(function() { return null; });
    if (!resp) return;
    if (resp.ok) {
        loadAccounts();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        alert('Failed: ' + (err.detail ? (err.detail.message || err.detail.error || JSON.stringify(err.detail)) : resp.status));
    }
}

async function deleteAccount(type, username) {
    if (!confirm('Delete account "' + username + '"? This cannot be undone.')) return;
    var path = type === 'admin' ? '/admin/accounts/' : '/admin/users/';
    var resp = await apiMutate(path + encodeURIComponent(username), {
        method: 'DELETE'
    }).catch(function() { return null; });
    if (!resp) return;
    if (resp.ok) {
        loadAccounts();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        alert('Failed: ' + (err.detail ? (err.detail.message || err.detail.error || JSON.stringify(err.detail)) : resp.status));
    }
}

// ── R5: edit an account (email + status) via the inline edit form ───────────
function editAccount(type, username, email, disabled) {
    var pre = (type === 'admin') ? 'edit-admin-' : 'edit-user-';
    document.getElementById(pre + 'username').value = username;
    document.getElementById(pre + 'email').value = email || '';
    document.getElementById(pre + 'status').value = (disabled === '1') ? 'disabled' : 'active';
    document.getElementById(pre + 'result').textContent = '';
    document.getElementById((type === 'admin' ? 'edit-admin-form' : 'edit-user-form')).classList.add('is-open');
}

function cancelEditAccount(type) {
    document.getElementById((type === 'admin' ? 'edit-admin-form' : 'edit-user-form')).classList.remove('is-open');
}

async function saveEditAccount(type) {
    var pre = (type === 'admin') ? 'edit-admin-' : 'edit-user-';
    var username = document.getElementById(pre + 'username').value;
    var email = document.getElementById(pre + 'email').value.trim();
    var disabled = document.getElementById(pre + 'status').value === 'disabled';
    var result = document.getElementById(pre + 'result');
    var path = (type === 'admin') ? '/admin/accounts/' : '/admin/users/';
    var body = { disabled: disabled };
    if (email) body.email = email;
    var resp = await apiMutate(path + encodeURIComponent(username), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) {
        result.innerHTML = '<span class="badge badge-green">Saved</span>';
        document.getElementById((type === 'admin' ? 'edit-admin-form' : 'edit-user-form')).classList.remove('is-open');
        loadAccounts();
    } else {
        var err = await resp.json().catch(function() { return {}; });
        result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status));
    }
}

// B3: populate the group and individual budget target dropdowns from the
// allocation-targets endpoint (same source as model allocations R4).
async function loadBudgetTargets() {
    // Group dropdown: non-admin RBAC groups
    var gd = await api('/admin/models/allocation-targets?target_type=group');
    var gItems = (gd && gd.targets) ? gd.targets : [];
    var gPlaceholder = gItems.length
        ? { value: '', label: 'Select a group…' }
        : { value: '', label: 'No groups available' };
    fillSelect('group-id', gItems, [gPlaceholder]);

    // Individual dropdown: non-admin users
    var ud = await api('/admin/models/allocation-targets?target_type=user');
    var uItems = (ud && ud.targets) ? ud.targets : [];
    var uPlaceholder = uItems.length
        ? { value: '', label: 'Select a user…' }
        : { value: '', label: 'No users available' };
    fillSelect('ind-id', uItems, [uPlaceholder]);
}

// Budgets
async function loadBudgets() {
    // Refresh target dropdowns alongside the budget data.
    loadBudgetTargets();
    var caps = await api('/admin/budget/org-caps');
    var tbody = document.getElementById('orgcaps-tbody');
    if (caps && caps.org_caps && caps.org_caps.length > 0) {
        var html = '';
        for (var i = 0; i < caps.org_caps.length; i++) {
            var c = caps.org_caps[i];
            html += '<tr><td>' + escapeHtml(c.provider || '*') + '</td><td>' + (c.token_cap || 0).toLocaleString() + '</td><td>' + escapeHtml(c.period || 'monthly') + '</td></tr>';
        }
        tbody.innerHTML = html;
        document.getElementById('stat-org-caps').textContent = caps.org_caps.length;
    } else {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">No caps configured</td></tr>';
        document.getElementById('stat-org-caps').textContent = '0';
    }

    var groups = await api('/admin/budget/groups');
    var gtbody = document.getElementById('groupbudgets-tbody');
    if (groups && groups.group_budgets && groups.group_budgets.length > 0) {
        var html = '';
        for (var i = 0; i < groups.group_budgets.length; i++) {
            var g = groups.group_budgets[i];
            html += '<tr><td>' + escapeHtml(g.group_id) + '</td><td>' + escapeHtml(g.provider || '*') + '</td><td>' + (g.token_budget || 0).toLocaleString() + '</td><td>' + escapeHtml(g.period || 'monthly') + '</td></tr>';
        }
        gtbody.innerHTML = html;
        document.getElementById('stat-group-budgets').textContent = groups.group_budgets.length;
    } else {
        gtbody.innerHTML = '<tr><td colspan="4" class="empty">No group budgets configured</td></tr>';
        document.getElementById('stat-group-budgets').textContent = '0';
    }

    var indiv = await api('/admin/budget/individuals');
    var itbody = document.getElementById('indbudgets-tbody');
    if (indiv && indiv.individual_budgets && indiv.individual_budgets.length > 0) {
        var html = '';
        for (var i = 0; i < indiv.individual_budgets.length; i++) {
            var ind = indiv.individual_budgets[i];
            html += '<tr><td>' + escapeHtml(ind.identity_id) + '</td><td>' + escapeHtml(ind.provider || '*') + '</td><td>' + (ind.token_budget || 0).toLocaleString() + '</td><td>' + escapeHtml(ind.period || 'monthly') + '</td></tr>';
        }
        itbody.innerHTML = html;
        document.getElementById('stat-individual-budgets').textContent = indiv.individual_budgets.length;
    } else {
        itbody.innerHTML = '<tr><td colspan="4" class="empty">No individual budgets configured</td></tr>';
        document.getElementById('stat-individual-budgets').textContent = '0';
    }
}

// Budget create functions
async function addOrgCap() {
    var result = document.getElementById('orgcap-result');
    var resp = await fetch('/admin/budget/org-caps', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            org_id: document.getElementById('orgcap-org').value.trim(),
            provider: document.getElementById('orgcap-provider').value,
            token_cap: parseInt(document.getElementById('orgcap-tokens').value),
            period: document.getElementById('orgcap-period').value
        })
    });
    if (resp.ok) { result.innerHTML = '<span class="badge badge-green">Saved</span>'; loadBudgets(); }
    else { var err = await resp.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(err.detail || resp.status); }
}

async function addGroupBudget() {
    var result = document.getElementById('group-result');
    var groupId = document.getElementById('group-id').value.trim();
    if (!groupId) { result.textContent = 'Select a group.'; return; }
    var resp = await fetch('/admin/budget/groups', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            group_id: groupId,
            provider: document.getElementById('group-provider').value,
            token_budget: parseInt(document.getElementById('group-tokens').value),
            period: document.getElementById('group-period').value
        })
    });
    if (resp.ok) { result.innerHTML = '<span class="badge badge-green">Saved</span>'; loadBudgets(); }
    else { var err = await resp.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(err.detail || resp.status); }
}

async function addIndBudget() {
    var result = document.getElementById('ind-result');
    var indId = document.getElementById('ind-id').value.trim();
    if (!indId) { result.textContent = 'Select a user.'; return; }
    var resp = await fetch('/admin/budget/individuals', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            identity_id: indId,
            provider: document.getElementById('ind-provider').value,
            token_budget: parseInt(document.getElementById('ind-tokens').value),
            period: document.getElementById('ind-period').value
        })
    });
    if (resp.ok) { result.innerHTML = '<span class="badge badge-green">Saved</span>'; loadBudgets(); }
    else { var err = await resp.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(err.detail || resp.status); }
}

// Models
async function loadModels() {
    // Available models from Ollama
    var data = await api('/admin/models/available');
    var tbody = document.getElementById('models-tbody');
    if (data && data.models && data.models.length > 0) {
        var html = '';
        for (var i = 0; i < data.models.length; i++) {
            var m = data.models[i];
            var size = m.size ? (m.size / (1024*1024*1024)).toFixed(1) + ' GB' : '-';
            var modified = m.modified_at ? new Date(m.modified_at).toLocaleDateString() : '-';
            html += '<tr><td class="td-mono">' + escapeHtml(m.name) + '</td><td>' + escapeHtml(size) + '</td><td>' + escapeHtml(modified) + '</td></tr>';
        }
        tbody.innerHTML = html;
    } else {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">No models available — check Ollama connection</td></tr>';
    }

    // R3: populate the alias "Model" dropdown from the pulled-models list so an
    // alias can never map to a non-existent model.
    var modelOpts = (data && data.models ? data.models : []).map(function(m) {
        return { value: m.name, label: m.name };
    });
    if (modelOpts.length === 0) {
        fillSelect('alias-model', [], [{ value: '', label: 'No models pulled — pull one first' }]);
    } else {
        fillSelect('alias-model', modelOpts, [{ value: '', label: 'Select a model…' }]);
    }

    // Aliases from API
    var aliases = await api('/admin/models');
    // R4(a): populate the allocation "Model Alias" dropdown from all aliases.
    var aliasOpts = (aliases && aliases.aliases ? aliases.aliases : []).map(function(a) {
        return { value: a.alias, label: a.alias };
    });
    fillSelect('alloc-alias', aliasOpts, [{ value: '', label: aliasOpts.length ? 'Select an alias…' : 'No aliases yet' }]);
    var atbody = document.getElementById('aliases-tbody');
    if (aliases && aliases.aliases && aliases.aliases.length > 0) {
        var html = '';
        for (var i = 0; i < aliases.aliases.length; i++) {
            var a = aliases.aliases[i];
            var localBadge = a.force_local ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-slate">No</span>';
            html += '<tr><td class="td-mono">' + escapeHtml(a.alias) + '</td><td>' + escapeHtml(a.provider) + '</td><td>' + escapeHtml(a.model) + '</td><td>' + localBadge + '</td><td><button data-action="deleteAlias" data-alias="' + escapeHtml(a.alias) + '" class="btn-tbl btn-tbl--red">Delete</button></td></tr>';
        }
        atbody.innerHTML = html;
    } else {
        atbody.innerHTML = '<tr><td colspan="5" class="empty">No aliases configured</td></tr>';
    }

    // Allocations
    var allocs = await api('/admin/models/allocations');
    var altbody = document.getElementById('allocs-tbody');
    if (allocs && allocs.allocations && allocs.allocations.length > 0) {
        var html = '';
        for (var i = 0; i < allocs.allocations.length; i++) {
            var al = allocs.allocations[i];
            html += '<tr><td class="td-mono">' + escapeHtml(al.model_alias) + '</td><td>' + escapeHtml(al.target_type) + '</td><td>' + escapeHtml(al.target_id) + '</td><td><button data-action="deleteAllocation" data-allocation-id="' + escapeHtml(al.id) + '" class="btn-tbl btn-tbl--red">Remove</button></td></tr>';
        }
        altbody.innerHTML = html;
    } else {
        altbody.innerHTML = '<tr><td colspan="4" class="empty">No allocations — models available to all by default</td></tr>';
    }

    // R4(b): populate the context-dependent Target ID dropdown for the current type.
    await loadAllocTargets();
}

// R4(b): load the Target ID dropdown for the selected target type.
//   user  -> non-admin users; org -> registered orgs; group -> non-admin groups.
async function loadAllocTargets() {
    var typeSel = document.getElementById('alloc-type');
    if (!typeSel) return;
    var tt = typeSel.value;
    var data = await api('/admin/models/allocation-targets?target_type=' + encodeURIComponent(tt));
    var targets = (data && data.targets) ? data.targets : [];
    var placeholder = targets.length
        ? { value: '', label: 'Select a ' + tt + '…' }
        : { value: '', label: 'No ' + tt + ' targets available' };
    fillSelect('alloc-target', targets, [placeholder]);
}

async function addAlias() {
    var result = document.getElementById('alias-result');
    var alias = document.getElementById('alias-name').value.trim();
    if (!alias) { result.textContent = 'Alias name is required.'; return; }
    var resp = await apiMutate('/admin/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            alias: alias,
            provider: document.getElementById('alias-provider').value,
            model: document.getElementById('alias-model').value.trim(),
            force_local: document.getElementById('alias-local').value === 'true'
        })
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) { result.innerHTML = '<span class="badge badge-green">Saved</span>'; document.getElementById('alias-name').value = ''; document.getElementById('alias-model').value = ''; loadModels(); }
    else { var err = await resp.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status)); }
}

async function pullModel() {
    // #25: pull an Ollama model (step-up gated). Can take a while for large models.
    var st = document.getElementById('pull-model-status');
    var name = document.getElementById('pull-model-name').value.trim();
    if (!name) { st.textContent = 'Enter a model name (e.g. gemma3:4b).'; return; }
    st.textContent = 'Pulling ' + name + '… (this can take a while)';
    var resp = await apiMutate('/admin/models/pull', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name })
    });
    if (!resp) { st.textContent = 'Request failed or was cancelled.'; return; }
    var d = await resp.json().catch(function(){return {};});
    if (resp.ok) { st.innerHTML = '<span class="badge badge-green">Pulled</span> ' + escapeHtml(name); document.getElementById('pull-model-name').value = ''; loadModels(); }
    else { st.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(d, resp.status)); }
}

// ── #25 dual-admin cloud-LLM override (parity with /admin/cloud-override API) ──
async function loadCloudOverride() {
    var el = document.getElementById('cloud-override-status');
    if (!el) return;
    var d = await api('/admin/cloud-override/status');
    if (!d) { el.textContent = 'Status unavailable.'; return; }
    var s = d.status || 'INACTIVE';
    if (s === 'ACTIVE') {
        el.innerHTML = '<span class="badge badge-red">ACTIVE</span> ' + escapeHtml(d.provider + '/' + d.model)
            + ' — proposed by ' + escapeHtml(d.initiated_by || '?') + ', approved by ' + escapeHtml(d.approver || '?')
            + ', expires ' + escapeHtml(d.expires_at || '') + '<br><span class="txt-note">Justification: ' + escapeHtml(d.justification || '') + '</span>';
    } else if (s === 'PENDING_APPROVAL') {
        el.innerHTML = '<span class="badge badge-amber">PENDING</span> '
            + escapeHtml(d.provider + '/' + d.model) + ' — proposed by ' + escapeHtml(d.initiated_by || '?')
            + ' awaiting a SECOND admin to Approve (within 5 min).';
    } else {
        el.innerHTML = '<span class="badge badge-green">INACTIVE</span> No cloud-LLM override in effect.';
    }
}

async function cloudOverridePropose() {
    var el = document.getElementById('cloud-override-status');
    var body = {
        provider: (document.getElementById('co-provider').value || '').trim(),
        model: (document.getElementById('co-model').value || '').trim(),
        justification: (document.getElementById('co-justification').value || '').trim(),
        ttl_hours: parseInt(document.getElementById('co-ttl').value || '4', 10)
    };
    if (!body.provider || !body.model) { el.textContent = 'Provider and model are required.'; return; }
    if (body.justification.length < 4) { el.textContent = 'A justification is required (ticket/contract/CEO email).'; return; }
    var resp = await apiMutate('/admin/cloud-override/propose', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    if (!resp) return;
    var d = await resp.json().catch(function(){return {};});
    if (resp.ok) { document.getElementById('co-justification').value = ''; loadCloudOverride(); }
    else { el.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(d, resp.status)); }
}

async function cloudOverrideApprove() {
    var el = document.getElementById('cloud-override-status');
    var resp = await apiMutate('/admin/cloud-override/approve', { method: 'POST' });
    if (!resp) return;
    var d = await resp.json().catch(function(){return {};});
    if (resp.ok) { loadCloudOverride(); }
    else { el.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(d, resp.status)); }
}

async function cloudOverrideRevoke() {
    if (!confirm('Revoke the cloud-LLM override now?')) return;
    var resp = await apiMutate('/admin/cloud-override/revoke', { method: 'POST' });
    if (resp && resp.ok) loadCloudOverride();
}

async function deleteAlias(alias) {
    if (!confirm('Delete alias "' + alias + '"?')) return;
    var resp = await apiMutate('/admin/models/' + encodeURIComponent(alias), { method: 'DELETE' });
    if (!resp) return;
    if (resp.ok) loadModels();
    else { var err = await resp.json().catch(function(){return {};}); alert('Delete failed: ' + errMsg(err, resp.status)); }
}

async function addAllocation() {
    var result = document.getElementById('alloc-result');
    var alias = document.getElementById('alloc-alias').value.trim();
    var target = document.getElementById('alloc-target').value.trim();
    if (!alias || !target) { result.textContent = 'All fields required.'; return; }
    var resp = await apiMutate('/admin/models/allocations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            model_alias: alias,
            target_type: document.getElementById('alloc-type').value,
            target_id: target
        })
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) { result.innerHTML = '<span class="badge badge-green">Allocated</span>'; loadModels(); }
    else { var err = await resp.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status)); }
}

async function deleteAllocation(id) {
    var resp = await apiMutate('/admin/models/allocations/' + id, { method: 'DELETE' });
    if (!resp) return;
    if (resp.ok) loadModels();
    else { var err = await resp.json().catch(function(){return {};}); alert('Remove failed: ' + errMsg(err, resp.status)); }
}

// Sensitivity — R14/R15 (v2.25.5): taxonomy + patterns

// Taxonomy cache used to enrich pattern classification column
var _taxonomyCache = null;

async function loadTaxonomy() {
    var data = await api('/admin/sensitivity/taxonomy');
    var tbody = document.getElementById('taxonomy-tbody');
    if (!data || !data.taxonomy) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">Failed to load taxonomy</td></tr>';
        return;
    }
    _taxonomyCache = {};
    var levels = data.taxonomy;
    if (levels.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">No taxonomy configured (using defaults)</td></tr>';
        return;
    }
    var html = '';
    for (var i = 0; i < levels.length; i++) {
        var t = levels[i];
        _taxonomyCache[String(t.level)] = t.label;
        var cc = escapeHtml(t.colour_class || 'sens-level-1');
        html += '<tr><td>' + escapeHtml(String(t.level)) + '</td>';
        html += '<td><span class="' + cc + '">' + escapeHtml(t.label) + '</span></td>';
        html += '<td><span class="' + cc + '">' + escapeHtml(t.colour_class) + '</span></td>';
        html += '<td><button data-action="deleteTaxonomyLevel" data-level="' + escapeHtml(String(t.level)) + '" class="btn-tbl btn-tbl--red">Delete</button></td></tr>';
    }
    tbody.innerHTML = html;

    // Update the Classification dropdown in the Add Pattern form with live taxonomy labels
    var patClass = document.getElementById('pat-class');
    if (patClass) {
        var opts = '';
        // Sort descending (highest first) for UX
        var sorted = levels.slice().sort(function(a, b) { return b.level - a.level; });
        for (var j = 0; j < sorted.length; j++) {
            var lvl = sorted[j];
            opts += '<option value="' + escapeHtml(String(lvl.level)) + '">' +
                    escapeHtml(String(lvl.level)) + ' — ' + escapeHtml(lvl.label) + '</option>';
        }
        patClass.innerHTML = opts;
    }
}

async function saveTaxonomyLevel() {
    var result = document.getElementById('taxonomy-result');
    var level = document.getElementById('tax-level').value.trim();
    var label = document.getElementById('tax-label').value.trim();
    var colour = document.getElementById('tax-colour').value;
    if (!level || !label) { result.textContent = 'Level number and label are required.'; return; }
    var lvlNum = parseInt(level, 10);
    if (isNaN(lvlNum) || lvlNum < 1 || lvlNum > 10) { result.textContent = 'Level must be a number 1–10.'; return; }
    var resp = await apiMutate('/admin/sensitivity/taxonomy/' + encodeURIComponent(lvlNum), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label, colour_class: colour })
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) {
        result.innerHTML = '<span class="badge badge-green">Saved</span>';
        document.getElementById('tax-level').value = '';
        document.getElementById('tax-label').value = '';
        loadTaxonomy();
    } else {
        var err = await resp.json().catch(function(){return {};});
        result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status));
    }
}

async function deleteTaxonomyLevel(level) {
    if (!confirm('Delete taxonomy level ' + level + '?')) return;
    var resp = await apiMutate('/admin/sensitivity/taxonomy/' + encodeURIComponent(level), { method: 'DELETE' });
    if (!resp) return;
    if (resp.ok) loadTaxonomy();
    else { var err = await resp.json().catch(function(){return {};}); alert('Delete failed: ' + errMsg(err, resp.status)); }
}

async function initSensitivity() {
    // Pipeline status
    var data = await api('/admin/sensitivity/status');
    if (data) {
        var classifierAvailable = (data.classifier_available !== undefined) ? data.classifier_available : data.fasttext_available;
        document.getElementById('classifier-status').textContent = classifierAvailable ? 'Active' : 'Unavailable';
        document.getElementById('classifier-status').className = 'badge ' + (classifierAvailable ? 'badge-green' : 'badge-yellow');
        document.getElementById('ollama-status').textContent = data.ollama_available ? 'Active' : 'Unavailable';
        document.getElementById('ollama-status').className = 'badge ' + (data.ollama_available ? 'badge-green' : 'badge-yellow');
    }
    // Load taxonomy first (populates the pat-class dropdown), then patterns
    await loadTaxonomy();
    await loadPatterns();
}

// loadSensitivity is now an alias for initSensitivity (backward-compat for showPage call)
async function loadSensitivity() { await initSensitivity(); }

async function loadPatterns() {
    var patterns = await api('/admin/sensitivity/patterns');
    var tbody = document.getElementById('patterns-tbody');
    if (patterns && patterns.patterns && patterns.patterns.length > 0) {
        var html = '';
        // Level → CSS class map for numeric levels
        var levelClass = { '5': 'sens-level-5', '4': 'sens-level-4', '3': 'sens-level-3', '2': 'sens-level-2', '1': 'sens-level-1' };
        // Legacy string fallback
        var legacyClass = { 'RESTRICTED': 'sens-level-4', 'CONFIDENTIAL': 'sens-level-3', 'INTERNAL': 'sens-level-2', 'PUBLIC': 'sens-level-1' };
        for (var i = 0; i < patterns.patterns.length; i++) {
            var p = patterns.patterns[i];
            var cls = levelClass[p.classification] || legacyClass[p.classification] || 'sens-level-1';
            // Use classification_label if available (enriched by API), else use taxonomy cache, else raw value
            var labelText = p.classification_label || (_taxonomyCache && _taxonomyCache[String(p.classification)]) || p.classification;
            html += '<tr><td><span class="' + cls + '">' + escapeHtml(labelText) + '</span></td><td>' + escapeHtml(p.type) + '</td><td class="td-mono-xxs">' + escapeHtml(p.pattern) + '</td><td>' + escapeHtml(p.description) + '</td><td><button data-action="deletePattern" data-pattern-id="' + escapeHtml(p.id) + '" class="btn-tbl btn-tbl--red">Delete</button></td></tr>';
        }
        tbody.innerHTML = html;
    } else {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No patterns configured</td></tr>';
    }
}

async function addPattern() {
    var result = document.getElementById('pattern-result');
    var pattern = document.getElementById('pat-pattern').value.trim();
    var desc = document.getElementById('pat-desc').value.trim();
    if (!pattern || !desc) { result.textContent = 'Pattern and description required.'; return; }
    var resp = await apiMutate('/admin/sensitivity/patterns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            classification: document.getElementById('pat-class').value,
            type: document.getElementById('pat-type').value,
            pattern: pattern,
            description: desc
        })
    });
    if (!resp) { result.innerHTML = '<span class="badge badge-red">Error</span> Request failed or was cancelled'; return; }
    if (resp.ok) { result.innerHTML = '<span class="badge badge-green">Saved</span>'; document.getElementById('pat-pattern').value = ''; document.getElementById('pat-desc').value = ''; await loadPatterns(); }
    else { var err = await resp.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">Error</span> ' + escapeHtml(errMsg(err, resp.status)); }
}

async function deletePattern(id) {
    if (!confirm('Delete this pattern?')) return;
    var resp = await apiMutate('/admin/sensitivity/patterns/' + id, { method: 'DELETE' });
    if (!resp) return;
    if (resp.ok) loadPatterns();
    else { var err = await resp.json().catch(function(){return {};}); alert('Delete failed: ' + errMsg(err, resp.status)); }
}

// Test classifier
async function testClassify() {
    var text = document.getElementById('test-text').value.trim();
    var result = document.getElementById('classify-result');
    if (!text) { result.textContent = 'Enter text to classify.'; return; }
    result.innerHTML = '<span class="loading">Classifying...</span>';
    var resp = await fetch('/admin/sensitivity/test', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text })
    });
    if (resp.status === 401) { window.location.href = '/admin/login'; return; }
    if (!resp.ok) { result.textContent = 'Error: ' + resp.status; return; }
    var data = await resp.json();
    var badge = data.is_injection ? 'badge-red' : 'badge-green';
    var label = data.is_injection ? 'INJECTION DETECTED' : 'CLEAN';
    result.innerHTML = '<span class="badge ' + badge + '">' + label + '</span> — confidence: ' + ((data.confidence || 0) * 100).toFixed(1) + '%';
}

// Settings
var _cryptoInventoryCache = null;

async function loadSettings() {
    var data = await api('/admin/license');
    var container = document.getElementById('license-info');
    if (data) {
        // Limits live under data.limits.<key>.{maximum,unlimited}; render all
        // four (agents / users / admins / orgs) the license enforces.
        var lim = data.limits || {};
        function fmtLimit(o) {
            if (!o) return '-';
            if (o.unlimited) return 'Unlimited';
            return (o.maximum !== null && o.maximum !== undefined) ? String(o.maximum) : '-';
        }
        container.innerHTML = '<p class="prose-sm"><strong>Tier:</strong> ' + escapeHtml(data.tier || 'community') +
            ' | <strong>Max Agents:</strong> ' + escapeHtml(fmtLimit(lim.agents)) +
            ' | <strong>Users:</strong> ' + escapeHtml(fmtLimit(lim.end_users)) +
            ' | <strong>Admins:</strong> ' + escapeHtml(fmtLimit(lim.admin_seats)) +
            ' | <strong>Orgs:</strong> ' + escapeHtml(fmtLimit(lim.orgs)) +
            ' | <strong>Expires:</strong> ' + escapeHtml(data.expires_at || 'Never') + '</p>';
    } else {
        container.innerHTML = '<p class="prose-sm"><strong>Tier:</strong> Community Edition — no license required.<br><span class="faint">To use other features please add a license for your preferred tier.</span></p>';
    }
    // Crypto inventory (ASVS 11.1.3)
    loadCryptoInventory();
    // v2.23.3 (#59) — HIBP API key status panel
    if (typeof window.loadHibpStatus === 'function') {
        window.loadHibpStatus();
    }
}

async function loadCryptoInventory() {
    var data = await api('/admin/crypto/inventory');
    _cryptoInventoryCache = data;
    var el = document.getElementById('crypto-inventory');
    if (!data) { el.innerHTML = '<span class="txt-err">Failed to load</span>'; return; }
    var html = '<table><thead><tr><th>Algorithm</th><th>Usage</th><th>Strength</th></tr></thead><tbody>';
    (data.algorithms || []).forEach(function(a) {
        html += '<tr><td>' + a.name + '</td><td>' + a.usage + '</td><td>' + a.strength + '</td></tr>';
    });
    html += '</tbody></table>';
    if (data.deprecated && data.deprecated.length) {
        html += '<p class="crypto-line crypto-line--bad"><strong>Deprecated:</strong> ' + data.deprecated.join(', ') + '</p>';
    } else {
        html += '<p class="crypto-line crypto-line--ok">No deprecated algorithms in use.</p>';
    }
    if (data.post_quantum && data.post_quantum.length) {
        html += '<p class="crypto-line--pq"><strong>Post-Quantum:</strong> ' + data.post_quantum.join(', ') + '</p>';
    }
    html += '<p class="crypto-line--compliance"><strong>Compliance:</strong> ' + (data.compliance || '') + '</p>';
    el.innerHTML = html;
}

function exportCryptoJson() {
    if (!_cryptoInventoryCache) { alert('Inventory not loaded yet'); return; }
    var blob = new Blob([JSON.stringify(_cryptoInventoryCache, null, 2)], {type: 'application/json'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a'); a.href = url; a.download = 'yashigani_crypto_inventory.json'; a.click();
    URL.revokeObjectURL(url);
}

// IdP config save (placeholder — full implementation in v2.2 with Caddy OIDC module)
async function saveIdpConfig(type) {
    var result = document.getElementById(type + '-save-result');
    result.innerHTML = '<span class="badge badge-yellow">Saved locally — requires restart to activate</span>';
    // In v2.2, this will POST to /admin/idp/{type} and update Caddy config
}

// Alert configuration
async function loadAlertConfig() {
    try {
        var r = await fetch('/admin/alerts/config', { credentials: 'same-origin' });
        if (r.ok) {
            var data = await r.json();
            var c = data.config || {};
            document.getElementById('alert-slack-url').value = c.slack_webhook_url || '';
            document.getElementById('alert-teams-url').value = c.teams_webhook_url || '';
            document.getElementById('alert-pagerduty-key').value = c.pagerduty_integration_key || '';
            document.getElementById('alert-trigger-exfil').checked = c.alert_on_credential_exfil !== false;
            document.getElementById('alert-trigger-anomaly').checked = c.alert_on_anomaly_threshold !== false;
            document.getElementById('alert-trigger-budget').checked = c.alert_on_budget_exhaustion === true;
            document.getElementById('alert-trigger-injection').checked = c.alert_on_prompt_injection !== false;
        }
    } catch(e) { /* ignore — alerts config optional */ }
}

async function saveAlertConfig() {
    var result = document.getElementById('alert-config-result');
    try {
        var r = await fetch('/admin/alerts/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
                slack_webhook_url: document.getElementById('alert-slack-url').value || null,
                teams_webhook_url: document.getElementById('alert-teams-url').value || null,
                pagerduty_integration_key: document.getElementById('alert-pagerduty-key').value || null,
                alert_on_credential_exfil: document.getElementById('alert-trigger-exfil').checked,
                alert_on_anomaly_threshold: document.getElementById('alert-trigger-anomaly').checked,
                alert_on_budget_exhaustion: document.getElementById('alert-trigger-budget').checked,
                alert_on_prompt_injection: document.getElementById('alert-trigger-injection').checked,
            })
        });
        if (r.ok) {
            result.innerHTML = '<span class="badge badge-green">Configuration saved</span>';
        } else {
            result.innerHTML = '<span class="badge badge-red">Failed: ' + escapeHtml(r.status) + '</span>';
        }
    } catch(e) {
        result.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

async function testAlertWebhook(sink) {
    var result = document.getElementById('alert-config-result');
    result.innerHTML = '<span class="badge badge-yellow">Sending test...</span>';
    try {
        var r = await fetch('/admin/alerts/test/' + sink, { method: 'POST', credentials: 'same-origin' });
        if (r.ok) {
            result.innerHTML = '<span class="badge badge-green">Test alert sent to ' + escapeHtml(sink) + '</span>';
        } else {
            var data = await r.json().catch(function() { return {}; });
            result.innerHTML = '<span class="badge badge-red">' + escapeHtml(sink) + ' test failed: ' + escapeHtml(data.detail || r.status) + '</span>';
        }
    } catch(e) {
        result.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(e.message) + '</span>';
    }
}

// Logout
async function logout() {
    await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    window.location.href = '/admin/login';
}

// Audit log search
var auditCursor = '';
// R19/R20: load the Verdict + Source-type dropdown options from the audit model.
async function loadAuditFacets() {
    var data = await api('/admin/audit/facets');
    if (!data) return;
    // The first facet entry is the "* (All)" wildcard — use it as the leading option.
    var verdicts = data.verdicts || [];
    var sources = data.source_types || [];
    fillSelect('audit-verdict', verdicts.slice(1), verdicts.slice(0, 1));
    fillSelect('audit-source-type', sources.slice(1), sources.slice(0, 1));
}

async function searchAudit(cursor) {
    var params = new URLSearchParams();
    var et = document.getElementById('audit-event-type').value;
    var verdict = document.getElementById('audit-verdict').value;
    var sourceType = document.getElementById('audit-source-type').value;
    var from = document.getElementById('audit-from').value;
    var to = document.getElementById('audit-to').value;
    var text = document.getElementById('audit-text').value.trim();
    if (et) params.set('event_type', et);
    if (verdict) params.set('verdict', verdict);
    if (sourceType) params.set('source_type', sourceType);
    if (from) params.set('date_from', from);
    if (to) params.set('date_to', to);
    // free_text is a substring match, not a glob — treat a lone '*' as "match all".
    if (text && text !== '*') params.set('free_text', text);
    if (cursor) params.set('cursor', cursor);
    var data = await api('/admin/audit/search?' + params.toString());
    var tbody = document.getElementById('audit-tbody');
    // Backend returns {rows, count, cursor, has_more} — not {events, next_cursor}.
    var rows = (data && data.rows) ? data.rows : null;
    if (!rows || rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No events found</td></tr>';
        document.getElementById('audit-count').textContent = 'Events (0)';
        document.getElementById('audit-pagination').innerHTML = '';
        return;
    }
    document.getElementById('audit-count').textContent = 'Events (' + rows.length + (data.has_more ? '+' : '') + ')';
    tbody.innerHTML = rows.map(function(e) {
        var who = e.admin_account || e.user || e.user_handle || e.agent_id || '';
        var outcome = e.verdict || e.outcome || '-';
        var blocked = /block|deni|reject|fail/i.test(outcome);
        var detail = e.detail || e.summary || e.client_ip_prefix || '';
        return '<tr><td class="td-xxs">' + escapeHtml(e.timestamp || e.created_at || '') + '</td>' +
            '<td>' + escapeHtml(e.event_type || '') + '</td>' +
            '<td>' + escapeHtml(who) + '</td>' +
            '<td><span class="badge ' + (blocked ? 'badge-red' : 'badge-green') + '">' + escapeHtml(outcome) + '</span></td>' +
            '<td class="td-ellipsis">' + escapeHtml(detail) + '</td></tr>';
    }).join('');
    auditCursor = data.cursor || '';
    var pag = document.getElementById('audit-pagination');
    if (data.has_more) {
        pag.innerHTML = '<button data-action="searchAuditMore" data-cursor="' + auditCursor + '" class="btn-page">Load more</button>';
    } else {
        pag.innerHTML = '';
    }
}

async function exportAudit() {
    var params = new URLSearchParams();
    var et = document.getElementById('audit-event-type').value;
    var verdict = document.getElementById('audit-verdict').value;
    var sourceType = document.getElementById('audit-source-type').value;
    var from = document.getElementById('audit-from').value;
    var to = document.getElementById('audit-to').value;
    if (et) params.set('event_type', et);
    if (verdict) params.set('verdict', verdict);
    if (sourceType) params.set('source_type', sourceType);
    if (from) params.set('date_from', from);
    if (to) params.set('date_to', to);
    params.set('output_format', 'csv');
    window.open('/admin/audit/export?' + params.toString(), '_blank');
}

// IP Access Control
async function loadIpAccess() {
    // Blocked IPs
    var blocked = await api('/auth/blocked-ips');
    var el = document.getElementById('blocked-ips-list');
    if (blocked && blocked.total > 0) {
        var html = '<table><thead><tr><th>IP</th><th>Blocked At</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
        for (var ip in blocked.blocked_ips) {
            var info = blocked.blocked_ips[ip];
            var ts = info.blocked_at ? new Date(info.blocked_at * 1000).toLocaleString() : '-';
            html += '<tr><td>' + escapeHtml(ip) + '</td><td class="td-xxs">' + escapeHtml(ts) + '</td><td class="td-xxs">' + escapeHtml(info.reason || '-') + '</td>';
            html += '<td><button data-action="unblockIp" data-ip="' + escapeHtml(ip) + '" class="btn-unblock">Unblock</button></td></tr>';
        }
        html += '</tbody></table>';
        el.innerHTML = html;
    } else {
        el.innerHTML = '<span class="badge badge-green">No blocked IPs</span>';
    }
    // Allowed IPs
    var allowed = await api('/auth/allowed-ips');
    var el2 = document.getElementById('allowed-ips-list');
    if (allowed && allowed.total > 0) {
        var html2 = '';
        allowed.allowed_ips.forEach(function(ip) {
            html2 += '<span class="ip-chip">' + escapeHtml(ip) + ' <button data-action="removeAllowedIp" data-ip="' + escapeHtml(ip) + '" class="chip-x">x</button></span>';
        });
        el2.innerHTML = html2;
    } else {
        el2.innerHTML = '<span class="badge badge-yellow">Open — all IPs permitted (no allowlist configured)</span>';
    }
}

async function unblockIp(ip) {
    var r = await fetch('/auth/blocked-ips/' + ip, { method: 'DELETE', credentials: 'same-origin' });
    if (r.ok) { loadIpAccess(); } else { document.getElementById('ip-access-result').innerHTML = '<span class="badge badge-red">Failed</span>'; }
}

async function addAllowedIp() {
    var ip = document.getElementById('new-allowed-ip').value.trim();
    if (!ip) return;
    var r = await fetch('/auth/allowed-ips', { method: 'POST', credentials: 'same-origin', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ip: ip}) });
    var result = document.getElementById('ip-access-result');
    if (r.ok) { document.getElementById('new-allowed-ip').value = ''; result.innerHTML = '<span class="badge badge-green">Added</span>'; loadIpAccess(); }
    else { var err = await r.json().catch(function(){return {};}); result.innerHTML = '<span class="badge badge-red">' + escapeHtml(err.detail?.message || 'Failed') + '</span>'; }
}

async function removeAllowedIp(ip) {
    var r = await fetch('/auth/allowed-ips/' + encodeURIComponent(ip), { method: 'DELETE', credentials: 'same-origin' });
    if (r.ok) { loadIpAccess(); }
}

// Dismiss helpers
function dismissAgentToken() {
    document.getElementById('agent-token-panel').classList.remove('is-open');
}

function dismissCredentials() {
    document.getElementById('credentials-panel').classList.remove('is-open');
}

function extendSession() {
    var banner = document.getElementById('session-warning');
    if (banner) banner.remove();
    sessionWarned = false;
    sessionStart = Date.now();
}

// Session timeout warning — check every 60s, warn at 10 min remaining
var sessionStart = Date.now();
var sessionMaxMs = 4 * 60 * 60 * 1000; // 4 hours
var warnMs = 10 * 60 * 1000; // 10 minutes before expiry
var sessionWarned = false;
setInterval(function() {
    var elapsed = Date.now() - sessionStart;
    var remaining = sessionMaxMs - elapsed;
    if (remaining <= 0) {
        window.location.href = '/admin/login';
    } else if (remaining <= warnMs && !sessionWarned) {
        sessionWarned = true;
        var mins = Math.ceil(remaining / 60000);
        var banner = document.createElement('div');
        banner.id = 'session-warning';
        banner.className = 'session-banner';
        banner.textContent = 'Session expires in ' + mins + ' minutes. ';
        var extendBtn = document.createElement('button');
        extendBtn.setAttribute('data-action', 'extendSession');
        extendBtn.className = 'session-banner-btn';
        extendBtn.textContent = 'Extend session';
        banner.appendChild(extendBtn);
        document.body.prepend(banner);
    }
}, 60000);

// Load dashboard on page load + auto-refresh every 15s
loadDashboard();
loadAlertConfig();
loadIpAccess();
setInterval(function() {
    // Only refresh if dashboard tab is active
    var dashPage = document.getElementById('page-dashboard');
    if (dashPage && dashPage.classList.contains('active')) {
        loadDashboard();
    }
}, 15000);

// -------------------------------------------------------
// Event delegation — replaces all inline onclick handlers
// -------------------------------------------------------
// R4(b): when the allocation Target Type changes, reload the Target ID dropdown.
document.addEventListener('change', function(e) {
    if (e.target && e.target.id === 'alloc-type') {
        loadAllocTargets();
    }
    // R11(b): when the binding subject kind changes, reload the subject dropdown.
    if (e.target && e.target.id === 'bind-scope-kind') {
        loadBindSubjects();
    }
});

document.addEventListener('click', function(e) {
    var target = e.target;
    // Walk up to find closest element with data-action
    var actionEl = target.closest('[data-action]');
    if (!actionEl) return;

    var action = actionEl.getAttribute('data-action');

    switch (action) {
        // Navigation
        case 'showPage':
            showPage(actionEl.getAttribute('data-param'), actionEl);
            break;
        case 'logout':
            logout();
            break;

        // Dismiss panels
        case 'dismissAgentToken':
            dismissAgentToken();
            break;
        case 'dismissCredentials':
            dismissCredentials();
            break;
        case 'extendSession':
            extendSession();
            break;

        // Toggle forms
        case 'toggleForm':
            toggleForm(actionEl.getAttribute('data-form-id'));
            break;

        // Agent actions
        case 'registerAgent':
            registerAgent();
            break;
        case 'rotateAgentToken':
            rotateAgentToken(actionEl.getAttribute('data-agent-id'), actionEl.getAttribute('data-agent-name'));
            break;
        case 'deactivateAgent':
            deactivateAgent(actionEl.getAttribute('data-agent-id'));
            break;
        case 'editAgent':
            editAgent(
                actionEl.getAttribute('data-agent-id'),
                actionEl.getAttribute('data-agent-name'),
                actionEl.getAttribute('data-agent-url'),
                actionEl.getAttribute('data-agent-groups'),
                actionEl.getAttribute('data-agent-caller-groups')
            );
            break;
        case 'saveEditAgent':
            saveEditAgent();
            break;
        case 'cancelEditAgent':
            cancelEditAgent();
            break;

        // Account actions
        case 'createAdmin':
            createAdmin();
            break;
        case 'createUser':
            createUser();
            break;
        case 'toggleAccount':
            toggleAccount(actionEl.getAttribute('data-account-type'), actionEl.getAttribute('data-username'), actionEl.getAttribute('data-toggle-action'));
            break;
        case 'deleteAccount':
            deleteAccount(actionEl.getAttribute('data-account-type'), actionEl.getAttribute('data-username'));
            break;
        case 'editAccount':
            editAccount(
                actionEl.getAttribute('data-account-type'),
                actionEl.getAttribute('data-username'),
                actionEl.getAttribute('data-email'),
                actionEl.getAttribute('data-disabled')
            );
            break;
        case 'saveEditAccount':
            saveEditAccount(actionEl.getAttribute('data-account-type'));
            break;
        case 'cancelEditAccount':
            cancelEditAccount(actionEl.getAttribute('data-account-type'));
            break;

        // Alert actions
        case 'saveAlertConfig':
            saveAlertConfig();
            break;
        case 'testAlertWebhook':
            testAlertWebhook(actionEl.getAttribute('data-sink'));
            break;

        // Budget actions
        case 'addOrgCap':
            addOrgCap();
            break;
        case 'addGroupBudget':
            addGroupBudget();
            break;
        case 'addIndBudget':
            addIndBudget();
            break;

        // Model actions
        case 'addAlias':
            addAlias();
            break;
        case 'pullModel':
            pullModel();
            break;
        case 'cloudOverridePropose':
            cloudOverridePropose();
            break;
        case 'cloudOverrideApprove':
            cloudOverrideApprove();
            break;
        case 'cloudOverrideRevoke':
            cloudOverrideRevoke();
            break;
        case 'deleteAlias':
            deleteAlias(actionEl.getAttribute('data-alias'));
            break;
        case 'addAllocation':
            addAllocation();
            break;
        case 'deleteAllocation':
            deleteAllocation(actionEl.getAttribute('data-allocation-id'));
            break;

        // Sensitivity actions
        case 'addPattern':
            addPattern();
            break;
        case 'deletePattern':
            deletePattern(actionEl.getAttribute('data-pattern-id'));
            break;
        case 'testClassify':
            testClassify();
            break;
        case 'saveTaxonomyLevel':
            saveTaxonomyLevel();
            break;
        case 'deleteTaxonomyLevel':
            deleteTaxonomyLevel(actionEl.getAttribute('data-level'));
            break;

        // Audit actions
        case 'searchAudit':
            searchAudit();
            break;
        case 'searchAuditMore':
            searchAudit(actionEl.getAttribute('data-cursor'));
            break;
        case 'exportAudit':
            exportAudit();
            break;

        // Monitoring — external links
        case 'openExternal':
            window.open(actionEl.getAttribute('data-url'), '_blank');
            break;

        // IP access
        case 'addAllowedIp':
            addAllowedIp();
            break;
        case 'unblockIp':
            unblockIp(actionEl.getAttribute('data-ip'));
            break;
        case 'removeAllowedIp':
            removeAllowedIp(actionEl.getAttribute('data-ip'));
            break;

        // Settings — IdP
        case 'saveIdpConfig':
            saveIdpConfig(actionEl.getAttribute('data-idp-type'));
            break;

        // Settings — Crypto
        case 'exportCryptoJson':
            exportCryptoJson();
            break;
        // Services
        case 'enableService':
            toggleService(e.target.dataset.service, 'enable');
            break;
        case 'disableService':
            toggleService(e.target.dataset.service, 'disable');
            break;
        // Backup
        case 'createBackup':
            createBackup();
            break;
        case 'verifyBackup':
            verifyBackup();
            break;

        // Runtime Settings — row-level actions (defined in runtime-settings.js)
        case 'rsEditRow':
            if (typeof rsEditRow === 'function') {
                rsEditRow(
                    actionEl.getAttribute('data-rs-key'),
                    actionEl.getAttribute('data-rs-value'),
                    actionEl.getAttribute('data-rs-type')
                );
            }
            break;
        case 'rsResetRow':
            if (typeof rsResetRow === 'function') {
                rsResetRow(actionEl.getAttribute('data-rs-key'));
            }
            break;

        // PKI actions (defined in pki.js) — data-action so they work under the
        // strict CSP (script-src 'self'; inline onclick handlers are blocked).
        case 'pkiView':
            if (typeof showPkiChain === 'function') showPkiChain(actionEl.getAttribute('data-service'));
            break;
        case 'pkiRotate':
            if (typeof pkiRotate === 'function') pkiRotate(actionEl.getAttribute('data-service'));
            break;
        case 'pkiDownload':
            if (typeof pkiDownloadBundle === 'function') pkiDownloadBundle(actionEl.getAttribute('data-service'));
            break;
        case 'pkiClose':
            if (typeof hidePkiChain === 'function') hidePkiChain();
            break;

        // Step-up verification modal
        case 'stepUpSubmit':
            submitStepUp();
            break;
        case 'stepUpCancel':
            cancelStepUp();
            break;

        // Policies (OPA) viewer + authoring
        case 'policyView':
            viewPolicy(actionEl.getAttribute('data-id'), actionEl.getAttribute('data-cat'));
            break;
        case 'bindPolicy':
            bindPolicy();
            break;
        case 'unbindBinding':
            unbindBinding(actionEl.getAttribute('data-binding-id'));
            break;

        // RBAC group management (parity with /admin/rbac API)
        case 'rbacAddResourceRow':
            rbacAddResourceRow();
            break;
        case 'createGroup':
            createGroup();
            break;
        case 'deleteGroup':
            deleteGroup(actionEl.getAttribute('data-group-id'), actionEl.getAttribute('data-group-name'));
            break;
        case 'rbacManageMembers':
            rbacManageMembers(actionEl.getAttribute('data-group-id'), actionEl.getAttribute('data-group-name'));
            break;
        case 'rbacMembersClose':
            rbacMembersClose();
            break;
        case 'addRbacMember':
            addRbacMember(actionEl.getAttribute('data-group-id'));
            break;
        case 'removeRbacMember':
            removeRbacMember(actionEl.getAttribute('data-group-id'), actionEl.getAttribute('data-member-email'));
            break;
        case 'rbacForcePush':
            rbacForcePush();
            break;
        case 'policyEditCopy':
            policyEditCopy();
            break;
        case 'policySaveCopy':
            policySaveCopy();
            break;
        case 'policyGenerate':
            generatePolicy();
            break;
        case 'policyClose':
            closePolicyView();
            break;
    }
});

// Service management
async function loadServices() {
    var data = await api('/admin/services');
    var el = document.getElementById('services-list');
    if (!el || !data || !data.services) return;
    var html = '';
    data.services.forEach(function(s) {
        // Observational: optional services are a deploy-time/IaC choice. Status
        // reflects what was enabled at install (YASHIGANI_ENABLED_PROFILES); there
        // are no runtime enable/disable buttons (the admin plane doesn't drive the
        // host engine). "Deployed" vs "Not deployed" instead of Running/Stopped.
        var badge = s.status === 'running'
            ? '<span class="badge badge-green">Deployed</span>'
            : '<span class="badge badge-slate">Not deployed</span>';
        var note = s.status === 'running'
            ? '<span class="svc-note">enabled at install</span>'
            : '<span class="svc-note-faint">re-run installer with --' + escapeHtml(s.profile || s.id) + ' to add</span>';
        html += '<tr><td>' + escapeHtml(s.name) + '</td><td class="td-muted">' + escapeHtml(s.description) + '</td><td>' + badge + '</td><td>' + note + '</td></tr>';
    });
    el.innerHTML = html || '<tr><td colspan="4" class="empty">No optional services available</td></tr>';
}

async function toggleService(serviceId, action) {
    var result = document.getElementById('services-result');
    if (result) result.innerHTML = '<span class="badge badge-yellow">' + action + 'ing ' + serviceId + '...</span>';
    var r = await apiMutate('/admin/services/' + serviceId, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({action: action})
    });
    if (!r) { if (result) result.innerHTML = '<span class="badge badge-red">Failed: request cancelled</span>'; return; }
    if (r.ok) {
        var data = await r.json();
        if (result) result.innerHTML = '<span class="badge badge-green">' + escapeHtml(data.message || 'Done') + '</span>';
        loadServices();
    } else {
        var err = await r.json().catch(function(){return {};});
        if (result) result.innerHTML = '<span class="badge badge-red">Failed: ' + escapeHtml(errMsg(err, r.status)) + '</span>';
    }
}

loadServices();

// Backup status + verify
async function loadBackup() {
    var container = document.getElementById('backup-status-container');
    var btn = document.getElementById('btn-verify-latest');
    if (!container) return;
    container.innerHTML = '<span class="loading">Loading...</span>';
    var data = await api('/admin/backup/status');
    if (!data) {
        container.innerHTML = '<p class="error">Failed to load backup status.</p>';
        return;
    }
    if (!data.backups || data.backups.length === 0) {
        container.innerHTML = '<p class="backup-empty">No backups found.</p>';
        if (btn) btn.disabled = true;
        return;
    }
    var manifestBadge = function(state) {
        if (state === 'signed') return '<span class="badge badge-green">Signed</span>';
        if (state === 'unsigned') return '<span class="badge badge-yellow">Unsigned</span>';
        return '<span class="badge badge-red">Corrupt</span>';
    };
    var rows = data.backups.map(function(b) {
        return '<tr>' +
            '<td class="td-mono-xs">' + escapeHtml(b.name) + '</td>' +
            '<td>' + escapeHtml(b.type) + '</td>' +
            '<td class="td-muted">' + (b.created_at ? escapeHtml(b.created_at) : 'unknown') + '</td>' +
            '<td>' + manifestBadge(b.manifest_state) + '</td>' +
            '<td class="td-xs">' + (b.size_bytes / 1024).toFixed(1) + ' KB</td>' +
            '</tr>';
    }).join('');
    container.innerHTML = '<table><thead><tr><th>Name</th><th>Type</th><th>Created</th><th>Manifest</th><th>Size</th></tr></thead><tbody>' + rows + '</tbody></table>';
    if (btn) {
        btn.disabled = false;
        btn.dataset.backupName = data.latest ? data.latest.name : '';
    }
}

async function createBackup() {
    var btn = document.getElementById('btn-create-backup');
    var resultDiv = document.getElementById('backup-create-result');
    if (!resultDiv) return;
    resultDiv.classList.add('is-open');
    resultDiv.innerHTML = '<span class="loading">Creating database backup…</span>';
    if (btn) btn.disabled = true;
    try {
        var resp = await apiMutate('/admin/backup/create', { method: 'POST', headers: {'Content-Type': 'application/json'} });
        if (!resp) { resultDiv.innerHTML = '<span class="badge badge-red">Error</span> <span class="txt-err-dk">Request failed or was cancelled</span>'; return; }
        var data = await resp.json().catch(function() { return {}; });
        if (resp.ok && data.status === 'ok') {
            var kb = Math.round((data.size_bytes || 0) / 1024);
            resultDiv.innerHTML = '<span class="badge badge-green">Created</span> <span class="txt-ok-dk">' + escapeHtml(data.backup_name) + ' &mdash; ' + kb + ' KB</span>';
            loadBackup();
        } else {
            resultDiv.innerHTML = '<span class="badge badge-red">Error</span> <span class="txt-err-dk">' + escapeHtml(errMsg(data, resp.status)) + '</span>';
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function verifyBackup() {
    var btn = document.getElementById('btn-verify-latest');
    var resultDiv = document.getElementById('backup-verify-result');
    if (!btn || !resultDiv) return;
    var backupName = btn.dataset.backupName;
    if (!backupName) return;
    resultDiv.classList.add('is-open');
    resultDiv.innerHTML = '<span class="loading">Verifying...</span>';
    btn.disabled = true;
    try {
        var resp = await apiMutate('/admin/backup/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({backup_name: backupName})
        });
        if (!resp) { resultDiv.innerHTML = '<span class="badge badge-red">Error</span> <span class="txt-err-dk">Request failed or was cancelled</span>'; return; }
        var data = await resp.json();
        if (resp.ok && data.ok) {
            resultDiv.innerHTML = '<span class="badge badge-green">PASS</span> <span class="txt-ok-dk">' + escapeHtml(data.backup_name) + ' &mdash; manifest: ' + escapeHtml(data.manifest_state) + ' &mdash; verified at ' + escapeHtml(data.verified_at) + '</span>';
        } else if (resp.ok && !data.ok) {
            var mismatches = (data.mismatches || []).map(function(m) {
                var rec = m.recorded ? m.recorded.substring(0, 12) + '...' : 'n/a';
                var comp = m.computed ? m.computed.substring(0, 12) + '...' : 'n/a';
                return '<li class="crypto-mismatch">' + escapeHtml(m.file) + ' (' + escapeHtml(m.issue || 'mismatch') + '): recorded=' + rec + ' computed=' + comp + '</li>';
            }).join('');
            resultDiv.innerHTML = '<span class="badge badge-red">FAIL</span> <span class="txt-ok-dk">' + escapeHtml(data.backup_name) + ' &mdash; manifest: ' + escapeHtml(data.manifest_state) + '</span>' + (mismatches ? '<ul class="mismatch-list">' + mismatches + '</ul>' : '');
        } else {
            var errDetail = (data && data.detail && data.detail.error) ? data.detail.error : ('HTTP ' + resp.status);
            resultDiv.innerHTML = '<span class="badge badge-red">Error</span> <span class="txt-err-dk">' + escapeHtml(errDetail) + '</span>';
        }
    } catch (err) {
        resultDiv.innerHTML = '<span class="badge badge-red">Error</span> <span class="txt-err-dk">Request failed: ' + escapeHtml(err.message) + '</span>';
    } finally {
        if (btn) btn.disabled = false;
    }
}
