// Yashigani Backoffice — Runtime Settings admin panel
// Phase 2 UI — thin consumer of Phase 1 API at /admin/runtime-settings
// admin-surfaces-all-runtime-settings rule / v2.24.3
// Last updated: 2026-05-25T00:00:00+00:00
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml, _stepupQueue)
// Loaded as: <script src="/static/js/runtime-settings.js" defer></script>

/* global api, apiMutate, escapeHtml */

// ---------------------------------------------------------------------------
// Toast helper (inline — no external dep)
// ---------------------------------------------------------------------------

function _rsToast(msg, ok) {
    var t = document.getElementById('rs-toast');
    if (!t) { return; }
    t.textContent = msg;
    t.className = 'rs-toast rs-toast-' + (ok ? 'ok' : 'err') + ' rs-toast-visible';
    clearTimeout(t._timer);
    t._timer = setTimeout(function() { t.className = 'rs-toast'; }, 3500);
}

// ---------------------------------------------------------------------------
// Load + render the settings table
// ---------------------------------------------------------------------------

async function loadRuntimeSettings() {
    var tbody = document.getElementById('rs-tbody');
    if (!tbody) { return; }
    tbody.innerHTML = '<tr><td colspan="6" class="empty">Loading…</td></tr>';
    _rsHideEditForm();

    var data = await api('/admin/runtime-settings');
    if (!data || !data.settings) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">Failed to load settings. Check network or server logs.</td></tr>';
        return;
    }

    var settings = data.settings;
    if (!settings.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No settings registered.</td></tr>';
        return;
    }

    var html = '';
    for (var i = 0; i < settings.length; i++) {
        var s = settings[i];
        var sourceBadge = {
            'env':     '<span class="badge badge-blue">env</span>',
            'ui':      '<span class="badge badge-green">ui</span>',
            'api':     '<span class="badge badge-green">api</span>',
            'default': '<span class="badge badge-p4">default</span>'
        }[s.source] || '<span class="badge badge-p4">' + escapeHtml(s.source || '—') + '</span>';

        var changedAt = s.changed_at ? escapeHtml(s.changed_at) : '—';
        var changedBy = s.changed_by ? escapeHtml(s.changed_by) : '—';

        html += '<tr id="rs-row-' + escapeHtml(s.key) + '">'
            + '<td class="rs-key"><code>' + escapeHtml(s.key) + '</code></td>'
            + '<td id="rs-val-' + escapeHtml(s.key) + '" class="rs-val">' + escapeHtml(String(s.value)) + '</td>'
            + '<td>' + sourceBadge + '</td>'
            + '<td class="rs-meta">' + changedBy + '</td>'
            + '<td class="rs-meta">' + changedAt + '</td>'
            + '<td class="rs-actions">'
            +   '<button class="btn-xs-add rs-btn-edit"'
            +     ' data-action="rsEditRow"'
            +     ' data-rs-key="' + escapeHtml(s.key) + '"'
            +     ' data-rs-value="' + escapeHtml(String(s.value)) + '"'
            +     ' data-rs-type="' + escapeHtml(s.value_type || 'string') + '">'
            +     'Edit'
            +   '</button>'
            +   ' <button class="btn-sm-secondary rs-btn-reset"'
            +     ' data-action="rsResetRow"'
            +     ' data-rs-key="' + escapeHtml(s.key) + '">'
            +     'Reset'
            +   '</button>'
            + '</td>'
            + '</tr>';
    }
    tbody.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Inline edit form — shown below the row being edited
// ---------------------------------------------------------------------------

function _rsHideEditForm() {
    var form = document.getElementById('rs-edit-form');
    if (form) { form.style.display = 'none'; }
    var resultEl = document.getElementById('rs-edit-result');
    if (resultEl) { resultEl.textContent = ''; }
}

function rsEditRow(key, currentValue, valueType) {
    var form = document.getElementById('rs-edit-form');
    if (!form) { return; }

    // Anchor form below the target row
    var targetRow = document.getElementById('rs-row-' + key);
    if (targetRow && targetRow.parentNode) {
        targetRow.parentNode.insertBefore(form, targetRow.nextSibling);
    }

    document.getElementById('rs-edit-key').textContent = key;
    document.getElementById('rs-edit-key-hidden').value = key;
    document.getElementById('rs-edit-type-hint').textContent = valueType;

    var input = document.getElementById('rs-edit-value');
    input.value = currentValue;
    // Set input type hint for numeric types
    input.type = (valueType === 'int' || valueType === 'float') ? 'number' : 'text';
    if (valueType === 'float') { input.step = 'any'; } else { input.removeAttribute('step'); }

    document.getElementById('rs-edit-result').textContent = '';
    form.style.display = 'block';
    input.focus();
    input.select();
}

// ---------------------------------------------------------------------------
// Save (PUT)
// ---------------------------------------------------------------------------

async function rsSaveEdit() {
    var key = document.getElementById('rs-edit-key-hidden').value;
    var rawVal = document.getElementById('rs-edit-value').value.trim();
    var typeHint = document.getElementById('rs-edit-type-hint').textContent;
    var resultEl = document.getElementById('rs-edit-result');

    if (!key) { return; }
    if (rawVal === '') {
        resultEl.innerHTML = '<span class="badge badge-red">Value is required.</span>';
        return;
    }

    // Client-side type coercion for clear feedback before the round-trip
    var coerced;
    if (typeHint === 'int') {
        coerced = parseInt(rawVal, 10);
        if (isNaN(coerced)) {
            resultEl.innerHTML = '<span class="badge badge-red">Must be an integer.</span>';
            return;
        }
    } else if (typeHint === 'float') {
        coerced = parseFloat(rawVal);
        if (isNaN(coerced)) {
            resultEl.innerHTML = '<span class="badge badge-red">Must be a number.</span>';
            return;
        }
    } else if (typeHint === 'bool') {
        var lc = rawVal.toLowerCase();
        if (lc === 'true' || lc === '1') { coerced = true; }
        else if (lc === 'false' || lc === '0') { coerced = false; }
        else {
            resultEl.innerHTML = '<span class="badge badge-red">Must be true or false.</span>';
            return;
        }
    } else {
        // json or string — send as-is; server validates
        coerced = rawVal;
    }

    resultEl.innerHTML = '<span class="loading">Saving…</span>';

    var resp = await apiMutate('/admin/runtime-settings/' + encodeURIComponent(key), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: coerced })
    }).catch(function() { return null; });

    if (!resp) {
        resultEl.innerHTML = '<span class="badge badge-red">Network error or step-up cancelled.</span>';
        return;
    }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message)) ? (err.detail.error || err.detail.message) : ('HTTP ' + resp.status);
        resultEl.innerHTML = '<span class="badge badge-red">Error: ' + escapeHtml(msg) + '</span>';
        return;
    }

    var updated = await resp.json().catch(function() { return null; });
    if (updated) {
        // Refresh the value cell in-place
        var valCell = document.getElementById('rs-val-' + key);
        if (valCell) { valCell.textContent = String(updated.value); }
        // Update the edit button data attrs
        var editBtn = document.querySelector('[data-rs-key="' + key + '"].rs-btn-edit');
        if (editBtn) {
            editBtn.setAttribute('data-rs-value', String(updated.value));
            editBtn.setAttribute('data-rs-type', updated.value_type || typeHint);
        }
    }

    _rsHideEditForm();
    _rsToast('Setting "' + key + '" updated.', true);
    // Full reload to pick up source + changed_by + changed_at
    loadRuntimeSettings();
}

// ---------------------------------------------------------------------------
// Reset to default (POST /key/reset)
// ---------------------------------------------------------------------------

async function rsResetRow(key) {
    if (!confirm('Reset "' + key + '" to its install-time default? This requires TOTP step-up.')) {
        return;
    }

    var resp = await apiMutate('/admin/runtime-settings/' + encodeURIComponent(key) + '/reset', {
        method: 'POST'
    }).catch(function() { return null; });

    if (!resp) {
        _rsToast('Network error or step-up cancelled for "' + key + '".', false);
        return;
    }
    if (!resp.ok) {
        var err = await resp.json().catch(function() { return {}; });
        var msg = (err.detail && (err.detail.error || err.detail.message)) ? (err.detail.error || err.detail.message) : ('HTTP ' + resp.status);
        _rsToast('Reset failed: ' + msg, false);
        return;
    }

    _rsToast('Setting "' + key + '" reset to default.', true);
    loadRuntimeSettings();
}

// ---------------------------------------------------------------------------
// Wire up DOM-ready event delegation (edit form buttons)
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function() {
    // Edit form — Save button
    var saveBtn = document.getElementById('rs-btn-save');
    if (saveBtn) {
        saveBtn.addEventListener('click', rsSaveEdit);
    }
    // Edit form — Cancel button
    var cancelBtn = document.getElementById('rs-btn-cancel');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', _rsHideEditForm);
    }
    // Edit form — Enter key in value input
    var editInput = document.getElementById('rs-edit-value');
    if (editInput) {
        editInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') { e.preventDefault(); rsSaveEdit(); }
            if (e.key === 'Escape') { e.preventDefault(); _rsHideEditForm(); }
        });
    }
});

// Expose for showPage() in dashboard.js
window.loadRuntimeSettings = loadRuntimeSettings;
