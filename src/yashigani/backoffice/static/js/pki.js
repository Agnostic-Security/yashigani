// Yashigani Backoffice — PKI admin panel
// v2.23.3 (#51 + #53) — CSP-compliant external JS (no inline scripts)
// ZAP 10015/10049 (3.0) — all inline style attributes replaced with CSS classes
// Last updated: 2026-06-27T00:00:00+01:00
//
// Depends on: dashboard.js (api, apiMutate, escapeHtml)
// Loaded as: <script src="/static/js/pki.js" defer></script>

/* global api, apiMutate, escapeHtml */

'use strict';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var _pkiCurrentService = null;

// ---------------------------------------------------------------------------
// PKI status table
// ---------------------------------------------------------------------------

async function loadPkiStatus() {
    var container = document.getElementById('pki-status-container');
    if (!container) { return; }
    container.innerHTML = '<span class="loading">Loading&hellip;</span>';

    var data = await api('/api/v1/admin/pki/status');
    if (!data) {
        container.innerHTML = '<span class="pki-err-text">Failed to load PKI status. Check authentication.</span>';
        return;
    }

    var caMode = data.ca_mode || 'internal';
    var services = data.services || [];

    if (services.length === 0) {
        container.innerHTML = '<p class="pki-muted-text">No services found in manifest.</p>';
        return;
    }

    // CA Mode banner — prominent, on top (issuing authority for all certs).
    var html = '<div class="pki-camode-banner">'
        + '<span class="pki-camode-label">CA Mode</span>'
        + '<strong class="pki-camode-value">' + escapeHtml(caMode) + '</strong>'
        + '<span class="pki-camode-issuer">Issuing authority for all service certificates</span>'
        + '</div>';

    function badgeFor(svc) {
        if (svc.error) { return '<span class="badge badge-red">Error</span>'; }
        if (svc.needs_renewal) { return '<span class="badge badge-yellow">Renewal needed</span>'; }
        return '<span class="badge badge-green">OK</span>';
    }
    function expiresFor(svc) {
        return svc.not_after
            ? escapeHtml(svc.not_after.replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, ''))
            : (svc.error ? '<span class="pki-err-text">Unknown</span>' : '—');
    }
    function rowHtml(svc) {
        return '<tr class="pki-row">'
            + '<td class="pki-td-mono">' + escapeHtml(svc.service) + '</td>'
            + '<td class="pki-td">' + badgeFor(svc) + '</td>'
            + '<td class="pki-td-exp">' + expiresFor(svc) + '</td>'
            + '<td class="pki-td">'
            + '<button class="btn btn-sm pki-btn-gap" data-action="pkiView" data-service="' + escapeHtml(svc.service) + '">View</button>'
            + '<button class="btn btn-sm btn-warning pki-btn-gap" data-action="pkiRotate" data-service="' + escapeHtml(svc.service) + '">Rotate</button>'
            + '<button class="btn btn-sm" data-action="pkiDownload" data-service="' + escapeHtml(svc.service) + '">Download</button>'
            + '</td></tr>';
    }
    function tableHtml(rowsHtml) {
        return '<table class="pki-table">'
            + '<thead><tr class="pki-thead-row">'
            + '<th class="pki-th">Service</th>'
            + '<th class="pki-th">Status</th>'
            + '<th class="pki-th">Expires</th>'
            + '<th class="pki-th">Actions</th>'
            + '</tr></thead><tbody>' + rowsHtml + '</tbody></table>';
    }

    // Front-end certificate = the Caddy edge that terminates TLS for the admin UI
    // AND the Open WebUI data plane — the cert users' browsers actually see.
    // Surface it separately from the internal service mesh certs.
    var frontend = services.filter(function(s) { return s.service === 'caddy'; });
    var internal = services.filter(function(s) { return s.service !== 'caddy'; });

    if (frontend.length) {
        html += '<h3 class="pki-section-title">Front-end certificate '
            + '<span class="pki-section-sub">(browser-facing — admin UI &amp; Open WebUI edge)</span></h3>';
        html += tableHtml(frontend.map(rowHtml).join(''));
    }
    html += '<h3 class="pki-section-title-mt">Internal service certificates</h3>';
    html += tableHtml(internal.map(rowHtml).join(''));
    container.innerHTML = html;
}

// ---------------------------------------------------------------------------
// View chain detail
// ---------------------------------------------------------------------------

async function showPkiChain(serviceName) {
    _pkiCurrentService = serviceName;
    var detailContainer = document.getElementById('pki-chain-detail');
    if (!detailContainer) { return; }

    detailContainer.innerHTML = '<span class="loading">Loading chain for ' + escapeHtml(serviceName) + '&hellip;</span>';
    detailContainer.style.display = 'block';

    var data = await api('/api/v1/admin/pki/chain/' + encodeURIComponent(serviceName));
    if (!data) {
        detailContainer.innerHTML = '<span class="pki-err-text">Failed to load chain info for ' + escapeHtml(serviceName) + '.</span>';
        return;
    }

    var rows = [
        ['Service', escapeHtml(data.service || serviceName)],
        ['Subject CN', escapeHtml(data.subject_cn || '—')],
        ['Issuer CN', escapeHtml(data.issuer_cn || '—')],
        ['Serial', '<code class="pki-code">' + escapeHtml(data.serial_hex || '—') + '</code>'],
        ['Not Before', escapeHtml((data.not_before || '—').replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, ''))],
        ['Not After', escapeHtml((data.not_after || '—').replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, ''))],
        ['SHA-256', '<code class="pki-code-fp">' + escapeHtml(data.fingerprint_sha256 || '—') + '</code>'],
        ['DNS SANs', data.dns_sans && data.dns_sans.length ? escapeHtml(data.dns_sans.join(', ')) : '—'],
        ['URI SANs', data.uri_sans && data.uri_sans.length ? escapeHtml(data.uri_sans.join(', ')) : '—'],
        ['IP SANs', data.ip_sans && data.ip_sans.length ? escapeHtml(data.ip_sans.join(', ')) : '—'],
        ['CA Mode', escapeHtml(data.ca_mode || '—')],
        ['Chain Depth', escapeHtml(String(data.chain_depth || '1'))],
        ['Needs Renewal', data.needs_renewal ? '<span class="badge badge-yellow">Yes</span>' : '<span class="badge badge-green">No</span>'],
    ];

    var tableHtml = '<table class="pki-table">';
    rows.forEach(function(row) {
        tableHtml += '<tr>'
            + '<td class="pki-detail-label">' + row[0] + '</td>'
            + '<td class="pki-detail-value">' + row[1] + '</td>'
            + '</tr>';
    });
    tableHtml += '</table>';

    var html = '<div class="pki-chain-panel">'
        + '<div class="pki-chain-header-row">'
        + '<strong>Chain details — ' + escapeHtml(serviceName) + '</strong>'
        + '<button class="btn btn-sm pki-chain-close" data-action="pkiClose">Close</button>'
        + '</div>'
        + tableHtml
        + '</div>';

    detailContainer.innerHTML = html;
}

function hidePkiChain() {
    var detailContainer = document.getElementById('pki-chain-detail');
    if (detailContainer) {
        detailContainer.style.display = 'none';
        detailContainer.innerHTML = '';
    }
}

// ---------------------------------------------------------------------------
// Rotate cert
// ---------------------------------------------------------------------------

async function pkiRotate(serviceName) {
    var resultEl = document.getElementById('pki-rotate-result');
    if (resultEl) {
        resultEl.className = 'pki-rotate-result pki-muted-text';
        resultEl.style.display = 'block';
        resultEl.textContent = 'Requesting rotation for ' + serviceName + '…';
    }

    var resp = await apiMutate('/api/v1/admin/pki/rotate/' + encodeURIComponent(serviceName), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    });

    if (!resp) {
        if (resultEl) {
            resultEl.className = 'pki-rotate-result pki-err-text';
            resultEl.textContent = 'Network error. Check step-up TOTP or try again.';
        }
        return;
    }

    var body = {};
    try { body = await resp.json(); } catch (_) { /* empty */ }

    if (resp.status === 401 && body && body.detail && body.detail.error === 'step_up_required') {
        // Handled by apiMutate step-up modal — will retry automatically
        if (resultEl) {
            resultEl.className = 'pki-rotate-result pki-muted-text';
            resultEl.textContent = 'Step-up required — enter TOTP code in the modal.';
        }
        return;
    }

    if (!resp.ok) {
        if (resultEl) {
            resultEl.className = 'pki-rotate-result pki-err-text';
            resultEl.textContent = 'Rotation failed (HTTP ' + resp.status + '): ' + ((body && body.detail && body.detail.message) || 'see server logs');
        }
        return;
    }

    if (body.success) {
        if (resultEl) {
            resultEl.className = 'pki-rotate-result';
            resultEl.style.color = '#16a34a';
            var newExpiry = (body.new_chain && body.new_chain.not_after)
                ? ' New expiry: ' + body.new_chain.not_after.replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, '')
                : '';
            resultEl.textContent = 'Rotation succeeded for ' + escapeHtml(serviceName) + '.' + newExpiry;
        }
        // Refresh the status table and chain detail if open
        await loadPkiStatus();
        if (_pkiCurrentService === serviceName) {
            await showPkiChain(serviceName);
        }
    } else {
        if (resultEl) {
            resultEl.className = 'pki-rotate-result pki-err-text';
            resultEl.textContent = 'Rotation failed: ' + escapeHtml(body.error || 'unknown error');
        }
    }
}

// ---------------------------------------------------------------------------
// Download bundle
// ---------------------------------------------------------------------------

async function pkiDownloadBundle(serviceName) {
    // Use a direct fetch so we can handle the blob download.
    // No step-up required for download (read-only).
    try {
        var resp = await fetch('/api/v1/admin/pki/bundle/' + encodeURIComponent(serviceName), {
            credentials: 'same-origin',
        });
        if (!resp.ok) {
            var body = {};
            try { body = await resp.json(); } catch (_) { /* empty */ }
            var resultEl = document.getElementById('pki-rotate-result');
            if (resultEl) {
                resultEl.className = 'pki-rotate-result pki-err-text';
                resultEl.style.display = 'block';
                resultEl.textContent = 'Download failed (HTTP ' + resp.status + '): ' + ((body && body.detail && body.detail.message) || 'see server logs');
            }
            return;
        }
        var blob = await resp.blob();
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = serviceName + '_cert_bundle.pem';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (err) {
        var resultEl2 = document.getElementById('pki-rotate-result');
        if (resultEl2) {
            resultEl2.className = 'pki-rotate-result pki-err-text';
            resultEl2.style.display = 'block';
            resultEl2.textContent = 'Download error: ' + String(err);
        }
    }
}

// ---------------------------------------------------------------------------
// Wire up + expose
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function() {
    var refreshBtn = document.getElementById('pki-btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadPkiStatus);
    }
});

// Expose so showPage() in dashboard.js can call it on pki panel navigation
window.loadPkiStatus = loadPkiStatus;
window.showPkiChain = showPkiChain;
window.hidePkiChain = hidePkiChain;
window.pkiRotate = pkiRotate;
window.pkiDownloadBundle = pkiDownloadBundle;
