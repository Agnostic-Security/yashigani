// Yashigani Backoffice — PKI admin panel
// v2.23.3 (#51 + #53) — CSP-compliant external JS (no inline scripts)
// Last updated: 2026-05-09T00:00:00+01:00
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
        container.innerHTML = '<span style="color:#ef4444">Failed to load PKI status. Check authentication.</span>';
        return;
    }

    var caMode = data.ca_mode || 'internal';
    var services = data.services || [];

    if (services.length === 0) {
        container.innerHTML = '<p style="color:#64748b">No services found in manifest.</p>';
        return;
    }

    // CA Mode banner — prominent, on top (issuing authority for all certs).
    var html = '<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;padding:12px 14px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;">'
        + '<span style="font-size:0.75rem;color:#475569;text-transform:uppercase;letter-spacing:0.05em;">CA Mode</span>'
        + '<strong style="font-size:1rem;color:#1e3a8a;">' + escapeHtml(caMode) + '</strong>'
        + '<span style="font-size:0.78rem;color:#64748b;margin-left:auto;">Issuing authority for all service certificates</span>'
        + '</div>';

    function badgeFor(svc) {
        if (svc.error) { return '<span class="badge badge-red">Error</span>'; }
        if (svc.needs_renewal) { return '<span class="badge badge-yellow">Renewal needed</span>'; }
        return '<span class="badge badge-green">OK</span>';
    }
    function expiresFor(svc) {
        return svc.not_after
            ? escapeHtml(svc.not_after.replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, ''))
            : (svc.error ? '<span style="color:#ef4444">Unknown</span>' : '—');
    }
    function rowHtml(svc) {
        return '<tr style="border-bottom:1px solid #f1f5f9;">'
            + '<td style="padding:8px 12px;font-family:monospace;">' + escapeHtml(svc.service) + '</td>'
            + '<td style="padding:8px 12px;">' + badgeFor(svc) + '</td>'
            + '<td style="padding:8px 12px;font-size:0.8rem;color:#475569;">' + expiresFor(svc) + '</td>'
            + '<td style="padding:8px 12px;">'
            + '<button class="btn btn-sm" data-action="pkiView" data-service="' + escapeHtml(svc.service) + '" style="margin-right:4px;">View</button>'
            + '<button class="btn btn-sm btn-warning" data-action="pkiRotate" data-service="' + escapeHtml(svc.service) + '" style="margin-right:4px;">Rotate</button>'
            + '<button class="btn btn-sm" data-action="pkiDownload" data-service="' + escapeHtml(svc.service) + '">Download</button>'
            + '</td></tr>';
    }
    function tableHtml(rowsHtml) {
        return '<table style="width:100%;border-collapse:collapse;font-size:0.85rem;">'
            + '<thead><tr style="background:#f1f5f9;text-align:left;">'
            + '<th style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">Service</th>'
            + '<th style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">Status</th>'
            + '<th style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">Expires</th>'
            + '<th style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">Actions</th>'
            + '</tr></thead><tbody>' + rowsHtml + '</tbody></table>';
    }

    // Front-end certificate = the Caddy edge that terminates TLS for the admin UI
    // AND the Open WebUI data plane — the cert users' browsers actually see.
    // Surface it separately from the internal service mesh certs.
    var frontend = services.filter(function(s) { return s.service === 'caddy'; });
    var internal = services.filter(function(s) { return s.service !== 'caddy'; });

    if (frontend.length) {
        html += '<h3 style="margin:0 0 6px;font-size:0.95rem;">Front-end certificate '
            + '<span style="font-weight:400;color:#64748b;font-size:0.8rem;">(browser-facing — admin UI &amp; Open WebUI edge)</span></h3>';
        html += tableHtml(frontend.map(rowHtml).join(''));
    }
    html += '<h3 style="margin:16px 0 6px;font-size:0.95rem;">Internal service certificates</h3>';
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
        detailContainer.innerHTML = '<span style="color:#ef4444">Failed to load chain info for ' + escapeHtml(serviceName) + '.</span>';
        return;
    }

    var rows = [
        ['Service', escapeHtml(data.service || serviceName)],
        ['Subject CN', escapeHtml(data.subject_cn || '—')],
        ['Issuer CN', escapeHtml(data.issuer_cn || '—')],
        ['Serial', '<code style="font-size:0.8rem;background:#f1f5f9;padding:2px 6px;border-radius:3px;">' + escapeHtml(data.serial_hex || '—') + '</code>'],
        ['Not Before', escapeHtml((data.not_before || '—').replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, ''))],
        ['Not After', escapeHtml((data.not_after || '—').replace('T', ' ').replace(/\+.*$/, ' UTC').replace(/\.\d+/, ''))],
        ['SHA-256', '<code style="font-size:0.75rem;background:#f1f5f9;padding:2px 6px;border-radius:3px;word-break:break-all;">' + escapeHtml(data.fingerprint_sha256 || '—') + '</code>'],
        ['DNS SANs', data.dns_sans && data.dns_sans.length ? escapeHtml(data.dns_sans.join(', ')) : '—'],
        ['URI SANs', data.uri_sans && data.uri_sans.length ? escapeHtml(data.uri_sans.join(', ')) : '—'],
        ['IP SANs', data.ip_sans && data.ip_sans.length ? escapeHtml(data.ip_sans.join(', ')) : '—'],
        ['CA Mode', escapeHtml(data.ca_mode || '—')],
        ['Chain Depth', escapeHtml(String(data.chain_depth || '1'))],
        ['Needs Renewal', data.needs_renewal ? '<span class="badge badge-yellow">Yes</span>' : '<span class="badge badge-green">No</span>'],
    ];

    var tableHtml = '<table style="width:100%;border-collapse:collapse;font-size:0.85rem;">';
    rows.forEach(function(row) {
        tableHtml += '<tr>'
            + '<td style="padding:6px 10px;color:#64748b;white-space:nowrap;font-weight:500;border-bottom:1px solid #f1f5f9;width:140px;">' + row[0] + '</td>'
            + '<td style="padding:6px 10px;border-bottom:1px solid #f1f5f9;">' + row[1] + '</td>'
            + '</tr>';
    });
    tableHtml += '</table>';

    var html = '<div style="background:#fff;border:1px solid #e2e8f0;border-radius:6px;padding:16px;margin-top:12px;">'
        + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">'
        + '<strong>Chain details — ' + escapeHtml(serviceName) + '</strong>'
        + '<button class="btn btn-sm" data-action="pkiClose" style="font-size:0.75rem;">Close</button>'
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
        resultEl.style.color = '#64748b';
        resultEl.textContent = 'Requesting rotation for ' + serviceName + '…';
    }

    var resp = await apiMutate('/api/v1/admin/pki/rotate/' + encodeURIComponent(serviceName), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    });

    if (!resp) {
        if (resultEl) {
            resultEl.style.color = '#ef4444';
            resultEl.textContent = 'Network error. Check step-up TOTP or try again.';
        }
        return;
    }

    var body = {};
    try { body = await resp.json(); } catch (_) { /* empty */ }

    if (resp.status === 401 && body && body.detail && body.detail.error === 'step_up_required') {
        // Handled by apiMutate step-up modal — will retry automatically
        if (resultEl) {
            resultEl.style.color = '#64748b';
            resultEl.textContent = 'Step-up required — enter TOTP code in the modal.';
        }
        return;
    }

    if (!resp.ok) {
        if (resultEl) {
            resultEl.style.color = '#ef4444';
            resultEl.textContent = 'Rotation failed (HTTP ' + resp.status + '): ' + ((body && body.detail && body.detail.message) || 'see server logs');
        }
        return;
    }

    if (body.success) {
        if (resultEl) {
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
            resultEl.style.color = '#ef4444';
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
                resultEl.style.color = '#ef4444';
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
            resultEl2.style.color = '#ef4444';
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
