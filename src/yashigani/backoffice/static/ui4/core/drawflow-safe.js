// ui4/core/drawflow-safe.js — DOMPurify + Trusted-Types wrapper for Drawflow (RISK-096)
//
// SECURITY CONTEXT
//   Drawflow is the visual agent builder canvas. It accepts a `html` parameter for
//   node content which it sets via innerHTML internally. An attacker who can inject
//   into node data (e.g. via a malicious graph import) would achieve stored XSS.
//
//   This module is the PINNED SEAM between the builder UI and Drawflow:
//     - Registers the 'drawflow-label' TrustedTypes policy (spec §2.4 conditional;
//       RECONCILIATION-20260627 R1: drawflow-label required because Drawflow's
//       2 innerHTML=variable calls cannot be textContent-replaced without forking).
//     - Policy uses DOMPurify with zero-allowlist (ALLOWED_TAGS=[], ALLOWED_ATTR=[])
//       — labels are plain-text identifiers, never markup.
//     - Calls setDrawflowTTPolicy() so the ESM shim's __df_tt() returns TrustedHTML.
//     - Enforces typenode=true on all addNode() calls (cloneNode path, no innerHTML
//       for node content; the drawflow-label policy is defence-in-depth for the
//       __df_tt() wrappers which then receive empty/developer-authored strings only).
//     - Re-sanitises all rendered node text after import() / addNode() via
//       textContent assignment (belt-and-suspenders against residual markup).
//
// POLICY NAME: 'drawflow-label'
//   CSP trusted-types directive: yashigani-render dompurify lit-html drawflow-label
//   (docker/Caddyfile.csp @strict_tt)
//
// EXPORTS (the builder UI MUST use these — never Drawflow directly):
//   mountDrawflowSafe(container, options)  — safe Drawflow constructor
//   addNodeSafe(editor, ...)               — sanitised addNode wrapper
//   importSafe(editor, graphData)          — sanitised import wrapper
//   sanitizeNodeData(data)                 — sanitise all string fields in node data
//   reRenderSafeText(editor)               — re-walk + textContent-fix rendered nodes
//   registerNodeTypeSafe(editor, name, html, props, options)  — register node type

import DOMPurify from '/static/vendor/dompurify/purify.es.mjs';
import { Drawflow, setDrawflowTTPolicy } from '/static/vendor/drawflow/drawflow.esm.js';

// ── drawflow-label TrustedTypes policy ───────────────────────────────────────
//
// Zero-allowlist: every tag and attribute is stripped. Labels are plain-text
// identifiers (agent name, tool name, port name). NO markup is ever valid here.
//
// On non-TT browsers (Firefox, Safari as of 2026): DOMPurify still runs, but the
// result is a plain string — Drawflow's innerHTML receives sanitised plain text
// (no tags remain) which is safe even without TT enforcement.

const _tt = typeof window !== 'undefined' ? window.trustedTypes : undefined;

let _drawflowLabelPolicy = null;

if (_tt && typeof _tt.createPolicy === 'function') {
  try {
    _drawflowLabelPolicy = _tt.createPolicy('drawflow-label', {
      /**
       * Strip ALL HTML from a Drawflow html-parameter string.
       * Returns a TrustedHTML containing ONLY plain text — never any markup.
       *
       * @param {string} dirty  Node html parameter (may contain attacker-supplied HTML)
       * @returns {string}      Plain-text string safe for use as inner HTML (no tags)
       */
      createHTML(dirty) {
        return DOMPurify.sanitize(
          String(dirty == null ? '' : dirty),
          {
            ALLOWED_TAGS: [],  // strip all tags — zero allowlist
            ALLOWED_ATTR: [],  // strip all attributes
          }
        );
      },
    });
  } catch (_) {
    // Duplicate policy registration (e.g. hot-reload). Fall through to plain-string mode.
    _drawflowLabelPolicy = null;
  }
}

// Inject the policy into the Drawflow ESM shim so __df_tt() returns TrustedHTML.
setDrawflowTTPolicy(_drawflowLabelPolicy);

// ── Sanitisation helpers ──────────────────────────────────────────────────────

/**
 * Strip all HTML from a node label / identifier string.
 * Returns a plain string (not TrustedHTML) for assignment to textContent.
 *
 * @param {string} s  Untrusted identifier
 * @returns {string}  Tag-free plain text safe for textContent
 */
function _sanitizeLabel(s) {
  return String(DOMPurify.sanitize(
    String(s == null ? '' : s),
    { ALLOWED_TAGS: [], ALLOWED_ATTR: [] }
  ));
}

/**
 * Deep-sanitise all string values in a node's data object.
 * Non-string values (numbers, booleans, null) are passed through unchanged.
 * Nested objects and arrays are recursed into.
 *
 * @param {*} data  Node data (may be any JSON-serialisable structure)
 * @returns {*}     Sanitised copy (no mutation of original)
 */
export function sanitizeNodeData(data) {
  if (data === null || data === undefined) return data;
  if (typeof data === 'string') return _sanitizeLabel(data);
  if (typeof data !== 'object') return data;  // number, boolean
  if (Array.isArray(data)) return data.map(sanitizeNodeData);
  const out = {};
  for (const [k, v] of Object.entries(data)) {
    out[_sanitizeLabel(k)] = sanitizeNodeData(v);
  }
  return out;
}

/**
 * Re-walk all rendered nodes inside a Drawflow canvas and overwrite any text
 * content via textContent (stripping any residual markup injected by Drawflow's
 * internal rendering). Belt-and-suspenders after addNode() / import().
 *
 * Targets: .drawflow_content_node (the node inner-content div set by Drawflow).
 * Sets textContent = DOMPurify(textContent) on every text node descendant to
 * prevent any HTML that leaked through from being interpreted as markup.
 *
 * @param {Element} canvasContainer  The container element passed to Drawflow()
 */
export function reRenderSafeText(canvasContainer) {
  if (!canvasContainer) return;
  const nodes = canvasContainer.querySelectorAll('.drawflow_content_node');
  for (const node of nodes) {
    // Collect all text nodes directly (not recursing into child elements that
    // are part of the developer-authored node template registered via registerNode).
    // For typenode=true, content came from cloneNode — developer-authored, safe.
    // This sweep is belt-and-suspenders for any stray innerHTML-sourced text.
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, null);
    let textNode;
    while ((textNode = walker.nextNode())) {
      if (textNode.nodeValue && /[<>&"']/.test(textNode.nodeValue)) {
        // Potential unescaped HTML entities or tags — re-encode via DOMPurify.
        textNode.nodeValue = _sanitizeLabel(textNode.nodeValue);
      }
    }
  }
}

// ── Safe builder API ──────────────────────────────────────────────────────────

/**
 * Safe Drawflow constructor. Initialises Drawflow on the given container,
 * registers the TT policy, and returns the editor instance.
 *
 * @param {HTMLElement} container  DOM element to mount the canvas on
 * @param {object} [options]       Drawflow constructor options (render, parent)
 * @returns {Drawflow}             Initialised Drawflow editor instance
 */
export function mountDrawflowSafe(container, options = {}) {
  if (!container || !(container instanceof Element)) {
    throw new TypeError('mountDrawflowSafe: container must be a DOM Element');
  }
  const editor = new Drawflow(container, options.render || null, options.parent || null);
  editor.start();
  return editor;
}

/**
 * Register a developer-authored node type. The `html` argument MUST be a
 * pre-created DOM Element (cloneNode path — no innerHTML at register time).
 * This enforces typenode=true usage in the builder.
 *
 * @param {Drawflow}    editor   Drawflow editor instance
 * @param {string}      name     Node type name (sanitised)
 * @param {HTMLElement} htmlEl   Pre-built DOM element for this node type
 * @param {object}      [props]  Drawflow props
 * @param {object}      [opts]   Drawflow options
 */
export function registerNodeTypeSafe(editor, name, htmlEl, props = {}, opts = {}) {
  const safeName = _sanitizeLabel(name);
  if (!htmlEl || !(htmlEl instanceof Element)) {
    throw new TypeError('registerNodeTypeSafe: htmlEl must be a DOM Element');
  }
  editor.registerNode(safeName, htmlEl, props, opts);
}

/**
 * Safe addNode wrapper. Enforces typenode=true (cloneNode path — no innerHTML
 * for node content). Sanitises all data values via sanitizeNodeData().
 *
 * @param {Drawflow} editor       Editor instance from mountDrawflowSafe()
 * @param {string}   name         Node type name (must be registered via registerNodeTypeSafe)
 * @param {number}   inputs       Number of input ports
 * @param {number}   outputs      Number of output ports
 * @param {number}   x            Canvas x position
 * @param {number}   y            Canvas y position
 * @param {string}   [className]  Additional CSS class override
 * @param {object}   [data]       Node data (all string values sanitised)
 * @returns {number}              Node ID assigned by Drawflow
 */
export function addNodeSafe(editor, name, inputs, outputs, x, y, className = '', data = {}) {
  const safeName = _sanitizeLabel(name);
  const safeClass = _sanitizeLabel(className);
  const safeData = sanitizeNodeData(data);

  // typenode=true → Drawflow uses cloneNode(!0) on registered template, NOT innerHTML.
  // The drawflow-label policy and __df_tt() are defence-in-depth; they receive the
  // type name string (safeName), not user data.
  const nodeId = editor.addNode(safeName, inputs, outputs, x, y, safeClass, safeData, safeName, true);

  // Re-sanitise rendered text after DOM write.
  reRenderSafeText(editor.container);
  return nodeId;
}

/**
 * Safe import wrapper. Sanitises all node data in the graph before calling
 * editor.import(), then re-walks rendered nodes to assert no markup leaks.
 *
 * @param {Drawflow} editor     Editor instance from mountDrawflowSafe()
 * @param {object}   graphData  Drawflow export() graph object (may be untrusted)
 */
export function importSafe(editor, graphData) {
  if (!graphData || typeof graphData !== 'object') {
    throw new TypeError('importSafe: graphData must be an object');
  }

  // Deep-clone and sanitise all node data fields before import.
  const safe = JSON.parse(JSON.stringify(graphData));
  if (safe.drawflow) {
    for (const moduleName of Object.keys(safe.drawflow)) {
      const mod = safe.drawflow[moduleName];
      if (mod && mod.data) {
        for (const [nodeId, node] of Object.entries(mod.data)) {
          // Sanitise the node's data map (user labels, descriptions, etc.)
          if (node.data) node.data = sanitizeNodeData(node.data);
          // Sanitise name (identifier only)
          if (typeof node.name === 'string') node.name = _sanitizeLabel(node.name);
          // Sanitise class override
          if (typeof node.class === 'string') node.class = _sanitizeLabel(node.class);
          // CRITICAL: set typenode=true to force cloneNode path.
          // If the graph was exported with typenode=false (html string in node),
          // we override it here. Builder-generated graphs should always be typenode=true.
          // If a node's html field is NOT a registered type key, import will fail
          // gracefully (Drawflow logs a warning and skips the node).
          node.typenode = true;
        }
      }
    }
  }

  editor.import(safe);

  // Re-sanitise all rendered text after import.
  reRenderSafeText(editor.container);
}
