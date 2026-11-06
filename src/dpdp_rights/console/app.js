// DPO console: a thin client over the Rights API. Every request carries the signed-in user's own credential, so
// the API's roles decide what each person can see and do. Data is only ever inserted as text (never as HTML).
"use strict";

const API = location.pathname.replace(/\/console\/?.*$/, "");
const KEY = "dpdp-console-auth";

// ---- credentials (kept for this browser tab only) -------------------------------------------------------------
function creds() { try { return JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch (e) { return null; } }
function setCreds(c) { try { c ? sessionStorage.setItem(KEY, JSON.stringify(c)) : sessionStorage.removeItem(KEY); } catch (e) { /* storage unavailable */ } }
function authHeaders() {
  const c = creds() || {};
  if (c.kind === "api_key") return { "X-API-Key": c.value };
  if (c.kind === "bearer") return { "Authorization": "Bearer " + c.value };
  if (c.kind === "dev") return { "X-Dev-User": c.value };
  return {};
}

class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function api(path, opts = {}) {
  const headers = Object.assign({}, authHeaders(), opts.body ? { "Content-Type": "application/json" } : {});
  const r = await fetch(API + path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
  if (opts.blob && r.ok) return r.blob();
  let data = null;
  try { data = await r.json(); } catch (e) { /* not JSON */ }
  if (!r.ok) {
    const d = data && (data.detail || (data.error && data.error.message));
    throw new ApiError(r.status, typeof d === "string" ? d : (d ? JSON.stringify(d) : r.statusText));
  }
  return data;
}

async function download(path, filename) {
  const blob = await api(path, { blob: true });
  const a = h("a", { href: URL.createObjectURL(blob), download: filename });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

// ---- tiny DOM helpers ---------------------------------------------------------------------------------------------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.appendChild(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const main = () => document.getElementById("main");
function show(...nodes) { const m = main(); m.replaceChildren(...nodes.flat()); }
function fmt(t) { if (!t) return "–"; const d = new Date(t); return isNaN(d) ? String(t) : d.toLocaleString(); }
function badge(text, tone) { return h("span", { class: "badge " + (tone || "") }, text); }
function tone(state) {
  if (["approved", "completed", "fulfilled", "ok", "active", "applied", "met", "true", "tokenised"].includes(String(state))) return "ok";
  if (["rejected", "failed", "overdue", "broken", "revoked", "false"].includes(String(state)) || String(state).startsWith("blocked")) return "bad";
  if (["pending", "needs_info", "in_review", "received", "acknowledged", "completed_with_exceptions", "partial"].includes(String(state))) return "warn";
  return "";
}
function table(cols, rows, onclick) {
  return h("table", {},
    h("thead", {}, h("tr", {}, cols.map(c => h("th", {}, c[0])))),
    h("tbody", {}, rows.length ? rows.map(r => h("tr", onclick ? { class: "click", onclick: () => onclick(r) } : {},
      cols.map(c => h("td", {}, c[1](r))))) : h("tr", {}, h("td", { colspan: cols.length, class: "muted" }, "Nothing here."))));
}
// A record's fields as readable lines: nested values compactly, long ids wrapped.
function details(obj) {
  if (obj === null || obj === undefined) return "–";
  if (typeof obj !== "object") return String(obj);
  const keys = Object.keys(obj).filter(k => obj[k] !== null && obj[k] !== undefined && k !== "at");
  if (!keys.length) return "–";
  return h("dl", { class: "kv detail" }, keys.flatMap(k => [h("dt", {}, k.replace(/_/g, " ")),
    h("dd", {}, typeof obj[k] === "object" ? (Array.isArray(obj[k]) && obj[k].every(x => typeof x !== "object") ? obj[k].join(", ") : details(obj[k])) : String(obj[k]))]));
}
function kv(pairs) { return h("dl", { class: "kv" }, pairs.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "–")])); }
function errorView(e) {
  if (e.status === 401) return h("div", { class: "banner bad" }, "Not signed in, or the credential was refused. ", h("a", { href: "#/signin" }, "Sign in"));
  if (e.status === 403) return h("div", { class: "banner warn" }, "Your role cannot see this: " + e.message);
  return h("div", { class: "banner bad" }, (e.status ? e.status + ": " : "") + e.message);
}
async function guard(fn) { try { await fn(); } catch (e) { show(errorView(e)); } }
function notice(form, text, ok) { const n = h("div", { class: "banner " + (ok ? "ok" : "bad") }, text); form.prepend(n); setTimeout(() => n.remove(), 6000); }

// ---- views ------------------------------------------------------------------------------------------------------------
const views = {};

views.signin = () => {
  const c = creds() || { kind: "api_key", value: "" };
  const kind = h("select", { name: "kind" }, [["api_key", "API key"], ["bearer", "Bearer token (OIDC)"], ["dev", "Development: act as"]]
    .map(([v, t]) => h("option", { value: v, selected: c.kind === v }, t)));
  const value = h("input", { name: "value", type: "password", size: 48, value: c.value || "", autocomplete: "off" });
  show(h("h1", {}, "Sign in"),
    h("div", { class: "panel" },
      h("p", { class: "muted" }, "Use the credential your organisation issued for the Rights API. It is kept only for this browser tab, and every screen is limited by its roles (dpo, reviewer, approver)."),
      h("form", { onsubmit: async (ev) => {
        ev.preventDefault();
        setCreds({ kind: kind.value, value: value.value.trim() });
        location.hash = "#/";
      } }, h("label", {}, "Credential type"), kind, h("label", {}, "Value"), value, h("p", {}, h("button", { type: "submit" }, "Sign in"), " ",
        h("button", { type: "button", class: "secondary", onclick: () => { setCreds(null); value.value = ""; renderWho(); } }, "Sign out")))));
};

views[""] = async () => {
  const [sla, queue, rights, breaches] = await Promise.allSettled([
    api("/v1/sla"), api("/v1/erasure-requests?sign_off=pending"), api("/v1/rights-requests"), api("/v1/breaches")]);
  if ([sla, queue, rights, breaches].every(p => p.status === "rejected")) throw sla.reason;
  const val = p => p.status === "fulfilled" ? p.value : null;
  const r = val(rights) || [], q = val(queue) || [], b = val(breaches) || [], s = val(sla);
  const open = r.filter(x => ["received", "in_review", "acknowledged"].includes(x.status));
  const tiles = [
    ["Erasures awaiting sign-off", q.length, "#/signoff"],
    ["Open rights cases", open.length, "#/rights"],
    ["Rights cases overdue", r.filter(x => x.overdue).length, "#/rights?overdue=1"],
    ["Open erasures overdue", s ? s.open_requests.overdue : "–", "#/signoff"],
    ["Breach assessments", b.length, "#/breaches"],
  ];
  show(h("h1", {}, "Overview"),
    h("div", { class: "grid" }, tiles.map(([t, n, href]) => h("div", { class: "tile" }, h("a", { href }, h("div", { class: "muted" }, t), h("div", { class: "n" }, n))))),
    h("h2", {}, "Rights cases due soonest"),
    table([["Case", x => h("code", {}, x.case_id)], ["Type", x => x.type], ["Status", x => badge(x.status, tone(x.status))],
           ["Due", x => x.overdue ? badge(fmt(x.due_by), "bad") : fmt(x.due_by)]],
      open.sort((a, z) => String(a.due_by).localeCompare(String(z.due_by))).slice(0, 8), x => location.hash = "#/rights/" + x.case_id),
    s && Object.keys(s.jobs || {}).length ? h("p", { class: "muted" }, "Erasure jobs: " + Object.entries(s.jobs).map(([k, n]) => `${n} ${k}`).join(", ")) : null);
};

views.signoff = async (_, qs) => {
  const state = qs.get("state") || "pending";
  const rows = await api("/v1/erasure-requests" + (state === "all" ? "" : "?sign_off=" + encodeURIComponent(state)));
  const sel = h("select", { onchange: e => location.hash = "#/signoff?state=" + e.target.value },
    ["pending", "needs_info", "approved", "rejected", "not_reviewable", "not_required", "all"].map(v => h("option", { value: v, selected: v === state }, v)));
  show(h("h1", {}, "Erasure sign-off"),
    h("form", { class: "inline" }, "Sign-off state ", sel),
    table([["Request", x => h("code", {}, x.request_id)], ["Scope", x => x.scope], ["Status", x => badge(x.status, tone(x.status))],
           ["Received", x => fmt(x.received_at)], ["Due", x => x.overdue ? badge(fmt(x.due_by), "bad") : fmt(x.due_by)],
           ["Sign-off", x => [badge(x.sign_off, tone(x.sign_off)), " ", x.required ? `${x.approvals}/${x.required}` : ""]]],
      rows, x => location.hash = "#/case/" + x.request_id));
};

views.case = async ([id]) => {
  const c = await api("/v1/erasure-requests/" + encodeURIComponent(id) + "/case");
  const cert = c.certificate || {}, chk = cert.check || {};
  const so = c.sign_off || {};
  const head = [
    h("h1", {}, "Erasure case ", h("code", {}, id)),
    h("div", { class: "row" },
      h("div", { class: "panel" }, h("h2", {}, "Request"), kv([
        ["Person", h("code", {}, c.request.principal_id)], ["Scope", c.request.scope], ["Status", badge(c.request.status, tone(c.request.status))],
        ["Requested via", c.request.requested_via], ["Verified by", c.request.verified_by], ["Verification ref", c.request.verification_ref],
        ["Received", fmt(c.sla.received_at)], ["Due", fmt(c.sla.due_by)], ["Completed", fmt(c.sla.completed_at)],
        ["Within due date", c.sla.met === null ? "–" : badge(c.sla.met ? "yes" : "no", c.sla.met ? "ok" : "bad")]])),
      h("div", { class: "panel" }, h("h2", {}, "Certificate and case log"), kv([
        ["Certificate", cert.sha256 ? h("code", {}, cert.sha256.slice(0, 16) + "…") : "not issued"],
        ["Hash / chain / signature", [badge("hash " + (chk.hash_ok ? "ok" : "–"), chk.hash_ok ? "ok" : ""), " ",
          badge("chain " + (chk.chain_ok ? "ok" : "–"), chk.chain_ok ? "ok" : ""), " ",
          badge("signature " + (chk.signature_ok ? "ok" : chk.signed ? "bad" : "unsigned"), chk.signature_ok ? "ok" : "warn")]],
        ["Archive", cert.archive_uri], ["Case log", badge((c.case_log_check || {}).ok ? "intact" : "broken", (c.case_log_check || {}).ok ? "ok" : "bad")],
        ["Sign-off", [badge(so.state, tone(so.state)), " ", so.required ? `${(so.approvals || []).length}/${so.required} approvals` : ""]],
        ["Stale approvals", (so.stale_approvals || []).join(", ") || "none"]]),
        h("p", {}, h("button", { class: "secondary", onclick: () => download(`/v1/erasure-requests/${encodeURIComponent(id)}/evidence`, id + "-evidence.zip").catch(e => alert(e.message)) }, "Download signed evidence bundle")))),
  ];
  const actions = table([["Store", x => x.store], ["Action", x => x.action], ["OK", x => badge(x.ok ? "ok" : "failed", x.ok ? "ok" : "bad")],
                         ["Artifact", x => h("code", {}, x.artifact_id)], ["When", x => fmt(x.executed_at)]], c.actions || []);
  const verification = table([["Store", x => x.store], ["Verified", x => badge(x.ok ? "clean" : "leftovers", x.ok ? "ok" : "bad")],
                              ["Findings", x => (x.findings || []).length], ["Note", x => x.note]], c.verification || []);
  const exceptions = (c.exceptions || []).concat(c.failures || []);
  const log = table([["When", x => fmt(x.at)], ["Kind", x => x.kind], ["By", x => x.actor],
                     ["Detail", x => details(x.body)]], c.case_log || []);
  // review form
  const items = (c.review_checklist || []).map(i => {
    const s = h("select", { name: i.id }, [["", "choose"], ["true", "yes"], ["false", "no"], ["n/a", "n/a"]].map(([v, t]) => h("option", { value: v }, t)));
    return [i, s];
  });
  const decision = h("select", { name: "decision" }, ["approved", "needs_info", "rejected"].map(v => h("option", { value: v }, v)));
  const notes = h("textarea", { name: "notes", placeholder: "Required for needs_info, rejected, or approving a case with exceptions. References only, no personal data." });
  const form = h("form", { class: "panel", onsubmit: async (ev) => {
    ev.preventDefault();
    const checklist = {};
    for (const [i, s] of items) { if (s.value) checklist[i.id] = s.value === "n/a" ? "n/a" : s.value === "true"; }
    try {
      const out = await api(`/v1/erasure-requests/${encodeURIComponent(id)}/reviews`, { method: "POST", body: { decision: decision.value, checklist, notes: notes.value || null } });
      notice(form, "Recorded. Sign-off is now " + out.sign_off.state + ".", true);
      setTimeout(() => route(), 800);
    } catch (e) { notice(form, e.message, false); }
  } }, h("h2", {}, "Review"), items.map(([i, s]) => h("div", {}, h("label", {}, i.text), s)),
    h("label", {}, "Decision"), decision, h("label", {}, "Notes"), notes, h("p", {}, h("button", { type: "submit", disabled: so.state === "not_reviewable" }, "Record review")),
    so.state === "not_reviewable" ? h("p", { class: "muted" }, "The request has not finished yet; it can be reviewed once it is complete.") : null);
  show(head, h("h2", {}, "Actions by store"), actions, h("h2", {}, "Verification"), verification,
    exceptions.length ? [h("h2", {}, "Exceptions and failures"), h("pre", {}, JSON.stringify(exceptions, null, 2))] : null,
    h("h2", {}, "Manual actions and reviews"), log, form);
};

views.rights = async (_, qs) => {
  const p = new URLSearchParams();
  for (const k of ["type", "status"]) if (qs.get(k)) p.set(k, qs.get(k));
  if (qs.get("overdue")) p.set("overdue", "true");
  const rows = await api("/v1/rights-requests" + (p.toString() ? "?" + p : ""));
  const type = h("select", { name: "type" }, ["", "access", "correction", "erasure", "withdrawal", "nomination", "nominee_invocation", "grievance"].map(v => h("option", { value: v, selected: qs.get("type") === v }, v || "any type")));
  const status = h("select", { name: "status" }, ["", "received", "in_review", "acknowledged", "fulfilled", "rejected", "closed"].map(v => h("option", { value: v, selected: qs.get("status") === v }, v || "any status")));
  const overdue = h("input", { type: "checkbox", checked: !!qs.get("overdue") });
  const apply = () => { const q = new URLSearchParams(); if (type.value) q.set("type", type.value); if (status.value) q.set("status", status.value); if (overdue.checked) q.set("overdue", "1"); location.hash = "#/rights" + (q.toString() ? "?" + q : ""); };
  [type, status, overdue].forEach(x => x.addEventListener("change", apply));
  show(h("h1", {}, "Rights cases"), h("form", { class: "inline" }, type, status, h("label", {}, overdue, " overdue only")),
    table([["Case", x => h("code", {}, x.case_id)], ["Type", x => x.type], ["Status", x => badge(x.status, tone(x.status))], ["Channel", x => x.channel],
           ["Received", x => fmt(x.received_at)], ["Due", x => x.overdue ? badge(fmt(x.due_by), "bad") : fmt(x.due_by)], ["Rule set", x => x.rules && x.rules.rule_version]],
      rows.slice().reverse(), x => location.hash = "#/rights/" + x.case_id));
};

views["rights-case"] = async ([id]) => {
  const c = await api("/v1/rights-requests/" + encodeURIComponent(id));
  const parts = [h("h1", {}, "Rights case ", h("code", {}, id)),
    h("div", { class: "row" },
      h("div", { class: "panel" }, kv([["Type", c.type], ["Status", badge(c.status, tone(c.status))], ["Person", h("code", {}, c.principal_id)],
        ["Channel", c.channel], ["Requested by", c.requested_by], ["Verified by", c.verified_by], ["Verification ref", c.verification_ref],
        ["Received", fmt(c.received_at)], ["Due", c.overdue ? badge(fmt(c.due_by), "bad") : fmt(c.due_by)], ["Closed", fmt(c.closed_at)],
        ["Rule set", c.rules ? `${c.rules.rule_set} ${c.rules.rule_version}` : "–"], ["Erasure request", c.erasure_request_id ? h("a", { href: "#/case/" + c.erasure_request_id }, c.erasure_request_id) : "–"],
        ["Event log", badge((c.integrity || {}).ok ? "intact" : "broken", (c.integrity || {}).ok ? "ok" : "bad")]])),
      h("div", { class: "panel" }, h("h2", {}, "Details"), details(c.details), h("h2", {}, "Outcome"), details(c.outcome)))];
  if (c.status === "in_review" && ["access", "correction", "nominee_invocation"].includes(c.type)) {
    const decision = h("select", {}, ["approve", "reject"].map(v => h("option", { value: v }, v)));
    const reason = h("textarea", { placeholder: "Required to reject, or to release a partial access report. The requester may read it." });
    const form = h("form", { class: "panel", onsubmit: async ev => {
      ev.preventDefault();
      try { await api(`/v1/rights-requests/${encodeURIComponent(id)}/decision`, { method: "POST", body: { decision: decision.value, reason: reason.value || null } }); route(); }
      catch (e) { notice(form, e.message, false); }
    } }, h("h2", {}, "Decide"), decision, h("label", {}, "Reason"), reason, h("p", {}, h("button", { type: "submit" }, "Record decision")),
      h("p", { class: "muted" }, "The person who submitted a request cannot decide it."));
    parts.push(form);
  }
  if (c.type === "grievance" && ["received", "in_review", "acknowledged"].includes(c.status)) {
    const st = h("select", {}, ["acknowledged", "fulfilled", "rejected"].map(v => h("option", { value: v }, v)));
    const resp = h("textarea", { placeholder: "Response to the Data Principal" });
    const form = h("form", { class: "panel", onsubmit: async ev => {
      ev.preventDefault();
      try { await api(`/v1/rights-requests/${encodeURIComponent(id)}/response`, { method: "POST", body: { status: st.value, response: resp.value || null } }); route(); }
      catch (e) { notice(form, e.message, false); }
    } }, h("h2", {}, "Respond to the grievance"), st, h("label", {}, "Response"), resp, h("p", {}, h("button", { type: "submit" }, "Send response")));
    parts.push(form);
  }
  if (c.type === "access" && c.status === "fulfilled") {
    parts.push(h("p", {}, h("button", { class: "secondary", onclick: async () => {
      try { const b = await api(`/v1/rights-requests/${encodeURIComponent(id)}/access-report?format=html`, { blob: true }); window.open(URL.createObjectURL(b), "_blank", "noopener"); }
      catch (e) { alert(e.message); }
    } }, "Open the released access report")));
  }
  parts.push(h("h2", {}, "Events"), table([["When", x => fmt(x.at)], ["Kind", x => x.kind], ["By", x => x.actor], ["Detail", x => details(x.body)]], c.events || []));
  show(parts);
};

function lineageSvg(nodes) {
  if (!nodes.length) return h("p", { class: "muted" }, "No artifacts recorded.");
  const legend = h("p", { class: "muted" }, "Blue: active · amber: redacted (this person's tokens removed) · green: deleted or erased. Sources on the left, derived artifacts to the right.");
  const NS = "http://www.w3.org/2000/svg";
  const s = (tag, attrs, text) => { const el = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v); if (text) el.textContent = text; return el; };
  // column = longest chain of parents within this person's artifacts (sources left, derived artifacts right)
  const byId = Object.fromEntries(nodes.map(n => [n.artifact_id, n])), level = {};
  const lv = (n, seen = new Set()) => {
    if (level[n.artifact_id] !== undefined) return level[n.artifact_id];
    if (seen.has(n.artifact_id)) return 0;
    seen.add(n.artifact_id);
    const ps = (n.parents || []).filter(p => byId[p]);
    return (level[n.artifact_id] = ps.length ? 1 + Math.max(...ps.map(p => lv(byId[p], seen))) : 0);
  };
  const cols = {}; nodes.forEach(n => { const d = lv(n); (cols[d] = cols[d] || []).push(n); });
  const W = 190, H = 40, GX = 60, GY = 14, pos = {};
  const depths = Object.keys(cols).map(Number).sort((a, b) => a - b);
  depths.forEach((d, ci) => cols[d].forEach((n, ri) => { pos[n.artifact_id] = { x: 10 + ci * (W + GX), y: 10 + ri * (H + GY) }; }));
  const width = 20 + depths.length * (W + GX), height = 20 + Math.max(...depths.map(d => cols[d].length)) * (H + GY);
  const svg = s("svg", { class: "lineage", width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Lineage of this person's data" });
  nodes.forEach(n => (n.parents || []).forEach(p => { if (pos[p]) svg.appendChild(s("line", { x1: pos[p].x + W, y1: pos[p].y + H / 2, x2: pos[n.artifact_id].x, y2: pos[n.artifact_id].y + H / 2 })); }));
  nodes.forEach(n => {
    const { x, y } = pos[n.artifact_id];
    svg.appendChild(s("rect", { x, y, width: W, height: H, rx: 6, class: n.status === "active" ? "" : (n.status === "redacted" ? "redacted" : "erased") }));
    svg.appendChild(s("text", { x: x + 8, y: y + 16 }, `${n.kind} · ${n.edge}`));
    svg.appendChild(s("text", { x: x + 8, y: y + 31 }, `${n.store} (${n.status})`));
  });
  return h("div", { class: "scroll" }, legend, svg);
}

views.person = async (_, qs) => {
  const ext = qs.get("id") || "";
  const input = h("input", { name: "id", value: ext, size: 32, placeholder: "the person's external id" });
  const form = h("form", { class: "inline", onsubmit: ev => { ev.preventDefault(); location.hash = "#/person?id=" + encodeURIComponent(input.value.trim()); } },
    input, h("button", { type: "submit" }, "Look up"));
  if (!ext) return show(h("h1", {}, "Person"), form, h("p", { class: "muted" }, "Consents and their signed history, status, lineage and cases for one Data Principal. Values are not shown."));
  const o = await api("/v1/principals/" + encodeURIComponent(ext) + "/overview");
  const hv = o.consent_history.verify;
  const ch = o.children || {};
  show(h("h1", {}, "Person ", h("code", {}, o.principal_id)), form,
    h("div", { class: "row" },
      h("div", { class: "panel" }, h("h2", {}, "Status"), kv([["Age status", ch.status ? badge(ch.status) : (ch.enforced ? badge("not recorded", "warn") : "not recorded")],
        ["Basis", ch.basis], ["Guardians", (ch.guardians || []).map(g => `${g.method} (${g.status})`).join(", ") || "none"],
        ["Consent history", [badge(hv.ok ? "intact" : "broken", hv.ok ? "ok" : "bad"), ` ${hv.events} events`, hv.signatures_ok ? " · signed" : ""]]])),
      h("div", { class: "panel" }, h("h2", {}, "Consents"), table([["Purpose", x => x.purpose_id], ["Element", x => x.element_type], ["Status", x => badge(x.status, tone(x.status === "granted" ? "ok" : x.status))],
        ["Source", x => x.consent_manager_ref || "direct"], ["Granted", x => fmt(x.granted_at)]], o.consents))),
    h("h2", {}, "Lineage"), lineageSvg(o.lineage),
    h("h2", {}, "Consent history (latest 100)"), table([["When", x => fmt(x.at)], ["Kind", x => x.kind], ["Purpose", x => x.purpose_id], ["Source", x => x.source], ["By", x => x.actor]], o.consent_history.events.slice().reverse()),
    h("div", { class: "row" },
      h("div", {}, h("h2", {}, "Rights cases"), table([["Case", x => h("code", {}, x.case_id)], ["Type", x => x.type], ["Status", x => badge(x.status, tone(x.status))]], o.rights_cases, x => location.hash = "#/rights/" + x.case_id)),
      h("div", {}, h("h2", {}, "Erasure requests"), table([["Request", x => h("code", {}, x.request_id)], ["Scope", x => x.scope], ["Status", x => badge(x.status, tone(x.status))]], o.erasure_requests, x => location.hash = "#/case/" + x.request_id))));
};

views.breaches = async () => {
  const rows = await api("/v1/breaches");
  show(h("h1", {}, "Breach assessments"),
    h("p", { class: "muted" }, "Assess a new breach with the CLI or POST /v1/breaches; detection and investigation stay with incident response."),
    table([["Breach", x => h("code", {}, x.breach_id)], ["Assessed", x => fmt(x.assessed_at)], ["Aware", x => fmt(x.aware_at)],
           ["Stores", x => (x.stores || []).join(", ")], ["Affected", x => x.affected], ["Board report due", x => fmt(x.board_detailed_due_by)]],
      rows, x => location.hash = "#/breach/" + x.breach_id));
};

views.breach = async ([id]) => {
  const [b, v] = await Promise.all([api("/v1/breaches/" + encodeURIComponent(id)), api("/v1/breaches/" + encodeURIComponent(id) + "/verify").catch(() => null)]);
  const t = b.totals || {}, d = b.deadlines || {};
  const draftsBox = h("div", {});
  show(h("h1", {}, "Breach ", h("code", {}, id)),
    v ? h("div", { class: "banner " + (v.ok ? "ok" : "bad") }, v.ok ? "Stored assessments verify: hashes and signatures intact." : "Verification failed: " + JSON.stringify(v)) : null,
    h("div", { class: "grid" }, [["Affected", t.affected], ["Possibly affected", t.possibly_affected], ["Artifacts", t.artifacts], ["No contact on record", t.without_contact_on_record], ["Already erased", t.already_erased]]
      .map(([k, n]) => h("div", { class: "tile" }, h("div", { class: "muted" }, k), h("div", { class: "n" }, n ?? "–")))),
    h("div", { class: "row" },
      h("div", { class: "panel" }, h("h2", {}, "Deadlines (rule set " + ((b.rule_set || {}).version || "") + ")"), kv([
        ["Aware at", fmt(b.aware_at)], ["Notify people", (d.principals || {}).text || (d.principals || {}).when || "without delay"],
        ["Board, initial", (d.board_initial || {}).text || (d.board_initial || {}).when || "without delay"],
        ["Board, detailed", fmt((d.board_detailed || {}).due_by)]])),
      h("div", { class: "panel" }, h("h2", {}, "Exposure"), kv(Object.entries(t.by_exposure || {}).map(([k, n]) => [k, n])),
        h("h2", {}, "Kinds of data"), kv(Object.entries(t.by_element_type || {}).map(([k, n]) => [k, n])))),
    h("h2", {}, "Stores"), table([["Store", x => x.store], ["System", x => x.system], ["Region", x => x.region], ["Processor", x => x.processor],
      ["Contract", x => x.processor_contract || badge("none", "warn")], ["Artifacts", x => x.artifacts], ["People", x => x.people], ["Raw values", x => x.raw_artifacts ? badge(x.raw_artifacts, "bad") : 0]], b.stores || []),
    (b.untracked_systems || []).length ? [h("h2", {}, "Systems the framework cannot list"), table([["System", x => x.system], ["Processor", x => x.processor], ["Reason", x => x.reason]], b.untracked_systems)] : null,
    h("p", {}, h("button", { onclick: async () => {
      try { const dr = await api("/v1/breaches/" + encodeURIComponent(id) + "/drafts");
        draftsBox.replaceChildren(h("h2", {}, "Board intimation (initial)"), h("pre", {}, dr.board_initial), h("h2", {}, "Board report (detailed)"), h("pre", {}, dr.board_detailed),
          h("h2", {}, `Notices to people (${dr.notices.length})`), h("pre", {}, JSON.stringify(dr.notices.slice(0, 3), null, 2) + (dr.notices.length > 3 ? "\n…" : "")));
      } catch (e) { draftsBox.replaceChildren(errorView(e)); }
    } }, "Show draft intimations"), " ",
      h("button", { class: "secondary", onclick: () => download("/v1/breaches/" + encodeURIComponent(id) + "/bundle", id + ".zip").catch(e => alert(e.message)) }, "Download signed bundle")),
    draftsBox);
};

views.audit = () => {
  const today = new Date(), first = new Date(today.getFullYear(), today.getMonth() - 1, 1), last = new Date(today.getFullYear(), today.getMonth(), 1);
  const iso = d => d.toISOString().slice(0, 10);
  const start = h("input", { type: "date", value: iso(first) }), end = h("input", { type: "date", value: iso(last) });
  const cases = h("input", { type: "checkbox", checked: true });
  const form = h("form", { class: "panel", onsubmit: async ev => {
    ev.preventDefault();
    try { await download(`/v1/audit-pack?start=${start.value}&end=${end.value}&include_cases=${cases.checked}`, `audit-pack-${start.value}-${end.value}.zip`); notice(form, "Downloaded. Check it offline with: dpdp-rights evidence verify <file>", true); }
    catch (e) { notice(form, e.message, false); }
  } }, h("label", {}, "From (inclusive)"), start, h("label", {}, "To (exclusive)"), end, h("label", {}, cases, " include each case record"), h("p", {}, h("button", { type: "submit" }, "Download signed audit pack")));
  show(h("h1", {}, "Audit pack"), h("p", { class: "muted" }, "A signed zip for the period: requests, certificates with a full chain check, rights metrics, SLA findings and case records."), form);
};

views.gateway = async () => {
  let rep;
  try { rep = await api("/v1/gateway/report"); } catch (e) { if (e.status === 404) return show(h("h1", {}, "Model gateway"), h("p", { class: "muted" }, "The gateway is not enabled.")); throw e; }
  const block = (title, o) => [h("h2", {}, title), kv(Object.entries(o || {}).map(([k, n]) => [k, String(n)]))];
  show(h("h1", {}, "Model gateway"),
    h("div", { class: "grid" }, [["Requests", rep.requests], ["With personal data", rep.with_personal_data_pct + "%"], ["Person identified", rep.person_identified_pct + "%"]]
      .map(([k, n]) => h("div", { class: "tile" }, h("div", { class: "muted" }, k), h("div", { class: "n" }, n)))),
    h("p", { class: "muted" }, `From ${fmt(rep.from)} to ${fmt(rep.to)}. Counts only; the gateway never records values.`),
    h("div", { class: "row" }, h("div", { class: "panel" }, block("Kinds of personal data", rep.entity_types), block("By purpose", rep.by_purpose)),
      h("div", { class: "panel" }, block("Decisions", rep.decisions), block("What enforce mode would decide", rep.would_have_decided), block("By model", rep.by_model))));
};

// ---- routing ----------------------------------------------------------------------------------------------------------
const ROUTES = [[/^#\/?$/, ""], [/^#\/signin$/, "signin"], [/^#\/signoff$/, "signoff"], [/^#\/case\/([^/?]+)$/, "case"],
  [/^#\/rights$/, "rights"], [/^#\/rights\/([^/?]+)$/, "rights-case"], [/^#\/person$/, "person"], [/^#\/breaches$/, "breaches"],
  [/^#\/breach\/([^/?]+)$/, "breach"], [/^#\/audit$/, "audit"], [/^#\/gateway$/, "gateway"]];

function renderWho() {
  const c = creds();
  document.getElementById("who").textContent = c ? (c.kind === "dev" ? "acting as " + c.value : "signed in") : "";
  document.getElementById("signin-link").textContent = c ? "Change" : "Sign in";
}

async function route() {
  renderWho();
  const raw = location.hash || "#/";
  const [path, query] = raw.split("?");
  const qs = new URLSearchParams(query || "");
  document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active", raw.startsWith(a.getAttribute("href")) && (a.getAttribute("href") !== "#/" || path === "#/" || path === "#")));
  if (!creds() && path !== "#/signin") { location.hash = "#/signin"; return; }
  for (const [re, name] of ROUTES) {
    const m = path.match(re);
    if (m) { show(h("p", { class: "muted" }, "Loading…")); return guard(() => views[name](m.slice(1).map(decodeURIComponent), qs)); }
  }
  show(h("p", {}, "Not found. ", h("a", { href: "#/" }, "Overview")));
}

window.addEventListener("hashchange", route);
route();
