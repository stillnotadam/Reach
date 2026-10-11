"""A self-contained HTML report for `reach audit --html`.

One file, no network: the audit is embedded as JSON and drawn by a small script, so the page opens anywhere
(an email attachment, a CI artifact, a ticket) and handles thousands of principals. Every string in it comes
from policies someone else wrote, so the data is never parsed as HTML: all of it, file names included, sits in
one JSON script block with `<` escaped, and the page builds the DOM with textContent only.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .audit import Report

SCOPE = (
    "ALLOWED comes with a witness: a concrete request, re-checked by a second, solver-free evaluator, and the "
    "statements that allow it. DENIED is a proof over the policies in the snapshot: identity policies, "
    "permissions boundaries, role trust policies, and any SCPs, RCPs and session policies given. Bucket, key "
    "and other resource policies are not in an IAM snapshot, and roles in other accounts are not checked. "
    "UNKNOWN names what the answer depends on."
)


def _answer(a: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"v": a["verdict"]}
    for key, short in (("witness", "w"), ("grants", "g"), ("assumptions", "as"), ("reasons", "r"), ("error", "e")):
        if a.get(key):
            out[short] = a[key]
    return out


def payload(report: Report, authz: str = "authz.json", notes: list[str] | None = None) -> dict[str, Any]:
    data = asdict(report)
    accounts = sorted({r.principal.split(":")[4] for r in report.rows if r.principal.count(":") >= 5})
    return {
        "meta": {
            "version": __version__,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "accounts": accounts,
            "seconds": round(report.seconds, 2),
            "workers": report.workers,
            "authz": authz,
            "scope": SCOPE,
            "notes": notes or [],
        },
        "questions": [list(q) for q in report.questions],
        "rows": [{"p": r["principal"], "k": r["kind"], "a": [_answer(a) for a in r["answers"]]} for r in data["rows"]],
    }


def to_html(report: Report, authz: str = "authz.json", notes: list[str] | None = None) -> str:
    data = json.dumps(payload(report, authz, notes), separators=(",", ":"), ensure_ascii=False)
    # Inside <script>, only "</" and "<!--" can end the block early; escaping every "<" covers both.
    data = data.replace("<", "\\u003c")
    return _PAGE.replace("__DATA__", data)


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reach audit</title>
<style>
:root {
  --bg: #f7f7f5; --panel: #ffffff; --ink: #1c1d1f; --muted: #6a6d73; --line: #e2e2de;
  --allow: #c62f2f; --allow-bg: #fbe6e4; --deny: #2f7d4f; --deny-bg: #eef5f0;
  --unknown: #9a6a00; --unknown-bg: #fdf3d8; --error: #6a3fb3; --error-bg: #efe8fb;
  --accent: #2b59c3; --mono: ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #111214; --panel: #1a1b1e; --ink: #e8e8e6; --muted: #9a9ca3; --line: #2c2e33;
    --allow: #ff7a70; --allow-bg: #3a1d1c; --deny: #6cc492; --deny-bg: #16251c;
    --unknown: #f0c35a; --unknown-bg: #33290f; --error: #b99af0; --error-bg: #2a2140;
    --accent: #8fb0ff; color-scheme: dark;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
header, main, footer { max-width: 1400px; margin: 0 auto; padding: 0 16px; }
header { padding-top: 28px; }
h1 { font-size: 22px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 15px; margin: 28px 0 10px; }
.sub { color: var(--muted); }
code, .mono { font-family: var(--mono); font-size: 12.5px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 20px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.tile b { display: block; font-size: 22px; font-variant-numeric: tabular-nums; }
.tile span { color: var(--muted); font-size: 12.5px; }
.tile.allow b { color: var(--allow); } .tile.unknown b { color: var(--unknown); }
.who { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 8px; }
.q { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px;
  text-align: left; color: inherit; font: inherit; cursor: pointer; }
.q:hover, .q[aria-pressed="true"] { border-color: var(--accent); }
.q .t { display: flex; justify-content: space-between; gap: 8px; }
.q .n { font-variant-numeric: tabular-nums; color: var(--allow); font-weight: 600; }
.q .n.zero { color: var(--deny); }
.bar { height: 6px; background: var(--deny-bg); border-radius: 3px; margin-top: 8px; overflow: hidden; display: flex; }
.bar i { display: block; height: 100%; }
.bar .a { background: var(--allow); } .bar .u { background: var(--unknown); }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 10px; }
.controls input[type=search], .controls select { font: inherit; padding: 6px 10px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--panel); color: inherit; }
.controls input[type=search] { flex: 1 1 240px; min-width: 0; }
.wrap { overflow: auto; max-height: 75vh; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
table { border-collapse: separate; border-spacing: 0; width: 100%; }
th, td { padding: 6px 8px; border-bottom: 1px solid var(--line); white-space: nowrap; }
thead th { position: sticky; top: 0; background: var(--panel); z-index: 2; font-weight: 600; font-size: 12.5px;
  text-align: center; vertical-align: bottom; }
thead th:first-child, tbody th { position: sticky; left: 0; background: var(--panel); z-index: 1; text-align: left; }
thead th:first-child { z-index: 3; }
tbody th { font-weight: 400; max-width: 360px; overflow: hidden; text-overflow: ellipsis; }
.kind { font-size: 11px; color: var(--muted); border: 1px solid var(--line); border-radius: 4px; padding: 0 4px; margin-right: 6px; }
td { text-align: center; padding: 3px; }
.cell { width: 100%; min-width: 64px; border: 0; border-radius: 6px; padding: 4px 6px; font: 600 12px/1.4 var(--mono);
  cursor: pointer; }
.cell.allowed { background: var(--allow-bg); color: var(--allow); }
.cell.denied { background: transparent; color: var(--muted); font-weight: 400; }
.cell.unknown { background: var(--unknown-bg); color: var(--unknown); }
.cell.error { background: var(--error-bg); color: var(--error); }
.cell:focus-visible, .q:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.more { margin: 10px 0; font: inherit; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--line);
  background: var(--panel); color: inherit; cursor: pointer; }
dialog { width: min(760px, calc(100vw - 32px)); border: 1px solid var(--line); border-radius: 12px;
  background: var(--panel); color: var(--ink); padding: 0; }
dialog::backdrop { background: rgb(0 0 0 / 0.45); }
.dh { display: flex; justify-content: space-between; gap: 12px; padding: 16px 18px; border-bottom: 1px solid var(--line); }
.dh h3 { margin: 0; font-size: 16px; }
.db { padding: 6px 18px 18px; max-height: 70vh; overflow: auto; }
.db h4 { margin: 16px 0 6px; font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
.db table td, .db table th { text-align: left; white-space: normal; word-break: break-all; padding: 4px 8px; }
.db ul { margin: 0; padding-left: 18px; }
.badge { display: inline-block; font: 600 12px var(--mono); padding: 2px 8px; border-radius: 6px; }
.badge.allowed { background: var(--allow-bg); color: var(--allow); }
.badge.denied { background: var(--deny-bg); color: var(--deny); }
.badge.unknown { background: var(--unknown-bg); color: var(--unknown); }
.badge.error { background: var(--error-bg); color: var(--error); }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 10px; overflow: auto;
  font: 12px/1.5 var(--mono); margin: 0; white-space: pre-wrap; word-break: break-all; }
.close { border: 0; background: none; color: var(--muted); font-size: 20px; cursor: pointer; line-height: 1; }
footer { color: var(--muted); font-size: 12.5px; padding-top: 18px; padding-bottom: 40px; }
footer p { max-width: 900px; }
.legend { display: flex; flex-wrap: wrap; gap: 12px; color: var(--muted); font-size: 12.5px; }
</style>
</head>
<body>
<header>
  <h1>Reach audit</h1>
  <div class="sub" id="sub"></div>
  <div class="tiles" id="tiles"></div>
</header>
<main>
  <h2>Who can</h2>
  <div class="who" id="who"></div>
  <h2>Access matrix</h2>
  <div class="controls">
    <input type="search" id="filter" placeholder="Filter principals" aria-label="Filter principals">
    <select id="kind" aria-label="Principal kind">
      <option value="">Users and roles</option><option value="user">Users</option><option value="role">Roles</option>
    </select>
    <select id="sort" aria-label="Sort">
      <option value="risk">Most reach first</option><option value="name">By name</option>
    </select>
    <label><input type="checkbox" id="onlyAllowed"> Only principals with a proven ALLOWED</label>
  </div>
  <div class="legend">
    <span><span class="badge allowed">ALLOW</span> proven, with a witness</span>
    <span><span class="badge denied">-</span> proven denied</span>
    <span><span class="badge unknown">?</span> depends on something not modelled</span>
    <span><span class="badge error">ERR</span> could not be decided</span>
  </div>
  <p class="sub" id="count"></p>
  <div class="wrap"><table id="matrix"><thead></thead><tbody></tbody></table></div>
  <button class="more" id="more" hidden>Show more</button>
</main>
<footer><p id="scope"></p><p id="notes"></p></footer>
<dialog id="detail" aria-labelledby="dtitle">
  <div class="dh"><div><h3 id="dtitle"></h3><div class="sub mono" id="dsub"></div></div>
  <button class="close" id="dclose" aria-label="Close">&times;</button></div>
  <div class="db" id="dbody"></div>
</dialog>
<script type="application/json" id="data">__DATA__</script>
<script>
"use strict";
const D = JSON.parse(document.getElementById("data").textContent);
const CELL = { allowed: "ALLOW", denied: "-", unknown: "?", error: "ERR" };
const PAGE = 400;
const $ = (id) => document.getElementById(id);
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids) if (k !== null && k !== undefined) e.append(k instanceof Node ? k : String(k));
  return e;
}
const short = (arn) => arn.split(":").slice(5).join(":") || arn;
const q = (s) => /^[A-Za-z0-9_\-.:\/*@=+,]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'";

const rows = D.rows.map((r) => ({ ...r, score: r.a.filter((a) => a.v === "allowed").length,
  unk: r.a.filter((a) => a.v === "unknown").length }));
const total = (v) => rows.reduce((n, r) => n + r.a.filter((a) => a.v === v).length, 0);
const decisions = rows.reduce((n, r) => n + r.a.length, 0);

const m = D.meta;
$("sub").textContent = `${m.accounts.length ? "Account " + m.accounts.join(", ") + " · " : ""}` +
  `generated ${m.generated} by reach ${m.version} · ${decisions} decisions in ${m.seconds} s on ${m.workers} worker(s)`;
const tiles = [["Principals", rows.length], ["Decisions", decisions], ["Proven ALLOWED", total("allowed"), "allow"],
  ["UNKNOWN", total("unknown"), "unknown"], ["Principals with reach", rows.filter((r) => r.score).length, "allow"]];
if (total("error")) tiles.push(["Errors", total("error"), "unknown"]);
for (const [label, n, cls] of tiles) $("tiles").append(el("div", { class: "tile " + (cls || "") }, el("b", {}, n), el("span", {}, label)));
$("scope").textContent = m.scope;
$("notes").textContent = m.notes.join(" ");

let focus = -1; // question index the matrix is filtered to, or -1
D.questions.forEach(([label, action, resource], i) => {
  const allowed = rows.filter((r) => r.a[i] && r.a[i].v === "allowed").length;
  const unknown = rows.filter((r) => r.a[i] && r.a[i].v === "unknown").length;
  const pct = (n) => rows.length ? (100 * n / rows.length).toFixed(2) + "%" : "0";
  const bar = el("div", { class: "bar" }, el("i", { class: "a", style: "width:" + pct(allowed) }),
    el("i", { class: "u", style: "width:" + pct(unknown) }));
  const btn = el("button", { class: "q", "aria-pressed": "false", title: `${action} on ${resource}`,
    onclick: () => { focus = focus === i ? -1 : i; document.querySelectorAll(".q").forEach((b, j) =>
      b.setAttribute("aria-pressed", String(j === focus))); draw(); } },
    el("div", { class: "t" }, el("span", {}, label), el("span", { class: "n" + (allowed ? "" : " zero") }, allowed)),
    el("div", { class: "sub mono" }, action, unknown ? ` · ${unknown} unknown` : ""), bar);
  $("who").append(btn);
});

const thead = $("matrix").tHead;
const hr = el("tr", {}, el("th", { scope: "col" }, "Principal"));
for (const [label, action] of D.questions) hr.append(el("th", { scope: "col", title: action }, label));
thead.append(hr);

let shown = PAGE, current = [];
function filtered() {
  const text = $("filter").value.trim().toLowerCase(), kind = $("kind").value, only = $("onlyAllowed").checked;
  let out = rows.filter((r) => (!text || r.p.toLowerCase().includes(text)) && (!kind || r.k === kind) &&
    (!only || r.score) && (focus < 0 || (r.a[focus] && r.a[focus].v !== "denied")));
  out.sort($("sort").value === "name" ? (a, b) => a.p.localeCompare(b.p)
    : (a, b) => b.score - a.score || b.unk - a.unk || a.p.localeCompare(b.p));
  return out;
}
function draw() {
  current = filtered();
  const body = $("matrix").tBodies[0];
  body.replaceChildren();
  const frag = document.createDocumentFragment();
  for (const r of current.slice(0, shown)) {
    const tr = el("tr", {}, el("th", { scope: "row", title: r.p }, el("span", { class: "kind" }, r.k), short(r.p)));
    r.a.forEach((a, i) => tr.append(el("td", {}, el("button", { class: "cell " + a.v,
      "aria-label": `${short(r.p)}: ${D.questions[i][0]}: ${a.v}`, onclick: () => show(r, i) }, CELL[a.v] || a.v))));
    frag.append(tr);
  }
  body.append(frag);
  $("count").textContent = `${current.length} of ${rows.length} principals` +
    (focus >= 0 ? ` that are not denied "${D.questions[focus][0]}"` : "");
  $("more").hidden = current.length <= shown;
  $("more").textContent = `Show ${Math.min(PAGE, current.length - shown)} more`;
}
$("more").addEventListener("click", () => { shown += PAGE; draw(); });
for (const id of ["filter", "kind", "sort", "onlyAllowed"]) $(id).addEventListener("input", () => { shown = PAGE; draw(); });

function section(title, node) { return [el("h4", {}, title), node]; }
function list(items) { return el("ul", {}, ...items.map((t) => el("li", {}, t))); }
function show(r, i) {
  const a = r.a[i], [label, action, resource] = D.questions[i];
  $("dtitle").replaceChildren(el("span", { class: "badge " + a.v }, a.v.toUpperCase()), " ", label);
  $("dsub").textContent = r.p;
  const body = [];
  body.push(...section("Question", el("div", { class: "mono" }, `${action} on ${resource}`)));
  if (a.w) {
    const t = el("table", {}, el("tr", {}, el("th", {}, "action"), el("td", { class: "mono" }, a.w.action)),
      el("tr", {}, el("th", {}, "resource"), el("td", { class: "mono" }, a.w.resource)));
    for (const [k, v] of Object.entries(a.w.context || {}).sort())
      t.append(el("tr", {}, el("th", { class: "mono" }, k), el("td", { class: "mono" }, v === null ? "absent" : JSON.stringify(v))));
    body.push(...section(a.v === "allowed" ? "Witness request (allowed)" : "Request that would be allowed", t));
  }
  if (a.g && a.g.length) body.push(...section("Allowed by", list(a.g)));
  if (a.v === "denied") body.push(...section("Proof", el("div", {}, "No request context satisfies the policies (UNSAT).")));
  if (a.r && a.r.length) body.push(...section("Why", list(a.r)));
  if (a.as && a.as.length) body.push(...section("Depends on", list(a.as)));
  if (a.e) body.push(...section("Error", el("pre", {}, a.e)));
  // The witness itself, pinned: the same verdict for exactly this request.
  const parts = ["reach can --authz", q(D.meta.authz), "--principal", q(r.p)];
  for (const [k, v] of Object.entries((a.w && a.w.context) || {}).sort())
    parts.push(v === null ? `--absent ${q(k)}` : `--context ${q(k + "=" + (Array.isArray(v) ? JSON.stringify(v) : v))}`);
  parts.push(q(a.w ? a.w.action : action), q(a.w ? a.w.resource : resource));
  const cmd = parts.join(" ");
  body.push(...section("Reproduce", el("pre", {}, cmd)));
  $("dbody").replaceChildren(...body);
  $("detail").showModal();
}
$("dclose").addEventListener("click", () => $("detail").close());
$("detail").addEventListener("click", (e) => { if (e.target === $("detail")) $("detail").close(); });
draw();
</script>
</body>
</html>
"""
