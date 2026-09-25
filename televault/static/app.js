/* TeleVault single-page UI. No framework, no build step.
   All mutating requests carry X-Requested-With (CSRF guard) and rely on the
   HttpOnly session cookie. Nothing here can delete a recording: the API has no such route. */
"use strict";

const $ = (sel, el = document) => el.querySelector(sel);
const h = (tag, attrs = {}, ...children) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) el.setAttribute(k, v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined) el.append(c.nodeType ? c : String(c));
  return el;
};

const setKids = (el, ...kids) => el.replaceChildren(...kids.flat().filter(k => k !== null && k !== undefined));

const state = { me: null, view: "recordings", customerId: null, customers: [], page: 1, filters: {}, playing: null };

async function api(path, { method = "GET", body, raw = false, _retried = false } = {}) {
  const opts = { method, headers: { "X-Requested-With": "TeleVault" }, credentials: "same-origin" };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  if (raw) return r;
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (!r.ok) {
    if (r.status === 401 && state.me) { state.me = null; render(); }
    // Sensitive admin action: re-confirm with a fresh authenticator code, then retry once.
    if (r.status === 403 && data && data.detail === "step_up_required" && !_retried) {
      await stepUp();
      return api(path, { method, body, raw, _retried: true });
    }
    throw new Error((data && data.detail) || `${r.status} ${r.statusText}`);
  }
  return data;
}

function stepUp() {
  return new Promise((resolve, reject) => {
    const err = h("p", { class: "error", role: "alert" });
    const code = h("input", { inputmode: "numeric", autocomplete: "one-time-code", maxlength: "7", required: "",
      placeholder: "123 456", class: "mfa-code", "aria-label": "6-digit code" });
    let done = false;
    const form = h("form", { class: "stepup", method: "dialog" },
      h("h2", {}, "Confirm it's you"),
      h("p", { class: "muted" }, "This change needs a fresh code from Microsoft Authenticator."),
      code, err,
      h("div", { class: "row picker-foot" },
        h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("button", { class: "btn primary", type: "submit" }, "Confirm")));
    const dlg = h("dialog", { class: "picker stepup-dialog", "aria-label": "Confirm with authenticator" }, form);
    form.addEventListener("submit", async (e) => {
      e.preventDefault(); err.textContent = "";
      try { await api("/api/auth/mfa/verify", { method: "POST", body: { code: code.value } }); done = true; dlg.close(); resolve(); }
      catch (x) { err.textContent = x.message; code.value = ""; code.focus(); }
    });
    dlg.addEventListener("close", () => { dlg.remove(); if (!done) reject(new Error("Cancelled — the change was not made.")); });
    document.body.append(dlg); dlg.showModal(); code.focus();
  });
}

function toast(msg, err = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : ""); t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.hidden = true), err ? 6000 : 3000);
}
const fmtBytes = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(0)} KB` : n < 1073741824 ? `${(n/1048576).toFixed(1)} MB` : `${(n/1073741824).toFixed(2)} GB`;
const fmtTs = (s) => s ? s.replace("T", " ") : "";
const isAdmin = () => state.me && (state.me.role === "superadmin" || state.me.role === "customer_admin");

/* Branding is optional: logos live in static/brand/ (not part of the public code). Hide the
   image cleanly when there is none. (Inline onerror handlers are blocked by the CSP.) */
for (const img of document.querySelectorAll("img.brand-logo, .login-brand img")) {
  const hide = () => { img.hidden = true; };
  if (img.complete && img.naturalWidth === 0) hide(); else img.addEventListener("error", hide);
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  try { state.me = await api("/api/auth/me"); } catch { state.me = null; }
  render();
}

function render() {
  const app = $("#app"), login = $("#login");
  if (!state.me) { app.hidden = true; login.hidden = false; $("#login-error").textContent = ""; $("#login-form input[name=username]").focus(); return; }
  login.hidden = true; app.hidden = false;
  $("#who-name").textContent = state.me.username;
  $("#who-scope").textContent = state.me.role === "superadmin" ? "Staff"
    : state.me.customer ? `${state.me.customer.name}${state.me.departments.length ? " · " + state.me.departments.map(d => d.name).join(", ") : ""}` : "";
  const main = $("#main"); main.replaceChildren();
  // Mandatory second factor: nothing else is reachable (server-side too) until it passes.
  if (!state.me.mfa_ok) { $("#nav").replaceChildren(); viewMfa(main); return; }
  if (state.me.must_change_password) { state.view = "password"; }
  renderNav();
  const views = { recordings: viewRecordings, password: viewPassword, customers: viewCustomers, departments: viewDepartments, users: viewUsers, staff: viewStaffAccess, dev: viewDevAccess, audit: viewAudit };
  (views[state.view] || viewRecordings)(main);
}

function renderNav() {
  const items = [["recordings", "Recordings"]];
  if (isAdmin() && !state.me.must_change_password) {
    if (state.me.role === "superadmin") items.push(["customers", "Customers"]);
    items.push(["departments", "Departments"], ["users", "Users"]);
    if (state.me.role === "superadmin") items.push(["staff", "Staff access"], ["dev", "Developer access"]);
    items.push(["audit", "Audit log"]);
  }
  items.push(["password", "Password"]);
  $("#nav").replaceChildren(...items.map(([k, label]) =>
    h("button", { type: "button", class: state.view === k ? "active" : "", onclick: () => { if (state.me.must_change_password && k !== "password") return toast("Change your password first.", true); state.view = k; state.page = 1; render(); } }, label)));
}

/* ------------------------------------------------------------------ login */
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target; $("#login-error").textContent = "";
  try {
    state.me = await api("/api/auth/login", { method: "POST", body: { username: f.username.value.trim(), password: f.password.value } });
    f.reset(); state.view = "recordings"; render();
  } catch (err) { $("#login-error").textContent = err.message; }
});
$("#btn-logout").addEventListener("click", async () => { try { await api("/api/auth/logout", { method: "POST" }); } catch {} state.me = null; stopPlayer(); render(); });

/* ------------------------------------------------------------------ MFA */
async function viewMfa(main) {
  const err = h("p", { class: "error", role: "alert" });
  const code = h("input", { name: "code", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}",
    maxlength: "7", required: "", placeholder: "123 456", class: "mfa-code", "aria-label": "6-digit code" });
  const form = h("form", { class: "mfa-form" },
    h("label", {}, "6-digit code from Microsoft Authenticator", code),
    h("button", { class: "btn primary", type: "submit" }, state.me.mfa_enrolled ? "Verify" : "Confirm and continue"), err);
  form.addEventListener("submit", async (e) => {
    e.preventDefault(); err.textContent = "";
    const btn = form.querySelector("button"); btn.disabled = true;
    try {
      const r = await api("/api/auth/mfa/verify", { method: "POST", body: { code: code.value } });
      state.me = await api("/api/auth/me");
      if (r.enrolled) toast("Microsoft Authenticator is now linked to your account.");
      state.view = "recordings"; render();
    } catch (x) { err.textContent = x.message; code.value = ""; code.focus(); btn.disabled = false; }
  });

  if (state.me.mfa_enrolled) {
    main.append(h("div", { class: "card login-card mfa-card" },
      h("h2", {}, "Two-step verification"),
      h("p", { class: "muted" }, "Open Microsoft Authenticator on your phone and enter the current code for ", h("b", {}, "TeleVault"), "."),
      form,
      h("p", { class: "muted small" }, "Lost your phone? Ask your administrator to reset your authenticator.")));
    code.focus();
    return;
  }

  const card = h("div", { class: "card mfa-card mfa-setup" }, h("h2", {}, "Set up two-step verification"), h("p", { class: "muted" }, "Loading…"));
  main.append(card);
  try {
    const s = await api("/api/auth/mfa/setup", { method: "POST" });
    setKids(card,
      h("h2", {}, "Set up two-step verification"),
      h("p", { class: "muted" }, "Two-step verification is required for every TeleVault account. It takes about a minute."),
      h("div", { class: "mfa-grid" },
        h("ol", { class: "mfa-steps" },
          h("li", {}, "Install ", h("b", {}, "Microsoft Authenticator"), " on your phone from the App Store or Google Play."),
          h("li", {}, "In the app tap ", h("b", {}, "+"), " → ", h("b", {}, "Other account (Google, Facebook, etc.)"), "."),
          h("li", {}, "Scan the QR code. The account appears as ", h("b", {}, s.issuer), "."),
          h("li", {}, "Type the 6-digit code the app shows.")),
        h("figure", { class: "mfa-qr" }, h("img", { src: s.qr, alt: "QR code to add TeleVault to Microsoft Authenticator", width: "220", height: "220" }),
          h("figcaption", { class: "muted" }, s.account))),
      h("details", { class: "mfa-manual" }, h("summary", {}, "Can't scan? Enter the key manually"),
        h("p", { class: "muted" }, "In the app choose ", h("b", {}, "Other account"), " → ", h("b", {}, "Or enter code manually"), ", account name ", h("b", {}, s.issuer), ", key:"),
        h("div", { class: "secret" }, s.secret)),
      form);
    code.focus();
  } catch (x) { setKids(card, h("h2", {}, "Set up two-step verification"), h("p", { class: "error" }, x.message)); }
}

/* ------------------------------------------------------------------ password */
function viewPassword(main) {
  const form = h("form", { class: "card login-card", autocomplete: "off" },
    h("h2", {}, state.me.must_change_password ? "Set a new password to continue" : "Change password"),
    h("label", {}, "Current password", h("input", { name: "cur", type: "password", autocomplete: "current-password", required: "" })),
    h("label", {}, "New password (12+ chars, mixed)", h("input", { name: "nw", type: "password", autocomplete: "new-password", required: "", minlength: "12" })),
    h("label", {}, "Repeat new password", h("input", { name: "nw2", type: "password", autocomplete: "new-password", required: "" })),
    h("button", { class: "btn primary", type: "submit" }, "Update password"),
    h("p", { class: "error", id: "pw-error" }));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (form.nw.value !== form.nw2.value) { $("#pw-error").textContent = "Passwords do not match."; return; }
    try {
      await api("/api/auth/change-password", { method: "POST", body: { current_password: form.cur.value, new_password: form.nw.value } });
      state.me.must_change_password = false; toast("Password updated."); state.view = "recordings"; render();
    } catch (err) { $("#pw-error").textContent = err.message; }
  });
  main.append(form);
}

/* ------------------------------------------------------------------ recordings */
async function customerPicker(onchange) {
  if (state.me.role !== "superadmin") return null;
  if (!state.customers.length) state.customers = await api("/api/admin/customers");
  if (state.customerId === null && state.customers.length) state.customerId = state.customers[0].id;
  const sel = h("select", { onchange: (e) => { state.customerId = Number(e.target.value); state.page = 1; onchange(); } },
    ...state.customers.map(c => h("option", { value: c.id, selected: c.id === state.customerId ? "" : null }, `${c.name} (${c.slug})${c.online ? "" : " — offline"}`)));
  return h("label", {}, "Customer", sel);
}

async function viewRecordings(main) {
  const picker = await customerPicker(() => viewRecordings(main));
  const f = state.filters;
  const filterRow = h("div", { class: "row" },
    picker,
    h("label", {}, "From", h("input", { type: "date", name: "date_from", value: f.date_from || "" })),
    h("label", {}, "To", h("input", { type: "date", name: "date_to", value: f.date_to || "" })),
    h("label", {}, "Type", h("select", { name: "type" }, ...[["", "Any"], ["in", "Inbound"], ["out", "Outbound"], ["q", "Queue"], ["external", "External"], ["exten", "To extension"], ["internal", "Internal"], ["unknown", "Unparsed"]].map(([v, l]) => h("option", { value: v, selected: (f.type || "") === v ? "" : null }, l)))),
    h("label", {}, "Extension", h("input", { name: "ext", value: f.ext || "", placeholder: "e.g. 436", inputmode: "numeric" })),
    h("label", {}, "Number contains", h("input", { name: "number", value: f.number || "", placeholder: "caller / DID / dialled", inputmode: "numeric" })),
    h("label", { class: "grow" }, "Filename contains", h("input", { name: "q", value: f.q || "" })),
    h("label", {}, h("span", {}, "\u00a0"), h("span", { class: "chip" }, h("input", { type: "checkbox", name: "include_empty", checked: f.include_empty ? "" : null }), " show empty (no audio)")),
    h("button", { class: "btn primary", type: "button", onclick: applyFilters }, "Search"),
    h("button", { class: "btn", type: "button", onclick: () => { state.filters = {}; state.page = 1; viewRecordings(main); } }, "Clear"));

  function readFilters() {
    const g = (n) => filterRow.querySelector(`[name=${n}]`);
    return { date_from: g("date_from").value, date_to: g("date_to").value, type: g("type").value, ext: g("ext").value.trim(), number: g("number").value.trim(), q: g("q").value.trim(), include_empty: g("include_empty").checked };
  }
  function applyFilters() { state.filters = readFilters(); state.page = 1; loadList(); }
  filterRow.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); applyFilters(); } });

  const summaryEl = h("div", { class: "chips" });
  const tableWrap = h("div", { class: "table-wrap" });
  const pager = h("div", { class: "pager" });
  const bulk = h("div", { class: "row" },
    h("button", { class: "btn", type: "button", onclick: () => zipSelected() }, "Download selected as zip"),
    h("button", { class: "btn", type: "button", onclick: () => zipFiltered() }, "Download all matching as zip"),
    h("span", { class: "muted", id: "sel-count" }, ""));
  main.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Recordings"), summaryEl),
    h("div", { class: "card" }, filterRow),
    h("div", { class: "card" }, tableWrap, pager, bulk),
    playerEl());

  function query() {
    const p = new URLSearchParams();
    if (state.me.role === "superadmin" && state.customerId) p.set("customer_id", state.customerId);
    for (const [k, v] of Object.entries(state.filters)) if (v) p.set(k, v === true ? "true" : v);
    return p;
  }

  async function loadSummary() {
    try {
      const p = new URLSearchParams(); if (state.me.role === "superadmin" && state.customerId) p.set("customer_id", state.customerId);
      const s = await api(`/api/recordings/summary?${p}`);
      const chips = [h("span", { class: "chip" }, h("b", {}, s.count.toLocaleString()), " files · ", fmtBytes(s.bytes))];
      if (s.first) chips.push(h("span", { class: "chip" }, fmtTs(s.first).slice(0, 10), " → ", fmtTs(s.last).slice(0, 10)));
      for (const t of s.by_type) chips.push(h("span", { class: "chip" }, h("span", { class: `badge ${t.type}` }, t.type), ` ${t.count.toLocaleString()}`, t.empty ? h("span", { class: "tag-empty" }, ` (${t.empty} empty)`) : ""));
      if (s.drive) chips.push(h("span", { class: "chip" }, "Drive ", h("b", { class: s.drive.online ? "ok" : "error" }, s.drive.online ? "online" : "OFFLINE"), ` ${s.drive.root}`));
      if (s.last_index) chips.push(h("span", { class: "chip muted" }, `indexed ${fmtTs(s.last_index.finished_at || s.last_index.started_at)} (${s.last_index.status})`));
      summaryEl.replaceChildren(...chips);
    } catch (e) { summaryEl.replaceChildren(h("span", { class: "error" }, e.message)); }
  }

  async function loadList() {
    tableWrap.replaceChildren(h("p", { class: "muted" }, "Loading…"));
    try {
      const p = query(); p.set("page", state.page);
      const data = await api(`/api/recordings?${p}`);
      const rows = data.items.map(r => h("tr", { "data-id": r.id },
        h("td", {}, h("input", { type: "checkbox", class: "sel", value: r.id, onchange: updateSel })),
        h("td", { class: "mono" }, fmtTs(r.ts)),
        h("td", {}, h("span", { class: `badge ${r.type}` }, r.type)),
        h("td", { class: "mono" }, r.target),
        h("td", { class: "mono" }, r.party),
        h("td", {}, r.empty ? h("span", { class: "tag-empty" }, "empty") : fmtBytes(r.size)),
        h("td", { class: "mono", title: r.path }, r.filename),
        h("td", { class: "actions" },
          h("button", { class: "btn small", type: "button", disabled: r.empty ? "" : null, onclick: () => play(r) }, "▶ Play"),
          h("a", { class: "btn small", href: `/api/recordings/${r.id}/download`, download: r.filename }, "Download"))));
      const table = h("table", {}, h("thead", {}, h("tr", {},
        h("th", {}, h("input", { type: "checkbox", onchange: (e) => { tableWrap.querySelectorAll(".sel").forEach(c => c.checked = e.target.checked); updateSel(); } })),
        h("th", {}, "Time"), h("th", {}, "Type"), h("th", {}, "Target / DID / Queue"), h("th", {}, "Extension / Party"), h("th", {}, "Size"), h("th", {}, "File"), h("th", {}, ""))),
        h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: "8", class: "muted" }, "No recordings match."))));
      tableWrap.replaceChildren(table);
      const pages = Math.max(1, Math.ceil(data.total / data.page_size));
      pager.replaceChildren(
        h("span", { class: "muted" }, `${data.total.toLocaleString()} matching · ${fmtBytes(data.total_bytes)}`),
        h("button", { class: "btn small", type: "button", disabled: state.page <= 1 ? "" : null, onclick: () => { state.page--; loadList(); } }, "‹ Prev"),
        h("span", {}, `Page ${data.page} / ${pages}`),
        h("button", { class: "btn small", type: "button", disabled: state.page >= pages ? "" : null, onclick: () => { state.page++; loadList(); } }, "Next ›"));
      updateSel();
    } catch (e) { tableWrap.replaceChildren(h("p", { class: "error" }, e.message)); }
  }
  function selected() { return [...tableWrap.querySelectorAll(".sel:checked")].map(c => Number(c.value)); }
  function updateSel() { const n = selected().length; $("#sel-count").textContent = n ? `${n} selected` : ""; }

  async function zipSelected() {
    const ids = selected(); if (!ids.length) return toast("Select some recordings first.", true);
    await downloadZip({ ids });
  }
  async function zipFiltered() {
    const f = { ...state.filters, customer_id: state.me.role === "superadmin" ? state.customerId : null };
    const body = { filters: { customer_id: f.customer_id, date_from: f.date_from || null, date_to: f.date_to || null, rec_type: f.type || null, ext: f.ext || null, number: f.number || null, q: f.q || null, include_empty: !!f.include_empty } };
    await downloadZip(body);
  }
  async function downloadZip(body) {
    toast("Preparing zip…");
    try {
      const r = await api("/api/recordings/zip", { method: "POST", body, raw: true });
      if (!r.ok) { let d = null; try { d = await r.json(); } catch {} throw new Error((d && d.detail) || r.statusText); }
      const blob = await r.blob();
      const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "televault.zip";
      const url = URL.createObjectURL(blob);
      const a = h("a", { href: url, download: name }); document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      toast(`Downloaded ${name}`);
    } catch (e) { toast(e.message, true); }
  }

  await loadSummary(); await loadList();
}

/* player */
function playerEl() {
  const el = h("div", { class: "player", id: "player", hidden: "" },
    h("span", { class: "fn", id: "player-fn" }), h("audio", { id: "player-audio", controls: "", preload: "none" }),
    h("button", { class: "btn ghost small", type: "button", onclick: stopPlayer }, "✕"));
  return el;
}
function play(r) {
  const p = $("#player"), a = $("#player-audio"); p.hidden = false;
  $("#player-fn").textContent = r.filename; a.src = `/api/recordings/${r.id}/stream`; a.play().catch(() => {});
}
function stopPlayer() { const a = $("#player-audio"); if (a) { a.pause(); a.removeAttribute("src"); a.load(); } const p = $("#player"); if (p) p.hidden = true; }

/* ------------------------------------------------------------------ admin: customers */
async function viewCustomers(main) {
  const list = await api("/api/admin/customers"); state.customers = list;
  const form = customerForm();
  main.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Customers · one storage drive per customer"),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ...["Name", "Slug", "Root path", "Drive", "Service access", "Files", "Last index", "Enabled", ""].map(t => h("th", {}, t)))),
        h("tbody", {}, ...list.map(c => h("tr", {},
          h("td", {}, c.name), h("td", { class: "mono" }, c.slug), h("td", { class: "mono" }, c.root_path),
          h("td", {}, h("b", { class: c.online ? "ok" : "error" }, c.online ? "online" : "OFFLINE")),
          h("td", {}, accessCell(c)),
          h("td", {}, c.recordings.toLocaleString()),
          h("td", { class: "muted" }, c.last_index ? `${fmtTs(c.last_index.finished_at || c.last_index.started_at)} · ${c.last_index.status}${c.last_index.message ? " · " + c.last_index.message : ""}` : "never"),
          h("td", {}, c.enabled ? "yes" : "no"),
          h("td", { class: "actions" },
            h("button", { class: "btn small", type: "button", onclick: () => customerForm(c, form) }, "Edit"),
            h("button", { class: "btn small", type: "button", onclick: async () => { try { await api(`/api/admin/customers/${c.id}/reindex`, { method: "POST" }); toast("Re-index queued."); } catch (e) { toast(e.message, true); } } }, "Re-index")))))))),
    h("div", { class: "card" }, form));
  // While a grant is waiting for the worker, refresh this page so the result shows up by itself.
  clearTimeout(viewCustomers._t);
  if (list.some(c => ["pending", "running"].includes(c.access?.grant?.status)))
    viewCustomers._t = setTimeout(() => { if (state.view === "customers" && !document.querySelector("dialog[open]")) render(); }, 15000);
}

/* Service-account access to a customer folder, and the button that requests it. The web app
   cannot change permissions itself; the SYSTEM grant worker applies requests within a minute. */
function accessCell(c) {
  const a = c.access; if (!a) return "";
  const g = a.grant;
  const grantBtn = (label) => h("button", { class: "btn small", type: "button", onclick: async () => {
    try { const r = await api(`/api/admin/customers/${c.id}/grant-access`, { method: "POST" });
      toast(r.queued ? "Requested. Read-only access is applied within about a minute." : "A request is already waiting."); render();
    } catch (x) { toast(x.message, true); } } }, label);
  if (g && ["pending", "running"].includes(g.status)) return h("span", { class: "muted" }, "granting… (applied within a minute)");
  if (!c.online) return h("span", { class: "muted" }, "drive offline");
  if (a.readable && a.protected) return h("span", { class: "ok", title: "Can read; write and delete are denied" }, "read-only ✓");
  const why = g && g.status === "error" ? h("div", { class: "error-inline" }, g.message) : null;
  if (a.readable && a.protected === false) return h("div", {}, h("span", { class: "warn-inline" }, "readable, not write-protected "), grantBtn("Make read-only"), why);
  if (!a.readable) return h("div", {}, h("span", { class: "error-inline" }, "no access "), grantBtn("Grant read-only access"), why);
  return h("span", { class: "muted" }, "unknown");
}

function customerForm(c = null, existing = null) {
  const form = existing || h("form", { class: "row" });
  setKids(form, 
    h("h2", { style: "width:100%" }, c ? `Edit ${c.name}` : "Add customer"),
    h("label", {}, "Slug", h("input", { name: "slug", value: c?.slug || "", required: "", pattern: "[a-z0-9][a-z0-9-]{1,31}", placeholder: "acme" })),
    h("label", { class: "grow" }, "Name", h("input", { name: "name", value: c?.name || "", required: "", placeholder: "Acme" })),
    h("label", { class: "grow" }, "Recording folder (drive and folder)",
      h("div", { class: "input-with-btn" },
        h("input", { name: "root_path", value: c?.root_path || "", required: "", placeholder: "D:\\  or  E:\\Recordings\\Acme", class: "mono" }),
        h("button", { class: "btn", type: "button", onclick: () => openFolderPicker(form.root_path.value.trim(), c?.id ?? null, (p) => { form.root_path.value = p; }) }, "Browse…"))),
    h("label", {}, "Enabled", h("select", { name: "enabled" }, h("option", { value: "1", selected: (c ? c.enabled : 1) ? "" : null }, "yes"), h("option", { value: "0", selected: c && !c.enabled ? "" : null }, "no"))),
    h("button", { class: "btn primary", type: "submit" }, c ? "Save" : "Add"),
    c ? h("button", { class: "btn", type: "button", onclick: () => customerForm(null, form) }, "Cancel") : null);
  form.onsubmit = async (e) => {
    e.preventDefault();
    const body = { slug: form.slug.value.trim(), name: form.name.value.trim(), root_path: form.root_path.value.trim(), enabled: form.enabled.value === "1" };
    try {
      if (c) await api(`/api/admin/customers/${c.id}`, { method: "PUT", body }); else await api("/api/admin/customers", { method: "POST", body });
      toast(c && c.root_path === body.root_path ? "Saved." : "Saved. Read-only access is applied within a minute, then indexing starts.");
      state.customers = []; render();
    } catch (err) { toast(err.message, true); }
  };
  return form;
}

/* Folder picker: lists drives, then folders. Directory names only — the API returns no files. */
function openFolderPicker(start, customerId, onPick) {
  const body = h("div", { class: "picker-body" });
  const crumb = h("div", { class: "picker-crumb mono" });
  const info = h("p", { class: "muted picker-info" });
  const useBtn = h("button", { class: "btn primary", type: "button", disabled: "" }, "Use this folder");
  const dlg = h("dialog", { class: "picker", "aria-label": "Choose recording folder" },
    h("div", { class: "picker-head" }, h("h2", {}, "Choose the customer's recording folder"),
      h("button", { class: "btn small", type: "button", onclick: () => dlg.close(), "aria-label": "Close" }, "✕")),
    crumb, body, info,
    h("div", { class: "row picker-foot" }, h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Cancel"), useBtn));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();

  let current = null;
  const others = (list) => list.filter(o => o.id !== customerId);
  const ownerNote = (x) => {
    const exact = others(x.assigned_to), ov = others(x.overlaps);
    if (exact.length) return h("span", { class: "error-inline" }, `used by ${exact.map(o => o.name).join(", ")}`);
    if (ov.length) return h("span", { class: "warn-inline" }, `overlaps ${ov.map(o => o.name).join(", ")}`);
    return null;
  };
  const row = (label, sub, onclick, note) => h("li", {},
    h("button", { type: "button", class: "picker-item", onclick }, h("span", { class: "picker-icon", "aria-hidden": "true" }, "▸"),
      h("span", { class: "grow" }, label, sub ? h("span", { class: "muted" }, ` ${sub}`) : null), note));

  async function showDrives() {
    current = null; useBtn.disabled = true; crumb.textContent = "This PC"; info.textContent = "";
    setKids(body, h("p", { class: "muted" }, "Loading drives…"));
    try {
      const drives = await api("/api/admin/fs/drives");
      setKids(body, h("ul", { class: "picker-list" }, ...drives.map(d =>
        row(d.path, `${d.label ? d.label + " · " : ""}${fmtBytes(d.total - d.free)} used of ${fmtBytes(d.total)}`, () => browse(d.path), ownerNote(d)))));
    } catch (e) { setKids(body, h("p", { class: "error" }, e.message)); }
  }

  async function browse(path) {
    setKids(body, h("p", { class: "muted" }, "Loading…"));
    try {
      const r = await api(`/api/admin/fs/browse?path=${encodeURIComponent(path)}`);
      current = r.path; crumb.textContent = r.path;
      const blocked = others(r.assigned_to).length || others(r.overlaps).length;
      useBtn.disabled = !!blocked;
      setKids(info,
        `${r.audio_files_here.toLocaleString()} recording file(s) directly in this folder · ${r.dirs.length.toLocaleString()} subfolder(s)${r.truncated ? " (first 1000 shown)" : ""}. `,
        blocked ? ownerNote(r) : "Recordings in all subfolders are included.");
      setKids(body, h("ul", { class: "picker-list" },
        row("..", r.parent ? "up one level" : "all drives", () => r.parent ? browse(r.parent) : showDrives()),
        ...r.dirs.map(d => row(d.name, "", () => browse(d.path), ownerNote(d)))));
    } catch (e) {
      if (/cannot read/i.test(e.message)) {
        // TeleVault has no rights here yet. It can still be chosen: saving the customer
        // requests read-only access, and the grant worker applies it.
        current = path; crumb.textContent = path; useBtn.disabled = false;
        setKids(info, "");
        setKids(body, h("p", { class: "muted picker-note" }, "TeleVault can't see inside this folder yet. You can still choose it: when you save the customer, read-only access is requested and applied within about a minute."),
          h("button", { class: "btn", type: "button", onclick: showDrives }, "Back to drives"));
        return;
      }
      current = null; useBtn.disabled = true;
      setKids(body, h("p", { class: "error" }, e.message), h("button", { class: "btn", type: "button", onclick: showDrives }, "Back to drives"));
    }
  }

  useBtn.onclick = () => { if (current) { onPick(current); dlg.close(); } };
  if (start) browse(start); else showDrives();
}

/* ------------------------------------------------------------------ admin: developer access (MCP) */
async function viewDevAccess(main) {
  const r = await api("/api/admin/mcp-tokens");
  const secretBox = h("div", { hidden: "" });
  const form = h("form", { class: "row" },
    h("label", { class: "grow" }, "Token name (who / which machine)", h("input", { name: "name", required: "", minlength: "2", maxlength: "60", placeholder: "alice-claude-code" })),
    h("label", {}, "Scope", h("select", { name: "scope" },
      h("option", { value: "read" }, "read — troubleshoot only"),
      h("option", { value: "operate" }, "operate — also reindex / unlock / request access"))),
    h("button", { class: "btn primary", type: "submit" }, "Create token"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const t = await api("/api/admin/mcp-tokens", { method: "POST", body: { name: form.name.value.trim(), scope: form.scope.value } });
      secretBox.hidden = false;
      secretBox.replaceChildren(
        h("p", {}, h("b", {}, "Token created — shown once. "), "Run this on the Archive PC to connect Claude Code:"),
        h("div", { class: "secret" }, t.claude_command), h("br"));
      form.reset();
    } catch (x) { toast(x.message, true); }
  });
  const rows = r.tokens.map(t => h("tr", {},
    h("td", {}, t.name), h("td", {}, t.scope), h("td", { class: "muted" }, `${fmtTs(t.created_at)} · ${t.created_by}`),
    h("td", { class: "muted" }, fmtTs(t.last_used_at) || "never"),
    h("td", {}, t.revoked_at ? h("span", { class: "muted" }, `revoked ${fmtTs(t.revoked_at)}`) : h("span", { class: "ok" }, "active")),
    h("td", { class: "actions" }, t.revoked_at ? null : h("button", { class: "btn small danger", type: "button", onclick: async () => {
      if (!confirm(`Revoke token "${t.name}"? Anything using it stops working immediately.`)) return;
      try { await api(`/api/admin/mcp-tokens/${t.id}`, { method: "DELETE" }); toast("Revoked."); render(); } catch (x) { toast(x.message, true); } } }, "Revoke"))));
  main.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Developer access · MCP"),
      h("p", { class: "muted" }, "Troubleshooting and development tools for AI assistants such as Claude Code, served at ",
        h("code", {}, r.endpoint || "(disabled)"), " — reachable only on this PC, never through Cloudflare or the office network. ",
        "Tokens can inspect health, logs, audit, customers, departments, users and explain why someone can or cannot see a recording. ",
        "They cannot play or download audio, delete anything, or change passwords or MFA. Every call is in the audit log."),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ...["Name", "Scope", "Created", "Last used", "Status", ""].map(x => h("th", {}, x)))),
        h("tbody", {}, ...rows, r.tokens.length ? null : h("tr", {}, h("td", { colspan: "6", class: "muted" }, "No tokens yet.")))))),
    h("div", { class: "card" }, h("h2", {}, "Create a token"), secretBox, form));
}

/* ------------------------------------------------------------------ admin: staff access */
async function viewStaffAccess(main) {
  const list = await api("/api/admin/staff-access");
  const form = h("form", { class: "row" },
    h("label", { class: "grow" }, "Email or domain", h("input", { name: "pattern", required: "", placeholder: "name@anydomain.com  or  @anydomain.com", class: "mono" })),
    h("label", { class: "grow" }, "Note", h("input", { name: "note", placeholder: "who / why" })),
    h("button", { class: "btn primary", type: "submit" }, "Allow"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await api("/api/admin/staff-access", { method: "POST", body: { pattern: form.pattern.value, note: form.note.value } });
      toast(`${r.pattern} can now verify as staff.`); render();
    } catch (x) { toast(x.message, true); }
  });
  main.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Staff access · away from the office"),
      h("p", { class: "muted" }, "Superadmin accounts work from the office network. Anywhere else, the person first proves they own an email address on this list (",
        h("i", {}, "verify your staff email"), " on the sign-in page), then signs in with password and authenticator as usual. Any domain works; a domain entry (@example.com) allows every address in it."),
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ...["Allowed", "Type", "Note", "Added by", "Added", ""].map(t => h("th", {}, t)))),
        h("tbody", {}, ...list.map(s => h("tr", {},
          h("td", { class: "mono" }, s.pattern), h("td", {}, s.pattern.startsWith("@") ? "whole domain" : "one address"),
          h("td", {}, s.note), h("td", { class: "muted" }, s.created_by), h("td", { class: "muted" }, fmtTs(s.created_at)),
          h("td", { class: "actions" }, h("button", { class: "btn small danger", type: "button", onclick: async () => {
            if (!confirm(`Remove ${s.pattern}? They will no longer be treated as staff off-site.`)) return;
            try { await api(`/api/admin/staff-access/${s.id}`, { method: "DELETE" }); toast("Removed."); render(); } catch (x) { toast(x.message, true); } } }, "Remove")))),
          list.length ? null : h("tr", {}, h("td", { colspan: "6", class: "muted" }, "Nobody yet — superadmins can only work from the office network.")))))),
    h("div", { class: "card" }, h("h2", {}, "Allow someone"), form));
}

/* Department folder picker: browses inside ONE customer's recording folder (admins of that customer too). */
function openDeptFolderPicker(cid, onPick) {
  const body = h("div", { class: "picker-body" });
  const crumb = h("div", { class: "picker-crumb mono" });
  const useBtn = h("button", { class: "btn primary", type: "button", disabled: "" }, "Add this folder");
  const dlg = h("dialog", { class: "picker", "aria-label": "Choose department folder" },
    h("div", { class: "picker-head" }, h("h2", {}, "Choose a folder for this department"),
      h("button", { class: "btn small", type: "button", onclick: () => dlg.close(), "aria-label": "Close" }, "✕")),
    crumb, body,
    h("p", { class: "muted picker-info" }, "The department sees every recording inside the chosen folder and its subfolders."),
    h("div", { class: "row picker-foot" }, h("button", { class: "btn", type: "button", onclick: () => dlg.close() }, "Close"), useBtn));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg); dlg.showModal();
  let current = "";
  const item = (label, onclick) => h("li", {}, h("button", { type: "button", class: "picker-item", onclick },
    h("span", { class: "picker-icon", "aria-hidden": "true" }, "▸"), h("span", { class: "grow" }, label)));
  async function browse(path) {
    setKids(body, h("p", { class: "muted picker-note" }, "Loading…"));
    try {
      const r = await api(`/api/admin/customers/${cid}/folders?path=${encodeURIComponent(path)}`);
      current = r.path; crumb.textContent = r.root + (r.path ? " › " + r.path.replaceAll("/", " › ") : "");
      useBtn.disabled = !r.path;  // the whole drive is what customer admins already see
      setKids(body, h("ul", { class: "picker-list" },
        r.parent !== null ? item("..", () => browse(r.parent)) : null,
        ...r.dirs.map(x => item(x.name, () => browse(x.path))),
        r.dirs.length ? null : h("li", { class: "muted picker-note" }, "No subfolders here.")));
    } catch (e) { setKids(body, h("p", { class: "error picker-note" }, e.message)); }
  }
  useBtn.onclick = () => { if (current) { onPick(current); toast(`Added ${current}`); } };
  browse("");
}

/* ------------------------------------------------------------------ admin: departments */
const splitList = (s) => s.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
async function viewDepartments(main) {
  const picker = await customerPicker(() => viewDepartments(main));
  const cid = state.me.role === "superadmin" ? state.customerId : state.me.customer.id;
  const list = cid ? await api(`/api/admin/departments?customer_id=${cid}`) : [];
  const form = deptForm(cid);
  main.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Departments · who sees which recordings"),
      h("p", { class: "muted" }, "A department user sees a recording when its extension, queue or DID matches — or when the recording is stored inside one of the department's folders on the customer drive. Use numbers, folders, or both."),
      picker ? h("div", { class: "row" }, picker) : null,
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ...["Department", "Extensions", "Queues", "DIDs", "Folders", ""].map(t => h("th", {}, t)))),
        h("tbody", {}, ...(list.length ? list : []).map(d => h("tr", {},
          h("td", {}, d.name), h("td", { class: "mono" }, d.extensions.join(", ")), h("td", { class: "mono" }, d.queues.join(", ")), h("td", { class: "mono" }, d.dids.join(", ")),
          h("td", { class: "mono" }, (d.folders || []).join("\n")),
          h("td", { class: "actions" },
            h("button", { class: "btn small", type: "button", onclick: () => deptForm(cid, d, form) }, "Edit"),
            h("button", { class: "btn small danger", type: "button", onclick: async () => { if (!confirm(`Remove department "${d.name}"? Users in it will lose access until reassigned. Recordings are never touched.`)) return; try { await api(`/api/admin/departments/${d.id}`, { method: "DELETE" }); toast("Removed."); render(); } catch (e) { toast(e.message, true); } } }, "Remove")))),
          list.length ? null : h("tr", {}, h("td", { colspan: "6", class: "muted" }, "No departments yet — customer admins see everything; add departments to narrow access.")))))),
    h("div", { class: "card" }, form));
}
function deptForm(cid, d = null, existing = null) {
  const form = existing || h("form", { class: "row" });
  setKids(form, 
    h("h2", { style: "width:100%" }, d ? `Edit ${d.name}` : "Add department"),
    h("label", {}, "Name", h("input", { name: "name", value: d?.name || "", required: "", placeholder: "Support" })),
    h("label", { class: "grow" }, "Extensions", h("input", { name: "extensions", value: d?.extensions.join(", ") || "", placeholder: "436, 437, 851" })),
    h("label", {}, "Queues", h("input", { name: "queues", value: d?.queues.join(", ") || "", placeholder: "126, 131" })),
    h("label", {}, "DIDs", h("input", { name: "dids", value: d?.dids.join(", ") || "", placeholder: "3282" })),
    h("label", { class: "grow" }, "Folders on the drive (one per line, subfolders included)",
      h("div", { class: "input-with-btn" },
        h("textarea", { name: "folders", rows: "2", class: "mono", placeholder: "Support\nRecordings/Sales" }, (d?.folders || []).join("\n")),
        h("button", { class: "btn", type: "button", disabled: cid ? null : "", onclick: () => openDeptFolderPicker(cid, (p) => {
          const cur = form.folders.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
          if (!cur.includes(p)) form.folders.value = [...cur, p].join("\n");
        }) }, "Browse…"))),
    h("button", { class: "btn primary", type: "submit" }, d ? "Save" : "Add"),
    d ? h("button", { class: "btn", type: "button", onclick: () => deptForm(cid, null, form) }, "Cancel") : null);
  form.onsubmit = async (e) => {
    e.preventDefault();
    const body = { customer_id: cid, name: form.name.value.trim(), extensions: splitList(form.extensions.value), queues: splitList(form.queues.value), dids: splitList(form.dids.value),
      folders: form.folders.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean) };
    try {
      if (d) await api(`/api/admin/departments/${d.id}`, { method: "PUT", body }); else await api("/api/admin/departments", { method: "POST", body });
      toast("Saved."); render();
    } catch (err) { toast(err.message, true); }
  };
  return form;
}

/* ------------------------------------------------------------------ admin: users */
async function viewUsers(main) {
  const picker = await customerPicker(() => viewUsers(main));
  const cid = state.me.role === "superadmin" ? state.customerId : state.me.customer.id;
  const [users, depts] = await Promise.all([api(`/api/admin/users${cid ? `?customer_id=${cid}` : ""}`), cid ? api(`/api/admin/departments?customer_id=${cid}`) : []]);
  const dname = (id) => depts.find(d => d.id === id)?.name || `#${id}`;
  const form = userForm(cid, depts);
  const secretBox = h("div", { hidden: "" });
  main.replaceChildren(
    h("div", { class: "card" }, h("h2", {}, "Users"),
      picker ? h("div", { class: "row" }, picker) : null,
      h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ...["Username", "Name", "Role", "Departments", "Status", "Authenticator", "Last login", ""].map(t => h("th", {}, t)))),
        h("tbody", {}, ...users.filter(u => u.role !== "superadmin").map(u => h("tr", {},
          h("td", { class: "mono" }, u.username), h("td", {}, u.display_name), h("td", {}, u.role === "customer_admin" ? "Customer admin" : "Department"),
          h("td", {}, u.role === "department" ? u.department_ids.map(dname).join(", ") : "all"),
          h("td", {}, u.active ? (u.locked_until && u.locked_until > new Date().toISOString() ? h("b", { class: "error" }, "locked") : u.must_change_password ? h("span", { class: "muted" }, "must change pw") : "active") : h("b", { class: "error" }, "disabled")),
          h("td", {}, u.mfa_enabled ? h("span", { class: "ok" }, "linked") : h("span", { class: "muted" }, "set up at next sign-in")),
          h("td", { class: "muted" }, fmtTs(u.last_login) || "never"),
          h("td", { class: "actions" },
            h("button", { class: "btn small", type: "button", onclick: () => userForm(cid, depts, u, form) }, "Edit"),
            u.mfa_enabled ? h("button", { class: "btn small", type: "button", onclick: async () => { if (!confirm(`Reset the authenticator for ${u.username}? They will scan a new QR code at next sign-in and are signed out now.`)) return; try { await api(`/api/admin/users/${u.id}/reset-mfa`, { method: "POST" }); toast("Authenticator reset."); render(); } catch (e) { toast(e.message, true); } } }, "Reset MFA") : null,
            h("button", { class: "btn small", type: "button", onclick: async () => { if (!confirm(`Reset password for ${u.username}? Their sessions will be signed out.`)) return; try { const r = await api(`/api/admin/users/${u.id}/reset-password`, { method: "POST" }); showSecret(secretBox, u.username, r.initial_password); } catch (e) { toast(e.message, true); } } }, "Reset password")))))))),
    h("div", { class: "card" }, secretBox, form));
}
function showSecret(box, username, pw) {
  box.hidden = false;
  box.replaceChildren(h("p", {}, h("b", {}, `Temporary password for ${username}`), " — shown once. Hand it over securely; they must change it at first sign-in."),
    h("div", { class: "secret" }, pw), h("br"));
}
function userForm(cid, depts, u = null, existing = null) {
  const form = existing || h("form", { class: "row" });
  const canAdmin = state.me.role === "superadmin";
  setKids(form, 
    h("h2", { style: "width:100%" }, u ? `Edit ${u.username}` : "Add user"),
    h("label", {}, "Username", h("input", { name: "username", value: u?.username || "", required: "", placeholder: "j.doe" })),
    h("label", {}, "Display name", h("input", { name: "display_name", value: u?.display_name || "" })),
    h("label", {}, "Role", h("select", { name: "role", onchange: (e) => form.querySelector("[name=depts]").closest("label").hidden = e.target.value !== "department" },
      h("option", { value: "department", selected: !u || u.role === "department" ? "" : null }, "Department user"),
      canAdmin ? h("option", { value: "customer_admin", selected: u?.role === "customer_admin" ? "" : null }, "Customer admin (whole drive)") : null)),
    h("label", { hidden: u?.role === "customer_admin" ? "" : null }, "Departments (ctrl-click for several)", h("select", { name: "depts", multiple: "", size: "4" }, ...depts.map(d => h("option", { value: d.id, selected: u?.department_ids.includes(d.id) ? "" : null }, d.name)))),
    h("label", {}, "Active", h("select", { name: "active" }, h("option", { value: "1", selected: (u ? u.active : true) ? "" : null }, "yes"), h("option", { value: "0", selected: u && !u.active ? "" : null }, "no"))),
    u ? null : h("label", {}, "Initial password (blank = generate)", h("input", { name: "password", type: "password", autocomplete: "new-password" })),
    h("button", { class: "btn primary", type: "submit" }, u ? "Save" : "Create"),
    u ? h("button", { class: "btn", type: "button", onclick: () => userForm(cid, depts, null, form) }, "Cancel") : null);
  form.onsubmit = async (e) => {
    e.preventDefault();
    const body = { username: form.username.value.trim(), display_name: form.display_name.value.trim(), role: form.role.value, customer_id: cid,
      department_ids: [...form.depts.selectedOptions].map(o => Number(o.value)), active: form.active.value === "1" };
    if (!u && form.password.value) body.password = form.password.value;
    try {
      if (u) { await api(`/api/admin/users/${u.id}`, { method: "PUT", body }); toast("Saved."); render(); }
      else { const r = await api("/api/admin/users", { method: "POST", body }); toast("User created."); await viewUsers($("#main")); showSecret($("#main .card:last-child > div"), body.username, r.initial_password); }
    } catch (err) { toast(err.message, true); }
  };
  return form;
}

/* ------------------------------------------------------------------ admin: audit */
async function viewAudit(main) {
  const picker = await customerPicker(() => viewAudit(main));
  const cid = state.me.role === "superadmin" ? state.customerId : null;
  const p = new URLSearchParams({ page: state.page }); if (cid) p.set("customer_id", cid);
  const data = await api(`/api/admin/audit?${p}`);
  const pages = Math.max(1, Math.ceil(data.total / 100));
  main.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Audit log"),
    picker ? h("div", { class: "row" }, picker) : null,
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ...["Time (UTC)", "User", "IP", "Action", "Detail"].map(t => h("th", {}, t)))),
      h("tbody", {}, ...data.items.map(r => h("tr", {}, h("td", { class: "mono" }, fmtTs(r.ts)), h("td", { class: "mono" }, r.username), h("td", { class: "mono" }, r.ip), h("td", {}, r.action), h("td", { class: "mono", style: "white-space:normal" }, r.detail)))))),
    h("div", { class: "pager" }, h("span", { class: "muted" }, `${data.total.toLocaleString()} entries`),
      h("button", { class: "btn small", type: "button", disabled: state.page <= 1 ? "" : null, onclick: () => { state.page--; viewAudit(main); } }, "‹ Prev"),
      h("span", {}, `Page ${data.page} / ${pages}`),
      h("button", { class: "btn small", type: "button", disabled: state.page >= pages ? "" : null, onclick: () => { state.page++; viewAudit(main); } }, "Next ›"))));
}

boot();
