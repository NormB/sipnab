// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

// The console page: a read-only client of the sipnab REST API.
//
// Two rules hold everywhere in this file.
//
// 1. Every value from the API is captured network data an attacker may have
//    chosen. It reaches the page through `textContent` only: never as markup,
//    never as a link target, a style or an event-handler attribute.
// 2. The bearer token lives in the `token` variable and nowhere else. It is
//    not written to web storage, a cookie, the URL or the log, and a reload
//    clears it.

import {
  NO_VALUE,
  PAGE_LIMIT,
  captureChanged,
  captureInstance,
  describeFailure,
  dialogPath,
  formatDuration,
  formatFinalStatus,
  formatUsage,
  formatUtc,
  tailPath,
  text,
  tokenProblem,
  treePath,
} from "./console-core.js";

/** The bearer token, in memory only. */
let token = "";
/** Raised on every connect and disconnect, so a late answer is dropped. */
let session = 0;
/** The cursor of the last page of dialogs, or null before the first. */
let cursor = null;
/** The capture instance the listed rows came from, or null. */
let instance = null;
/** Call-ID to its row, so a dialog that changes again updates in place. */
const rows = new Map();

const el = (id) => document.getElementById(id);
const views = ["view-connect", "view-list", "view-detail"];

/** A request the API did not answer with 2xx. */
class ApiFailure extends Error {
  constructor(status, problem) {
    super(`API request failed (${status})`);
    this.status = status;
    this.problem = problem;
  }
}

/** GET one API path with the token, and return the parsed JSON body. */
async function api(path) {
  const headers = { Accept: "application/json" };
  if (token !== "") {
    headers.Authorization = `Bearer ${token}`;
  }
  let response;
  try {
    response = await fetch(path, {
      headers,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
    });
  } catch {
    throw new ApiFailure(0, null);
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw new ApiFailure(response.status, body);
  }
  if (body === null || typeof body !== "object") {
    throw new ApiFailure(response.status, null);
  }
  return body;
}

/** Announce progress or a result in the polite live region. */
function say(message) {
  el("status").textContent = message;
}

/** Show an error in the alert region, or clear it with "". */
function fail(message) {
  el("error").textContent = message;
}

/** Show one view, hide the others and move focus to its heading. */
function show(view) {
  for (const id of views) {
    el(id).hidden = id !== view;
  }
  el(view).querySelector("h2").focus();
}

/** Forget the token and everything loaded with it. */
function forget() {
  token = "";
  session += 1;
  cursor = null;
  instance = null;
  rows.clear();
  el("dialog-rows").replaceChildren();
  clearDetail();
  el("runtime").hidden = true;
  el("disconnect").hidden = true;
  el("more").hidden = true;
  el("connection").textContent = "Not connected.";
}

/**
 * Report a failed request. A refused token ends the session and returns to
 * the connect form; anything else leaves the view as it is.
 */
function report(error, what, stateId) {
  const status = error instanceof ApiFailure ? error.status : 0;
  const problem = error instanceof ApiFailure ? error.problem : null;
  const { message, signOut } = describeFailure(status, problem, what);
  if (stateId) {
    el(stateId).textContent = `Not loaded: ${what}.`;
  }
  say("");
  if (signOut) {
    forget();
    show("view-connect");
  }
  fail(message);
}

/** Append a cell holding `value` as text. */
function cell(row, value, rowHeader = false) {
  const node = document.createElement(rowHeader ? "th" : "td");
  if (rowHeader) {
    node.scope = "row";
  }
  node.textContent = value;
  row.append(node);
  return node;
}

/** Append a row-header cell holding a button that opens `callId`. */
function callIdCell(row, callId) {
  const node = document.createElement("th");
  node.scope = "row";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "call-id";
  button.textContent = callId;
  button.addEventListener("click", () => openDialog(callId));
  node.append(button);
  row.append(node);
}

/** One row of the dialog list. */
function dialogRow(dialog) {
  const row = document.createElement("tr");
  callIdCell(row, text(dialog.call_id));
  cell(row, text(dialog.state));
  cell(row, text(dialog.method));
  cell(row, text(dialog.from_user));
  cell(row, text(dialog.to_user));
  cell(row, text(dialog.msg_count));
  cell(row, formatFinalStatus(dialog));
  cell(row, formatUtc(dialog.updated_at));
  return row;
}

/** Load the status header from `/v1/runtime`. */
async function loadRuntime() {
  const mine = session;
  const runtime = await api("/v1/runtime");
  if (mine !== session) {
    return;
  }
  el("runtime-uptime").textContent = formatDuration(runtime.uptime_seconds);
  el("runtime-dialogs").textContent = formatUsage(runtime.dialogs);
  el("runtime-streams").textContent = formatUsage(runtime.streams);
  el("runtime-packets").textContent = text(runtime.capture_packets_total);
  el("runtime").hidden = false;
}

/** Put one page of changed dialogs into the table. */
function addPage(page) {
  const body = el("dialog-rows");
  const dialogs = Array.isArray(page.dialogs) ? page.dialogs : [];
  for (const dialog of dialogs) {
    if (dialog === null || typeof dialog !== "object") {
      continue;
    }
    const callId = text(dialog.call_id);
    const fresh = dialogRow(dialog);
    const old = rows.get(callId);
    if (old) {
      old.remove();
    }
    rows.set(callId, fresh);
    body.append(fresh);
  }
  return dialogs.length;
}

/**
 * Load the next page of dialogs with the API's own cursor. `restart` drops
 * the rows and the cursor first.
 */
async function loadDialogs(restart) {
  const mine = session;
  const table = el("dialogs");
  if (restart) {
    cursor = null;
    instance = null;
    rows.clear();
    el("dialog-rows").replaceChildren();
  }
  el("more").hidden = true;
  el("list-state").textContent = "Loading dialogs.";
  table.ariaBusy = "true";
  try {
    const page = await api(tailPath(cursor));
    if (mine !== session) {
      return;
    }
    if (captureChanged(instance, page)) {
      table.ariaBusy = "false";
      say("The capture changed, so the list starts again.");
      await loadDialogs(true);
      return;
    }
    instance = captureInstance(page) ?? instance;
    const added = addPage(page);
    if (typeof page.next_cursor === "string" && page.next_cursor !== "") {
      cursor = page.next_cursor;
    }
    fail("");
    const more = added >= PAGE_LIMIT;
    if (rows.size === 0) {
      el("list-state").textContent =
        "No dialogs yet. sipnab has not seen a SIP dialog in this capture. Select Refresh to check again.";
    } else if (more) {
      el("list-state").textContent = `Showing ${rows.size} dialogs. There may be more: select Load more.`;
    } else {
      el("list-state").textContent = `Showing ${rows.size} dialogs. That is every change so far: select Load more to check for new ones.`;
    }
    el("more").hidden = rows.size === 0;
    say(`Loaded ${added} dialogs.`);
  } catch (error) {
    if (mine === session) {
      report(error, "the dialog list", "list-state");
      el("more").hidden = rows.size === 0;
    }
  } finally {
    table.ariaBusy = "false";
  }
}

/** Empty the detail view. */
function clearDetail() {
  for (const id of ["detail-fields", "sdp-rows", "stream-rows", "leg-rows"]) {
    el(id).replaceChildren();
  }
  for (const id of ["detail-state", "sdp-state", "streams-state", "legs-state"]) {
    el(id).textContent = "";
  }
}

/** Append one term and its value to the detail list. */
function field(label, value) {
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.textContent = value;
  el("detail-fields").append(term, description);
}

/** Fill a table body from `items`, and say so when there are none. */
function fillTable(bodyId, stateId, items, emptyMessage, build) {
  const list = Array.isArray(items) ? items.filter((item) => item !== null && typeof item === "object") : [];
  const body = el(bodyId);
  body.replaceChildren();
  for (const item of list) {
    const row = document.createElement("tr");
    build(row, item);
    body.append(row);
  }
  el(stateId).textContent = list.length === 0 ? emptyMessage : `${list.length} shown.`;
}

/** Draw the dialog detail. */
function drawDialog(dialog) {
  const timing = dialog.timing !== null && typeof dialog.timing === "object" ? dialog.timing : {};
  field("Call-ID", text(dialog.call_id));
  field("State", text(dialog.state));
  field("Method", text(dialog.method));
  field("From", text(dialog.from ?? dialog.from_user));
  field("From display name", text(dialog.from_display));
  field("To", text(dialog.to ?? dialog.to_user));
  field("To display name", text(dialog.to_display));
  field("Final status", formatFinalStatus(dialog));
  field("Messages", text(dialog.msg_count));
  field("Duration", typeof dialog.duration_sec === "number" ? `${dialog.duration_sec} s` : NO_VALUE);
  field("Post-dial delay", typeof timing.pdd_ms === "number" ? `${timing.pdd_ms} ms` : NO_VALUE);
  field("Setup time", typeof timing.setup_ms === "number" ? `${timing.setup_ms} ms` : NO_VALUE);
  field("Retransmissions", text(timing.retransmits));
  el("detail-state").textContent = "Loaded.";
  fillTable("sdp-rows", "sdp-state", dialog.sdp_timeline, "This dialog carried no SDP.", (row, sdp) => {
    cell(row, formatUtc(sdp.timestamp), true);
    cell(row, text(sdp.direction));
    cell(row, text(sdp.codecs));
    cell(row, `${text(sdp.media_addr)} port ${text(sdp.media_port)}`);
    cell(row, text(sdp.mode));
  });
  fillTable("stream-rows", "streams-state", dialog.streams, "sipnab matched no RTP stream to this dialog.", (row, stream) => {
    cell(row, text(stream.ssrc), true);
    cell(row, text(stream.codec));
    cell(row, text(stream.src));
    cell(row, text(stream.dst));
    cell(row, text(stream.packets));
    cell(row, text(stream.loss_pct));
    cell(row, text(stream.jitter_ms));
  });
}

/** Draw the leg tree. */
function drawTree(tree) {
  fillTable("leg-rows", "legs-state", tree.legs, "The API returned no legs for this dialog.", (row, leg) => {
    callIdCell(row, text(leg.call_id));
    cell(row, text(leg.depth));
    cell(row, leg.parent_call_id ? text(leg.parent_call_id) : "none (this is the root)");
    cell(row, leg.strategy ? text(leg.strategy) : "none (this is the root)");
    cell(row, text(leg.score));
    cell(row, leg.followed === false ? "No: a timing guess is not followed" : "Yes");
  });
  if (tree.truncated === true) {
    el("legs-state").textContent += " The row cap stopped the walk early, so more legs exist.";
  }
}

/** Open the detail view for one Call-ID. */
async function openDialog(callId) {
  const mine = session;
  clearDetail();
  fail("");
  show("view-detail");
  el("detail-state").textContent = "Loading the dialog.";
  el("legs-state").textContent = "Loading the call legs.";
  say("Loading the dialog.");
  const [dialog, tree] = await Promise.allSettled([api(dialogPath(callId)), api(treePath(callId))]);
  if (mine !== session) {
    return;
  }
  if (dialog.status === "fulfilled") {
    drawDialog(dialog.value);
    say("Dialog loaded.");
  } else {
    report(dialog.reason, "the dialog", "detail-state");
    if (mine !== session) {
      return;
    }
  }
  if (tree.status === "fulfilled") {
    drawTree(tree.value);
  } else if (dialog.status === "fulfilled") {
    report(tree.reason, "the call legs", "legs-state");
  } else {
    el("legs-state").textContent = "Not loaded: the call legs.";
  }
}

/** Connect with the token in the form. */
async function connect(event) {
  event.preventDefault();
  const input = el("token");
  const pasted = input.value.trim();
  // The field is emptied at once, so the token is not left in the page.
  input.value = "";
  const problem = tokenProblem(pasted);
  if (problem !== "") {
    fail(problem);
    input.focus();
    return;
  }
  forget();
  token = pasted;
  const mine = session;
  fail("");
  say("Connecting.");
  try {
    await loadRuntime();
  } catch (error) {
    if (mine === session) {
      report(error, "the runtime status", "");
      // Not connected, so the token is dropped whatever the failure was.
      if (token !== "") {
        forget();
      }
    }
    return;
  }
  if (mine !== session) {
    return;
  }
  el("connection").textContent = "Connected. The token is held in memory until you reload or disconnect.";
  el("disconnect").hidden = false;
  show("view-list");
  await loadDialogs(true);
}

/** Refresh the status header and start the list again. */
async function refresh() {
  const mine = session;
  try {
    await loadRuntime();
  } catch (error) {
    if (mine === session) {
      report(error, "the runtime status", "");
    }
    return;
  }
  await loadDialogs(true);
}

el("connect-form").addEventListener("submit", connect);
el("refresh").addEventListener("click", refresh);
el("more").addEventListener("click", () => loadDialogs(false));
el("back").addEventListener("click", () => {
  fail("");
  show("view-list");
});
el("disconnect").addEventListener("click", () => {
  forget();
  fail("");
  show("view-connect");
  say("Disconnected. The token was cleared from this page.");
});
