// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

// The console's rules that need no page: request paths, time and number
// text, and what to tell the operator when a request fails. Kept apart from
// console.js so each rule can be called directly by a test.

/** Rows asked for per page. The API clamps it to its own row cap. */
export const PAGE_LIMIT = 50;

/** What a cell shows when the API sent no value. */
export const NO_VALUE = "not reported";

/**
 * The API path of one dialog. A Call-ID is captured text and may hold `/`,
 * `?`, `#`, `%` or `..`, so it goes in as one encoded path segment.
 */
export function dialogPath(callId) {
  return `/v1/dialogs/${encodeURIComponent(String(callId))}`;
}

/** The API path of the leg tree reachable from one dialog. */
export function treePath(callId) {
  return `${dialogPath(callId)}/tree`;
}

/**
 * The API path of one page of changed dialogs. `cursor` is the previous
 * page's `next_cursor`, passed back as it came; without one the walk starts
 * at the first change.
 */
export function tailPath(cursor, limit = PAGE_LIMIT) {
  const query = new URLSearchParams({ limit: String(limit) });
  if (typeof cursor === "string" && cursor !== "") {
    query.set("since", cursor);
  }
  return `/v1/dialogs/tail?${query.toString()}`;
}

/**
 * Why `token` cannot be sent, or "" when it can. An HTTP header value takes
 * visible ASCII only; a pasted line break or space is the usual cause.
 */
export function tokenProblem(token) {
  if (/^[\x21-\x7e]*$/.test(token)) {
    return "";
  }
  return "The token holds a space, a line break or a character outside ASCII, which a bearer token cannot. Paste the token again, without surrounding text.";
}

/** Display text for any API value. Never markup: callers write it as text. */
export function text(value) {
  if (value === null || value === undefined || value === "") {
    return NO_VALUE;
  }
  if (Array.isArray(value)) {
    return value.length === 0 ? NO_VALUE : value.map(text).join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

/** The shape of an RFC 3339 instant: date, `T`, time, and `Z` or an offset. */
const RFC_3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * An RFC 3339 instant as UTC with the offset stated, for example
 * `2026-09-15 12:00:03 UTC (+00:00)`. Text that is not an instant is
 * returned as it came, so nothing the API sent is hidden.
 *
 * The shape is checked before `Date` reads the text. `Date` alone accepts far
 * more than an instant: a browser reads `<img src=x onerror="a=1">` as a date
 * in 2001, and the page would show a time nobody captured.
 */
export function formatUtc(value) {
  if (typeof value !== "string" || value === "") {
    return NO_VALUE;
  }
  if (!RFC_3339.test(value)) {
    return value;
  }
  const instant = new Date(value);
  if (Number.isNaN(instant.getTime())) {
    return value;
  }
  const iso = instant.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC (+00:00)`;
}

/** Seconds as `1d 2h 3m 4s`, leaving out leading zero units. */
export function formatDuration(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) {
    return NO_VALUE;
  }
  const whole = Math.floor(seconds);
  const parts = [
    [Math.floor(whole / 86400), "d"],
    [Math.floor((whole % 86400) / 3600), "h"],
    [Math.floor((whole % 3600) / 60), "m"],
    [whole % 60, "s"],
  ];
  const first = parts.findIndex(([count]) => count > 0);
  return parts
    .slice(first === -1 ? 3 : first)
    .map(([count, unit]) => `${count}${unit}`)
    .join(" ");
}

/** `used of capacity (pct%)` from a runtime usage object. */
export function formatUsage(usage) {
  if (usage === null || typeof usage !== "object") {
    return NO_VALUE;
  }
  const { used, capacity, pct } = usage;
  if (typeof used !== "number" || typeof capacity !== "number") {
    return NO_VALUE;
  }
  const share = typeof pct === "number" ? ` (${pct.toFixed(1)}%)` : "";
  return `${used} of ${capacity}${share}`;
}

/** The final status of a dialog: code and reason, either or neither. */
export function formatFinalStatus(dialog) {
  const code = dialog.final_status_code;
  const reason = dialog.final_status_reason;
  if (code === null || code === undefined) {
    return "none yet";
  }
  return reason ? `${code} ${reason}` : String(code);
}

/** The `detail` of an RFC 9457 problem body, or "" when it has none. */
function problemDetail(problem) {
  if (problem !== null && typeof problem === "object" && typeof problem.detail === "string") {
    return problem.detail;
  }
  return "";
}

/**
 * What to tell the operator when a request failed.
 *
 * `status` is the HTTP status, or 0 when no response arrived. `problem` is
 * the parsed response body or null. `what` names what was being loaded.
 * Returns the message and whether the token must be asked for again.
 */
export function describeFailure(status, problem, what) {
  const detail = problemDetail(problem);
  const said = detail === "" ? "" : ` The API said: ${detail}`;
  switch (status) {
    case 0:
      return {
        signOut: false,
        message: `Could not load ${what}: no answer from the API. Check that sipnab is still running and that you can reach it, then try again.`,
      };
    case 400:
      return {
        signOut: false,
        message: `Could not load ${what}: the API refused the request (400).${said} Select Refresh to start again.`,
      };
    case 401:
      return {
        signOut: true,
        message: `The API refused the token (401). It is missing, wrong, expired or revoked, or its scope does not cover reading ${what}.${said} Paste a valid token and connect again.`,
      };
    case 403:
      return {
        signOut: false,
        message: `Could not load ${what}: the API forbids this request (403).${said} If it names the Host header, add the name in your address bar with --api-allowed-host. If it names a scope, use a token that carries it.`,
      };
    case 404:
      return {
        signOut: false,
        message: `Could not load ${what}: the API does not have it (404). The dialog may have been evicted from the capture. Go back to the list and select Refresh.`,
      };
    case 408:
    case 429:
    case 503:
      return {
        signOut: false,
        message: `Could not load ${what}: the API is busy or is limiting requests from this address (${status}). Wait a few seconds and try again.`,
      };
    default:
      return {
        signOut: false,
        message: `Could not load ${what}: the API answered ${status}.${said} Try again, and check the sipnab log if it repeats.`,
      };
  }
}

/**
 * Whether a tail page came from a different capture than the pages before
 * it. A cursor indexes one capture instance; after a change the list must
 * start again.
 */
export function captureChanged(previousInstance, page) {
  const identity = page === null || typeof page !== "object" ? null : page.capture_identity;
  const instance = identity && typeof identity.instance === "string" ? identity.instance : null;
  return previousInstance !== null && instance !== null && previousInstance !== instance;
}

/** The capture instance a page names, or null. */
export function captureInstance(page) {
  const identity = page === null || typeof page !== "object" ? null : page.capture_identity;
  return identity && typeof identity.instance === "string" ? identity.instance : null;
}
