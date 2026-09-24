// GET /v1/dialogs/{call_id}: one dialog's state and message count.
//
// The example docs/rest-api.md shows is the body of main(), between the snippet
// markers; this file adds where the inputs come from and what a failure
// prints. Node.js 18 or later (global fetch); no dependencies.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).
// The first argument is the Call-ID (default 12013223@203.0.113.195).

const base = process.env.SIPNAB_URL || "http://127.0.0.1:8080";
const token = process.env.SIPNAB_API_KEY || "my-secret-token";
const callId = process.argv[2] ?? "12013223@203.0.113.195";

async function main() {
  // snippet:start get-dialog
  const resp = await fetch(`${base}/v1/dialogs/${encodeURIComponent(callId)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`GET /v1/dialogs/${callId}: ${resp.status} ${resp.statusText}`);
  const dialog = await resp.json();
  console.log(`State: ${dialog.state}, Messages: ${dialog.msg_count}`);
  // snippet:end get-dialog
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`get-dialog: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
