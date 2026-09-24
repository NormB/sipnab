// GET /v1/dialogs: list the failed dialogs.
//
// The example docs/rest-api.md shows is the body of main(), between the snippet
// markers; this file adds where the inputs come from and what a failure
// prints. Node.js 18 or later (global fetch); no dependencies.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).

const base = process.env.SIPNAB_URL || "http://127.0.0.1:8080";
const token = process.env.SIPNAB_API_KEY || "my-secret-token";

async function main() {
  // snippet:start list-dialogs
  const resp = await fetch(`${base}/v1/dialogs?state=Failed&limit=10`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`GET /v1/dialogs: ${resp.status} ${resp.statusText}`);
  const { dialogs, total } = await resp.json();
  dialogs.forEach(d => console.log(`${d.call_id}: ${d.state}`));
  console.log(`${dialogs.length} dialogs (${total} total)`);
  // snippet:end list-dialogs
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`list-dialogs: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
