// GET /v1/stats: dialog totals and post-dial delay percentiles.
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
  // snippet:start stats
  const resp = await fetch(`${base}/v1/stats`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`GET /v1/stats: ${resp.status} ${resp.statusText}`);
  const stats = await resp.json();
  const { dialogs, timing } = stats;
  console.log(`Dialogs: ${dialogs.total} total, ${dialogs.active} active`);
  console.log(`PDD p50: ${timing.pdd_p50_ms}ms, p95: ${timing.pdd_p95_ms}ms`);
  // snippet:end stats
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`stats: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
