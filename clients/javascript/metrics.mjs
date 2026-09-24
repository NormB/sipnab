// GET /metrics: the Prometheus exposition, as a scraper sees it.
//
// The example docs/prometheus-metrics.md shows is the body of main(), between the snippet
// markers; this file adds where the inputs come from and what a failure
// prints. Node.js 18 or later (global fetch); no dependencies.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).

const base = process.env.SIPNAB_URL || "http://127.0.0.1:8080";
const token = process.env.SIPNAB_API_KEY || "my-secret-token";

async function main() {
  // snippet:start metrics
  const resp = await fetch(`${base}/metrics`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`GET /metrics: ${resp.status} ${resp.statusText}`);
  process.stdout.write(await resp.text()); // Prometheus text format
  // snippet:end metrics
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`metrics: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
