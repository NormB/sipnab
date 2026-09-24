// GET /health: is the REST API up? Prints ok.
//
// The example docs/rest-api.md shows is the body of main(), between the snippet
// markers; this file adds where the inputs come from and what a failure
// prints. Node.js 18 or later (global fetch); no dependencies.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080).

const base = process.env.SIPNAB_URL || "http://127.0.0.1:8080";

async function main() {
  // snippet:start health
  const resp = await fetch(`${base}/health`);
  if (!resp.ok) throw new Error(`GET /health: ${resp.status} ${resp.statusText}`);
  console.log(await resp.text()); // "ok"
  // snippet:end health
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`health: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
