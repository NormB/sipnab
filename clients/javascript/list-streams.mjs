// GET /v1/streams?mos_below=3.0: the RTP streams that sound bad.
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
  // snippet:start list-streams
  const resp = await fetch(`${base}/v1/streams?mos_below=3.0`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`GET /v1/streams: ${resp.status} ${resp.statusText}`);
  const { streams } = await resp.json();
  streams.forEach(s =>
    console.log(`SSRC ${s.ssrc}: MOS=${s.mos.toFixed(1)}, loss=${s.loss_pct.toFixed(1)}%`)
  );
  // snippet:end list-streams
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`list-streams: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
