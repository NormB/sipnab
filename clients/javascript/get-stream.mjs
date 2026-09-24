// GET /v1/streams/{id}: one RTP stream's codec and packet count.
//
// The example docs/rest-api.md shows is the body of main(), between the snippet
// markers; this file adds where the inputs come from and what a failure
// prints. Node.js 18 or later (global fetch); no dependencies.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).
// The first argument is the SSRC (default 0x1a2b3c4d).

const base = process.env.SIPNAB_URL || "http://127.0.0.1:8080";
const token = process.env.SIPNAB_API_KEY || "my-secret-token";
const ssrc = process.argv[2] ?? "0x1a2b3c4d";

async function main() {
  // snippet:start get-stream
  const resp = await fetch(`${base}/v1/streams/${encodeURIComponent(ssrc)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) throw new Error(`GET /v1/streams/${ssrc}: ${resp.status} ${resp.statusText}`);
  const stream = await resp.json();
  console.log(`Codec: ${stream.codec}, Packets: ${stream.packets}`);
  // snippet:end get-stream
}

main().catch((err) => {
  const why = err.cause?.code ?? err.cause?.message;
  console.error(`get-stream: ${err.message}${why ? ` (${why})` : ""}`);
  process.exitCode = 1;
});
