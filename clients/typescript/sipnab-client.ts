// snippet:start sipnab-client
// sipnab-client.ts: runs on Node 22.18+ (built-in fetch, type stripping)
const API = process.env.SIPNAB_URL ?? "http://localhost:8080";
const KEY = process.env.SIPNAB_API_KEY;
if (!KEY) throw new Error("SIPNAB_API_KEY not set");

interface DialogSummary {
  call_id: string;
  state: string;
  method: string;
  from_user: string | null;
  to_user: string | null;
  duration_sec: number;
  msg_count: number;
}

interface DialogsPage {
  dialogs: DialogSummary[];
  total: number;
  limit: number;
  offset: number;
}

async function api<T>(
  path: string,
  params: Record<string, string | number> = {},
): Promise<T> {
  const url = new URL(`${API}${path}`);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, String(v));
  }
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${KEY}` },
  });
  if (r.status === 401) throw new Error(`GET ${path}: 401 auth failed`);
  if (r.status === 503) throw new Error(`GET ${path}: 503 rate-limited or conn cap reached`);
  if (!r.ok) throw new Error(`GET ${path}: HTTP ${r.status}`);
  return (await r.json()) as T;
}

async function listDialogs(
  state: string | null = null,
  limit = 50,
): Promise<DialogSummary[]> {
  const all: DialogSummary[] = [];
  let offset = 0;
  for (;;) {
    const params: Record<string, string | number> = { limit, offset };
    if (state) params.state = state;
    const page = await api<DialogsPage>("/v1/dialogs", params);
    if (page.dialogs.length === 0) break;
    all.push(...page.dialogs);
    if (all.length >= page.total) break;
    offset += page.dialogs.length;
  }
  return all;
}

// REST API doesn't expose per-message data — see the note at the top of
// "Client Examples" for how to build per-call response-code histograms
// via the CLI or MCP. Here we just summarize what REST exposes. A timing
// sipnab did not measure is absent from one dialog, not null:
interface FullDialog {
  call_id: string;
  state: string;
  msg_count: number;
  timing: { pdd_ms?: number; setup_ms?: number; retransmits: number };
  diagnosis: { one_way_audio: boolean; nat_mismatch: boolean; no_media: boolean };
}

// ── Demo ──────────────────────────────────────────────────────────
const failed = await listDialogs("Failed");
console.log(`${failed.length} failed dialogs`);

for (const d of failed.slice(0, 5)) {
  const full = await api<FullDialog>(`/v1/dialogs/${encodeURIComponent(d.call_id)}`);
  const pdd = full.timing.pdd_ms === undefined ? "—" : `${full.timing.pdd_ms}ms`;
  console.log(`  ${d.call_id}  state=${d.state}  ` +
              `pdd=${pdd}  ` +
              `nat_mismatch=${full.diagnosis.nat_mismatch}`);
}
// snippet:end sipnab-client
