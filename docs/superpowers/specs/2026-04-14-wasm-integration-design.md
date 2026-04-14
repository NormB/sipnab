# sipnab WASM Integration — Design Spec

> Date: 2026-04-14
> Status: Proposed

## Problem

Users must install sipnab locally to analyze pcap files. This creates friction for:
- Quick one-off analysis ("someone sent me a pcap in Slack")
- Teams where not everyone has Rust/cargo installed
- Conference demos and training workshops
- Evaluating sipnab before committing to install

## Solution

Compile sipnab's core analysis engine to WebAssembly (WASM) and run it in the browser. Users drag-and-drop a pcap file on sipnab.com and get the full TUI experience — call list, call flow ladder, message detail, filter DSL, export — with zero installation.

## Privacy Model

**All processing happens in the browser. No data leaves the user's machine.**

- The pcap file is read into an `ArrayBuffer` via the File API
- WASM module parses it entirely in-memory (no upload)
- TUI renders to a `<canvas>` or `xterm.js` terminal in the browser tab
- Each browser tab is a completely isolated sandbox
- Two users on the same page have zero visibility into each other's data
- No cookies, no analytics, no telemetry on the analysis page
- The WASM binary is served as a static file (cacheable, no server-side processing)

The privacy guarantee is architectural, not policy-based: there is literally no server endpoint that receives pcap data.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Browser Tab                                             │
│                                                         │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  File     │───▶│  WASM Module │───▶│  xterm.js     │  │
│  │  Drop     │    │  (sipnab)    │    │  Terminal      │  │
│  │  Zone     │    │              │    │  Renderer      │  │
│  └──────────┘    │  - pcap parse │    └───────────────┘  │
│                  │  - SIP parser │                        │
│                  │  - dialog     │    ┌───────────────┐  │
│                  │    tracking   │───▶│  Export        │  │
│                  │  - RTP quality│    │  (download)    │  │
│                  │  - filter DSL │    └───────────────┘  │
│                  │  - call flow  │                        │
│                  └──────────────┘                        │
│                                                         │
│  No network requests. No server. No data leaves tab.    │
└─────────────────────────────────────────────────────────┘
```

## What Works in WASM

| Feature | WASM Support | Notes |
|---------|-------------|-------|
| Pcap file parsing | Yes | File API → ArrayBuffer → WASM |
| SIP parser | Yes | Pure Rust, no system deps |
| Dialog tracking | Yes | In-memory, no threads needed |
| RTP quality analysis | Yes | Pure computation |
| Filter DSL | Yes | Pure Rust parser/evaluator |
| Call flow rendering | Yes | Renders to terminal abstraction |
| Export (JSON, CSV, Mermaid, etc.) | Yes | Generate in WASM, download via Blob URL |
| TUI rendering | Yes | Via ratatui → xterm.js backend |
| Theme/colors | Yes | CSS variables or terminal colors |
| Keybindings | Yes | Keyboard events forwarded to WASM |

## What Does NOT Work in WASM

| Feature | Why Not | Alternative |
|---------|---------|-------------|
| Live capture (`-d eth0`) | No raw socket access in browser | N/A — file analysis only |
| TLS decryption | Needs keylog file (could work if user provides it) | Optional: file upload for keylog |
| HEP send/receive | No UDP sockets | N/A |
| REST API server | No TCP listener in browser | N/A |
| Privilege dropping | No OS process model | N/A |
| File system access | Sandboxed | File API for input, Blob download for output |
| pcap writing | No file system | Download via Blob URL |

## Technical Approach

### 1. Compilation Target

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm
```

New feature flag:
```toml
[features]
wasm = []  # Enables browser-compatible code paths, disables pcap/system deps
```

The `wasm` feature:
- Excludes `pcap` crate (C FFI, not WASM-compatible)
- Excludes `libc`, `signals`, `privilege` modules
- Excludes `crossterm` (terminal I/O, not browser-compatible)
- Replaces file I/O with in-memory buffers
- Replaces `chrono::Utc::now()` with `js_sys::Date::now()`

### 2. WASM Bridge (wasm-bindgen)

```rust
// src/wasm.rs
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct SipnabSession {
    dialog_store: DialogStore,
    stream_store: StreamStore,
}

#[wasm_bindgen]
impl SipnabSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self { ... }

    /// Load a pcap file from an ArrayBuffer
    pub fn load_pcap(&mut self, data: &[u8]) -> Result<JsValue, JsError> {
        // Parse pcap header, iterate packets, feed to dialog_store
    }

    /// Get dialog list as JSON
    pub fn get_dialogs(&self) -> String { ... }

    /// Get call flow for a dialog as JSON
    pub fn get_call_flow(&self, call_id: &str) -> String { ... }

    /// Apply a filter expression, return matching dialog IDs
    pub fn filter(&self, expr: &str) -> String { ... }

    /// Export as format (json, csv, mermaid, markdown, sipp)
    pub fn export(&self, format: &str) -> String { ... }

    /// Get RTP stream quality data as JSON
    pub fn get_streams(&self) -> String { ... }
}
```

### 3. JavaScript Integration

```javascript
import init, { SipnabSession } from './sipnab_wasm.js';

await init();  // Load WASM module

const session = new SipnabSession();

// User drops a pcap file
dropZone.addEventListener('drop', async (e) => {
    const file = e.dataTransfer.files[0];
    const buffer = await file.arrayBuffer();
    const result = session.load_pcap(new Uint8Array(buffer));
    
    // Render dialog list
    const dialogs = JSON.parse(session.get_dialogs());
    renderDialogList(dialogs);
});
```

### 4. Terminal Rendering (Two Options)

**Option A: xterm.js (recommended)**

Use ratatui with a custom WASM backend that writes ANSI escape sequences to xterm.js:

```rust
// Custom ratatui backend for xterm.js
pub struct XtermBackend {
    buffer: Vec<u8>,  // ANSI escape sequence buffer
}

impl Backend for XtermBackend {
    fn draw<'a, I>(&mut self, content: I) -> Result<()>
    where I: Iterator<Item = (u16, u16, &'a Cell)> {
        // Convert ratatui cells to ANSI sequences
        // Send to JS via wasm-bindgen callback
    }
}
```

The xterm.js terminal handles:
- Keyboard input (forwarded to WASM event handler)
- Mouse support (selection, scroll)
- Copy/paste
- Terminal resizing
- Color rendering (full 24-bit support)

**Option B: Custom HTML renderer**

Skip xterm.js. Render the TUI directly to a `<pre>` element or `<canvas>`. Simpler but loses terminal features (scrollback, selection, copy).

**Recommendation: Option A (xterm.js).** It's battle-tested, handles all edge cases, and gives the authentic terminal feel. The WASM binary emits ANSI sequences and xterm.js renders them — exactly like a real terminal.

### 5. Build Pipeline

```
src/ (shared Rust code)
├── sip/          ← Shared between native and WASM
├── rtp/          ← Shared
├── capture/
│   ├── parse.rs  ← Shared (packet parsing)
│   ├── file.rs   ← Native only (uses pcap crate)
│   └── wasm.rs   ← WASM only (parses raw bytes)
├── tui/          ← Shared (ratatui widgets)
│   └── backend/
│       ├── crossterm.rs  ← Native
│       └── xterm.rs      ← WASM
└── wasm.rs       ← WASM entry point (wasm-bindgen)
```

Build:
```bash
wasm-pack build --target web --no-default-features --features wasm
```

Output: `pkg/sipnab_wasm.js` + `sipnab_wasm_bg.wasm` (~2-3 MB)

### 6. Website Integration

New page: `https://www.sipnab.com/analyze/`

```html
<div id="app">
    <!-- Drop zone (shown initially) -->
    <div id="drop-zone" class="drop-zone">
        <h2>Drop a PCAP file to analyze</h2>
        <p>Your file stays in your browser. Nothing is uploaded.</p>
        <input type="file" accept=".pcap,.pcapng,.cap" id="file-input">
    </div>
    
    <!-- Terminal (shown after file loaded) -->
    <div id="terminal-container" style="display:none">
        <div id="terminal"></div>
    </div>
</div>

<script type="module">
import init, { SipnabSession } from '/wasm/sipnab_wasm.js';
// ... initialization and event handling
</script>
```

### 7. File Size Budget

| Component | Estimated Size |
|-----------|---------------|
| sipnab WASM binary (gzipped) | ~800 KB |
| xterm.js + addons | ~300 KB |
| JavaScript glue | ~20 KB |
| CSS | ~15 KB |
| **Total** | **~1.1 MB** |

Acceptable for a one-time load. The WASM binary is cacheable.

## Implementation Phases

### Phase 1: Core WASM module (2-3 days)
- Add `wasm` feature flag to Cargo.toml
- Create `src/wasm.rs` with `SipnabSession` API
- Implement pcap parsing from `&[u8]` (bypass pcap crate)
- Expose dialog list, call flow, filter, export as JSON
- Build with `wasm-pack`, verify in Node.js

### Phase 2: Browser UI (2-3 days)
- Create `/analyze/` page with drop zone
- Integrate xterm.js terminal
- Wire keyboard events to WASM
- Implement dialog list rendering
- Implement call flow rendering

### Phase 3: Full TUI in browser (3-5 days)
- Port ratatui backend to xterm.js
- Implement all views (call list, call flow, raw message, streams)
- Implement all popups (save, filter, settings, file open)
- Export via Blob download instead of file write

### Phase 4: Polish (1-2 days)
- Loading spinner during WASM init
- Error handling for invalid files
- Mobile-friendly layout
- Progressive loading for large pcaps (>10MB)
- Sample pcap files for demo (no upload needed)

## Dependencies

```toml
[target.'cfg(target_arch = "wasm32")'.dependencies]
wasm-bindgen = "0.2"
js-sys = "0.3"
web-sys = { version = "0.3", features = ["File", "FileReader", "Blob", "Url", "HtmlElement"] }
console_error_panic_hook = "0.1"
```

## Risks

1. **Binary size** — The full sipnab with all features may exceed 3MB WASM. Mitigation: use `wasm-opt -Oz`, strip unused features, enable LTO.

2. **Performance on large pcaps** — Parsing a 100MB pcap in WASM may take several seconds. Mitigation: use `requestAnimationFrame` yield points, show progress bar, consider Web Workers for background parsing.

3. **ratatui WASM backend** — No production-quality xterm.js backend exists for ratatui today. The `ratatui-xterm-js` crate is experimental. May need to write a custom backend (~500 lines). Alternatively, use the JSON API approach (Phase 1-2) first, add the full TUI later.

4. **Memory** — Large pcaps consume RAM proportional to their size. A 500MB pcap would need ~500MB of WASM linear memory. Most browsers cap at 2-4GB. For very large files, show a warning and suggest the native binary.

## Privacy Verification

To prove the privacy claim, the `/analyze/` page should:
- Include a Content-Security-Policy header blocking all outbound requests: `default-src 'self'; connect-src 'none'`
- Have zero `fetch()` calls in the JavaScript
- Work completely offline (after initial load)
- Show a "🔒 Your data stays in your browser" badge
- Link to source code for verification

## Success Criteria

1. User can drag-drop a pcap and see the call list in <3 seconds
2. Call flow ladder renders with Unicode arrows and semantic colors
3. Filter DSL works identically to native
4. Export produces valid JSON/CSV/Mermaid/Markdown
5. Page works offline after initial load
6. Zero network requests during analysis (verifiable in DevTools)
7. WASM binary < 1.5MB gzipped
