// =============================================================================
// sipnab -- Browser PCAP Analyzer
// =============================================================================

// ---------------------------------------------------------------------------
// Mock WASM session (used until real WASM module is built)
// ---------------------------------------------------------------------------

class MockSipnabSession {
  constructor() {
    this._dialogs = [
      {
        call_id: "12013223@10.0.2.20",
        method: "INVITE",
        state: "Completed",
        from_user: "sipp",
        to_user: "service",
        src_addr: "10.0.2.20",
        dst_addr: "10.0.2.15",
        message_count: 6,
        pdd_ms: 847,
        setup_ms: 2134,
        created_at: "2026-04-14T14:52:59Z"
      },
      {
        call_id: "12013224@10.0.2.20",
        method: "INVITE",
        state: "Confirmed",
        from_user: "alice",
        to_user: "bob",
        src_addr: "10.0.2.20",
        dst_addr: "10.0.2.15",
        message_count: 5,
        pdd_ms: 312,
        setup_ms: 1540,
        created_at: "2026-04-14T14:53:10Z"
      },
      {
        call_id: "78992001@10.0.3.5",
        method: "REGISTER",
        state: "Completed",
        from_user: "ext100",
        to_user: "ext100",
        src_addr: "10.0.3.5",
        dst_addr: "10.0.2.15",
        message_count: 4,
        pdd_ms: null,
        setup_ms: null,
        created_at: "2026-04-14T14:51:02Z"
      },
      {
        call_id: "44558812@10.0.2.30",
        method: "INVITE",
        state: "Failed",
        from_user: "1001",
        to_user: "1999",
        src_addr: "10.0.2.30",
        dst_addr: "10.0.2.15",
        message_count: 3,
        pdd_ms: null,
        setup_ms: null,
        created_at: "2026-04-14T14:53:45Z"
      },
      {
        call_id: "99001234@10.0.2.20",
        method: "OPTIONS",
        state: "Completed",
        from_user: "monitor",
        to_user: "proxy",
        src_addr: "10.0.2.20",
        dst_addr: "10.0.2.15",
        message_count: 2,
        pdd_ms: null,
        setup_ms: null,
        created_at: "2026-04-14T14:54:00Z"
      }
    ];

    this._streams = [
      {
        ssrc: 305419896,
        codec: "PCMU",
        payload_type: 0,
        src: "10.0.2.20:6000",
        dst: "10.0.2.15:7000",
        packets: 1875,
        jitter_ms: 2.84,
        loss_pct: 0.27,
        lost_packets: 5,
        mos: 4.38,
        duration_secs: 8.53,
        associated_dialog: "12013223@10.0.2.20",
        orphaned: false,
        first_seen: "2026-04-14T14:53:01.810Z",
        last_seen: "2026-04-14T14:53:10.340Z",
        octet_count: 300000
      },
      {
        ssrc: 2271560481,
        codec: "PCMU",
        payload_type: 0,
        src: "10.0.2.15:7000",
        dst: "10.0.2.20:6000",
        packets: 1875,
        jitter_ms: 3.41,
        loss_pct: 0.54,
        lost_packets: 10,
        mos: 4.31,
        duration_secs: 8.53,
        associated_dialog: "12013223@10.0.2.20",
        orphaned: false,
        first_seen: "2026-04-14T14:53:01.830Z",
        last_seen: "2026-04-14T14:53:10.360Z",
        octet_count: 300000
      }
    ];

    this._flows = {
      "12013223@10.0.2.20": [
        { timestamp: "2026-04-14T14:52:59.666Z", is_request: true, method: "INVITE", status_code: null, reason: null, src_addr: "10.0.2.20", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 283, raw_length: 891 },
        { timestamp: "2026-04-14T14:52:59.670Z", is_request: false, method: null, status_code: 100, reason: "Trying", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 342 },
        { timestamp: "2026-04-14T14:53:00.513Z", is_request: false, method: null, status_code: 180, reason: "Ringing", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 378 },
        { timestamp: "2026-04-14T14:53:01.800Z", is_request: false, method: null, status_code: 200, reason: "OK", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 264, raw_length: 724 },
        { timestamp: "2026-04-14T14:53:01.801Z", is_request: true, method: "ACK", status_code: null, reason: null, src_addr: "10.0.2.20", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 412 },
        { timestamp: "2026-04-14T14:53:10.200Z", is_request: true, method: "BYE", status_code: null, reason: null, src_addr: "10.0.2.20", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 398 }
      ],
      "12013224@10.0.2.20": [
        { timestamp: "2026-04-14T14:53:10.100Z", is_request: true, method: "INVITE", status_code: null, reason: null, src_addr: "10.0.2.20", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 283, raw_length: 891 },
        { timestamp: "2026-04-14T14:53:10.105Z", is_request: false, method: null, status_code: 100, reason: "Trying", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 342 },
        { timestamp: "2026-04-14T14:53:10.412Z", is_request: false, method: null, status_code: 180, reason: "Ringing", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 378 },
        { timestamp: "2026-04-14T14:53:11.640Z", is_request: false, method: null, status_code: 200, reason: "OK", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 264, raw_length: 724 },
        { timestamp: "2026-04-14T14:53:11.641Z", is_request: true, method: "ACK", status_code: null, reason: null, src_addr: "10.0.2.20", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 412 }
      ],
      "78992001@10.0.3.5": [
        { timestamp: "2026-04-14T14:51:02.100Z", is_request: true, method: "REGISTER", status_code: null, reason: null, src_addr: "10.0.3.5", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 456 },
        { timestamp: "2026-04-14T14:51:02.112Z", is_request: false, method: null, status_code: 401, reason: "Unauthorized", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.3.5", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 512 },
        { timestamp: "2026-04-14T14:51:02.230Z", is_request: true, method: "REGISTER", status_code: null, reason: null, src_addr: "10.0.3.5", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 634 },
        { timestamp: "2026-04-14T14:51:02.245Z", is_request: false, method: null, status_code: 200, reason: "OK", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.3.5", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 482 }
      ],
      "44558812@10.0.2.30": [
        { timestamp: "2026-04-14T14:53:45.000Z", is_request: true, method: "INVITE", status_code: null, reason: null, src_addr: "10.0.2.30", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 283, raw_length: 891 },
        { timestamp: "2026-04-14T14:53:45.010Z", is_request: false, method: null, status_code: 100, reason: "Trying", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.30", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 342 },
        { timestamp: "2026-04-14T14:53:45.520Z", is_request: false, method: null, status_code: 404, reason: "Not Found", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.30", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 389 }
      ],
      "99001234@10.0.2.20": [
        { timestamp: "2026-04-14T14:54:00.000Z", is_request: true, method: "OPTIONS", status_code: null, reason: null, src_addr: "10.0.2.20", src_port: 5060, dst_addr: "10.0.2.15", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 312 },
        { timestamp: "2026-04-14T14:54:00.008Z", is_request: false, method: null, status_code: 200, reason: "OK", src_addr: "10.0.2.15", src_port: 5060, dst_addr: "10.0.2.20", dst_port: 5060, is_retransmission: false, body_length: 0, raw_length: 345 }
      ]
    };

    this._rawMessages = {
      "12013223@10.0.2.20": [
        "INVITE sip:service@10.0.2.15:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-1966-1-0\r\nMax-Forwards: 70\r\nFrom: \"sipp\" <sip:sipp@10.0.2.20:5060>;tag=1\r\nTo: <sip:service@10.0.2.15:5060>\r\nCall-ID: 12013223@10.0.2.20\r\nCSeq: 1 INVITE\r\nContact: <sip:sipp@10.0.2.20:5060>\r\nContent-Type: application/sdp\r\nContent-Length: 137\r\n\r\nv=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000",
        "SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-1966-1-0\r\nFrom: \"sipp\" <sip:sipp@10.0.2.20:5060>;tag=1\r\nTo: <sip:service@10.0.2.15:5060>\r\nCall-ID: 12013223@10.0.2.20\r\nCSeq: 1 INVITE\r\nContent-Length: 0",
        "SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-1966-1-0\r\nFrom: \"sipp\" <sip:sipp@10.0.2.20:5060>;tag=1\r\nTo: <sip:service@10.0.2.15:5060>;tag=314159\r\nCall-ID: 12013223@10.0.2.20\r\nCSeq: 1 INVITE\r\nContact: <sip:service@10.0.2.15:5060>\r\nContent-Length: 0",
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-1966-1-0\r\nFrom: \"sipp\" <sip:sipp@10.0.2.20:5060>;tag=1\r\nTo: <sip:service@10.0.2.15:5060>;tag=314159\r\nCall-ID: 12013223@10.0.2.20\r\nCSeq: 1 INVITE\r\nContact: <sip:service@10.0.2.15:5060>\r\nContent-Type: application/sdp\r\nContent-Length: 131\r\n\r\nv=0\r\no=- 43 43 IN IP4 10.0.2.15\r\ns=-\r\nc=IN IP4 10.0.2.15\r\nt=0 0\r\nm=audio 7000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000",
        "ACK sip:service@10.0.2.15:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-1966-1-5\r\nMax-Forwards: 70\r\nFrom: \"sipp\" <sip:sipp@10.0.2.20:5060>;tag=1\r\nTo: <sip:service@10.0.2.15:5060>;tag=314159\r\nCall-ID: 12013223@10.0.2.20\r\nCSeq: 1 ACK\r\nContent-Length: 0",
        "BYE sip:service@10.0.2.15:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.2.20:5060;branch=z9hG4bK-1966-1-7\r\nMax-Forwards: 70\r\nFrom: \"sipp\" <sip:sipp@10.0.2.20:5060>;tag=1\r\nTo: <sip:service@10.0.2.15:5060>;tag=314159\r\nCall-ID: 12013223@10.0.2.20\r\nCSeq: 2 BYE\r\nContent-Length: 0"
      ]
    };
  }

  get_streams() {
    return JSON.stringify(this._streams);
  }

  get_stream_detail(ssrc, src, dst) {
    var s = this._streams.find(function(st) {
      return st.ssrc === ssrc && st.src === src && st.dst === dst;
    });
    if (!s) return "{}";
    // Add quality_intervals and burst_gap for detail view
    return JSON.stringify(Object.assign({}, s, {
      clock_rate: 8000,
      cn_frames: 0,
      quality_intervals: [
        { timestamp: "2026-04-14T14:53:02Z", jitter_ms: 2.1, loss_pct: 0.0, packets: 250, mos: 4.41 },
        { timestamp: "2026-04-14T14:53:07Z", jitter_ms: 3.8, loss_pct: 0.5, packets: 248, mos: 4.32 },
        { timestamp: "2026-04-14T14:53:12Z", jitter_ms: 2.5, loss_pct: 0.0, packets: 250, mos: 4.40 }
      ],
      burst_gap: null
    }));
  }

  load_pcap(_data) {
    console.warn("Using MOCK session — WASM module not loaded. Showing sample data.");
    return JSON.stringify({
      packets: 4269,
      sip_messages: 20,
      dialogs: 5,
      rtp_packets: 3750,
      streams: 2
    });
  }

  get_dialogs() {
    return JSON.stringify(this._dialogs);
  }

  get_call_flow(call_id) {
    const flow = this._flows[call_id];
    return JSON.stringify(flow || []);
  }

  get_raw_message(call_id, index) {
    const msgs = this._rawMessages[call_id];
    if (msgs && msgs[index] !== undefined) {
      return msgs[index];
    }
    // Generate a plausible raw message for any dialog/index
    const flow = this._flows[call_id];
    if (!flow || !flow[index]) return "";
    const m = flow[index];
    if (m.is_request) {
      return [
        m.method + " sip:user@" + m.dst_addr + ":" + m.dst_port + " SIP/2.0",
        "Via: SIP/2.0/UDP " + m.src_addr + ":" + m.src_port + ";branch=z9hG4bK-mock",
        "From: <sip:user@" + m.src_addr + ">;tag=mock1",
        "To: <sip:user@" + m.dst_addr + ">",
        "Call-ID: " + call_id,
        "CSeq: 1 " + m.method,
        "Content-Length: 0"
      ].join("\r\n");
    }
    return [
      "SIP/2.0 " + m.status_code + " " + m.reason,
      "Via: SIP/2.0/UDP " + m.dst_addr + ":" + m.dst_port + ";branch=z9hG4bK-mock",
      "From: <sip:user@" + m.dst_addr + ">;tag=mock1",
      "To: <sip:user@" + m.src_addr + ">;tag=mock2",
      "Call-ID: " + call_id,
      "CSeq: 1 INVITE",
      "Content-Length: 0"
    ].join("\r\n");
  }

  filter(expr) {
    if (!expr || !expr.trim()) {
      return JSON.stringify(this._dialogs.map(function(d) { return d.call_id; }));
    }
    // Simple mock filter: match method or from_user or to_user
    var lower = expr.toLowerCase();
    var matching = this._dialogs.filter(function(d) {
      var hay = [d.method, d.from_user, d.to_user, d.state, d.call_id, d.src_addr, d.dst_addr].join(" ").toLowerCase();
      return hay.indexOf(lower) !== -1;
    });
    return JSON.stringify(matching.map(function(d) { return d.call_id; }));
  }

  export_json() {
    return this.get_dialogs();
  }

  export_csv() {
    var out = "call_id,method,state,from,to,src_ip,dst_ip,messages,pdd_ms,created_at\n";
    for (var i = 0; i < this._dialogs.length; i++) {
      var d = this._dialogs[i];
      out += d.call_id + "," + d.method + "," + d.state + "," + d.from_user + "," + d.to_user + "," + d.src_addr + "," + d.dst_addr + "," + d.message_count + "," + (d.pdd_ms != null ? d.pdd_ms : "") + "," + d.created_at + "\n";
    }
    return out;
  }

  export_mermaid(call_id) {
    var flow = this._flows[call_id];
    if (!flow || flow.length === 0) return "";
    var src = flow[0].src_addr + ":" + flow[0].src_port;
    var dst = flow[0].dst_addr + ":" + flow[0].dst_port;
    var srcId = src.replace(/[.:]/g, "_");
    var dstId = dst.replace(/[.:]/g, "_");
    var out = "sequenceDiagram\n";
    out += "    participant " + srcId + " as " + src + "\n";
    out += "    participant " + dstId + " as " + dst + "\n";
    for (var i = 0; i < flow.length; i++) {
      var m = flow[i];
      var from = (m.src_addr + ":" + m.src_port).replace(/[.:]/g, "_");
      var to = (m.dst_addr + ":" + m.dst_port).replace(/[.:]/g, "_");
      var arrow = m.is_request ? "->>" : "-->>";
      var label = m.is_request ? m.method : (m.status_code + " " + m.reason);
      out += "    " + from + arrow + to + ": " + label + "\n";
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Session initialization (WASM with mock fallback)
// ---------------------------------------------------------------------------

var session;

async function initSession() {
  try {
    var wasm = await import("/wasm/sipnab.js?v=2");
    await wasm.default();
    session = new wasm.SipnabSession();
    console.log("sipnab WASM module loaded");
  } catch (e) {
    console.warn("WASM load failed:", e.message || e, "— using sample data");
    session = new MockSipnabSession();
  }
}

// ---------------------------------------------------------------------------
// DOM references
// ---------------------------------------------------------------------------

function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

var allDialogs = [];
var allStreams = [];
var filteredCallIds = null;
var selectedCallId = null;
var selectedMsgIndex = null;
var selectedStream = null;  // { ssrc, src, dst }
var currentFlow = [];
var activeTab = "dialogs";
var sortColumn = "index";
var sortAsc = true;
var streamSortColumn = "ssrc";
var streamSortAsc = true;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(str) {
  var div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function getMethodColor(method) {
  var m = (method || "").toUpperCase();
  var map = {
    INVITE: "var(--color-invite)",
    ACK: "var(--color-ack)",
    BYE: "var(--color-bye)",
    CANCEL: "var(--color-cancel)",
    REGISTER: "var(--color-register)",
    OPTIONS: "var(--color-options)"
  };
  return map[m] || "var(--text-dim)";
}

function getStatusColor(code) {
  if (!code) return "var(--text-dim)";
  if (code < 200) return "var(--color-provisional)";
  if (code < 300) return "var(--color-success)";
  if (code < 400) return "var(--color-redirect)";
  if (code < 500) return "var(--color-client-err)";
  return "var(--color-server-err)";
}

function downloadBlob(content, filename, mime) {
  var blob = new Blob([content], { type: mime });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// File handling
// ---------------------------------------------------------------------------

function setupDropzone() {
  var dropzone = $("#dropzone");
  var fileInput = $("#file-input");
  var inner = dropzone.querySelector(".dropzone-inner");

  inner.addEventListener("click", function() { fileInput.click(); });

  fileInput.addEventListener("change", function(e) {
    if (e.target.files.length > 0) handleFile(e.target.files[0]);
  });

  dropzone.addEventListener("dragover", function(e) {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.add("drag-over");
  });

  dropzone.addEventListener("dragleave", function(e) {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("drag-over");
  });

  dropzone.addEventListener("drop", function(e) {
    e.preventDefault();
    e.stopPropagation();
    dropzone.classList.remove("drag-over");
    if (e.dataTransfer.files.length > 0) handleFile(e.dataTransfer.files[0]);
  });

  // Also support paste
  document.addEventListener("paste", function(e) {
    var items = e.clipboardData ? e.clipboardData.items : null;
    if (!items) return;
    for (var i = 0; i < items.length; i++) {
      if (items[i].kind === "file") {
        handleFile(items[i].getAsFile());
        return;
      }
    }
  });
}

function showLoading(filename) {
  var overlay = document.createElement("div");
  overlay.className = "analyze-loading";
  overlay.id = "loading-overlay";
  var spinner = document.createElement("div");
  spinner.className = "analyze-loading-spinner";
  var text = document.createElement("div");
  text.className = "analyze-loading-text";
  text.textContent = "Analyzing " + filename + "...";
  overlay.appendChild(spinner);
  overlay.appendChild(text);
  document.body.appendChild(overlay);
}

function hideLoading() {
  var overlay = $("#loading-overlay");
  if (overlay) overlay.remove();
}

async function handleFile(file) {
  var validExts = [".pcap", ".pcapng", ".cap"];
  var dot = file.name.lastIndexOf(".");
  var ext = dot >= 0 ? file.name.substring(dot).toLowerCase() : "";
  if (validExts.indexOf(ext) === -1) {
    alert("Unsupported file type. Please use .pcap, .pcapng, or .cap files.");
    return;
  }

  showLoading(file.name);

  var buffer = await file.arrayBuffer();
  var data = new Uint8Array(buffer);

  // Small delay so the loading overlay renders
  await new Promise(function(r) { setTimeout(r, 50); });

  try {
    var resultStr = session.load_pcap(data);
    var result = JSON.parse(resultStr);

    var isMock = session instanceof MockSipnabSession;
    $("#topbar-filename").textContent = isMock
      ? file.name + " (demo mode — WASM loading failed, showing sample data)"
      : file.name;
    updateStat("topbar-packets", result.packets, "pkts");
    updateStat("topbar-sip", result.sip_messages, "SIP");
    updateStat("topbar-dialogs", result.dialogs, "dialogs");
    updateStat("topbar-streams", result.streams || 0, "streams");
    updateStat("topbar-rtp", result.rtp_packets || 0, "RTP");

    allDialogs = JSON.parse(session.get_dialogs());
    allStreams = (typeof session.get_streams === "function") ? JSON.parse(session.get_streams()) : [];
    filteredCallIds = null;
    selectedCallId = null;
    selectedMsgIndex = null;
    selectedStream = null;
    currentFlow = [];

    $("#dropzone").style.display = "none";
    $("#workspace").style.display = "flex";

    renderDialogList();
    renderStreamList();
    clearCallFlow();
    clearRawMessage();
  } catch (err) {
    alert("Failed to parse file: " + (err.message || err));
  } finally {
    hideLoading();
  }
}

function updateStat(id, value, label) {
  var el = document.getElementById(id);
  var strong = document.createElement("strong");
  strong.textContent = value.toLocaleString();
  el.textContent = "";
  el.appendChild(strong);
  el.appendChild(document.createTextNode(" " + label));
}

// ---------------------------------------------------------------------------
// Dialog list
// ---------------------------------------------------------------------------

function getVisibleDialogs() {
  if (!filteredCallIds) return allDialogs;
  var idSet = {};
  for (var i = 0; i < filteredCallIds.length; i++) idSet[filteredCallIds[i]] = true;
  return allDialogs.filter(function(d) { return idSet[d.call_id]; });
}

function sortDialogs(dialogs) {
  var sorted = dialogs.slice();
  sorted.sort(function(a, b) {
    var va, vb;
    if (sortColumn === "index") {
      va = allDialogs.indexOf(a);
      vb = allDialogs.indexOf(b);
    } else if (sortColumn === "message_count" || sortColumn === "pdd_ms" || sortColumn === "setup_ms") {
      va = a[sortColumn] != null ? a[sortColumn] : -1;
      vb = b[sortColumn] != null ? b[sortColumn] : -1;
    } else {
      va = (a[sortColumn] || "").toString().toLowerCase();
      vb = (b[sortColumn] || "").toString().toLowerCase();
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    }
    return sortAsc ? va - vb : vb - va;
  });
  return sorted;
}

function renderDialogList() {
  var tbody = $("#call-list-body");
  // Clear via DOM
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  var visible = sortDialogs(getVisibleDialogs());

  for (var i = 0; i < visible.length; i++) {
    var d = visible[i];
    var idx = allDialogs.indexOf(d) + 1;
    var tr = document.createElement("tr");
    tr.dataset.callId = d.call_id;
    if (d.call_id === selectedCallId) tr.classList.add("selected");

    var methodClass = "method-" + (d.method || "").toLowerCase();
    var stateClass = "state-" + (d.state || "").toLowerCase();
    var pdd = d.pdd_ms != null ? d.pdd_ms + "ms" : "--";

    appendCell(tr, String(idx), "");
    appendCell(tr, d.method || "", "cell-method " + methodClass);
    appendCell(tr, d.from_user || "--", "");
    appendCell(tr, d.to_user || "--", "");
    appendCell(tr, d.src_addr || "", "");
    appendCell(tr, d.dst_addr || "", "");
    appendCell(tr, d.state || "", stateClass);
    appendCell(tr, String(d.message_count), "");
    appendCell(tr, pdd, "cell-pdd");

    tr.addEventListener("click", (function(callId) {
      return function() { selectDialog(callId); };
    })(d.call_id));

    tbody.appendChild(tr);
  }
}

function appendCell(tr, text, className) {
  var td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  tr.appendChild(td);
}

function selectDialog(callId) {
  selectedCallId = callId;
  selectedMsgIndex = null;

  var rows = $$("#call-list-body tr");
  for (var i = 0; i < rows.length; i++) {
    rows[i].classList.toggle("selected", rows[i].dataset.callId === callId);
  }

  var flowStr = session.get_call_flow(callId);
  currentFlow = JSON.parse(flowStr);
  renderCallFlow();

  // Auto-select first message so raw SIP is always visible
  if (currentFlow.length > 0) {
    selectMessage(0);
  } else {
    clearRawMessage();
  }
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

function setupSorting() {
  var headers = $$(".call-list th.sortable");
  for (var i = 0; i < headers.length; i++) {
    headers[i].addEventListener("click", (function(th) {
      return function() {
        var col = th.dataset.sort;
        if (sortColumn === col) {
          sortAsc = !sortAsc;
        } else {
          sortColumn = col;
          sortAsc = true;
        }

        var allHeaders = $$(".call-list th.sortable");
        for (var j = 0; j < allHeaders.length; j++) {
          allHeaders[j].classList.remove("sort-active", "sort-asc", "sort-desc");
        }
        th.classList.add("sort-active", sortAsc ? "sort-asc" : "sort-desc");

        renderDialogList();
      };
    })(headers[i]));
  }
}

// ---------------------------------------------------------------------------
// Call Flow Rendering
// ---------------------------------------------------------------------------

function renderCallFlow() {
  var container = $("#flow-container");
  var placeholder = $("#flow-placeholder");
  var endpointsEl = $("#flow-endpoints");
  var messagesEl = $("#flow-messages");

  if (currentFlow.length === 0) {
    container.style.display = "none";
    placeholder.style.display = "flex";
    return;
  }

  container.style.display = "block";
  placeholder.style.display = "none";

  // Discover unique endpoints (preserving insertion order)
  var endpointKeys = [];
  var endpointIndex = {};
  for (var i = 0; i < currentFlow.length; i++) {
    var m = currentFlow[i];
    var src = m.src_addr + ":" + m.src_port;
    var dst = m.dst_addr + ":" + m.dst_port;
    if (endpointIndex[src] === undefined) {
      endpointIndex[src] = endpointKeys.length;
      endpointKeys.push(src);
    }
    if (endpointIndex[dst] === undefined) {
      endpointIndex[dst] = endpointKeys.length;
      endpointKeys.push(dst);
    }
  }

  var colCount = endpointKeys.length;

  // Render endpoint headers
  while (endpointsEl.firstChild) endpointsEl.removeChild(endpointsEl.firstChild);
  for (var e = 0; e < endpointKeys.length; e++) {
    var div = document.createElement("div");
    div.className = "flow-endpoint";
    div.textContent = endpointKeys[e];
    endpointsEl.appendChild(div);
  }

  // Compute base timestamp
  var baseTs = new Date(currentFlow[0].timestamp).getTime();

  // Render messages
  while (messagesEl.firstChild) messagesEl.removeChild(messagesEl.firstChild);

  // Add swim lane lines
  for (var l = 0; l < colCount; l++) {
    var lane = document.createElement("div");
    lane.className = "flow-lane";
    var pct = colCount === 1 ? 50 : (l / (colCount - 1)) * 100;
    lane.style.left = "calc(72px + (100% - 72px) * " + (pct / 100) + ")";
    messagesEl.appendChild(lane);
  }

  for (var i = 0; i < currentFlow.length; i++) {
    var m = currentFlow[i];
    var row = document.createElement("div");
    row.className = "flow-msg";
    row.dataset.index = i;
    if (m.is_retransmission) row.classList.add("retransmission");
    if (i === selectedMsgIndex) row.classList.add("selected");

    // Time offset
    var ts = new Date(m.timestamp).getTime();
    var delta = ((ts - baseTs) / 1000).toFixed(3);
    var timeSpan = document.createElement("span");
    timeSpan.className = "flow-time";
    timeSpan.textContent = "+" + delta + "s";

    // Arrow area
    var arrowArea = document.createElement("span");
    arrowArea.className = "flow-arrow-area";

    var srcKey = m.src_addr + ":" + m.src_port;
    var dstKey = m.dst_addr + ":" + m.dst_port;
    var srcCol = endpointIndex[srcKey];
    var dstCol = endpointIndex[dstKey];

    var srcPct = colCount === 1 ? 50 : (srcCol / (colCount - 1)) * 100;
    var dstPct = colCount === 1 ? 50 : (dstCol / (colCount - 1)) * 100;
    var leftPct = Math.min(srcPct, dstPct);
    var rightPct = Math.max(srcPct, dstPct);
    var goingRight = srcCol <= dstCol;

    // Build arrow
    var arrow = document.createElement("span");
    var isReq = m.is_request;
    arrow.className = "flow-arrow " + (isReq ? "request" : "response") + " " + (goingRight ? "right" : "left");
    arrow.style.left = leftPct + "%";
    arrow.style.width = (rightPct - leftPct || 3) + "%";

    var line = document.createElement("span");
    line.className = "flow-line";

    // Color the response line
    if (!isReq && m.status_code) {
      var sc = m.status_code;
      var lineColor;
      if (sc < 200) lineColor = "var(--color-provisional)";
      else if (sc < 300) lineColor = "var(--color-success)";
      else if (sc < 400) lineColor = "var(--color-redirect)";
      else if (sc < 500) lineColor = "var(--color-client-err)";
      else lineColor = "var(--color-server-err)";
      line.style.background = "repeating-linear-gradient(to right, " + lineColor + " 0px, " + lineColor + " 4px, transparent 4px, transparent 8px)";
    }

    var label = document.createElement("span");
    label.className = "flow-label";

    var labelText, labelColorClass;
    if (isReq) {
      labelText = m.method || "?";
      labelColorClass = "flow-label-" + (m.method || "").toLowerCase();
    } else {
      labelText = m.status_code + " " + (m.reason || "");
      var century = Math.floor((m.status_code || 0) / 100);
      labelColorClass = "flow-label-" + century + "xx";
    }
    label.textContent = labelText;
    label.classList.add(labelColorClass);

    var head = document.createElement("span");
    head.className = "flow-head";

    if (isReq) {
      head.style.color = getMethodColor(m.method);
    } else {
      head.style.color = getStatusColor(m.status_code);
    }

    if (goingRight) {
      head.textContent = "\u25B6"; // right triangle
      arrow.appendChild(line);
      arrow.appendChild(head);
    } else {
      head.textContent = "\u25C0"; // left triangle
      arrow.appendChild(head);
      arrow.appendChild(line);
    }

    arrow.appendChild(label);
    arrowArea.appendChild(arrow);

    row.appendChild(timeSpan);
    row.appendChild(arrowArea);

    row.addEventListener("click", (function(idx) {
      return function() { selectMessage(idx); };
    })(i));

    messagesEl.appendChild(row);
  }
}

function clearCallFlow() {
  $("#flow-container").style.display = "none";
  $("#flow-placeholder").style.display = "flex";
  var ep = $("#flow-endpoints");
  while (ep.firstChild) ep.removeChild(ep.firstChild);
  var fm = $("#flow-messages");
  while (fm.firstChild) fm.removeChild(fm.firstChild);
}

// ---------------------------------------------------------------------------
// Raw Message
// ---------------------------------------------------------------------------

function selectMessage(index) {
  selectedMsgIndex = index;

  var rows = $$("#flow-messages .flow-msg");
  for (var i = 0; i < rows.length; i++) {
    rows[i].classList.toggle("selected", parseInt(rows[i].dataset.index) === index);
  }

  var raw = session.get_raw_message(selectedCallId, index);
  if (raw) {
    $("#raw-placeholder").style.display = "none";
    var pre = $("#raw-message");
    pre.style.display = "block";
    // Use safe DOM-based rendering for the raw message
    renderHighlightedSip(pre, raw);
  } else {
    clearRawMessage();
  }
}

function clearRawMessage() {
  $("#raw-placeholder").style.display = "flex";
  $("#raw-message").style.display = "none";
  var pre = $("#raw-message");
  while (pre.firstChild) pre.removeChild(pre.firstChild);
}

// ---------------------------------------------------------------------------
// SIP Syntax Highlighting (DOM-based, no innerHTML)
// ---------------------------------------------------------------------------

function renderHighlightedSip(container, raw) {
  while (container.firstChild) container.removeChild(container.firstChild);

  var lines = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  var inBody = false;

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    if (i > 0) container.appendChild(document.createTextNode("\n"));

    if (!inBody && line === "") {
      inBody = true;
      continue;
    }

    if (inBody) {
      var sdpMatch = line.match(/^([a-z])=(.*)/);
      if (sdpMatch) {
        appendSpan(container, sdpMatch[1] + "=", "sip-body-key");
        appendSpan(container, sdpMatch[2], "sip-body");
      } else {
        appendSpan(container, line, "sip-body");
      }
      continue;
    }

    if (i === 0) {
      var reqMatch = line.match(/^(\S+)\s+(sip:\S+)\s+(SIP\/2\.0)$/i);
      if (reqMatch) {
        appendSpan(container, reqMatch[1], "sip-method");
        container.appendChild(document.createTextNode(" "));
        appendSpan(container, reqMatch[2], "sip-uri");
        container.appendChild(document.createTextNode(" "));
        appendSpan(container, reqMatch[3], "sip-version");
        continue;
      }
      var statusMatch = line.match(/^(SIP\/2\.0)\s+(\d{3})\s+(.*)$/i);
      if (statusMatch) {
        appendSpan(container, statusMatch[1], "sip-version");
        container.appendChild(document.createTextNode(" "));
        appendSpan(container, statusMatch[2], "sip-status-code");
        container.appendChild(document.createTextNode(" "));
        appendSpan(container, statusMatch[3], "sip-status-reason");
        continue;
      }
    }

    // Header line
    var headerMatch = line.match(/^([^:]+)(:)\s?(.*)$/);
    if (headerMatch) {
      appendSpan(container, headerMatch[1], "sip-header-name");
      appendSpan(container, ":", "sip-header-sep");
      container.appendChild(document.createTextNode(" " + headerMatch[3]));
    } else {
      container.appendChild(document.createTextNode(line));
    }
  }
}

function appendSpan(parent, text, className) {
  var span = document.createElement("span");
  span.className = className;
  span.textContent = text;
  parent.appendChild(span);
}

// ---------------------------------------------------------------------------
// Filter
// ---------------------------------------------------------------------------

// Detect if input looks like a DSL expression (contains operators)
function isDslExpression(s) {
  return /[=!<>~]/.test(s) || /\bAND\b|\bOR\b|\bNOT\b/i.test(s);
}

// Simple text search across all dialog fields
function textSearch(query) {
  var q = query.toLowerCase();
  return allDialogs
    .filter(function(d) {
      return (d.call_id || "").toLowerCase().indexOf(q) >= 0
        || (d.method || "").toLowerCase().indexOf(q) >= 0
        || (d.from_user || "").toLowerCase().indexOf(q) >= 0
        || (d.to_user || "").toLowerCase().indexOf(q) >= 0
        || (d.src_addr || "").toLowerCase().indexOf(q) >= 0
        || (d.dst_addr || "").toLowerCase().indexOf(q) >= 0
        || (d.state || "").toLowerCase().indexOf(q) >= 0;
    })
    .map(function(d) { return d.call_id; });
}

function setupFilter() {
  var input = $("#filter-input");
  var debounce = null;

  input.addEventListener("input", function() {
    clearTimeout(debounce);
    debounce = setTimeout(function() {
      var expr = input.value.trim();
      if (!expr) {
        filteredCallIds = null;
      } else if (isDslExpression(expr)) {
        // DSL filter: method == 'INVITE' AND rtp.mos < 3.0
        try {
          var resultStr = session.filter(expr);
          filteredCallIds = JSON.parse(resultStr);
        } catch (_e) {
          // DSL parse failed — fall back to text search
          filteredCallIds = textSearch(expr);
        }
      } else {
        // Simple text search across all columns
        filteredCallIds = textSearch(expr);
      }
      renderDialogList();
    }, 200);
  });

  input.addEventListener("keydown", function(e) {
    if (e.key === "Escape") {
      input.value = "";
      filteredCallIds = null;
      renderDialogList();
      input.blur();
    }
  });
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

function setupExport() {
  var btn = $("#export-btn");
  var dropdown = $("#export-dropdown");

  btn.addEventListener("click", function(e) {
    e.stopPropagation();
    dropdown.classList.toggle("open");
  });

  document.addEventListener("click", function() {
    dropdown.classList.remove("open");
  });

  var items = dropdown.querySelectorAll("button");
  for (var i = 0; i < items.length; i++) {
    items[i].addEventListener("click", function(e) {
      e.stopPropagation();
      var format = this.dataset.format;
      exportData(format);
      dropdown.classList.remove("open");
    });
  }
}

function exportData(format) {
  var content, filename, mime;

  switch (format) {
    case "json":
      content = session.export_json();
      filename = "sipnab-dialogs.json";
      mime = "application/json";
      break;
    case "csv":
      content = session.export_csv();
      filename = "sipnab-dialogs.csv";
      mime = "text/csv";
      break;
    case "mermaid":
      if (!selectedCallId) {
        alert("Select a dialog first to export its Mermaid diagram.");
        return;
      }
      content = session.export_mermaid(selectedCallId);
      filename = "sipnab-flow-" + selectedCallId.replace(/[^a-zA-Z0-9]/g, "_") + ".mmd";
      mime = "text/plain";
      break;
    default:
      return;
  }

  downloadBlob(content, filename, mime);
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

function setupClear() {
  $("#clear-btn").addEventListener("click", function() {
    allDialogs = [];
    allStreams = [];
    filteredCallIds = null;
    selectedCallId = null;
    selectedMsgIndex = null;
    selectedStream = null;
    currentFlow = [];

    $("#workspace").style.display = "none";
    $("#dropzone").style.display = "flex";
    $("#filter-input").value = "";

    var tbody = $("#call-list-body");
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    var stbody = $("#stream-list-body");
    while (stbody.firstChild) stbody.removeChild(stbody.firstChild);
    clearCallFlow();
    clearRawMessage();
    clearStreamDetail();

    // Reset to dialogs tab
    switchTab("dialogs");
  });
}

// ---------------------------------------------------------------------------
// Panel resizing
// ---------------------------------------------------------------------------

function setupResize() {
  setupResizeHandle($("#resize-h"), "horizontal");
  setupResizeHandle($("#resize-v"), "vertical");
}

function setupResizeHandle(handle, direction) {
  var startPos, startSize;

  function onMouseDown(e) {
    e.preventDefault();
    handle.classList.add("active");
    startPos = direction === "horizontal" ? e.clientX : e.clientY;

    if (direction === "horizontal") {
      startSize = $("#panel-left").getBoundingClientRect().width;
    } else {
      startSize = $("#panel-flow").getBoundingClientRect().height;
    }

    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = direction === "horizontal" ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";
  }

  function onMouseMove(e) {
    var currentPos = direction === "horizontal" ? e.clientX : e.clientY;
    var diff = currentPos - startPos;
    var newSize = startSize + diff;

    if (direction === "horizontal") {
      var containerW = $("#panels").getBoundingClientRect().width;
      var pctH = Math.max(15, Math.min(75, (newSize / containerW) * 100));
      $("#panel-left").style.width = pctH + "%";
    } else {
      var containerH = $("#panel-right").getBoundingClientRect().height;
      var pctV = Math.max(15, Math.min(85, (newSize / containerH) * 100));
      $("#panel-flow").style.flex = "none";
      $("#panel-flow").style.height = pctV + "%";
      $("#panel-raw").style.height = (100 - pctV) + "%";
    }
  }

  function onMouseUp() {
    handle.classList.remove("active");
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }

  handle.addEventListener("mousedown", onMouseDown);
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts
// ---------------------------------------------------------------------------

function toggleHelpPopup() {
  var popup = $("#help-popup");
  if (!popup) return;
  if (popup.style.display === "none" || !popup.style.display) {
    popup.style.display = "flex";
  } else {
    popup.style.display = "none";
  }
}

function navigateList(selector, direction) {
  var trs = $$(selector);
  if (trs.length === 0) return;
  var currentIdx = -1;
  for (var i = 0; i < trs.length; i++) {
    if (trs[i].classList.contains("selected")) { currentIdx = i; break; }
  }
  var nextIdx;
  if (direction > 0) {
    nextIdx = Math.min(currentIdx + 1, trs.length - 1);
  } else {
    nextIdx = Math.max(currentIdx - 1, 0);
  }
  if (nextIdx >= 0) {
    trs[nextIdx].click();
    trs[nextIdx].scrollIntoView({ block: "nearest" });
  }
}

function setupKeyboard() {
  document.addEventListener("keydown", function(e) {
    // Let Escape close help popup first, then blur/go back
    if (e.key === "Escape") {
      var helpPopup = $("#help-popup");
      if (helpPopup && helpPopup.style.display !== "none" && helpPopup.style.display) {
        helpPopup.style.display = "none";
        return;
      }
      if (e.target.tagName === "INPUT") {
        e.target.blur();
        return;
      }
      // If workspace is visible and we have a selection, clear it step by step
      if ($("#workspace").style.display !== "none") {
        // Streams tab: clear stream selection
        if (activeTab === "streams" && selectedStream !== null) {
          selectedStream = null;
          var strs = $$("#stream-list-body tr");
          for (var i = 0; i < strs.length; i++) strs[i].classList.remove("selected");
          clearStreamDetail();
          $("#panel-flow-header").textContent = "Stream Detail";
          $("#flow-placeholder").textContent = "Select a stream to view its quality metrics";
          $("#flow-placeholder").style.display = "flex";
          $("#raw-placeholder").textContent = "Select a stream to view burst/gap analysis";
          $("#raw-placeholder").style.display = "flex";
          return;
        }
        // Dialogs tab: step back through message -> dialog selection
        if (selectedMsgIndex !== null) {
          selectedMsgIndex = null;
          var rows = $$("#flow-messages .flow-msg");
          for (var i = 0; i < rows.length; i++) rows[i].classList.remove("selected");
          clearRawMessage();
          return;
        }
        if (selectedCallId !== null) {
          selectedCallId = null;
          var trs = $$("#call-list-body tr");
          for (var i = 0; i < trs.length; i++) trs[i].classList.remove("selected");
          clearCallFlow();
          clearRawMessage();
          return;
        }
      }
      return;
    }

    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;

    // Only handle keys when workspace is visible
    var wsVisible = $("#workspace") && $("#workspace").style.display !== "none";

    // Help popup
    if (e.key === "h" || e.key === "H" || e.key === "?") {
      e.preventDefault();
      toggleHelpPopup();
      return;
    }
    // Export dropdown
    if ((e.key === "e" || e.key === "E") && wsVisible) {
      e.preventDefault();
      var dropdown = $("#export-dropdown");
      if (dropdown) dropdown.classList.toggle("open");
      return;
    }
    // Search / filter
    if ((e.key === "f" || e.key === "F") && wsVisible) {
      e.preventDefault();
      var filterInput = $("#filter-input");
      if (filterInput) filterInput.focus();
      return;
    }

    if (!wsVisible) return;

    // 1/2 — switch tabs
    if (e.key === "1") { e.preventDefault(); switchTab("dialogs"); return; }
    if (e.key === "2") { e.preventDefault(); switchTab("streams"); return; }

    // j/k/arrows — context-dependent navigation
    if (e.key === "j" || e.key === "J" || e.key === "ArrowDown") {
      e.preventDefault();
      if (activeTab === "streams") {
        navigateList("#stream-list-body tr", 1);
      } else if (selectedCallId && currentFlow.length > 0) {
        // Navigate flow messages
        var newIdx = (selectedMsgIndex === null) ? 0 : Math.min(selectedMsgIndex + 1, currentFlow.length - 1);
        selectMessage(newIdx);
        var flowRows = $$("#flow-messages .flow-msg");
        if (flowRows[newIdx]) flowRows[newIdx].scrollIntoView({ block: "nearest" });
      } else {
        navigateList("#call-list-body tr", 1);
      }
      return;
    }
    if (e.key === "k" || e.key === "K" || e.key === "ArrowUp") {
      e.preventDefault();
      if (activeTab === "streams") {
        navigateList("#stream-list-body tr", -1);
      } else if (selectedCallId && currentFlow.length > 0) {
        // Navigate flow messages
        var newIdx = (selectedMsgIndex === null) ? 0 : Math.max(selectedMsgIndex - 1, 0);
        selectMessage(newIdx);
        var flowRows = $$("#flow-messages .flow-msg");
        if (flowRows[newIdx]) flowRows[newIdx].scrollIntoView({ block: "nearest" });
      } else {
        navigateList("#call-list-body tr", -1);
      }
      return;
    }

    // Enter — if dialog selected with no message, select first message
    if (e.key === "Enter" && selectedCallId && selectedMsgIndex === null) {
      e.preventDefault();
      if (currentFlow.length > 0) selectMessage(0);
      // Already showing flow when dialog is selected
      return;
    }

    // q — back to drop zone (quit)
    if (e.key === "q" || e.key === "Q") {
      e.preventDefault();
      var clearBtn = $("#clear-btn");
      if (clearBtn) clearBtn.click();
      return;
    }

    // o — open new file
    if (e.key === "o" || e.key === "O") {
      e.preventDefault();
      var fileInput = $("#file-input");
      if (fileInput) fileInput.click();
      return;
    }
  });
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------

function switchTab(tab) {
  activeTab = tab;
  var tabs = $$(".panel-tab");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.toggle("active", tabs[i].dataset.tab === tab);
  }
  var contents = $$(".tab-content");
  for (var i = 0; i < contents.length; i++) {
    contents[i].classList.toggle("active", contents[i].id === "tab-content-" + tab);
  }

  // When switching to dialogs tab, restore dialog detail view
  if (tab === "dialogs") {
    clearStreamDetail();
    if (selectedCallId) {
      selectDialog(selectedCallId);
    } else {
      clearCallFlow();
      clearRawMessage();
    }
  }
  // When switching to streams tab, restore stream detail view
  if (tab === "streams") {
    if (selectedStream) {
      showStreamDetail(selectedStream.ssrc, selectedStream.src, selectedStream.dst);
    } else {
      clearCallFlow();
      clearRawMessage();
      clearStreamDetail();
      $("#panel-flow-header").textContent = "Stream Detail";
      $("#flow-placeholder").textContent = "Select a stream to view its quality metrics";
      $("#flow-placeholder").style.display = "flex";
      $("#raw-placeholder").textContent = "Select a stream to view burst/gap analysis";
      $("#raw-placeholder").style.display = "flex";
    }
  }
}

function setupTabs() {
  var tabs = $$(".panel-tab");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].addEventListener("click", (function(tab) {
      return function() { switchTab(tab.dataset.tab); };
    })(tabs[i]));
  }
}

// ---------------------------------------------------------------------------
// RTP Stream list rendering
// ---------------------------------------------------------------------------

function getMosClass(mos) {
  if (mos >= 4.0) return "mos-good";
  if (mos >= 3.0) return "mos-fair";
  return "mos-poor";
}

function formatSsrc(ssrc) {
  return "0x" + (ssrc >>> 0).toString(16).toUpperCase().padStart(8, "0");
}

function sortStreams(streams) {
  var sorted = streams.slice();
  sorted.sort(function(a, b) {
    var col = streamSortColumn;
    var va, vb;
    if (col === "packets" || col === "jitter_ms" || col === "loss_pct" || col === "mos" || col === "duration_secs" || col === "ssrc") {
      va = a[col] != null ? a[col] : -1;
      vb = b[col] != null ? b[col] : -1;
      return streamSortAsc ? va - vb : vb - va;
    }
    va = (a[col] || "").toString().toLowerCase();
    vb = (b[col] || "").toString().toLowerCase();
    if (va < vb) return streamSortAsc ? -1 : 1;
    if (va > vb) return streamSortAsc ? 1 : -1;
    return 0;
  });
  return sorted;
}

function renderStreamList() {
  var tbody = $("#stream-list-body");
  var emptyEl = $("#stream-empty");
  while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

  if (allStreams.length === 0) {
    emptyEl.style.display = "block";
    // Update tab label to show count
    $("#tab-streams").textContent = "RTP Streams";
    return;
  }

  emptyEl.style.display = "none";
  $("#tab-streams").textContent = "RTP Streams (" + allStreams.length + ")";

  var sorted = sortStreams(allStreams);

  for (var i = 0; i < sorted.length; i++) {
    var s = sorted[i];
    var tr = document.createElement("tr");
    tr.dataset.ssrc = s.ssrc;
    tr.dataset.src = s.src;
    tr.dataset.dst = s.dst;

    if (selectedStream && selectedStream.ssrc === s.ssrc && selectedStream.src === s.src && selectedStream.dst === s.dst) {
      tr.classList.add("selected");
    }

    appendCell(tr, formatSsrc(s.ssrc), "");
    appendCell(tr, s.codec || "?", "");
    appendCell(tr, s.src, "");
    appendCell(tr, s.dst, "");
    appendCell(tr, String(s.packets), "");
    appendCell(tr, s.jitter_ms.toFixed(2) + "ms", "");
    appendCell(tr, s.loss_pct.toFixed(2) + "%", s.loss_pct > 5 ? "mos-poor" : s.loss_pct > 1 ? "mos-fair" : "");
    appendCell(tr, s.mos.toFixed(2), getMosClass(s.mos));
    appendCell(tr, s.duration_secs.toFixed(1) + "s", "");

    tr.addEventListener("click", (function(stream) {
      return function() { selectStream(stream); };
    })(s));

    tbody.appendChild(tr);
  }
}

function selectStream(s) {
  selectedStream = { ssrc: s.ssrc, src: s.src, dst: s.dst };

  var rows = $$("#stream-list-body tr");
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var match = parseInt(row.dataset.ssrc) === s.ssrc && row.dataset.src === s.src && row.dataset.dst === s.dst;
    row.classList.toggle("selected", match);
  }

  showStreamDetail(s.ssrc, s.src, s.dst);
}

function setupStreamSorting() {
  var headers = $$(".stream-sortable");
  for (var i = 0; i < headers.length; i++) {
    headers[i].addEventListener("click", (function(th) {
      return function() {
        var col = th.dataset.sort;
        if (streamSortColumn === col) {
          streamSortAsc = !streamSortAsc;
        } else {
          streamSortColumn = col;
          streamSortAsc = true;
        }

        var allHeaders = $$(".stream-sortable");
        for (var j = 0; j < allHeaders.length; j++) {
          allHeaders[j].classList.remove("sort-active", "sort-asc", "sort-desc");
        }
        th.classList.add("sort-active", streamSortAsc ? "sort-asc" : "sort-desc");

        renderStreamList();
      };
    })(headers[i]));
  }
}

// ---------------------------------------------------------------------------
// Stream Detail View
// ---------------------------------------------------------------------------

function showStreamDetail(ssrc, src, dst) {
  var detailStr = session.get_stream_detail(ssrc, src, dst);
  var detail = JSON.parse(detailStr);
  if (!detail || !detail.ssrc) {
    clearStreamDetail();
    return;
  }

  // Hide call flow, show stream detail
  $("#flow-container").style.display = "none";
  $("#flow-placeholder").style.display = "none";
  $("#stream-detail").style.display = "block";
  $("#panel-flow-header").textContent = "Stream Detail";

  // Summary cards
  var summaryEl = $("#stream-detail-summary");
  while (summaryEl.firstChild) summaryEl.removeChild(summaryEl.firstChild);

  var cards = [
    { label: "SSRC", value: formatSsrc(detail.ssrc) },
    { label: "Codec", value: detail.codec + " (PT " + detail.payload_type + ")" },
    { label: "Source", value: detail.src },
    { label: "Destination", value: detail.dst },
    { label: "Packets", value: detail.packets.toLocaleString() },
    { label: "Lost", value: detail.lost_packets.toLocaleString() + " (" + detail.loss_pct.toFixed(2) + "%)" },
    { label: "Jitter", value: detail.jitter_ms.toFixed(2) + " ms" },
    { label: "MOS", value: detail.mos.toFixed(2), cls: getMosClass(detail.mos) },
    { label: "Duration", value: detail.duration_secs.toFixed(1) + "s" },
    { label: "Payload", value: formatBytes(detail.octet_count) },
    { label: "Dialog", value: detail.associated_dialog || "(orphaned)" }
  ];

  for (var i = 0; i < cards.length; i++) {
    var card = document.createElement("div");
    card.className = "stream-detail-card";

    var lbl = document.createElement("div");
    lbl.className = "label";
    lbl.textContent = cards[i].label;

    var val = document.createElement("div");
    val.className = "value";
    if (cards[i].cls) val.classList.add(cards[i].cls);
    val.textContent = cards[i].value;

    card.appendChild(lbl);
    card.appendChild(val);
    summaryEl.appendChild(card);
  }

  // Quality intervals table
  var intervalsEl = $("#stream-detail-intervals");
  while (intervalsEl.firstChild) intervalsEl.removeChild(intervalsEl.firstChild);

  var intervals = detail.quality_intervals || [];
  if (intervals.length > 0) {
    var tbl = document.createElement("table");
    var thead = document.createElement("thead");
    var headerRow = document.createElement("tr");
    var cols = ["Time", "Jitter (ms)", "Loss %", "Packets", "MOS"];
    for (var c = 0; c < cols.length; c++) {
      var th = document.createElement("th");
      th.textContent = cols[c];
      headerRow.appendChild(th);
    }
    thead.appendChild(headerRow);
    tbl.appendChild(thead);

    var tbody = document.createElement("tbody");
    for (var r = 0; r < intervals.length; r++) {
      var qi = intervals[r];
      var row = document.createElement("tr");
      appendCell(row, new Date(qi.timestamp).toLocaleTimeString(), "");
      appendCell(row, qi.jitter_ms.toFixed(2), "");
      appendCell(row, qi.loss_pct.toFixed(2), "");
      appendCell(row, String(qi.packets), "");
      appendCell(row, qi.mos.toFixed(2), getMosClass(qi.mos));
      tbody.appendChild(row);
    }
    tbl.appendChild(tbody);
    intervalsEl.appendChild(tbl);
  } else {
    var noData = document.createElement("div");
    noData.className = "stream-empty";
    noData.textContent = "No quality intervals recorded (stream too short).";
    intervalsEl.appendChild(noData);
  }

  // Burst/gap in bottom pane
  showBurstGap(detail);
}

function showBurstGap(detail) {
  var rawPlaceholder = $("#raw-placeholder");
  var rawMessage = $("#raw-message");
  var burstGapEl = $("#stream-burst-gap");

  rawPlaceholder.style.display = "none";
  rawMessage.style.display = "none";
  burstGapEl.style.display = "block";
  $("#panel-raw-header").textContent = "Burst/Gap Analysis";

  while (burstGapEl.firstChild) burstGapEl.removeChild(burstGapEl.firstChild);

  var bg = detail.burst_gap;
  if (!bg) {
    var noData = document.createElement("div");
    noData.className = "stream-empty";
    noData.textContent = "No burst/gap data (zero packet loss detected).";
    burstGapEl.appendChild(noData);
    return;
  }

  var grid = document.createElement("div");
  grid.className = "burst-gap-grid";

  var items = [
    { label: "Bursty", value: bg.is_bursty ? "Yes" : "No", cls: bg.is_bursty ? "mos-poor" : "mos-good" },
    { label: "Burst Count", value: String(bg.burst_count) },
    { label: "Avg Burst Duration", value: bg.burst_duration_ms.toFixed(1) + " ms" },
    { label: "Avg Gap Duration", value: bg.gap_duration_ms.toFixed(1) + " ms" },
    { label: "Burst Loss Rate", value: (bg.burst_loss_rate * 100).toFixed(2) + "%" },
    { label: "Gap Loss Rate", value: (bg.gap_loss_rate * 100).toFixed(2) + "%" }
  ];

  for (var i = 0; i < items.length; i++) {
    var card = document.createElement("div");
    card.className = "burst-gap-card";

    var lbl = document.createElement("div");
    lbl.className = "label";
    lbl.textContent = items[i].label;

    var val = document.createElement("div");
    val.className = "value";
    if (items[i].cls) val.classList.add(items[i].cls);
    val.textContent = items[i].value;

    card.appendChild(lbl);
    card.appendChild(val);
    grid.appendChild(card);
  }

  burstGapEl.appendChild(grid);
}

function clearStreamDetail() {
  $("#stream-detail").style.display = "none";
  var burstGapEl = $("#stream-burst-gap");
  if (burstGapEl) {
    burstGapEl.style.display = "none";
    while (burstGapEl.firstChild) burstGapEl.removeChild(burstGapEl.firstChild);
  }
  // Restore headers
  $("#panel-flow-header").textContent = "Call Flow";
  $("#panel-raw-header").textContent = "Raw Message";
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
  await initSession();
  setupDropzone();
  setupSorting();
  setupStreamSorting();
  setupTabs();
  setupFilter();
  setupExport();
  setupClear();
  setupResize();
  setupKeyboard();
}

init();
