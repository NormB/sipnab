//! WASM entry point for browser-based pcap analysis.
//! Exposes sipnab's analysis engine via wasm-bindgen JSON API.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::capture::packet::Packet;
#[cfg(target_arch = "wasm32")]
use crate::capture::parse::parse_packet;
#[cfg(target_arch = "wasm32")]
use crate::capture::pcap_reader::PcapReader;
#[cfg(target_arch = "wasm32")]
use crate::rtp::stream_store::StreamStore;
#[cfg(target_arch = "wasm32")]
use crate::sip::dialog_store::DialogStore;
#[cfg(target_arch = "wasm32")]
use crate::sip::{self, parser::parse_sip};

/// A browser-side sipnab analysis session.
/// All data stays in WASM linear memory -- nothing is uploaded.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct SipnabSession {
    dialog_store: DialogStore,
    stream_store: StreamStore,
    packet_count: u64,
    sip_count: u64,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl SipnabSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();
        Self {
            dialog_store: DialogStore::new(100_000, false),
            stream_store: StreamStore::new(50_000),
            packet_count: 0,
            sip_count: 0,
        }
    }

    /// Load a pcap file from raw bytes. Returns a JSON summary.
    pub fn load_pcap(&mut self, data: &[u8]) -> Result<String, JsError> {
        // Clear previous data
        self.dialog_store.clear();
        self.stream_store.clear();
        self.packet_count = 0;
        self.sip_count = 0;

        let reader =
            PcapReader::new(data).map_err(|e| JsError::new(&e.to_string()))?;
        let link_type = reader.link_type as i32;

        for pkt in reader {
            self.packet_count += 1;

            let ts = chrono::DateTime::from_timestamp(
                pkt.timestamp_secs as i64,
                pkt.timestamp_usecs * 1000,
            )
            .unwrap_or_default();

            let caplen = pkt.data.len();
            let orig_len = pkt.orig_len as usize;
            let capture_pkt = Packet::new(ts, pkt.data, caplen, orig_len, None, link_type);

            if let Ok(parsed) = parse_packet(&capture_pkt) {
                if !parsed.payload.is_empty()
                    && sip::is_sip_message(&parsed.payload)
                {
                    if let Ok(sip_msg) = parse_sip(
                        &parsed.payload,
                        parsed.timestamp,
                        parsed.src_addr,
                        parsed.dst_addr,
                        parsed.src_port,
                        parsed.dst_port,
                        parsed.transport,
                    ) {
                        self.dialog_store.process_message(sip_msg);
                        self.sip_count += 1;
                    }
                }
            }
        }

        Ok(serde_json::json!({
            "packets": self.packet_count,
            "sip_messages": self.sip_count,
            "dialogs": self.dialog_store.len(),
        })
        .to_string())
    }

    /// Get all dialogs as JSON array.
    pub fn get_dialogs(&self) -> String {
        let dialogs: Vec<serde_json::Value> = self
            .dialog_store
            .iter()
            .map(|d| {
                serde_json::json!({
                    "call_id": d.call_id,
                    "method": d.method,
                    "state": format!("{:?}", d.state),
                    "from_user": d.from_user,
                    "to_user": d.to_user,
                    "src_addr": d.src_addr.to_string(),
                    "dst_addr": d.dst_addr.to_string(),
                    "message_count": d.messages.len(),
                    "created_at": d.created_at.to_rfc3339(),
                    "pdd_ms": d.timing.pdd_ms(),
                    "setup_ms": d.timing.setup_ms(),
                })
            })
            .collect();
        serde_json::to_string(&dialogs).unwrap_or_default()
    }

    /// Get messages for a specific dialog as JSON.
    pub fn get_call_flow(&self, call_id: &str) -> String {
        if let Some(dialog) = self.dialog_store.get(call_id) {
            let messages: Vec<serde_json::Value> = dialog
                .messages
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "timestamp": m.timestamp.to_rfc3339(),
                        "is_request": m.is_request,
                        "method": m.method,
                        "status_code": m.status_code,
                        "reason": m.reason,
                        "src_addr": m.src_addr.to_string(),
                        "src_port": m.src_port,
                        "dst_addr": m.dst_addr.to_string(),
                        "dst_port": m.dst_port,
                        "is_retransmission": m.is_retransmission,
                        "body_length": m.body.len(),
                        "raw_length": m.raw.len(),
                    })
                })
                .collect();
            serde_json::to_string(&messages).unwrap_or_default()
        } else {
            "[]".to_string()
        }
    }

    /// Get raw SIP message text for a specific message.
    pub fn get_raw_message(&self, call_id: &str, index: usize) -> String {
        if let Some(dialog) = self.dialog_store.get(call_id) {
            if let Some(msg) = dialog.messages.get(index) {
                return String::from_utf8_lossy(&msg.raw).to_string();
            }
        }
        String::new()
    }

    /// Apply a filter expression, return matching dialog Call-IDs as JSON array.
    pub fn filter(&self, expr: &str) -> Result<String, JsError> {
        use crate::sip::dsl::FilterExpr;
        let filter = FilterExpr::parse(expr)
            .map_err(|e| JsError::new(&format!("Filter error: {e}")))?;
        let empty_streams: Vec<&crate::rtp::stream::RtpStream> = Vec::new();
        let matching: Vec<&str> = self
            .dialog_store
            .iter()
            .filter(|d| filter.matches_dialog(d, &empty_streams))
            .map(|d| d.call_id.as_str())
            .collect();
        Ok(serde_json::to_string(&matching).unwrap_or_default())
    }

    /// Export all dialogs as JSON.
    pub fn export_json(&self) -> String {
        self.get_dialogs()
    }

    /// Export as CSV.
    pub fn export_csv(&self) -> String {
        let mut out = String::from(
            "call_id,method,state,from,to,src_ip,dst_ip,messages,pdd_ms,created_at\n",
        );
        for d in self.dialog_store.iter() {
            out.push_str(&format!(
                "{},{},{:?},{},{},{},{},{},{},{}\n",
                d.call_id,
                d.method,
                d.state,
                d.from_user.as_deref().unwrap_or("-"),
                d.to_user.as_deref().unwrap_or("-"),
                d.src_addr,
                d.dst_addr,
                d.messages.len(),
                d.timing.pdd_ms().unwrap_or(-1),
                d.created_at.to_rfc3339(),
            ));
        }
        out
    }

    /// Export as Mermaid sequence diagram for a specific dialog.
    pub fn export_mermaid(&self, call_id: &str) -> String {
        if let Some(dialog) = self.dialog_store.get(call_id) {
            let mut out = String::from("sequenceDiagram\n");
            let first_src_port = dialog
                .messages
                .first()
                .map(|m| m.src_port)
                .unwrap_or(0);
            let first_dst_port = dialog
                .messages
                .first()
                .map(|m| m.dst_port)
                .unwrap_or(0);
            let src_participant =
                format!("{}_{}", dialog.src_addr, first_src_port)
                    .replace('.', "_")
                    .replace(':', "_");
            let dst_participant =
                format!("{}_{}", dialog.dst_addr, first_dst_port)
                    .replace('.', "_")
                    .replace(':', "_");
            out.push_str(&format!(
                "    participant {} as {}:{}\n",
                src_participant, dialog.src_addr, first_src_port
            ));
            out.push_str(&format!(
                "    participant {} as {}:{}\n",
                dst_participant, dialog.dst_addr, first_dst_port
            ));
            for msg in &dialog.messages {
                let from = format!("{}_{}", msg.src_addr, msg.src_port)
                    .replace('.', "_")
                    .replace(':', "_");
                let to = format!("{}_{}", msg.dst_addr, msg.dst_port)
                    .replace('.', "_")
                    .replace(':', "_");
                let arrow = if msg.is_request { "->>" } else { "-->>" };
                let label = if msg.is_request {
                    msg.method.as_deref().unwrap_or("?").to_string()
                } else {
                    format!(
                        "{} {}",
                        msg.status_code.unwrap_or(0),
                        msg.reason.as_deref().unwrap_or("")
                    )
                };
                out.push_str(&format!("    {}{}{}: {}\n", from, arrow, to, label));
            }
            out
        } else {
            String::new()
        }
    }

    pub fn dialog_count(&self) -> u32 {
        self.dialog_store.len() as u32
    }
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }
    pub fn sip_message_count(&self) -> u64 {
        self.sip_count
    }
}
