// snippet:start sipnab-client
// Cargo.toml [dependencies]:
//   anyhow = "1"
//   reqwest = { version = "0.13", default-features = false, features = ["blocking", "json"] }
//   serde = { version = "1", features = ["derive"] }

//! Lists every failed dialog, a page at a time, and prints the post-dial
//! delay and NAT diagnosis of the first five.
//!
//! SIPNAB_URL sets the API base URL (default http://localhost:8080) and
//! SIPNAB_API_KEY the bearer token, which is required.

use anyhow::{Result, anyhow, bail};
use reqwest::Url;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::env;
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct DialogSummary {
    call_id: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct DialogsPage {
    dialogs: Vec<DialogSummary>,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct Timing {
    pdd_ms: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Diagnosis {
    nat_mismatch: bool,
}

/// One dialog, aggregated. REST does not expose individual messages; for
/// those, use the CLI `sipnab -N --json` mode or the MCP `get_dialog` tool.
#[derive(Debug, Deserialize)]
struct FullDialog {
    timing: Timing,
    diagnosis: Diagnosis,
}

struct Sipnab {
    base: Url,
    client: Client,
}

impl Sipnab {
    fn new() -> Result<Self> {
        let base = env::var("SIPNAB_URL").unwrap_or_else(|_| "http://localhost:8080".into());
        let key = env::var("SIPNAB_API_KEY").map_err(|_| anyhow!("SIPNAB_API_KEY not set"))?;
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {key}").parse()?,
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            base: Url::parse(&base)?,
            client,
        })
    }

    /// GET `segments` under the base URL, each one percent-encoded, and
    /// decode the JSON body. Every status but 2xx is an error.
    fn get<T: DeserializeOwned>(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<T> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| anyhow!("{} cannot be a base URL", self.base))?
            .pop_if_empty()
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let path = url.path().to_string();
        let resp = self.client.get(url).send()?;
        match resp.status().as_u16() {
            401 => bail!("GET {path}: 401 auth failed"),
            503 => bail!("GET {path}: 503 rate-limited or conn cap reached"),
            code if code >= 400 => bail!("GET {path}: HTTP {code}"),
            _ => {}
        }
        Ok(resp.json()?)
    }

    fn list_dialogs(&self, state: Option<&str>) -> Result<Vec<DialogSummary>> {
        let mut all = Vec::new();
        loop {
            let offset = all.len().to_string();
            let mut query = vec![("limit", "100"), ("offset", offset.as_str())];
            if let Some(s) = state {
                query.push(("state", s));
            }
            let page: DialogsPage = self.get(&["v1", "dialogs"], &query)?;
            if page.dialogs.is_empty() {
                break;
            }
            all.extend(page.dialogs);
            if all.len() >= page.total {
                break;
            }
        }
        Ok(all)
    }

    fn get_dialog(&self, call_id: &str) -> Result<FullDialog> {
        self.get(&["v1", "dialogs", call_id], &[])
    }
}

fn main() -> Result<()> {
    let s = Sipnab::new()?;
    let failed = s.list_dialogs(Some("Failed"))?;
    println!("{} failed dialogs", failed.len());

    for d in failed.iter().take(5) {
        let full = s.get_dialog(&d.call_id)?;
        let pdd = full
            .timing
            .pdd_ms
            .map_or_else(|| "—".to_string(), |ms| format!("{ms}ms"));
        println!(
            "  {}  state={}  pdd={}  nat_mismatch={}",
            d.call_id, d.state, pdd, full.diagnosis.nat_mismatch
        );
    }
    Ok(())
}
// snippet:end sipnab-client
