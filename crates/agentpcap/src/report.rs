// The report's sessions view. Normative source: `docs/spec.md#9-operator-cli`:
// one line per session, per peer and per server — the tools discovered,
// the capability fingerprints, the invocation counts, transport and mode.

use agentpcap_ledger::{now_rfc3339, LedgerReader};
use serde_json::{json, Map, Value};
use std::io::Write;

/// One session line: the operator's who-called-what answer. The
/// aggregation reads the ledger's session event records: the session's
/// capability face from `init`, the tools from `tools-list`, the
/// invocation count from `tools-call`.
pub fn sessions(ledger_path: &std::path::Path, actor: &str) -> Result<Vec<Value>, String> {
    let reader = LedgerReader::open(ledger_path, actor).map_err(|e| e.to_string())?;
    let mut views: Map<String, Value> = Map::new();
    for rec in reader.records() {
        let session_key = rec["session_id"]
            .as_str()
            .unwrap_or_else(|| rec["peer"].as_str().unwrap_or("unknown"))
            .to_string();
        let view = views
            .entry(session_key.clone())
            .or_insert_with(|| {
                json!({
                    "peer": rec["peer"],
                    "session_id": session_key,
                    "transport": rec["transport"],
                    "mode": rec["mode"],
                    "server": null,
                    "cap_fingerprint": null,
                    "protocol_version": null,
                    "tools": [],
                    "invocations": 0,
                    "unidentified": 0,
                    "first_ts": rec["ts"],
                    "last_ts": rec["ts"],
                })
            });
        let obj = view.as_object_mut().expect("the view stays an object");
        let ts = rec["ts"].as_str().unwrap_or_default();
        if ts > obj["last_ts"].as_str().unwrap_or_default() {
            obj["last_ts"] = json!(ts);
        }
        if ts < obj["first_ts"].as_str().unwrap_or_default() {
            obj["first_ts"] = json!(ts);
        }
        // the capability face: the session's established face wins over
        // per-record absence
        if rec["cap_fingerprint"].is_string() {
            obj["cap_fingerprint"] = json!(rec["cap_fingerprint"]);
        }
        if rec["protocol_version"].is_string() {
            obj["protocol_version"] = json!(rec["protocol_version"]);
        }
        // the server name rides the initialize result's serverInfo
        if let Some(server) = rec["payload"]["result"]["serverInfo"]["name"]
            .as_str()
        {
            obj["server"] = json!(server);
        }
        // the discovered tools ride the tools-list result
        if let Some(tools) = rec["payload"]["result"]["tools"].as_array() {
            let list = obj["tools"].as_array_mut().expect("the tools keep a list");
            for t in tools {
                if let Some(name) = t["name"].as_str() {
                    let description = t["description"].as_str().unwrap_or("");
                    if !list
                        .iter()
                        .any(|e| e["name"].as_str() == Some(name))
                    {
                        list.push(json!({"name": name, "description": description}));
                    }
                }
            }
        }
        if rec["event"] == "tools-call" {
            let calls = obj["invocations"].as_u64().unwrap_or(0);
            obj["invocations"] = json!(calls + 1);
        }
        if rec["verdict"] == "agent-unidentified" {
            let n = obj["unidentified"].as_u64().unwrap_or(0);
            obj["unidentified"] = json!(n + 1);
        }
    }
    Ok(views.into_values().collect())
}

/// Print the sessions view as JSON Lines to stdout.
pub fn print_sessions(view: Vec<Value>) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for v in &view {
        serde_json::to_writer(&mut out, v)?;
        writeln!(out)?;
    }
    out.flush()
}

/// A fresh event stamp for the drift lines.
pub fn stamp() -> String {
    now_rfc3339()
}
