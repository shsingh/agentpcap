// The diff: two report sets in, capability drift events out. Normative
// source: `docs/spec.md#9-operator-cli`. The drift surfaces from ledger
// data only: new tools, changed tool descriptions, removed tools and
// re-scoped servers (the capability fingerprint change), never from
// decryption and never from a scan.

use crate::report::{sessions, stamp};
use serde_json::{json, Value};

/// The tool map: name -> description, per session.
fn tools(view: &Value) -> Vec<(String, String)> {
    view["tools"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|t| {
                    (
                        t["name"].as_str().unwrap_or_default().to_string(),
                        t["description"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The capability drift between two report sets. The `before` set and
/// the `after` set name two ledgers; each renders through the sessions
/// view; the drift events stream to the caller in the emit order.
pub fn drift(before_path: &std::path::Path, after_path: &std::path::Path) -> Result<Vec<Value>, String> {
    let before = sessions(before_path, "agentpcap.diff")?;
    let after = sessions(after_path, "agentpcap.diff")?;
    // The sessions of the two sets key by the server face when present
    // (the operator's per-server drift — the same served server tracks
    // across time), else by the session id face.
    //
    // The served name identifies the SERVER SOFTWARE, not a unique
    // instance: when one set holds two sessions advertising the same
    // (host, server) face, a server key would fold them into one map
    // slot — only the last session in order survives, and an unchanged
    // sibling would hide its peer's changed tools or capabilities
    // (peer review 4662429079). A duplicated face rides the session-id
    // keys in BOTH sets, so every distinct peer keeps its own slot: an
    // unmatched peer surfaces as whole-scope drift, and a matched peer
    // keeps per-instance faces. The per-server key only fires when the
    // (host, server) face names exactly one session on each side.
    // The dup scan runs PER SET: a server appearing once in each set is
    // the between-captures shape (two fresh taps, new pipe faces per
    // capture) and pairs by the server face — the fallback keys never
    // pair across captures (peer review 4662904887). Only a duplicate
    // WITHIN one set marks the face shared.
    let mut duplicated = std::collections::BTreeSet::new();
    for set in [&before, &after] {
        let mut seen = std::collections::BTreeSet::new();
        for v in set {
            let server = v["server"].as_str().unwrap_or_default();
            if server.is_empty() {
                continue;
            }
            let host = v["host"].as_str().unwrap_or_default();
            if !seen.insert(format!("{host}@{server}")) {
                duplicated.insert(format!("{host}@{server}"));
            }
        }
    }
    let key = |v: &Value| -> String {
        let host = v["host"].as_str().unwrap_or_default();
        let server = v["server"].as_str().unwrap_or_default();
        if !server.is_empty() && !duplicated.contains(&format!("{host}@{server}")) {
            // the per-server drift: the served name tracks across time
            format!("server:{host}@{server}")
        } else {
            format!(
                "session:{host}@{}",
                v["session_id"].as_str().unwrap_or_default()
            )
        }
    };
    let before_map: std::collections::BTreeMap<String, Value> = before
        .iter()
        .map(|v| (key(v), v.clone()))
        .collect();
    let after_map: std::collections::BTreeMap<String, Value> = after
        .iter()
        .map(|v| (key(v), v.clone()))
        .collect();
    let mut out = Vec::new();
    for (k, a) in &after_map {
        match before_map.get(k) {
            None => {
                // a server that appears after the before set is drift on
                // its whole scope
                let list = tools(a)
                    .into_iter()
                    .map(|(n, _)| n)
                    .collect::<Vec<_>>();
                if !list.is_empty() {
                    out.push(json!({
                        "ts": stamp(),
                        "kind": "tools-added",
                        "host": a["host"],
                        "server": a["server"],
                        "session_id": a["session_id"],
                        "tools": list,
                    }));
                }
            }
            Some(b) => {
                let added: Vec<String> = tools(a)
                    .iter()
                    .filter(|(n, _)| !tools(b).iter().any(|(bn, _)| bn == n))
                    .map(|(n, _)| n.clone())
                    .collect();
                let removed: Vec<String> = tools(b)
                    .iter()
                    .filter(|(n, _)| !tools(a).iter().any(|(an, _)| an == n))
                    .map(|(n, _)| n.clone())
                    .collect();
                if !added.is_empty() {
                    out.push(json!({
                        "ts": stamp(),
                        "kind": "tools-added",
                        "host": a["host"],
                        "server": a["server"],
                        "session_id": a["session_id"],
                        "tools": added,
                    }));
                }
                if !removed.is_empty() {
                    out.push(json!({
                        "ts": stamp(),
                        "kind": "tools-removed",
                        "host": a["host"],
                        "server": a["server"],
                        "session_id": a["session_id"],
                        "tools": removed,
                    }));
                }
                for (n, d) in tools(a) {
                    if let Some((_, before_desc)) = tools(b).iter().find(|(bn, _)| *bn == n) {
                        if *before_desc != d {
                            out.push(json!({
                                "ts": stamp(),
                                "kind": "tool-description-changed",
                                "host": a["host"],
                                "server": a["server"],
                                "session_id": a["session_id"],
                                "tool": n,
                                "before": before_desc,
                                "after": d,
                            }));
                        }
                    }
                }
                let fb = b["cap_fingerprint"].as_str().unwrap_or_default();
                let fa = a["cap_fingerprint"].as_str().unwrap_or_default();
                if !fb.is_empty() && !fa.is_empty() && fb != fa {
                    out.push(json!({
                        "ts": stamp(),
                        "kind": "server-rescoped",
                        "host": a["host"],
                        "server": a["server"],
                        "session_id": a["session_id"],
                        "before": fb,
                        "after": fa,
                    }));
                } else if fb.is_empty() && fa.is_empty() && !tools(b).is_empty() {
                    // a re-scope without plaintext fingerprints still
                    // surfaces from the tool set itself
                    let changed = tools(a).len() != tools(b).len()
                        || tools(a)
                            .iter()
                            .any(|(n, d)| tools(b).iter().any(|(bn, bd)| bn == n && bd != d));
                    if changed {
                        out.push(json!({
                            "ts": stamp(),
                            "kind": "server-rescoped",
                            "host": a["host"],
                            "server": a["server"],
                            "session_id": a["session_id"],
                            "before": null,
                            "after": null,
                        }));
                    }
                }
            }
        }
    }
    // servers that vanished between the sets: the scope left
    for (k, b) in &before_map {
        if !after_map.contains_key(k) {
            let list = tools(b)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>();
            if !list.is_empty() {
                out.push(json!({
                    "ts": stamp(),
                    "kind": "tools-removed",
                    "host": b["host"],
                    "server": b["server"],
                    "session_id": b["session_id"],
                    "tools": list,
                }));
            }
        }
    }
    Ok(out)
}
