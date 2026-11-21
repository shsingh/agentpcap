//! The reassembler: a userspace state machine that turns the classified
//! frame stream into session events. Normative sources: spec
//! `docs/spec.md#6-classification` and `docs/spec.md#4-event-record-schema`
//! (one event record per session event; the record carries the method,
//! the arguments, and the result).
//!
//! Frames arrive one per classified collector sample. The state machine
//! correlates requests and responses by payload id inside a session and
//! emits one merged event record per session event:
//!
//! - `init`: the initialize request plus its result. The result's
//!   `capabilities` object hashes to the 16-hex capability fingerprint
//!   (the ledger hash rule); `protocolVersion` rides as evidence.
//! - `tools-list`: the tools/list request plus its result; the
//!   discovered tool names ride the evidence (16 tools cap).
//! - `tools-call`: the tools/call request plus its result; `tool_name`
//!   carries the request's `params.name`.
//! - `notify`: a server-initiated notification, emitted on arrival.
//! - `a2a-handoff`: `message/send`, `message/stream`, or `tasks/`
//!   frames carry verdict `a2a`.
//! - `unidentified`: an agent-shaped frame the machine cannot bind —
//!   an unframed JSON object, an unparseable truncation, or an orphan
//!   response with no pending request. Evidence features carry the
//!   shape and, on repeated frames inside one second on one channel,
//!   the burst cadence.
//!
//! Session keying. The pipe class keys a session by the pipe pair: the
//! client pid P that writes requests and the child server pid S whose
//! responses resolve `ppid = P`. A request parks in the client's
//! pending bucket (`req:{P}`) until a response binds its id and its
//! server's pair (`pipe-pair:{P}:{S}`); the pairing parent answers
//! which server, the payload id answers which request. Multi-server
//! clients pair per response, never across ids. The socket classes key
//! the session by the channel's peer string: the tap supplies one
//! canonical five-tuple for both directions. A response whose writer's
//! parent does not resolve stays honest: it emits as `unidentified`
//! with the orphan evidence, the same shape the alpha1 tap keyed
//! `fd-unresolved-at-pop`. Capture loss at the tap's window end emits
//! every still-pending request as its own event with the
//! `no-response` evidence.
//!
//! Mode. The reassembler is mode-agnostic: in opaque mode the tap feeds
//! already-stripped payloads, and the merged payload stays the record's
//! only content face. The schema note rides the tap's slice
//! (`docs/spec.md#8-modes`): `cap_fingerprint` is absent in opaque mode
//! without plaintext.

use agentpcap_events::{Event, Verdict};
use agentpcap_ledger::now_rfc3339;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// The tap hands one frame per classified sample.
pub struct Frame {
    /// The transport face (`stdio-pipe`, `tcp`, ...).
    pub transport: String,
    /// The channel key the tap resolved for THIS sample's writer
    /// (`pipe:{inode}` for the pipe class; the canonical five-tuple for
    /// the socket classes).
    pub peer: String,
    /// The writer's machine pid.
    pub pid: u32,
    /// The writer's parent pid; `0` where `/proc` does not resolve.
    pub ppid: u32,
    /// The writer's `comm`.
    pub comm: String,
    /// The parsed JSON-RPC object. The tap feeds only frames that parse.
    pub payload: Value,
    /// The evidence lines the tap already established for this sample
    /// (transport face, lineage, fd-unresolved-at-pop).
    pub tap_evidence: Vec<String>,
}

/// The capability fingerprint rule: the ledger hash rule over the
/// server's advertised `capabilities` object — the first 16 hex digits
/// of the SHA-256 of the object's serialized form.
pub fn capability_fingerprint(capabilities: &Value) -> String {
    let mut h = Sha256::new();
    h.update(capabilities.to_string().as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// One parked request frame, awaiting a response that binds its id.
struct Pending {
    transport: String,
    peer: String,
    req: Value,
    method: String,
    id: String,
    pid: u32,
    comm: String,
    tap_evidence: Vec<String>,
}

struct PendingBucket {
    by_id: HashMap<String, Vec<Pending>>,
}

/// One known session: the capability face and the burst cadence window.
struct Session {
    cap_fingerprint: Option<String>,
    protocol_version: Option<String>,
    burst_at: Option<Instant>,
    burst_count: u16,
    notify_seq: u64,
    orphan_seq: u64,
}

impl Session {
    fn new() -> Self {
        Self {
            cap_fingerprint: None,
            protocol_version: None,
            burst_at: None,
            burst_count: 0,
            notify_seq: 0,
            orphan_seq: 0,
        }
    }
}

pub struct Reassembler {
    host: String,
    mode: Mode,
    source: String,
    sessions: HashMap<String, Session>,
    pending: HashMap<String, PendingBucket>,
}

const TOOLS_EVIDENCE_CAP: usize = 16;
const BURST_WINDOW: Duration = Duration::from_secs(1);

use agentpcap_events::Mode;

impl Reassembler {
    pub fn new(host: String, mode: Mode, source: String) -> Self {
        Self {
            host,
            mode,
            source,
            sessions: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Feed one classified frame; returns the events to append now.
    pub fn feed(&mut self, frame: Frame) -> Vec<Event> {
        let Some(obj) = frame.payload.as_object() else {
            return vec![];
        };
        let method = obj.get("method").and_then(|m| m.as_str()).map(str::to_string);
        let id = obj.get("id").map(json_id);
        let has_result = obj.get("result").is_some() || obj.get("error").is_some();
        if let Some(m) = method {
            match id {
                Some(id) => self.on_request(frame, m, id),
                None => self.on_notification(frame),
            }
        } else if has_result {
            match id {
                Some(id) => self.on_response(frame, id),
                None => vec![self.emit_orphan(frame, vec!["request-shape:unframed".into()])],
            }
        } else {
            vec![self.emit_orphan(frame, vec!["request-shape:unframed".into()])]
        }
    }

    /// Emit the still-pending frames at the tap window's end: capture
    /// loss degrades the ledger, it never drops it silently.
    pub fn flush(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let keys: Vec<String> = self.pending.keys().cloned().collect();
        for k in keys {
            let Some(mut bucket) = self.pending.remove(&k) else {
                continue;
            };
            for ((_, mut parked)) in bucket.by_id.drain() {
                for p in parked.drain(..) {
                    out.push(self.emit_merged(None, &p, Value::Null, vec!["no-response".into()]));
                }
            }
        }
        out
    }

    // -- request path ---------------------------------------------------

    fn on_request(&mut self, frame: Frame, method: String, id: String) -> Vec<Event> {
        // The socket classes key pending by the session's own peer; the
        // pipe class parks requests under the client pid until a
        // response nominates the server pair. The same id may park on
        // two channels of one client: both stay preserved, never
        // overwritten.
        let key = if frame.peer.starts_with("pipe:") {
            format!("req:{}", frame.pid)
        } else {
            frame.peer.clone()
        };
        let bucket = self
            .pending
            .entry(key)
            .or_insert_with(|| PendingBucket { by_id: HashMap::new() });
        bucket.by_id.entry(id.clone()).or_default().push(Pending {
            transport: frame.transport.clone(),
            peer: frame.peer.clone(),
            req: frame.payload.clone(),
            method,
            id,
            pid: frame.pid,
            comm: frame.comm.clone(),
            tap_evidence: frame.tap_evidence.clone(),
        });
        vec![]
    }

    // -- notification path ----------------------------------------------

    fn on_notification(&mut self, frame: Frame) -> Vec<Event> {
        // The client side of a pipe session also sends notifications
        // (notifications/initialized rides the request channel after the
        // init pair). Where the writer is the client that owns a
        // pending bucket, the record keys that client face, never a
        // pair the client is not a member of.
        let pipe_class = frame.peer.starts_with("pipe:");
        let mut client_face = false;
        let key = if pipe_class && self.pending.contains_key(&format!("req:{}", frame.pid)) {
            client_face = true;
            format!("client:{}", frame.pid)
        } else {
            self.session_key_for(&frame)
        };
        let m = frame
            .payload
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        let verdict = if self.method_is_a2a(m) {
            Verdict::A2a
        } else if self.method_is_mcp(m) {
            Verdict::Mcp
        } else {
            Verdict::AgentUnidentified
        };
        let payload = Some(frame.payload.clone());
        let session = self
            .sessions
            .entry(key.clone())
            .or_insert_with(Session::new);
        session.notify_seq += 1;
        let seq = session.notify_seq;
        let fp = session.cap_fingerprint.clone();
        let proto = session.protocol_version.clone();
        let mut evidence = frame.tap_evidence.clone();
        evidence.push(format!("chan:{}", frame.peer));
        evidence.push("reassembled:notify".into());
        if client_face {
            evidence.push("notification:client-side".into());
        }
        let ev = Event {
            ts: now_rfc3339(),
            host: self.host.clone(),
            process: frame.comm.clone(),
            pid: frame.pid,
            transport: frame.transport.clone(),
            mode: self.mode.clone(),
            verdict,
            event: "notify".into(),
            method: frame.payload.get("method").and_then(|m| m.as_str()).map(str::to_string),
            tool_name: None,
            cap_fingerprint: fp,
            protocol_version: proto,
            session_id: Some(key.clone()),
            peer: key.clone(),
            dedup: format!("{}:{}:notify:notify-{seq}", frame.transport, key),
            payload,
            evidence: Some(evidence),
            source: self.source.clone(),
            schema_version: "1.0".into(),
        };
        vec![ev]
    }

    // -- response path ---------------------------------------------------

    fn on_response(&mut self, frame: Frame, id: String) -> Vec<Event> {
        // Bind the response to its pending request. The pipe class
        // pairs by the writer's parent (the client that owns the
        // pending bucket) — the pairing parent answers which server.
        // The by-id fallback fires ONLY for a writer that died inside
        // the pop window (the parent unresolvable or the fd
        // unresolved): a resolved, unrelated channel never reads
        // another client's id. One id parked on more than one request
        // stays ambiguous: the response orphans and both requests stay
        // preserved, never overwritten.
        let pipe_class = frame.peer.starts_with("pipe:");
        let dying_writer = frame.ppid == 0
            || frame
                .tap_evidence
                .iter()
                .any(|e| e == "fd-unresolved-at-pop");
        let mut bound: Option<(String, Pending)> = None;
        let mut pair_face = false;
        if pipe_class && frame.ppid > 0 {
            let bucket_key = format!("req:{}", frame.ppid);
            if let Some(b) = self.pending.get_mut(&bucket_key) {
                if let Some(v) = b.by_id.get_mut(&id) {
                    if v.len() == 1 {
                        let p = v.remove(0);
                        bound = Some((format!("pipe-pair:{}:{}", frame.ppid, frame.pid), p));
                        pair_face = true;
                    }
                }
            }
        }
        if bound.is_none() {
            let matches: usize = self
                .pending
                .values()
                .map(|b| b.by_id.get(&id).map_or(0, |v| v.len()))
                .sum();
            if matches > 1 || (matches == 1 && !dying_writer) {
                // ambiguous id reuse, or a live writer no pairing owns:
                // the response stays honest as an orphan, the parked
                // requests stay preserved
                return vec![self.emit_orphan(
                    frame,
                    vec![
                        "orphan-response".into(),
                        "pair-unresolved:ambiguous-id".into(),
                    ],
                )];
            }
            if matches == 1 {
                let keys: Vec<String> = self
                    .pending
                    .iter()
                    .filter(|(_, b)| b.by_id.contains_key(&id))
                    .map(|(k, _)| k.clone())
                    .collect();
                if let Some(b) = self.pending.get_mut(&keys[0]) {
                    if let Some(v) = b.by_id.get_mut(&id) {
                        if v.len() == 1 {
                            let p = v.remove(0);
                            // the session keys on the request's own channel
                            bound = Some((p.peer.clone(), p));
                        }
                    }
                }
            }
        }
        let Some((bind_key, p)) = bound else {
            return vec![self.emit_orphan(frame, vec!["orphan-response".into()])];
        };
        // the merge binds the result member, or the error member when
        // the response carries one: the error face rides the evidence
        // and the payload both
        let error_face = frame.payload.get("error").is_some();
        let result = frame
            .payload
            .get("result")
            .cloned()
            .or_else(|| frame.payload.get("error").cloned())
            .unwrap_or(Value::Null);
        let mut extra = vec![];
        if pair_face {
            extra.push(format!("chan:{}", frame.peer));
        } else {
            extra.push("pair:by-id".into());
        }
        if error_face {
            extra.push("error-response".into());
        }
        let ev = self.emit_merged(Some(bind_key), &p, result, extra);
        vec![ev]
    }

    // -- emission --------------------------------------------------------

    /// The merged session event: the request side and the response side
    /// of one bind. `bind_key = None` marks the flush path, where no
    /// server ever bound and the record rides the request's own
    /// channel with the loss evidence.
    fn emit_merged(
        &mut self,
        bind_key: Option<String>,
        p: &Pending,
        result: Value,
        extra_evidence: Vec<String>,
    ) -> Event {
        let peer = match &bind_key {
            Some(k) => k.clone(),
            None => p.peer.clone(),
        };
        // The session's capability face rides every event from the
        // initialize onward (spec section 4: cap_fingerprint SHOULD).
        if p.method == "initialize" {
            if let Some(caps) = result.get("capabilities") {
                let session = self
                    .sessions
                    .entry(peer.clone())
                    .or_insert_with(Session::new);
                session.cap_fingerprint = Some(capability_fingerprint(caps));
                session.protocol_version = result
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
        }
        let session = self.sessions.entry(peer.clone()).or_insert_with(Session::new);
        let fp = session.cap_fingerprint.clone();
        let proto = session.protocol_version.clone();

        let mut evidence = p.tap_evidence.clone();
        evidence.push(format!("chan:{}", p.peer));
        evidence.extend(extra_evidence);
        evidence.push(format!("reassembled:{}", event_name_for(&p.method)));
        if p.method == "tools/list" {
            if let Some(tools) = result.get("tools").and_then(|t| t.as_array()) {
                evidence.push(format!("tools:{}", tools.len()));
                for t in tools.iter().take(TOOLS_EVIDENCE_CAP) {
                    if let Some(name) = t.get("name").and_then(|x| x.as_str()) {
                        evidence.push(format!("tool:{name}"));
                    }
                }
            }
        }
        let tool_name = if p.method == "tools/call" {
            p.req
                .get("params")
                .and_then(|q| q.get("name"))
                .and_then(|x| x.as_str())
                .map(str::to_string)
        } else {
            None
        };
        let verdict = if self.method_is_a2a(&p.method) {
            Verdict::A2a
        } else if self.method_is_mcp(&p.method) {
            Verdict::Mcp
        } else {
            // an unknown method face stays honest: the verdict comes
            // from the protocol semantics, never from a catalog
            Verdict::AgentUnidentified
        };
        let event_name = event_name_for(&p.method);
        let dedup = format!("{}:{}:{}:{}", p.transport, peer, event_name, p.id);
        let payload = match &bind_key {
            Some(_) => Some(serde_json::json!({"request": p.req, "result": result})),
            None => Some(serde_json::json!({"request": p.req, "result": Value::Null})),
        };
        Event {
            ts: now_rfc3339(),
            host: self.host.clone(),
            process: p.comm.clone(),
            pid: p.pid,
            transport: p.transport.clone(),
            mode: self.mode.clone(),
            verdict,
            event: event_name.to_string(),
            method: Some(p.method.clone()),
            tool_name,
            cap_fingerprint: fp,
            protocol_version: proto,
            session_id: Some(peer.clone()),
            peer,
            dedup,
            payload,
            evidence: Some(evidence),
            source: self.source.clone(),
            schema_version: "1.0".into(),
        }
    }

    /// The agent-shaped frame the machine cannot bind. Evidence carries
    /// the shape features and, on repeated frames inside the burst
    /// window on one session, the cadence line (spec section 6).
    fn emit_orphan(&mut self, frame: Frame, mut features: Vec<String>) -> Event {
        // the orphan keys its own channel: no pair bound, so no pipe
        // pair face rides the record
        let key = frame.peer.clone();
        let (burst_line, orphan_n) = {
            let session = self
                .sessions
                .entry(key.clone())
                .or_insert_with(Session::new);
            session.orphan_seq += 1;
            let n = session.orphan_seq;
            let now = Instant::now();
            let line = match session.burst_at {
                Some(start) if now.duration_since(start) <= BURST_WINDOW => {
                    session.burst_count += 1;
                    Some(format!("cadence:burst-{}-in-1s", session.burst_count))
                }
                _ => {
                    session.burst_at = Some(now);
                    session.burst_count = 1;
                    None
                }
            };
            (line, n)
        };
        if let Some(l) = burst_line {
            features.push(l);
        }
        features.push(format!("chan:{}", frame.peer));
        let ev = Event {
            ts: now_rfc3339(),
            host: self.host.clone(),
            process: frame.comm.clone(),
            pid: frame.pid,
            transport: frame.transport.clone(),
            mode: self.mode.clone(),
            verdict: Verdict::AgentUnidentified,
            event: "unidentified".into(),
            method: frame
                .payload
                .get("method")
                .and_then(|m| m.as_str())
                .map(str::to_string),
            tool_name: None,
            cap_fingerprint: None,
            protocol_version: None,
            session_id: Some(key.clone()),
            peer: key.clone(),
            dedup: format!(
                "{}:{}:unidentified:orphan-{orphan_n}",
                frame.transport, key
            ),
            payload: Some(frame.payload.clone()),
            evidence: Some([frame.tap_evidence, features].concat()),
            source: self.source.clone(),
            schema_version: "1.0".into(),
        };
        ev
    }

    // -- helpers ---------------------------------------------------------

    fn session_key_for(&self, frame: &Frame) -> String {
        if frame.peer.starts_with("pipe:") && frame.ppid > 0 {
            format!("pipe-pair:{}:{}", frame.ppid, frame.pid)
        } else {
            frame.peer.clone()
        }
    }

    fn method_is_a2a(&self, method: &str) -> bool {
        method == "message/send" || method == "message/stream" || method.starts_with("tasks/")
    }

    fn method_is_mcp(&self, method: &str) -> bool {
        method == "initialize" || method == "tools/list" || method == "tools/call"
            || method.starts_with("notifications/")
    }
}

fn event_name_for(method: &str) -> &'static str {
    match method {
        "initialize" => "init",
        "tools/list" => "tools-list",
        "tools/call" => "tools-call",
        m if m == "message/send" || m == "message/stream" => "a2a-handoff",
        m if m.starts_with("tasks/") => "a2a-handoff",
        _ => "unidentified",
    }
}

/// The JSON-RPC id face: numbers keep their digits, strings prefix into
/// the key, absent ids stay `none` (a response without an id never
/// binds and rides the orphan path).
fn json_id(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => format!("str:{s}"),
        _ => "none".to_string(),
    }
}
