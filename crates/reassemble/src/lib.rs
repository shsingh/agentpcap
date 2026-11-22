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
    /// the socket classes; the session id face for a Streamable HTTP
    /// exchange whose header rode).
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
    /// (transport face, lineage, fd-unresolved-at-pop; a Streamable
    /// HTTP exchange's `http-session:{id}` face rides here — the
    /// record's session id prefers it, the bind keys stay the
    /// connection faces so a reply whose side omits the header never
    /// loses its request, spec Section 5).
    pub tap_evidence: Vec<String>,
}

/// The record's session-id face: a Streamable HTTP exchange whose
/// header rode carries the `http-session:{id}` evidence face, and the
/// RECORD prefers it (spec Section 5's reconstruction MUST); the bind
/// keys stay the connection faces, so a reply whose side omits the
/// header never loses its request.
fn session_id_face(tap_evidence: &[String], fallback: String) -> String {
    tap_evidence
        .iter()
        .find(|e| e.starts_with("http-session:"))
        .cloned()
        .unwrap_or(fallback)
}

/// The reply's requester face, selected by the reply's PROBE face: a
/// receive face (the reply observed by the requesting client) names the
/// reply's OWN local face; a send face (the reply observed by the
/// replying server) names the reply's remote face. The helper rides the
/// match, the completed store and the completed check alike — the two
/// copies of one reply carried at both endpoints always compare the
/// same face.
fn requester_face_of(tap_evidence: &[String]) -> Option<String> {
    let frame_local = tap_evidence
        .iter()
        .find_map(|e| e.strip_prefix("local-end:").map(|v| v.to_string()));
    match tap_evidence
        .iter()
        .find_map(|e| e.strip_prefix("probe-face:").map(|v| v.to_string()))
        .as_deref()
    {
        Some("receive") => frame_local,
        Some("send") => tap_evidence
            .iter()
            .find_map(|e| e.strip_prefix("remote-end:").map(|v| v.to_string())),
        _ => None,
    }
}

/// The capability fingerprint rule: the ledger hash rule over the
/// server's advertised `capabilities` object — the first 16 hex digits
/// of the SHA-256 of the object's serialized form.
pub fn capability_fingerprint(capabilities: &Value) -> String {
    let mut h = Sha256::new();
    h.update(capabilities.to_string().as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// The session-event record's schema face (ADR-0007): the merged
/// payload shape differs from the frame face, and the version
/// distinguishes them inside one ledger.
pub const RECORD_SCHEMA_VERSION: &str = "2.1";

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
    /// The frame's observation time: the time the reassembler first
    /// saw it (≈ the sample's pop, within one drain tick). The
    /// flush face stamps this, never the window's end.
    observed_ts: String,
    /// The park moment: the sweep expires the stale unanswered
    /// requests against it (the deployed service never grows its
    /// pending face without limit).
    parked_at: Instant,
    /// The run-unique observation sequence AT THE PARK: the session
    /// event's key faces by it, so two exchanges reusing one id within
    /// the same second key twice (R120), and one call observed by both
    /// its endpoints keys once (R119's observation-merge face).
    seq_at_park: u64,
    /// The socket requester's own endpoint (the frame's `local-end`
    /// face): the response's remote face must equal it, so two
    /// endpoints' same-id requests never cross.
    sock_local: Option<String>,
    /// The probe direction face (send | receive): the same call seen
    /// by both endpoints carries one copy per direction.
    probe_face: Option<String>,
}

struct PendingBucket {
    by_id: HashMap<String, Vec<Pending>>,
    /// The channels the client parked requests on: a later
    /// client-side notification resolves its session through them.
    channels: Vec<String>,
}

/// One known session: the capability face, its channel faces, and the
/// burst cadence window.
struct Session {
    cap_fingerprint: Option<String>,
    protocol_version: Option<String>,
    /// The channel keys the session's frames rode (the request's
    /// channel at bind time, the response's channel beside it): a
    /// client-side notification finds its session through the one it
    /// wrote on.
    channels: Vec<String>,
    burst_at: Option<Instant>,
    burst_count: u16,
    /// The last frame that touched the session: the sweep expires the
    /// idle ones (the deployed service never grows its session face
    /// without limit).
    last_activity: Instant,
    /// The notification bodies this session already emitted inside
    /// the dedupe window (the socket class only): the send and the
    /// receive probes both observe one message; the ledger carries it
    /// once. The window prunes the face, so it never grows with the
    /// session's history.
    emitted_notifications: std::collections::HashMap<u64, Instant>,
}

/// The FNV-1a hash over bytes: the dedupe keys ride content, not a
/// per-run counter — a restarted capture never re-mints an earlier
/// run's key.
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

impl Session {
    fn new() -> Self {
        Self {
            cap_fingerprint: None,
            protocol_version: None,
            channels: Vec::new(),
            burst_at: None,
            burst_count: 0,
            last_activity: Instant::now(),
            emitted_notifications: std::collections::HashMap::new(),
        }
    }
}

pub struct Reassembler {
    host: String,
    mode: Mode,
    source: String,
    sessions: HashMap<String, Session>,
    pending: HashMap<String, PendingBucket>,
    /// The idle face: requests parked longer, and sessions untouched
    /// longer, expire at the sweep (the writer bounds its face for the
    /// deployed service).
    ttl: Duration,
    /// The sweep's next due moment: the loop's calls between sweeps
    /// stay O(1) (the cadence rides a ttl quarter).
    next_sweep: Instant,
    /// The observation counter: every notification and orphan faces a
    /// run-unique observation number, so even twins inside one second
    /// never share a key (across runs the timestamp separates them).
    obs_seq: u64,
    /// The socket replies that bound (peer -> id -> the bound body's
    /// FNV face): the same reply's second probe copy never re-binds,
    /// while the peer's other reply body passes its own face. The face
    /// clears per id at the next park and the sweep clears it whole
    /// (bounded).
    socket_completed: HashMap<String, HashMap<String, Vec<(u64, String)>>>,
}

const TOOLS_EVIDENCE_CAP: usize = 16;
const BURST_WINDOW: Duration = Duration::from_secs(1);
/// The deployed service's idle face: requests parked longer, and
/// sessions untouched longer, expire at the sweep.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(600);

use agentpcap_events::Mode;

impl Reassembler {
    pub fn new(host: String, mode: Mode, source: String) -> Self {
        Self::new_with_ttl(host, mode, source, DEFAULT_SESSION_TTL)
    }

    /// The idle-face constructor: the sweep expires parked requests
    /// and idle sessions against this ttl. The deployed service never
    /// grows its in-memory faces without limit.
    pub fn new_with_ttl(host: String, mode: Mode, source: String, ttl: Duration) -> Self {
        Self {
            host,
            mode,
            source,
            sessions: HashMap::new(),
            pending: HashMap::new(),
            ttl,
            next_sweep: Instant::now(),
            obs_seq: 0,
            socket_completed: HashMap::new(),
        }
    }

    /// The idle face: the stale parked requests ride the no-response
    /// face one last time (capture loss degrades the ledger, it never
    /// drops them), then they leave the pending map; the idle sessions
    /// follow. A later frame re-observes an expired session the same
    /// way a fresh one forms.
    pub fn sweep(&mut self) -> Vec<Event> {
        // the cadence face: the sweep fires at most once per ttl
        // quarter — the loop's idle ticks stay O(1)
        let now = Instant::now();
        if now < self.next_sweep {
            return Vec::new();
        }
        self.next_sweep = now + self.ttl / 4;

        let mut out = Vec::new();
        let mut stale: Vec<Pending> = Vec::new();
        // per-REQUEST granularity: only the requests past the ttl ride
        // the loss face; a same-id request parked later keeps its park
        let keys: Vec<String> = self.pending.keys().cloned().collect();
        for k in keys {
            let Some(bucket) = self.pending.get_mut(&k) else {
                continue;
            };
            let ids: Vec<String> = bucket.by_id.keys().cloned().collect();
            for id in ids {
                let Some(v) = bucket.by_id.get_mut(&id) else {
                    continue;
                };
                let mut kept: Vec<Pending> = Vec::new();
                let mut dropped: Vec<Pending> = Vec::new();
                for p in v.drain(..) {
                    if p.parked_at.elapsed() > self.ttl {
                        dropped.push(p);
                    } else {
                        kept.push(p);
                    }
                }
                *v = kept;
                stale.append(&mut dropped);
                if bucket.by_id.get(&id).is_some_and(|v| v.is_empty()) {
                    bucket.by_id.remove(&id);
                }
            }
        }
        self.pending.retain(|_, b| !b.by_id.is_empty());
        for p in &stale {
            out.push(self.emit_loss(p));
        }
        // the idle sessions follow — a session with a request still
        // waiting on one of its channels stays: an active call keeps
        // its capability face while the answer is in flight
        let waiting: std::collections::HashSet<String> = self
            .pending
            .values()
            .flat_map(|b| {
                b.by_id
                    .values()
                    .flatten()
                    .map(|p| p.peer.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.last_activity.elapsed() > self.ttl
                    && s.channels.iter().all(|c| !waiting.contains(c))
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.sessions.remove(&k);
        }
        // the completed-call face prunes at the sweep: its ids
        // re-park (the next park clears per id), and the peers whose
        // session and pending faces both left drop their entries - the
        // face never grows with old connections
        self.socket_completed.retain(|peer, done| {
            done.clear();
            self.sessions.contains_key(peer) || self.pending.contains_key(peer)
        });
        out
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

    /// Emit one parked request's no-response face: the pair that
    /// bound earlier responses on this request's channel carries the
    /// session's fingerprint; more than one pair on the channel is
    /// honest ambiguity and the raw channel face answers. Shared by
    /// the window-end flush and the sweep.
    fn emit_loss(&mut self, p: &Pending) -> Event {
        let known = self
            .sessions
            .iter()
            .filter(|(k, s)| {
                k.starts_with("pipe-pair:")
                    && s.channels.contains(&p.peer)
            })
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>();
        let bind_key = if known.len() == 1 {
            known.first().cloned()
        } else {
            None
        };
        let ev = self
            .emit_merged(bind_key.clone(), p, Value::Null, vec!["no-response".into()], true);
        // the resolved session keeps riding the channel face
        if let Some(bk) = &bind_key {
            if let Some(s) = self.sessions.get_mut(bk) {
                if !s.channels.contains(&p.peer) {
                    s.channels.push(p.peer.clone());
                }
                s.last_activity = Instant::now();
            }
        }
        ev
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
            for (_, mut parked) in bucket.by_id.drain() {
                for p in parked.drain(..) {
                    out.push(self.emit_loss(&p));
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
        let pending_local = frame
            .tap_evidence
            .iter()
            .find_map(|e| e.strip_prefix("local-end:").map(|v| v.to_string()));
        let new_payload = frame.payload.clone();
        // the observation merge face: the same call observed by both
        // its endpoints parks once. A same-id copy whose own endpoint
        // differs from the existing copy's, and whose body matches it,
        // is that same call's other side — it drops. A differing body
        // stays: the id-reuse face. The two copies' own endpoints
        // differ, and their bodies match.
        {
            let bucket = self
                .pending
                .entry(key)
                .or_insert_with(|| PendingBucket { by_id: HashMap::new(), channels: Vec::new() });
            if !bucket.channels.contains(&frame.peer) && is_channel_face(&frame.peer) {
                bucket.channels.push(frame.peer.clone());
            }
            let probe_face = frame
                .tap_evidence
                .iter()
                .find_map(|e| e.strip_prefix("probe-face:").map(|v| v.to_string()));
            // the id's completed face clears at its next park: the
            // same-id reuse after a complete call re-runs
            if let Some(done) = self.socket_completed.get_mut(&frame.peer) {
                done.remove(&id);
            }
            let duplicate = bucket
                .by_id
                .get(&id)
                .map(|v| {
                    v.iter().any(|existing| {
                        // the same message seen by its two endpoints:
                        // the DIRECTION faces differ (a send and a
                        // receive), the bodies match. Two independent
                        // sends share a direction - they ride.
                        existing.probe_face.as_deref() != probe_face.as_deref()
                            && existing.req == new_payload
                    })
                })
                .unwrap_or(false);
            if duplicate {
                return vec![];
            }
            self.obs_seq += 1;
            bucket.by_id.entry(id.clone()).or_default().push(Pending {
                transport: frame.transport.clone(),
                peer: frame.peer.clone(),
                req: new_payload,
                method,
                id,
                pid: frame.pid,
                comm: frame.comm.clone(),
                tap_evidence: frame.tap_evidence.clone(),
                observed_ts: now_rfc3339(),
                seq_at_park: self.obs_seq,
                parked_at: Instant::now(),
                sock_local: pending_local.clone(),
                probe_face: frame
                    .tap_evidence
                    .iter()
                    .find_map(|e| {
                        e.strip_prefix("probe-face:").map(|v| v.to_string())
                    }),
            });
        }
        vec![]
    }

    // -- notification path ----------------------------------------------

    fn on_notification(&mut self, frame: Frame) -> Vec<Event> {
        // Session face priority: the notification's own channel already
        // joined a session (the request channel at its pair's bind, the
        // reply channel beside it) - the notification rides THAT
        // session, never a split one. Without a joined session, the
        // client that owns a pending bucket keys its client face
        // (`client:{pid}`) until a pair binds; otherwise the pipe-pair
        // rule answers.
        let pipe_class = frame.peer.starts_with("pipe:");
        // the joined candidates: every session the channel rode. A
        // pair answers only when the evidence identifies ONE: two
        // pairs sharing the channel (the multi-server client) is
        // ambiguity, and the notification keys its client face or its
        // parent-pair face, never an arbitrary session.
        let joined = if is_channel_face(&frame.peer) {
            self.sessions
                .iter()
                .filter(|(_, s)| s.channels.contains(&frame.peer))
                .filter(|(k, _)| !k.starts_with("client:"))
                .map(|(k, _)| k.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut client_face = false;
        let key = if joined.len() == 1 {
            joined[0].clone()
        } else {
            client_face = joined.len() > 1;
            if pipe_class && self.pending.contains_key(&format!("req:{}", frame.pid)) {
                client_face = true;
                format!("client:{}", frame.pid)
            } else {
                self.session_key_for(&frame)
            }
        };
        let m = frame
            .payload
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        let framed = frame_is_jsonrpc(&frame.payload);
        let verdict = if self.method_is_a2a(m) && framed {
            Verdict::A2a
        } else if framed && self.method_is_mcp(m) {
            Verdict::Mcp
        } else {
            Verdict::AgentUnidentified
        };
        let event_face = if framed { "notify" } else { "unidentified" };
        let payload = Some(frame.payload.clone());
        let session = self
            .sessions
            .entry(key.clone())
            .or_insert_with(Session::new);
        // touch: the event marks the session's activity face
        session.last_activity = Instant::now();
        self.obs_seq += 1;
        if !session.channels.contains(&frame.peer) && is_channel_face(&frame.peer) {
            session.channels.push(frame.peer.clone());
        }
        let fp = session.cap_fingerprint.clone();
        let proto = session.protocol_version.clone();
        let notify_hash = fnv64(serde_json::to_vec(&frame.payload).unwrap_or_default().as_slice());
        // the socket class only: a message the send and the receive
        // probes both captured rides once inside the dedupe window (a
        // repeated message past the window is a separate observation —
        // the capture scope never narrows). The stdio pipe class never
        // dedupes: a repeated notification is real traffic. The
        // window prunes the face, so it never grows with history.
        if frame.peer.starts_with("net-") {
            let now = Instant::now();
            session
                .emitted_notifications
                .retain(|_, seen| now.duration_since(*seen) <= BURST_WINDOW);
            if let Some(seen) = session.emitted_notifications.get(&notify_hash) {
                if now.duration_since(*seen) <= BURST_WINDOW {
                    return vec![];
                }
            }
            session.emitted_notifications.insert(notify_hash, now);
        }
        let mut evidence = frame.tap_evidence.clone();
        evidence.push(format!("chan:{}", frame.peer));
        evidence.push("reassembled:notify".into());
        if client_face {
            evidence.push("notification:client-side".into());
        }
        // the duplicate face hashes the RAW message when the face
        // carries it: a mode rebuild would strip two different
        // notifications to one body and one would drop in the burst
        // window — the honest fingerprint never narrows capture
        let notify_fingerprint = frame
            .tap_evidence
            .iter()
            .find(|e| e.starts_with("nhash:"))
            .and_then(|e| e.strip_prefix("nhash:").map(String::from))
            .unwrap_or_else(|| {
                format!("{:016x}", fnv64(serde_json::to_vec(&frame.payload).unwrap_or_default().as_slice()))
            });
        let ev = Event {
            ts: now_rfc3339(),
            host: self.host.clone(),
            process: frame.comm.clone(),
            pid: frame.pid,
            transport: frame.transport.clone(),
            mode: self.mode.clone(),
            verdict,
            event: event_face.into(),
            method: frame.payload.get("method").and_then(|m| m.as_str()).map(str::to_string),
            tool_name: None,
            cap_fingerprint: fp,
            protocol_version: proto,
            session_id: Some(session_id_face(&frame.tap_evidence, key.clone())),
            peer: key.clone(),
            dedup: format!(
                "{}:{}:notify:notify-{}@{}.{:012}",
                frame.transport,
                key,
                notify_fingerprint,
                now_rfc3339(),
                self.obs_seq,
            ),
            payload,
            evidence: Some(evidence),
            source: self.source.clone(),
            schema_version: RECORD_SCHEMA_VERSION.into(),
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
        if !pipe_class && frame.peer != "unresolved" {
            // the resolved connection binds its OWN bucket first: a
            // socket response pairs with the request parked on the
            // same five-tuple (two connections carrying the same id
            // never merge), it never reads the global fallback, and
            // the DIRECTION face holds - the response's remote face
            // must equal the requester's own endpoint, so two
            // endpoints' same-id requests never cross
            let response_remote = frame
                .tap_evidence
                .iter()
                .find_map(|e| e.strip_prefix("remote-end:").map(|v| v.to_string()));
            // the repeat-result face: the same reply body's other
            // probe copy drops once that call bound; a DIFFERENT body
            // under the same id (the peer's other request) passes its
            // own face and binds
            let reply_body_hash = fnv64(
                serde_json::to_vec(&frame.payload).unwrap_or_default().as_slice(),
            );
            if let Some(completed) = self.socket_completed.get(&frame.peer) {
                if let Some(entries) = completed.get(&id) {
                    // the SAME requester already received this body: the
                    // probe's other copy drops. A DIFFERENT requester's
                    // same-shaped reply (opaque strips their bodies to
                    // one face) binds its OWN request — the completed
                    // face keeps HISTORY PER REQUESTER, so one end never
                    // erases the other's record. The check rides the
                    // PROBE-FACE-SELECTED requester face — the same
                    // selection the store made — so both endpoint copies
                    // of one reply compare the same name
                    let selected = requester_face_of(&frame.tap_evidence);
                    if entries.iter().any(|(h, requester)| {
                        *h == reply_body_hash && selected.as_deref() == Some(requester.as_str())
                    }) {
                        return vec![];
                    }
                }
            }
            if let Some(b) = self.pending.get_mut(&frame.peer) {
                if let Some(v) = b.by_id.get_mut(&id) {
                    // the PROBE face chooses the requester's endpoint:
                    // a receive face (the reply observed by the
                    // requesting client) names it as the reply's OWN
                    // local face; a send face (the reply observed by the
                    // replying server) names it as the reply's REMOTE
                    // face. The face never accepts both — two ends'
                    // same-id requests never cross
                    let requester_face = requester_face_of(&frame.tap_evidence);
                    let matched = match &requester_face {
                        Some(face) => v
                            .iter()
                            .position(|p| {
                                // the requester face rides the both-sides
                                // face; the SERVER-ONLY face (only the
                                // server side in the tap's scope) rides the
                                // reply writer's OWN local face against a
                                // request the same writer READ (the p's
                                // probe face names receive) — the p that
                                // parked through a send never enters the
                                // alternate, so the cross-end face stays
                                // closed
                                p.sock_local.as_deref() == Some(face.as_str())
                                    || (p.probe_face.as_deref() == Some("receive")
                                        && requester_face_of(&frame.tap_evidence)
                                            .as_deref()
                                            == p.sock_local.as_deref())
                            }),
                        None => {
                            if v.is_empty() {
                                None
                            } else {
                                Some(0)
                            }
                        }
                    };
                    if let Some(pos) = matched {
                        let mut p = v.remove(pos);
                        // the reply's header faces merge into the parked
                        // evidence: the merged event carries the session
                        // id or the version face the reply observed even
                        // when its request's side carried none
                        for face in &frame.tap_evidence {
                            if (face.starts_with("http-session:")
                                || face.starts_with("http-version:"))
                                && !p.tap_evidence.contains(face)
                            {
                                p.tap_evidence.push(face.clone());
                            }
                        }
                        let consumed = v.is_empty();
                        if consumed && response_remote.is_some() {
                            b.by_id.remove(&id);
                        }
                        bound = Some((frame.peer.clone(), p));
                        let stored_requester =
                            requester_face_of(&frame.tap_evidence).unwrap_or_default();
                        let done = self
                            .socket_completed
                            .entry(frame.peer.clone())
                            .or_default()
                            .entry(id.clone())
                            .or_default();
                        if !done
                            .iter()
                            .any(|e| *e == (reply_body_hash, stored_requester.clone()))
                        {
                            done.push((reply_body_hash, stored_requester));
                        }
                    }
                }
            }
        }
        if bound.is_none() && pipe_class && frame.ppid > 0 {
            let bucket_key = format!("req:{}", frame.ppid);
            if let Some(b) = self.pending.get_mut(&bucket_key) {
                let mut consumed = false;
                if let Some(v) = b.by_id.get_mut(&id) {
                    if v.len() == 1 {
                        let p = v.remove(0);
                        consumed = v.is_empty();
                        bound = Some((format!("pipe-pair:{}:{}", frame.ppid, frame.pid), p));
                        pair_face = true;
                    }
                }
                // the completed id's empty vec leaves the map: a stale
                // empty face under the id would pollute the fallback's
                // later lookups
                if consumed {
                    b.by_id.remove(&id);
                }
            }
        }
        // the global fallback answers only the pipe faces and the
        // unresolved placeholder: a RESOLVED socket connection's
        // response never reads another connection's id
        if bound.is_none() && (pipe_class || frame.peer == "unresolved") {
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
                let bucket_key: Option<String> = self
                    .pending
                    .iter()
                    .find(|(_, b)| b.by_id.get(&id).is_some_and(|v| !v.is_empty()))
                    .map(|(k, _)| k.clone());
                if let Some(bucket_key) = bucket_key {
                    if let Some(b) = self.pending.get_mut(&bucket_key) {
                        let mut consumed = false;
                        let consumed_pair: Option<String>;
                        if let Some(v) = b.by_id.get_mut(&id) {
                            if v.len() == 1 {
                                let p = v.remove(0);
                                consumed = v.is_empty();
                                // the session face resolves first: the
                                // pair that bound earlier responses on
                                // this channel rides, exactly as the
                                // flush face resolves (the dying
                                // writer's fallback carries the known
                                // session, never a separate raw face)
                                consumed_pair = if p.peer.starts_with("pipe:") {
                                    let known: Vec<String> = self
                                        .sessions
                                        .iter()
                                        .filter(|(k, s)| {
                                            k.starts_with("pipe-pair:")
                                                && s.channels.contains(&p.peer)
                                        })
                                        .map(|(k, _)| k.clone())
                                        .collect();
                                    if known.len() == 1 {
                                        known.first().cloned()
                                    } else {
                                        None
                                    }
                                } else {
                                    // the socket classes key the
                                    // session by the peer itself
                                    Some(p.peer.clone())
                                };
                                // the session keys on the request's own channel
                                bound = Some((
                                    consumed_pair.unwrap_or_else(|| p.peer.clone()),
                                    p,
                                ));
                            }
                        }
                        if consumed {
                            b.by_id.remove(&id);
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
        // the response half's boundary faces ride the merged record's
        // evidence (the R123 face): a chunked-join or tls-boundary face
        // names the capture the reply survived, so the merged record
        // never drops the reply's capture proof
        extra.extend(frame.tap_evidence);
        if error_face {
            extra.push("error-response".into());
        }
        let ev = self.emit_merged(Some(bind_key), &p, result, extra, false);
        // the session's channel face: both halves' channels ride it, so
        // the client-side notifications of this conversation resolve to
        // this same session. The `unresolved` placeholder never rides:
        // a dead writer's face names no channel, and registering it
        // would let unrelated dying writers hijack the session.
        if let Some(s) = self.sessions.get_mut(&ev.peer) {
            if !s.channels.contains(&p.peer) && is_channel_face(&p.peer) {
                s.channels.push(p.peer.clone());
            }
            if !s.channels.contains(&frame.peer) && is_channel_face(&frame.peer) {
                s.channels.push(frame.peer.clone());
            }
        }
        vec![ev]
    }

    // -- emission --------------------------------------------------------

    /// The merged session event: the request side and the response side
    /// of one bind. `bind_key = None` marks the flush path, where no
    /// server ever bound and the record rides the request's own
    /// channel with the loss evidence. `stamped_at_observation`
    /// carries the flush face: the record stamps the request's
    /// observation time, never the emission moment.
    fn emit_merged(
        &mut self,
        bind_key: Option<String>,
        p: &Pending,
        result: Value,
        extra_evidence: Vec<String>,
        stamped_at_observation: bool,
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
                // touch: the event marks the session's activity face
                session.last_activity = Instant::now();
                session.cap_fingerprint = Some(capability_fingerprint(caps));
                session.protocol_version = result
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
        }
        let session = self.sessions.entry(peer.clone()).or_insert_with(Session::new);
        // touch: the event marks the session's activity face
        session.last_activity = Instant::now();
        let fp = session.cap_fingerprint.clone();
        let proto = session.protocol_version.clone();

        let mut evidence = p.tap_evidence.clone();
        evidence.push(format!("chan:{}", p.peer));
        // the dedup face: the extra faces (the response half's capture
        // proof, the bind faces) never duplicate a line the request
        // half already carries
        for face in extra_evidence {
            if !evidence.contains(&face) {
                evidence.push(face);
            }
        }
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
        let verdict = if self.method_is_a2a(&p.method) && frame_is_jsonrpc(&p.req) {
            Verdict::A2a
        } else if frame_is_jsonrpc(&p.req) && self.method_is_mcp(&p.method) {
            Verdict::Mcp
        } else {
            // an unframed face stays honest: the verdict comes from the
            // protocol semantics, never from a method name alone - a
            // frame that carries no valid JSON-RPC framing member never
            // becomes mcp, whatever its method string claims
            Verdict::AgentUnidentified
        };
        let event_name = if frame_is_jsonrpc(&p.req) {
            event_name_for(&p.method)
        } else {
            "unidentified"
        };
        // the observation time rides the key: a restarted capture that
        // re-observes the same id on the same session is a NEW call,
        // never a replay of an earlier run's event. The run-unique
        // observation sequence rides beside it: two exchanges that
        // reuse one id within the SAME second key twice, never once
        // (the R120 face; across runs the observation moment carries
        // the separation, the run counter carries this run's)
        let dedup = format!(
            "{}:{}:{}:{}@{}.{:012x}",
            p.transport, peer, event_name, p.id, p.observed_ts, p.seq_at_park
        );
        let payload = match &bind_key {
            Some(_) => Some(serde_json::json!({"request": p.req, "result": result})),
            None => Some(serde_json::json!({"request": p.req, "result": Value::Null})),
        };
        // the merged bind stamps the bind time (the response half
        // completes the record); every flush face stamps the request's
        // observation time, never the capture window's end (ADR-0007)
        let ts = if stamped_at_observation {
            p.observed_ts.clone()
        } else {
            now_rfc3339()
        };
        Event {
            ts,
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
            session_id: Some(session_id_face(&p.tap_evidence, peer.clone())),
            peer,
            dedup,
            payload,
            evidence: Some(evidence),
            source: self.source.clone(),
            schema_version: RECORD_SCHEMA_VERSION.into(),
        }
    }

    /// The agent-shaped frame the machine cannot bind. Evidence carries
    /// the shape features and, on repeated frames inside the burst
    /// window on one session, the cadence line (spec section 6).
    fn emit_orphan(&mut self, frame: Frame, mut features: Vec<String>) -> Event {
        // the orphan keys its own channel: no pair bound, so no pipe
        // pair face rides the record
        let key = frame.peer.clone();
        let burst_line = {
            let session = self
                .sessions
                .entry(key.clone())
                .or_insert_with(Session::new);
                // touch: the event marks the session's activity face
                session.last_activity = Instant::now();
                self.obs_seq += 1;
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
            line
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
            session_id: Some(session_id_face(&frame.tap_evidence, key.clone())),
            peer: key.clone(),
            dedup: format!(
                "{}:{}:unidentified:orphan-{:016x}@{}.{:012}",
                frame.transport,
                key,
                fnv64(serde_json::to_vec(&frame.payload).unwrap_or_default().as_slice()),
                now_rfc3339(),
                self.obs_seq,
            ),
            payload: Some(frame.payload.clone()),
            evidence: Some([frame.tap_evidence, features].concat()),
            source: self.source.clone(),
            schema_version: RECORD_SCHEMA_VERSION.into(),
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

/// the JSON-RPC framing face: the verdict requires the member the
/// classifier keys on - a frame without `jsonrpc: "2.0"` never takes
/// `mcp` or `a2a`, whatever its method string claims.
fn frame_is_jsonrpc(payload: &Value) -> bool {
    payload.get("jsonrpc").and_then(|j| j.as_str()) == Some("2.0")
}

/// The channel-face check (ADR-0007 face rule): only a real channel
/// resolves or rides a session. The tap's `unresolved` placeholder
/// names no channel - a dead writer's traffic never hijacks another
/// conversation's session.
fn is_channel_face(peer: &str) -> bool {
    !peer.is_empty() && peer != "unresolved"
}
