// C129 — the ledger writer's buffered landing face (issue #88, ADR-0002):
// the writer rides one buffered surface and the records land whole at
// the batch boundary, never per record. A concurrent reader (the export
// follow, the gate-side poller) between appends sees NOTHING until the
// flush face fires, then sees complete lines only — never a torn tail.
// The ADR-0002 sync face rides the boundary too: the writer syncs at
// least every five seconds and always at exit (the `close` face), so
// the durability contract tightens with the landing face rather than
// loosening it.
use agentpcap_ledger::LedgerWriter;
use serde_json::json;
use std::fs;
use std::io::Read;

fn rec(i: u64) -> serde_json::Value {
    json!({
        "pid": 100000 + i, "process": "python3", "event": "tools-call",
        "verdict": "mcp", "dedup": format!("u:c129:{}:{}", std::process::id(), i),
        "request": {"jsonrpc":"2.0","id":i,"method":"tools/call",
                    "params":{"name":"read","arguments":{"path":"/etc/hostname"}}},
        "schema_version": "1.0",
    })
}

#[test]
fn c129_the_writer_lands_at_the_batch_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c129.jsonl");
    let mut writer = LedgerWriter::create(&path).unwrap();

    // three records ride the buffer; NO record lands until the batch face
    writer.append(&rec(1)).unwrap();
    writer.append(&rec(2)).unwrap();
    writer.append(&rec(3)).unwrap();

    let mut buf = String::new();
    {
        let mut f = fs::File::open(&path).unwrap();
        f.read_to_string(&mut buf).unwrap();
    }
    assert_eq!(
        buf, "",
        "no record lands before the batch face: the per-record flush \
         leaves the hot path"
    );

    // the boundary face: the caller flushes and the lines land whole
    writer.flush_pending().unwrap();
    let mut buf = String::new();
    {
        let mut f = fs::File::open(&path).unwrap();
        f.read_to_string(&mut buf).unwrap();
    }
    assert_eq!(buf.lines().count(), 3, "the boundary lands every record");
    for line in buf.lines() {
        // each landed line parses whole — a torn tail face would fail
        let v: serde_json::Value = serde_json::from_str(line)
            .expect("the landed record is a whole JSON object");
        assert!(v.get("prev").is_some(), "the chain face rides");
    }

    // the ADR-0002 exit face: append a 4th record WITH PENDING state,
    // then close — the close face must flush what holds, so if close()
    // stopped flushing pending records this face would fail
    writer.append(&rec(4)).unwrap();
    let mut buf = String::new();
    {
        let mut f = fs::File::open(&path).unwrap();
        f.read_to_string(&mut buf).unwrap();
    }
    assert_eq!(
        buf.lines().count(),
        3,
        "the record stays in memory until the close face lands it"
    );
    writer.close().unwrap();
    let mut buf = String::new();
    {
        let mut f = fs::File::open(&path).unwrap();
        f.read_to_string(&mut buf).unwrap();
    }
    assert_eq!(buf.lines().count(), 4, "the close face lands the tail");
}
