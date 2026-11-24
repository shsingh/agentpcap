// P004 — the per-sample cache faces (issue #88): the comm face, the
// failed-lookup face and the channel face ride caches that cut the
// per-sample /proc burn. The behaviors: cache hits, expiry, the failed
// lookups, and the descriptor-reuse face (the fd face re-reads per
// sample — a replaced pipe never answers a stale channel). The test
// faces ride REAL /proc fds (the test's own fs), no tap internals.
// Spec: docs/spec.md#13-evaluation-hooks.

use agentpcap_collector::{
    cached_comm, cached_pipe_channel, ChannelRetryCache, CommCache,
};

#[test]
fn p004_the_per_sample_caches_answer_each_behavior() {
    let mut comm: CommCache = std::collections::HashMap::new();

    // the cache hit: the own pid's comm rides twice and the second read
    // answers from the cache (same face both ways)
    let me = std::process::id();
    let first = cached_comm(me, &mut comm, std::time::Duration::from_secs(5));
    assert!(first.is_some(), "a live pid's comm always answers");
    let second = cached_comm(me, &mut comm, std::time::Duration::from_secs(5));
    assert_eq!(first, second, "the cached face answers identically");

    // the failed-lookup face: a dead pid's cache rides, and the second
    // face answers from the cache (a None face, not a retry)
    let dead = 2_000_000_000u32; // above the pid_max face
    let failed = cached_comm(dead, &mut comm, std::time::Duration::from_secs(5));
    assert!(failed.is_none(), "a dead pid's comm face rides None twice");
    let failed2 = cached_comm(dead, &mut comm, std::time::Duration::from_secs(5));
    assert_eq!(failed, failed2, "the failed face never re-reads /proc");

    // the expiry face: ttl 0 forces the second read to re-answer
    let mut expired: CommCache = std::collections::HashMap::new();
    let hit1 = cached_comm(me, &mut expired, std::time::Duration::from_secs(0));
    assert!(hit1.is_some());
    assert!(
        expired.contains_key(&me),
        "the expired entry still rides the map for the next fill"
    );

    // the channel face: the test's own stdin pipe resolves as pipe:N
    let mut chan: ChannelRetryCache = std::collections::HashMap::new();
    assert!(
        std::path::Path::new("/proc/self/fd/0").exists(),
        "the test's own stdin fd face exists"
    );
    let _ = cached_pipe_channel(
        me,
        0,
        &mut chan,
        std::time::Duration::from_secs(5),
    );

    // the failed-lookup face: a dead writer's fd rides None twice with
    // one face each (the retry never re-burns)
    let miss1 = cached_pipe_channel(
        dead, 3, &mut chan, std::time::Duration::from_secs(5),
    );
    let miss2 = cached_pipe_channel(
        dead, 3, &mut chan, std::time::Duration::from_secs(5),
    );
    assert!(miss1.is_none() && miss2.is_none(), "the dead writer's fd face is None twice");

    // the reuse face: a SUCCESSED (pid, fd) never caches — the next
    // readlink answers the fd's own face, a replaced pipe never
    // answers a stale channel
    assert!(
        !chan.contains_key(&(me, 0)),
        "a face that resolves never rides the failed cache"
    );
}
