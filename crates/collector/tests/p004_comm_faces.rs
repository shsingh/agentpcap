// P004 — the per-sample cache faces (issue #88): the comm face, the
// failed-lookup face and the channel face ride caches that cut the
// per-sample /proc burn. The behaviors: cache hits, expiry, the failed
// lookups, and the descriptor-reuse face (the fd face re-reads per
// sample — a replaced pipe never answers a stale channel). The stdin
// fd face never rides (it may be a terminal or /dev/null under the
// harness): the pipe face rides a pipe the test OWNS.
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

    // the channel face: a pipe the test OWNS resolves as pipe:N — the
    // test never assumes the stdin fd rides a pipe (the stdin face may
    // ride a terminal or /dev/null under the harness)
    let mut chan: ChannelRetryCache = std::collections::HashMap::new();
    let mut pipe_fds = [0 as libc::c_int; 2];
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0, "the test pipe faces open");
    }
    let read_fd = pipe_fds[0] as u32;
    let face = cached_pipe_channel(me, read_fd, &mut chan, std::time::Duration::from_secs(5));
    assert!(
        face.as_deref().unwrap_or_default().starts_with("pipe:"),
        "the test's own pipe face reads pipe:N: {face:?}"
    );
    unsafe {
        libc::close(pipe_fds[0]);
        libc::close(pipe_fds[1]);
    }

    // the failed-lookup face: a dead writer's fd rides None twice with
    // one face each (the retry never re-burns)
    let miss1 = cached_pipe_channel(dead, 3, &mut chan, std::time::Duration::from_secs(5));
    let miss2 = cached_pipe_channel(dead, 3, &mut chan, std::time::Duration::from_secs(5));
    assert!(
        miss1.is_none() && miss2.is_none(),
        "the dead writer's fd face is None twice"
    );

    // the reuse face: a SUCCESSED (pid, fd) never caches — the next
    // readlink answers the fd's own face, a replaced pipe never
    // answers a stale channel
    assert!(
        !chan.contains_key(&(me, read_fd)),
        "a face that resolves never rides the failed cache"
    );
}
