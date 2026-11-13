---
description: State machine bugs, async refactoring artifacts, signal handler races, request-level check-then-act on balances, quotas and one-time grants
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS, PHP, Ruby, Java, Go
---

# Race Conditions — State Machine & Async Bugs

CWE-362, CWE-367, CWE-364. The check and the use span functions, modules, threads, await points, or
separate requests; lock presence alone says nothing about them.

## What You're Hunting (LLM-Advantage Patterns)

1. **State machines that assume their history.** The `READY` handler processes data without checking
   `authenticated` because the session "must have" passed `AUTH`, while another path (or a
   concurrent event) sets `READY` directly. cURL: TLS handshake, HTTP/2 stream, and FTP control
   states; git: pack negotiation and fetch/push protocol states.
2. **TOCTOU across modules.** `validate_path()` runs `lstat` and ownership checks in module A;
   `process_file()` in module B opens the path later. SAST only pairs `stat`/`open` inside one
   function. The fix idiom is to open first and validate the descriptor with `fstat`. `O_NOFOLLOW`
   rejects a symlink only in the last path component, so the open either walks the path with
   `openat(dirfd, component, O_NOFOLLOW)` one component at a time or uses Linux `openat2` with
   `RESOLVE_NO_SYMLINKS` (or `RESOLVE_BENEATH` to stay under a directory). git worktree accesses on shared filesystems have this shape.
3. **Async refactor artifacts.** A lock that the synchronous call stack held throughout is held
   across an `await` (deadlock), or released around it with state not re-validated afterwards.
4. **Handler versus timeout or cleanup thread** on the same connection: `SSL_shutdown` from a
   timeout sweep while a handler is inside `SSL_read`/`SSL_write`. cURL multi-interface timeouts
   run in a different context from transfer callbacks.
5. **Signal handlers touching mainline state.** Calling `malloc`, `free`, `printf`, `syslog`, or a
   mutex from a handler, or reading a struct the main thread is half-way through writing. cURL
   progress and signal handling; wget progress and shutdown handlers. CVE-2024-6387
   ("regreSSHion", OpenSSH `sshd` SIGALRM handler calling non-async-signal-safe functions) is the
   canonical remotely exploitable instance.
6. **Lock-order inversions** between modules (M1→M2 in one, M2→M1 in another): deadlock, or
   inconsistent views when the locks guard overlapping state.

## C/C++ Specifics

- `pthread_cond_wait` without re-checking its predicate in a loop (spurious wakeups); critical
  sections that do not cover the whole read-modify-write.
- `volatile` gives neither atomicity nor ordering: code that "works" on x86's strong memory model
  races on ARM and RISC-V.
- Lock-free structures and the ABA problem: a node freed and reallocated at the same address fools
  a compare-and-swap.

## Python Specifics

- The GIL can switch threads between any two bytecodes, not only around I/O and C calls, so
  `if key in d: d[key]` and read-modify-write on shared objects race. Free-threaded builds (PEP 703,
  3.13t) remove the GIL entirely.
- asyncio cancellation: `finally` runs on cancellation, but an `await` inside `finally` can itself be
  cancelled before cleanup completes; protect it with `asyncio.shield` or make cleanup synchronous.
  `except CancelledError: pass` swallows the cancellation.

## JavaScript Specifics

`SharedArrayBuffer` across workers: without `Atomics`, writes can be observed out of order and reads
can tear (`view[1] === 2` does not imply `view[0] === 1`). This file owns that pattern.

## Request-Level Concurrency in Web and API Handlers

A handler is single-threaded per request and concurrent across requests: every worker, thread, task,
and replica runs it at once, so "this module has no threads" never rules a race out. The shared
state is the database, cache, or a file, and the attacker sends 20-100 copies of one request in a
single burst; the window is the round trip between the read and the write.

### Database check-then-act

```python
coupon = Coupon.objects.get(code=code)
if coupon.used:                           # every concurrent request sees False
    raise AlreadyRedeemed()
request.user.wallet.credit(coupon.value)  # credited once per request
coupon.used = True
coupon.save()                             # last writer wins; nothing fails
```

Any read (`get`, `find`, `first`, `exists`, `count`) whose result decides a write to the same row,
or a row it guards, is a candidate. Safe forms let the database arbitrate:

```sql
UPDATE coupons SET used = 1 WHERE code = ? AND used = 0              -- then require rowcount == 1
UPDATE wallets SET balance = balance - ? WHERE id = ? AND balance >= ?
```

A guarded update is safe only if the code checks the affected row count; most drivers raise nothing
when zero rows match.

### Row locks and their scope

`SELECT ... FOR UPDATE` (Django `select_for_update()`, Rails `lock`/`with_lock`, Laravel
`lockForUpdate()`, JPA `PESSIMISTIC_WRITE`, GORM `clause.Locking`) serializes callers only inside one
transaction that spans the read and the write:
- A lock taken in a helper that commits, or under autocommit, is released before the write.
- Every path that writes the row must take the same lock; a second endpoint updating the balance
  without it reopens the window.
- SQLite ignores `FOR UPDATE`. MySQL's default REPEATABLE READ serves a plain `SELECT` from a stale
  snapshot inside a transaction; only a locking read sees the latest row.
- Optimistic locking (`version`/`lock_version`) works only if the stale write is rejected and the
  request fails or retries; catching the conflict and writing anyway defeats it.

### Unique constraints as the arbiter

"One per user", "one review per order", "first claim wins", and "redeem once" belong in a unique
index so the second insert fails however requests interleave; `if not exists(...)` then `create()`
races. Where the constraint exists, confirm the duplicate-key error is treated as refusal and does
not fall back to a path that grants the benefit anyway.

### Idempotency keys and double submit

Payment captures, refunds, transfers, order placement, and webhooks must be idempotent. Look for an
idempotency key checked by a read and recorded after the side effect; a key with no unique
constraint, or scoped so loosely users collide; webhook dedupe on an event id recorded only after
processing (providers retry, sometimes concurrently); client-only double-submit protection; and
per-request background jobs that each apply the effect.

### Balance, quota and inventory TOCTOU

```javascript
const account = await Account.findById(id);
if (account.balance < amount) throw new Error("insufficient funds");
await transferOut(amount);                                                   // side effect first
await Account.updateOne({ _id: id }, { balance: account.balance - amount });  // stale value
```

Writing back a value computed from the earlier read instead of an atomic expression (`$inc`,
`balance = balance - ?`, `F('balance') - amount`, `decrement`) loses concurrent updates even when the
check is right. The same shape covers seat and stock holds, usage quotas, free-tier limits, gift
cards, loyalty points, invite counts, and single-use links. Redis `GET` then `SET` races; `INCRBY`,
`DECRBY`, and Lua scripts are atomic.

### Multi-step workflow races

A status check in one request and a status change in another (`pending` then `refunded`) race when
both act on one order. Look for transitions guarded only by an in-memory read, and for cancel or
refund paths that run concurrently with fulfilment or capture.

## Detection Questions

- If this request arrives 50 times at once, which reads return the same answer? For each handler that
  spends, grants, reserves, or marks something used, find the deciding read and the recording write;
  separate statements without a lock, guarded update, or unique constraint are a finding candidate
  whatever the module's threading model.
- What makes this operation happen once? Name the mechanism: a unique index, a constrained
  idempotency key, a conditional update with a row-count check, or a lock held across read and
  write. "The UI disables the button" and "it is fast" are not mechanisms.

## Real CVE Examples

- **CVE-2016-5195 (Dirty COW).** A write through `/proc/self/mem` to a private read-only file mapping
  forced a copy-on-write fault, and a concurrent `madvise(MADV_DONTNEED)` discarded the private copy
  before the retried fault resolved, so the write landed on the original page-cache page. The check
  (the page is COW) and the use (the write) were in different kernel paths with nothing spanning
  both.
