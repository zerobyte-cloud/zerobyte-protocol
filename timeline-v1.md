# ZeroByte Timeline v1

One keyed state that every device of a link keeps a copy of. Each device writes its
changes as commits; every device merges every commit into the same state and the same
order, so both copies converge on one timeline. Only changes travel: a device that edits
one key sends one key. It runs on top of [Relay Protocol v1](relay-v1.md) and changes
nothing in it: the relay still sees envelopes and nothing else. Byte orders are big-endian.

## 1. Model

- A **replica** is one device's copy. It names itself with a random 16-byte **replica id**
  (not all zero) the first time it opens the timeline, and draws a new one whenever it has
  lost its state. A replica id is never reused after a loss.
- The **state** maps a **collection** and a **key** to an **entry**: a value of bytes, or a
  deletion. Collections and keys are the app's: valid UTF-8, a collection 1 to 64 bytes, a
  key 1 to 1,024 bytes.
- Every entry carries the **stamp** of the commit that wrote it: the commit's clock, replica
  id and sequence.
- Stamps are ordered by clock, then by replica id as unsigned bytes. The **timeline** is
  every commit in that order. A key's entry is the one with the greatest stamp; a deletion
  competes like a value, so a value written before a deletion can never come back.

The merge is commutative, associative and idempotent: two replicas that merged the same
commits hold the same state, whatever order the commits arrived in.

## 2. Clock

A 64-bit hybrid logical clock: milliseconds since 1970-01-01T00:00:00Z shifted left by 16,
plus a counter in the low 16 bits. A replica keeps the greatest clock it has written or
merged, `last`. A commit takes

```
clock = max(last + 1, now_ms << 16)
```

and every merged commit, catch-up entry and head raises `last` to at least its clock. A
change made after seeing another therefore always orders after it, whatever the two
devices' wall clocks say; the clocks decide only between changes that did not see each
other. A replica never refuses a clock for being far from its own; it only orders by it.

## 3. Commit

```
version (1)          0x01
replica (16)
sequence (8)         1, 2, 3 … per replica, without gaps
parent (32)          id of this replica's commit sequence − 1; 32 zero bytes for sequence 1
clock (8)            greater than the parent's clock
seen count (2)       then, ascending by replica id, one per other replica merged before it:
  replica (16) ‖ sequence (8)
entry count (4)      at least 1; then, ascending by collection and then key, bytewise,
                     no collection and key twice:
  collection length (1) ‖ collection
  key length (2) ‖ key
  kind (1)           0x00 deletion, 0x01 value
  value length (4) ‖ value          only for 0x01
```

The **commit id** is the SHA-256 of these bytes. Every entry of a commit takes the commit's
stamp. A commit is at most the message limit (§5) minus 7 bytes; a writer splits its
changes over several commits so that each fits, and refuses a single change that cannot fit
in a commit of its own (`too_large`). Large values are the app's to split into several keys.

A receiver refuses, in this order: fewer than 71 bytes (`malformed`); a version other than 1
(`unsupported_version`); a zero replica id, sequence 0, a zero parent above sequence 1 or a
non-zero one at sequence 1 (`malformed`); `seen` out of order, naming the commit's own
replica or a sequence of 0 (`malformed`); no entries, a collection or key out of its length
range or not UTF-8, another kind, entries out of order or repeated (`malformed`); bytes left
over (`malformed`); more bytes than a commit may have (`too_large`).

## 4. Merging

A replica holds its entries, its **heads** (per replica id: the sequence, clock and id of the
last commit merged from it) and `last`.

**A commit.** With `h` the head of the commit's replica:

1. Sequence at or below `h`: already merged. The same sequence with another id is
   `diverged`; otherwise skip it.
2. Sequence other than `h` + 1 (or 1 without `h`): a **gap**. Skip it and ask for a
   catch-up (§5, flag `gap`).
3. Parent other than `h`'s id, or clock not above `h`'s clock: `diverged`.
4. Each entry replaces the key's entry if there is none or the commit's stamp is greater.
5. The head becomes this commit; `last` rises to its clock.

**A local change.** The replica commits its pending changes with the next sequence, its head
as parent, `clock` per §2 and its other heads as `seen`, then merges that commit as above.

**A catch-up** (§5). Each entry replaces the key's entry if there is none or its stamp is
greater, and raises `last`. The final part's heads then replace the replica's heads where
their sequence is greater.

## 5. Messages

A message is the plaintext of one relay envelope, or one frame of any other channel between
the two devices. It is at most 1,048,576 bytes, the envelope's plaintext limit, or the lower
plaintext limit a relay set for the app.

```
type (1)
```

| Type | Name | Body |
|---|---|---|
| `0x01` | commits | count (2, at least 1), then per commit: length (4) ‖ commit |
| `0x02` | state | flags (1) ‖ heads |
| `0x03` | catch-up | flags (1) ‖ heads ‖ entry count (4) ‖ entries |

`heads` is a count (2) followed, ascending by replica id, by `replica (16) ‖ sequence (8) ‖
clock (8) ‖ id (32)`.

**state** tells the other replica what this one has merged, including its own head. Flag
bit 0 asks for a catch-up because this replica is new or lost its state; bit 1 because it
found a gap. Other bits are zero.

**catch-up** answers a state: every entry whose stamp is after the requester's heads, that is
whose sequence is above the requester's head for the entry's replica, or whose replica it
has no head for. Entries go ascending by collection and key, each as

```
collection length (1) ‖ collection ‖ key length (2) ‖ key
clock (8) ‖ replica (16) ‖ sequence (8) ‖ kind (1) ‖ [value length (4) ‖ value]
```

Flag bit 0 marks the final part, the only one with heads: the answering replica's heads.
Earlier parts have no heads. An entry always fits in a part of its own, because a commit's
fixed fields take more room than an entry's stamp and a part's header together.

Over the relay, a replica answering a request with only bit 0 may leave out its own entries
and its own head when the requester's head for it is at least the sequence the requester
last confirmed: those commits are still on their way. It sends them all when bit 1 is set
or the requester's head went back, which means the requester lost them.

A receiver refuses a type it does not know (`unsupported_version`), a message over the limit
(`too_large`), and anything out of order, out of range or with bytes left over (`malformed`).

## 6. Over the relay

Each replica writes its messages in its own direction: the primary `p2c`, the companion
`c2p`. One run of a replica:

1. Fetch the other direction after the last envelope read, open each envelope, merge each
   message in order. Keep the latest catch-up request. The other replica confirms this one's
   commits through a sequence with its head for this replica in a state, or with `seen` in
   a commit; drop confirmed commits that are still waiting to be written.
2. Persist, then prune through the highest envelope sequence fetched.
3. Commit pending changes.
4. Answer the catch-up request, if any. A long answer may be written over several runs,
   keeping its place; its final part then carries the heads from when the answer began, so
   that commits made meanwhile are not taken as covered by it. A newer request replaces an
   answer still being written. An answer with no entries and no head above the
   requester's is not written.
5. Write, in order: the commits and catch-up parts not yet written; then a state if this
   run merged a commit, replaced an entry or raised a head and wrote no commit, or if this
   replica asks for a catch-up. A new replica asks on its first run. A run that read only
   what this replica already had writes no state.
6. On `quota_exceeded`, stop and keep what was not written for the next run.

The last envelope of a run may ask the relay for a silent push to wake the other device.

## 7. Directly

Two replicas connected directly (a local network, for example) exchange state messages,
answer each other's state with a full catch-up (own entries and own head included) and
close. Commits the relay delivers later are then at or below the heads and are skipped.
Commits a replica makes and sends while connected directly also wait to be written to the
relay (§6), until the other replica confirms them.

## 8. What anyone else sees

The timeline adds nothing to what the relay sees (relay-v1 §7): envelope sizes and times.
A commit's size follows the size of the change, as any message's does.

## 9. Test vectors

[`spec/timeline.json`](spec/timeline.json) holds clock steps, three commits with their
encodings and ids, one message of each type, two merge orders that must reach the same
state, a catch-up selection and the rejections of §3 and §5. It is produced by
[`spec/timeline.py`](spec/timeline.py), an independent reference that uses only the
Python standard library. Implementations copy the file; they never regenerate it.
