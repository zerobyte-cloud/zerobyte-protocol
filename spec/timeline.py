#!/usr/bin/env python3
"""Known-answer vectors for ZeroByte Timeline v1.

The independent reference every SDK tests its timeline against. It shares no
code with any of them: the commit and message formats, the clock, the merge
and the catch-up selection are written out below from timeline-v1.md, over
the Python standard library only (hashlib for SHA-256).

    python3 spec/timeline.py > spec/timeline.json

Never regenerate the vectors from an implementation under test; change this
file, review the diff, and copy the result into each SDK. Cases that need a
message over the 1 MiB limit (`too_large`) are left to each implementation's
own tests: as hex they would be over 2 MB.
"""

import hashlib
import json

MESSAGE_LIMIT = 1_048_576
COMMIT_LIMIT = MESSAGE_LIMIT - 7
ZERO16 = bytes(16)
ZERO32 = bytes(32)


class Reject(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def u(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def next_clock(last: int, now_ms: int) -> int:
    return max(last + 1, now_ms << 16)


# ---------------------------------------------------------------- encoding


def entry_body(collection: bytes, key: bytes, value) -> bytes:
    out = u(len(collection), 1) + collection + u(len(key), 2) + key
    if value is None:
        return out + b"\x00"
    return out + b"\x01" + u(len(value), 4) + value


def encode_commit(replica, sequence, parent, clock, seen, entries) -> bytes:
    out = b"\x01" + replica + u(sequence, 8) + parent + u(clock, 8)
    out += u(len(seen), 2) + b"".join(r + u(s, 8) for r, s in seen)
    out += u(len(entries), 4)
    for collection, key, value in entries:
        out += u(len(collection), 1) + collection + u(len(key), 2) + key
        out += b"\x00" if value is None else b"\x01" + u(len(value), 4) + value
    return out


def encode_heads(heads) -> bytes:
    out = u(len(heads), 2)
    for replica in sorted(heads):
        sequence, clock, commit_id = heads[replica]
        out += replica + u(sequence, 8) + u(clock, 8) + commit_id
    return out


def encode_commits_message(commits) -> bytes:
    return b"\x01" + u(len(commits), 2) + b"".join(u(len(c), 4) + c for c in commits)


def encode_state(flags: int, heads) -> bytes:
    return b"\x02" + bytes([flags]) + encode_heads(heads)


def encode_catch_up(final: bool, heads, entries) -> bytes:
    out = b"\x03" + bytes([1 if final else 0]) + encode_heads(heads if final else {})
    out += u(len(entries), 4)
    for (collection, key), (clock, replica, sequence, value) in entries:
        out += u(len(collection), 1) + collection + u(len(key), 2) + key
        out += u(clock, 8) + replica + u(sequence, 8)
        out += b"\x00" if value is None else b"\x01" + u(len(value), 4) + value
    return out


# ---------------------------------------------------------------- decoding


class Reader:
    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.offset = offset

    def take(self, n: int) -> bytes:
        if self.offset + n > len(self.data):
            raise Reject("malformed")
        chunk = self.data[self.offset:self.offset + n]
        self.offset += n
        return chunk

    def int(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def done(self):
        if self.offset != len(self.data):
            raise Reject("malformed")


def name(reader: Reader, width: int, high: int) -> bytes:
    raw = reader.take(reader.int(width))
    if not 1 <= len(raw) <= high:
        raise Reject("malformed")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Reject("malformed")
    return raw


def value_of(reader: Reader):
    kind = reader.int(1)
    if kind == 0:
        return None
    if kind == 1:
        return reader.take(reader.int(4))
    raise Reject("malformed")


def decode_commit(data: bytes) -> dict:
    if len(data) < 71:
        raise Reject("malformed")
    if data[0] != 1:
        raise Reject("unsupported_version")
    r = Reader(data, 1)
    replica, sequence, parent, clock = r.take(16), r.int(8), r.take(32), r.int(8)
    if replica == ZERO16 or sequence == 0 or (sequence == 1) != (parent == ZERO32):
        raise Reject("malformed")
    seen, previous = [], None
    for _ in range(r.int(2)):
        other, other_sequence = r.take(16), r.int(8)
        if other in (ZERO16, replica) or other_sequence == 0 or (
                previous is not None and other <= previous):
            raise Reject("malformed")
        seen.append((other, other_sequence))
        previous = other
    count = r.int(4)
    if count == 0:
        raise Reject("malformed")
    entries, previous = [], None
    for _ in range(count):
        collection, key = name(r, 1, 64), name(r, 2, 1024)
        value = value_of(r)
        if previous is not None and (collection, key) <= previous:
            raise Reject("malformed")
        entries.append((collection, key, value))
        previous = (collection, key)
    r.done()
    if len(data) > COMMIT_LIMIT:
        raise Reject("too_large")
    return {"replica": replica, "sequence": sequence, "parent": parent, "clock": clock,
            "seen": seen, "entries": entries, "id": hashlib.sha256(data).digest()}


def decode_heads(r: Reader) -> dict:
    heads, previous = {}, None
    for _ in range(r.int(2)):
        replica, sequence, clock, commit_id = r.take(16), r.int(8), r.int(8), r.take(32)
        if replica == ZERO16 or sequence == 0 or (previous is not None and replica <= previous):
            raise Reject("malformed")
        heads[replica] = (sequence, clock, commit_id)
        previous = replica
    return heads


def decode_message(data: bytes) -> dict:
    if not data:
        raise Reject("malformed")
    if len(data) > MESSAGE_LIMIT:
        raise Reject("too_large")
    kind = data[0]
    r = Reader(data, 1)
    if kind == 1:
        count = r.int(2)
        if count == 0:
            raise Reject("malformed")
        commits = [r.take(r.int(4)) for _ in range(count)]
        r.done()
        for commit in commits:
            decode_commit(commit)
        return {"type": "commits", "commits": commits}
    if kind == 2:
        flags = r.int(1)
        if flags & ~0b11:
            raise Reject("malformed")
        heads = decode_heads(r)
        r.done()
        return {"type": "state", "flags": flags, "heads": heads}
    if kind == 3:
        flags = r.int(1)
        if flags & ~0b1:
            raise Reject("malformed")
        heads = decode_heads(r)
        if not flags & 1 and heads:
            raise Reject("malformed")
        entries, previous = [], None
        for _ in range(r.int(4)):
            collection, key = name(r, 1, 64), name(r, 2, 1024)
            clock, replica, sequence = r.int(8), r.take(16), r.int(8)
            if replica == ZERO16 or sequence == 0:
                raise Reject("malformed")
            value = value_of(r)
            if previous is not None and (collection, key) <= previous:
                raise Reject("malformed")
            entries.append(((collection, key), (clock, replica, sequence, value)))
            previous = (collection, key)
        r.done()
        return {"type": "catch-up", "final": bool(flags & 1), "heads": heads,
                "entries": entries}
    raise Reject("unsupported_version")


# ---------------------------------------------------------------- merging


class Replica:
    def __init__(self):
        self.entries = {}  # (collection, key) -> (clock, replica, sequence, value)
        self.heads = {}    # replica -> (sequence, clock, id)
        self.last = 0

    def put(self, slot, stamped):
        current = self.entries.get(slot)
        if current is None or stamped[:2] > current[:2]:
            self.entries[slot] = stamped

    def merge_commit(self, data: bytes) -> str:
        c = decode_commit(data)
        head = self.heads.get(c["replica"])
        if head is not None and c["sequence"] <= head[0]:
            if c["sequence"] == head[0] and c["id"] != head[2]:
                raise Reject("diverged")
            return "skipped"
        if c["sequence"] != (head[0] if head else 0) + 1:
            return "gap"
        if head is not None and (c["parent"] != head[2] or c["clock"] <= head[1]):
            raise Reject("diverged")
        for collection, key, value in c["entries"]:
            self.put((collection, key), (c["clock"], c["replica"], c["sequence"], value))
        self.heads[c["replica"]] = (c["sequence"], c["clock"], c["id"])
        self.last = max(self.last, c["clock"])
        return "merged"

    def catch_up(self, requester_heads):
        """Every entry whose stamp is after the requester's heads (§5)."""
        chosen = []
        for slot in sorted(self.entries):
            clock, replica, sequence, value = self.entries[slot]
            head = requester_heads.get(replica)
            if head is None or sequence > head:
                chosen.append((slot, self.entries[slot]))
        return chosen

    def view(self):
        return [{"collection": c.decode(), "key": k.decode(), "clock": str(clock),
                 "replica": replica.hex(), "sequence": sequence,
                 "value": None if value is None else value.hex()}
                for (c, k), (clock, replica, sequence, value) in sorted(self.entries.items())]


def heads_view(heads):
    return [{"replica": r.hex(), "sequence": s, "clock": str(c), "id": i.hex()}
            for r, (s, c, i) in sorted(heads.items())]


# ---------------------------------------------------------------- vectors


def build() -> dict:
    a = bytes.fromhex("a1" * 16)
    b = bytes.fromhex("b2" * 16)
    t0 = 1_762_855_200_000  # 2025-11-11T10:00:00Z

    clock_cases = []
    for last, now in [
        (0, t0),                                  # fresh: the wall clock
        ((t0 << 16) + 5, t0),                     # same millisecond: the counter
        ((t0 + 9) << 16, t0),                     # wall clock behind: still forward
        ((t0 << 16) | 0xFFFF, t0),                # counter full: into the next millisecond
    ]:
        clock_cases.append({"last": str(last), "now_ms": now, "next": str(next_clock(last, now))})

    commits = {}

    def commit(label, replica, sequence, parent, clock, seen, entries):
        data = encode_commit(replica, sequence, parent, clock, seen, entries)
        decoded = decode_commit(data)
        commits[label] = {
            "name": label, "replica": replica.hex(), "sequence": sequence,
            "parent": parent.hex(), "clock": str(clock),
            "seen": [{"replica": r.hex(), "sequence": s} for r, s in seen],
            "entries": [{"collection": c.decode(), "key": k.decode(),
                         "value": None if v is None else v.hex()} for c, k, v in entries],
            "hex": data.hex(), "id": decoded["id"].hex(),
            "_data": data, "_id": decoded["id"],
        }
        return data

    a1_clock = next_clock(0, t0)
    commit("a1", a, 1, ZERO32, a1_clock, [], [
        (b"day", b"20251110", b"hrv=45"),
        (b"plan", b"p-1", b"tempo"),
    ])
    a2_clock = next_clock(a1_clock, t0 + 5)
    commit("a2", a, 2, commits["a1"]["_id"], a2_clock, [], [
        (b"day", b"20251111", b"hrv=47"),
        (b"plan", b"p-1", None),
    ])
    # B merged a1, then wrote at the same millisecond as a2 without seeing it:
    # equal clocks, so the replica id decides, and b2… is above a1….
    b1_clock = next_clock(max(0, a1_clock), t0 + 5)
    assert b1_clock == a2_clock
    commit("b1", b, 1, ZERO32, b1_clock, [(a, 1)], [
        (b"plan", b"p-1", b"tempo 2x10"),
        (b"submission", b"w-1", b'{"sport":"run"}'),
    ])

    orders = [["a1", "a2", "b1"], ["b1", "a1", "a2"], ["a1", "b1", "a2"]]
    states = []
    for order in orders:
        replica = Replica()
        outcomes = [replica.merge_commit(commits[name]["_data"]) for name in order]
        assert outcomes == ["merged"] * 3
        states.append((replica.view(), heads_view(replica.heads), replica.last))
    assert all(s == states[0] for s in states)
    merged = Replica()
    for name in orders[0]:
        merged.merge_commit(commits[name]["_data"])

    gap = Replica()
    gap_outcome = gap.merge_commit(commits["a2"]["_data"])
    assert gap_outcome == "gap"
    again = Replica()
    again.merge_commit(commits["a1"]["_data"])
    skipped = again.merge_commit(commits["a1"]["_data"])
    assert skipped == "skipped"

    requester = {a: 1}
    chosen = merged.catch_up(requester)
    catch_up_hex = encode_catch_up(True, merged.heads, chosen)
    assert decode_message(catch_up_hex)["entries"] == chosen

    commits_message = encode_commits_message([commits["a1"]["_data"], commits["a2"]["_data"]])
    state_heads = {a: merged.heads[a]}
    state_message = encode_state(0b01, state_heads)
    part_message = encode_catch_up(False, {}, chosen[:1])
    for message in (commits_message, state_message, part_message, catch_up_hex):
        decode_message(message)

    # ------------------------------------------------------------ rejections
    a1 = commits["a1"]["_data"]
    bad = []

    def reject(label, kind, data, code):
        try:
            (decode_commit if kind == "commit" else decode_message)(data)
        except Reject as error:
            assert error.code == code, (label, error.code)
        else:
            raise AssertionError(label)
        bad.append({"name": label, "kind": kind, "hex": data.hex(), "error": code})

    entry = [(b"day", b"20251110", b"hrv=45")]
    reject("short", "commit", a1[:70], "malformed")
    reject("version", "commit", b"\x02" + a1[1:], "unsupported_version")
    reject("zero replica", "commit", encode_commit(ZERO16, 1, ZERO32, 1, [], entry), "malformed")
    reject("sequence zero", "commit", encode_commit(a, 0, ZERO32, 1, [], entry), "malformed")
    reject("zero parent above one", "commit", encode_commit(a, 2, ZERO32, 9, [], entry), "malformed")
    reject("parent at one", "commit", encode_commit(a, 1, b"\x01" * 32, 1, [], entry), "malformed")
    reject("seen names itself", "commit", encode_commit(a, 1, ZERO32, 1, [(a, 1)], entry), "malformed")
    reject("seen out of order", "commit",
           encode_commit(a, 1, ZERO32, 1, [(b, 1), (bytes.fromhex("33" * 16), 1)], entry),
           "malformed")
    reject("seen sequence zero", "commit", encode_commit(a, 1, ZERO32, 1, [(b, 0)], entry), "malformed")
    reject("no entries", "commit", encode_commit(a, 1, ZERO32, 1, [], []), "malformed")
    reject("empty collection", "commit", encode_commit(a, 1, ZERO32, 1, [], [(b"", b"k", None)]),
           "malformed")
    reject("long collection", "commit", encode_commit(a, 1, ZERO32, 1, [], [(b"c" * 65, b"k", None)]),
           "malformed")
    reject("key not utf-8", "commit", encode_commit(a, 1, ZERO32, 1, [], [(b"day", b"\xff", None)]),
           "malformed")
    unknown_kind = bytearray(encode_commit(a, 1, ZERO32, 1, [], [(b"day", b"k", None)]))
    unknown_kind[-1] = 2
    reject("unknown kind", "commit", bytes(unknown_kind), "malformed")
    reject("entries out of order", "commit",
           encode_commit(a, 1, ZERO32, 1, [], [(b"plan", b"a", None), (b"day", b"z", None)]),
           "malformed")
    reject("entry twice", "commit",
           encode_commit(a, 1, ZERO32, 1, [], [(b"day", b"k", None), (b"day", b"k", b"1")]),
           "malformed")
    reject("trailing byte", "commit", a1 + b"\x00", "malformed")
    reject("unknown type", "message", b"\x09\x00", "unsupported_version")
    reject("empty message", "message", b"", "malformed")
    reject("no commits", "message", b"\x01\x00\x00", "malformed")
    reject("commit inside refused", "message", encode_commits_message([a1 + b"\x00"]), "malformed")
    reject("state flag", "message", b"\x02\x04\x00\x00", "malformed")
    reject("heads out of order", "message",
           b"\x02\x00" + u(2, 2) + b + u(1, 8) + u(1, 8) + ZERO32 + a + u(1, 8) + u(1, 8) + ZERO32,
           "malformed")
    reject("head sequence zero", "message", b"\x02\x00" + u(1, 2) + a + u(0, 8) + u(1, 8) + ZERO32,
           "malformed")
    reject("heads before the final part", "message",
           b"\x03\x00" + encode_heads(state_heads) + u(0, 4), "malformed")
    reject("catch-up out of order", "message",
           encode_catch_up(True, {}, list(reversed(chosen))), "malformed")
    reject("truncated", "message", catch_up_hex[:-1], "malformed")

    diverged = []

    def diverge(label, sequence):
        replica = Replica()
        try:
            for data in sequence:
                replica.merge_commit(data)
        except Reject as error:
            assert error.code == "diverged", label
        else:
            raise AssertionError(label)
        diverged.append({"name": label, "commits": [d.hex() for d in sequence], "error": "diverged"})

    other_a1 = encode_commit(a, 1, ZERO32, a1_clock, [], [(b"day", b"20251110", b"hrv=46")])
    diverge("same sequence, other commit", [a1, other_a1])
    diverge("wrong parent", [a1, encode_commit(a, 2, b"\x07" * 32, a2_clock, [], entry)])
    diverge("clock not above the parent", [a1, encode_commit(
        a, 2, commits["a1"]["_id"], a1_clock, [], entry)])

    view, heads, last = states[0]
    return {
        "spec": "timeline-v1.md",
        "message_limit": MESSAGE_LIMIT,
        "commit_limit": COMMIT_LIMIT,
        "clock": clock_cases,
        "commits": [{k: v for k, v in commits[n].items() if not k.startswith("_")}
                    for n in ("a1", "a2", "b1")],
        "messages": [
            {"name": "commits", "hex": commits_message.hex()},
            {"name": "state", "flags": 1, "heads": heads_view(state_heads),
             "hex": state_message.hex()},
            {"name": "catch-up part", "final": False, "entries": 1, "hex": part_message.hex()},
        ],
        "merge": {"orders": orders, "state": view, "heads": heads, "last": str(last)},
        "gap": {"order": ["a2"], "outcome": "gap"},
        "skip": {"order": ["a1", "a1"], "outcome": "skipped"},
        "catch_up": {
            "requester_heads": [{"replica": a.hex(), "sequence": 1}],
            "entries": [{"collection": c.decode(), "key": k.decode(), "clock": str(clock),
                         "replica": r.hex(), "sequence": s,
                         "value": None if v is None else v.hex()}
                        for (c, k), (clock, r, s, v) in chosen],
            "hex": catch_up_hex.hex(),
        },
        "rejections": bad,
        "diverged": diverged,
    }


if __name__ == "__main__":
    print(json.dumps(build(), indent=1))
