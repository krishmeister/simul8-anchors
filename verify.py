#!/usr/bin/env python3
"""Simul8 reference verifier. Stdlib only — no pip install, no network, no accounts.

    python3 verify.py --self-test
    python3 verify.py --claim claim.json --anchors anchors/

This program answers one question, and refuses to answer it optimistically:

    Was this prediction committed to a Merkle root that a third party timestamped BEFORE
    the prediction was resolved?

The Simul8 Constitution v2.4 §45(e) permits presenting a prediction as independently
verifiable only if that is true. A privately held tree can be rebuilt at any time, so "we
recomputed it and it checks out" is not verification. Verification is someone with none of our
code and none of our infrastructure getting the same bytes we did, and then finding the result
in a place we do not control.

WHAT THIS PROGRAM WILL NOT DO, AND WHY THAT IS THE POINT.

It will not use the anchor's own `anchored_at` field to decide precedence. That field is the
instant *we* say we built the tree, read from *our* clock, and we could have written anything
in it. docs/VERIFY.md part 1 section 2 states the rule for the ledger's other self-reported
timestamp and it applies here identically: "a verifier should not read `created_at` as evidence
of when a row was written. The anchor carries that." An anchor that vouched for itself would
carry nothing. So the precedence test reads a timestamp obtained from OUTSIDE the payload —
GitHub's commit history, or one you supply having checked it yourself — and if it cannot get
one it reports NOT VERIFIED rather than falling back to ours. See `precedence_check`.

That refusal is the single most important behaviour here. A verifier that quietly accepted
`anchored_at` would pass every honest row, pass every dishonest one, and look identical.

THE PROCEDURE (docs/VERIFY.md part 1 section 8, completed by part 2 section 12):

    1. canonicalize the row's payload           RFC 8785, and no JSON numbers ever
    2. recompute row_hash FROM THE ROW          not from the row's claim about its own hash
    3. leaf_hash(row_hash)                      domain-separated, "leaf:"
    4. fold the sibling path to a root          domain-separated, "node:"
    5. find that root in the published anchors  the payload line, byte for byte
    6. check the third-party timestamp          obtained outside the payload, and precedes

WHAT `--self-test` COVERS THAT `--claim` DOES NOT. The currency rule of part 1 section 1 is
implemented here and checked against the document's vectors, but it is NOT on the path a claim
takes: by the time a row is published its monetary values are already decimal strings, and
verifying the row hashes those strings. The rule matters to whoever PRODUCES them, and to you
if you want to check our arithmetic rather than only our commitment to it. It is implemented
because the document publishes vectors for it, and every vector the document publishes is one
this file must reproduce.

Steps 1-4 are part 1 and need nothing but this file. Steps 5-6 are part 2 and need the public
anchor history, which is the repository this file ships in.

Everything below mirrors `ledger/canonical.py`, `ledger/hashing.py`, `ledger/merkle.py`,
`ledger/proof.py` and `ledger/anchor_payload.py` in the private repository. It is a deliberate
second implementation, not a shortcut: the claim in §45(e) is that the *document* is sufficient
for an outsider, and the only way to test that claim is to write the outsider's implementation
from the document and check the two agree. `tests/constitutional/test_verify_py_end_to_end.py`
runs this file against rows produced by the frozen writer, from a clean checkout containing
nothing but the public repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# =====================================================================================
# 1. Canonical JSON — RFC 8785 (JCS). docs/VERIFY.md part 1 section 1.
# =====================================================================================

_JSON_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class VerificationError(Exception):
    """The input cannot be verified, and saying so is the correct outcome."""


def _render_string(value):
    r"""Escape exactly as ECMAScript JSON.stringify does, and no more (part 1 section 1).

    Not `/`. Not any non-ASCII character, which is emitted as UTF-8. Control characters below
    U+0020 with no short escape become `\u` and FOUR LOWERCASE hex digits — uppercase would be
    a different byte string and therefore a different hash.
    """
    out = ['"']
    for character in value:
        escape = _JSON_ESCAPES.get(character)
        point = ord(character)
        if escape is not None:
            out.append(escape)
        elif point < 0x20:
            out.append(f"\\u{point:04x}")
        elif 0xD800 <= point <= 0xDFFF:
            raise VerificationError(
                "a lone surrogate has no UTF-8 encoding and therefore no canonical form"
            )
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _sorted_keys(mapping):
    """Sort object keys by UTF-16 CODE UNIT, which is not the same as by code point.

    The two orders agree for every character in the Basic Multilingual Plane and disagree
    above it, because a supplementary character is one code point but two surrogate code
    units. Python's default string sort is by code point, so `sorted(keys)` is subtly wrong
    here: U+10000 must sort BEFORE U+FFFD, because its first code unit is U+D800. Encoding to
    UTF-16 big-endian and sorting the bytes gives the required order.

    Part 1 pins this with vector C10. If you implemented the obvious sort, that vector is
    where you will find out.
    """
    keys = []
    for key in mapping:
        if not isinstance(key, str):
            raise VerificationError(
                f"a canonical JSON object key must be a string, got {type(key).__name__}"
            )
        keys.append(key)
    return sorted(keys, key=lambda k: k.encode("utf-16-be"))


def _render(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _render_string(value)
    if isinstance(value, dict):
        members = [f"{_render_string(k)}:{_render(value[k])}" for k in _sorted_keys(value)]
        return "{" + ",".join(members) + "}"
    if isinstance(value, (int, float)):
        # Part 1, "No numbers. At all.": every numeric quantity in the Log is a decimal
        # string, and "a verifier that meets a JSON number inside a payload should treat the
        # row as malformed rather than canonicalize it". Binary floating point cannot
        # represent decimal fractions exactly, so a number here would make the root
        # irreproducible. This is a refusal, not a limitation.
        raise VerificationError(
            f"a JSON number ({value!r}) appeared in a payload. Every numeric quantity in a "
            "Simul8 payload is a decimal string at a stated precision; a row containing a "
            "number is malformed"
        )
    if isinstance(value, (list, tuple)):
        # Array order is content, not layout, so JCS does not touch it.
        return "[" + ",".join(_render(item) for item in value) + "]"
    raise VerificationError(f"{type(value).__name__} has no canonical JSON form")


def canonical(value):
    """RFC 8785 canonical JSON as UTF-8 bytes. No BOM, no insignificant whitespace."""
    return _render(value).encode("utf-8")


# =====================================================================================
# 2. Timestamps. docs/VERIFY.md part 1 section 2.
# =====================================================================================

_TIMESTAMP_INPUT = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?(?P<offset>Z|[+-]\d{2}:\d{2})$"
)


def parse_timestamp(text):
    """Parse RFC 3339 strictly, and reject every spelling that admits two readings.

    Rejected on purpose: a lowercase `t` or `z`, a space separator, a missing offset, and any
    sub-microsecond precision that is not merely trailing zeros. Each either loses information
    or lets one instant be written two ways, and a hash cannot survive either.
    """
    if not isinstance(text, str):
        raise VerificationError(f"a timestamp is a string, got {type(text).__name__}")
    match = _TIMESTAMP_INPUT.match(text)
    if match is None:
        raise VerificationError(
            f"{text!r} is not an accepted RFC 3339 timestamp: expected "
            "YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+HH:MM), uppercase T, offset required"
        )

    frac = match.group("frac") or ""
    if len(frac) > 6:
        if set(frac[6:]) != {"0"}:
            raise VerificationError(
                f"{text!r} carries sub-microsecond precision the canonical form cannot hold, "
                "and truncating it would silently change the value"
            )
        frac = frac[:6]
    microsecond = int(frac.ljust(6, "0")) if frac else 0

    offset = match.group("offset")
    year, month, day = (int(part) for part in match.group("date").split("-"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))

    if offset == "Z":
        delta = timedelta(0)
    else:
        sign = 1 if offset[0] == "+" else -1
        offset_hours, offset_minutes = (int(part) for part in offset[1:].split(":"))
        delta = sign * timedelta(hours=offset_hours, minutes=offset_minutes)

    naive = datetime(year, month, day, hour, minute, second, microsecond)  # noqa: DTZ001
    return (naive - delta).replace(tzinfo=timezone.utc)


def canonical_timestamp(value):
    """The one form the Log hashes: RFC 3339, UTC, `Z`, ALWAYS six fractional digits.

    Twenty-seven characters, always. The six digits are not cosmetic: unspecified
    trailing-zero handling is the byte-level ambiguity most likely to make a foreign verifier
    fail to reproduce our root.
    """
    moment = parse_timestamp(value) if isinstance(value, str) else value
    if moment.tzinfo is None:
        raise VerificationError("a naive datetime names no instant")
    moment = moment.astimezone(timezone.utc)
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
        f".{moment.microsecond:06d}Z"
    )


# =====================================================================================
# 2a. Currency. docs/VERIFY.md part 1 section 1, "Currency, and the ISO 4217 exponent".
# =====================================================================================

#: The complete set. An unrecognised unit is refused, never guessed at.
MONEY_UNITS = ("major_unit", "minor_unit")

_DECIMAL_TEXT = re.compile(r"^\d+(\.\d+)?$")


def minor_unit_string(amount, exponent, unit):
    """An amount as an integer count of its currency's minor unit.

    Written from the document's three steps and NOT from the private implementation, which is
    the only way the document's sufficiency gets tested rather than assumed. The private code
    shifts a decimal's own digit tuple; this shifts the text. Two mechanisms agreeing on every
    published vector says something; one mechanism copied twice would not.

    THE CURRENCY CODE IS NOT AN ARGUMENT. Only the exponent is. Given the code, an
    implementation would be one edit away from looking the exponent up in a table, and then
    reproducing a Simul8 root would require that table at the version we happened to hold.
    """
    if unit not in MONEY_UNITS:
        raise VerificationError(f"unit must be one of {list(MONEY_UNITS)}, got {unit!r}")
    if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 0:
        raise VerificationError(f"exponent must be a non-negative integer, got {exponent!r}")

    text = str(amount).strip()
    sign = ""
    if text[:1] in "+-":
        sign = "-" if text[0] == "-" else ""
        text = text[1:]
    if not _DECIMAL_TEXT.match(text):
        raise VerificationError(f"{amount!r} is not a decimal amount")

    whole, _, frac = text.partition(".")
    # `minor_unit` is already an integer count of the minor unit, so it shifts by nothing.
    shift = exponent if unit == "major_unit" else 0

    if shift >= len(frac):
        digits = whole + frac + "0" * (shift - len(frac))
    else:
        if set(frac[shift:]) != {"0"}:
            raise VerificationError(
                f"{amount!r} is finer than one minor unit at exponent {exponent}; the "
                "specification refuses it rather than rounding it"
            )
        digits = whole + frac[:shift]

    digits = digits.lstrip("0") or "0"
    return digits if digits == "0" else f"{sign}{digits}"


# =====================================================================================
# 3. Hashing: the row, the leaf, the node. docs/VERIFY.md part 1 sections 5 and 6.
# =====================================================================================

LEAF_PREFIX = b"leaf:"
NODE_PREFIX = b"node:"
GENESIS_PREV_HASH = "0" * 64

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _require_hash(value, what):
    if not isinstance(value, str) or not _HEX64.match(value):
        raise VerificationError(f"{what} must be 64 lowercase hex characters, got {value!r}")
    return value


def row_hash(payload, prev_hash, row_type, operator_id, created_at):
    """SHA-256 over the five parts, concatenated with NO separator (part 1 section 5).

        canonical(payload) || prev_hash || row_type || operator_id || canonical(created_at)

    The parse is unique without a delimiter: canonical(payload) is a JSON object whose extent
    its own braces fix, prev_hash is exactly 64 characters, row_type comes from a five-value
    set in which no value is a prefix of another, and canonical(created_at) is exactly 27
    characters and comes last.
    """
    preimage = b"".join(
        (
            canonical(payload),
            _require_hash(prev_hash, "prev_hash").encode("utf-8"),
            row_type.encode("utf-8"),
            operator_id.encode("utf-8"),
            canonical_timestamp(created_at).encode("utf-8"),
        )
    )
    return sha256_hex(preimage)


def leaf_hash(row_hash_hex):
    """SHA-256("leaf:" + the 64 hex CHARACTERS), not the 32 bytes (part 1 section 6)."""
    return sha256_hex(LEAF_PREFIX + _require_hash(row_hash_hex, "row_hash").encode("ascii"))


def node_hash(left, right):
    """SHA-256("node:" + left + right), both as hex characters (part 1 section 6).

    The two prefixes make the leaf and interior hash spaces disjoint. Without them a value
    could serve as both, and a tree of a different shape could be presented as having the same
    root.
    """
    return sha256_hex(
        NODE_PREFIX
        + _require_hash(left, "left child").encode("ascii")
        + _require_hash(right, "right child").encode("ascii")
    )


def merkle_root(row_hashes):
    """Rebuild a root from every row hash in row_id order (part 1 section 7).

    The odd-node rule is duplicate-last: at any level with an odd number of nodes the last
    node is paired with itself. A tree over one row roots at that row's leaf hash, with no
    interior node computed at all. A tree over zero rows has no root.
    """
    if not row_hashes:
        raise VerificationError("a tree over zero rows has no root")
    level = [leaf_hash(each) for each in row_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = [*level, level[-1]]
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def fold(leaf, path):
    """Fold a leaf along its sibling path to a root (part 1 section 8, step 4).

    `side` is the side the SIBLING sits on. For a leaf that is the duplicated last node of an
    odd level, its sibling is itself and appears in the path like any other.
    """
    accumulator = leaf
    for index, step in enumerate(path):
        side = step.get("side")
        sibling = _require_hash(step.get("hash"), f"proof step {index}")
        if side == "left":
            accumulator = node_hash(sibling, accumulator)
        elif side == "right":
            accumulator = node_hash(accumulator, sibling)
        else:
            raise VerificationError(
                f"proof step {index} has side {side!r}; a step's side is 'left' or 'right'"
            )
    return accumulator


# =====================================================================================
# 4. The published anchor payload. docs/VERIFY.md part 2 sections 9 and 12.
# =====================================================================================

ANCHOR_PAYLOAD_KEYS = frozenset(
    ("root_hash", "tree_size", "latest_row_id", "ledger_schema_version", "anchored_at")
)

#: A quiet day's artifact. The published history carries an entry every day, and on a day the
#: Log held no rows that entry says so rather than being absent. It is NOT an anchor: it
#: commits to no tree, carries no root, and no proof can ever fold to it.
EMPTY_MARKER_KEYS = frozenset(("status", "tree_size", "ledger_schema_version", "anchored_at"))

STATUS_EMPTY = "empty"

OTS_HEADER_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_OP_SHA256 = b"\x08"
_OTS_DIGEST_END = 34


class Anchor:
    """One published artifact: its payload, its digest, and where it came from.

    Covers both published shapes, because a reader walking the history meets both and the
    difference must be reported rather than smoothed over. `is_empty` decides which, from the
    marker's own `status` field — never from noticing that `root_hash` is missing, because a
    shape identified by what it lacks stops being identified the moment a field is added.
    """

    def __init__(self, path, payload, line):
        self.path = path
        self.payload = payload
        self.line = line
        self.digest = sha256_hex(canonical(payload))

    @property
    def is_empty(self):
        return self.payload.get("status") == STATUS_EMPTY

    @property
    def root_hash(self):
        """The committed root. An empty marker has none, and asking is a programming error."""
        if self.is_empty:
            raise VerificationError(
                f"{self.path.name} is an empty marker: it records that the Log held no rows "
                "at that instant and commits to no tree, so it has no root to compare against"
            )
        return self.payload["root_hash"]

    @property
    def tree_size(self):
        return int(self.payload["tree_size"])

    def describe(self):
        """One line saying which kind of artifact this is, in a reader's words."""
        if self.is_empty:
            return f"{self.path.name}: no rows anchored on this date"
        return f"{self.path.name}: anchor over {self.tree_size} row(s), root {self.root_hash}"

    def receipt_path(self):
        return Path(str(self.path) + ".ots")


def load_anchor(path):
    """Read one anchor payload file and refuse it unless it is already canonical.

    Re-serializing what was parsed and requiring identical bytes is what makes this a check. A
    line that has been reformatted, reordered, or had a number substituted for a decimal
    string is a different artifact whose SHA-256 is not the digest that was stamped — and it
    would still parse as JSON, which is exactly why parsing alone is not enough.

    The trailing newline is a text-file convention and not part of the hashed bytes: RFC 8785
    emits no insignificant whitespace, so it is stripped before comparison.
    """
    raw = Path(path).read_text(encoding="utf-8")
    line = raw.strip()
    try:
        payload = json.loads(line)
    except ValueError as exc:
        raise VerificationError(f"{path} is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise VerificationError(f"{path} does not contain a JSON object")
    if payload.get("status") == STATUS_EMPTY:
        expected, description = EMPTY_MARKER_KEYS, "an empty marker"
    else:
        expected, description = ANCHOR_PAYLOAD_KEYS, "a published anchor payload"
    if set(payload) != expected:
        raise VerificationError(
            f"{path} has fields {sorted(payload)}; {description} has exactly "
            f"{sorted(expected)}"
        )
    for key, value in payload.items():
        if not isinstance(value, str):
            raise VerificationError(
                f"{path}: {key} is {type(value).__name__}. Every value in a published payload "
                "is a string"
            )
    if _render(payload) != line:
        raise VerificationError(
            f"{path} is not in canonical form: it parses, but re-serializing it produces "
            "different bytes, so its SHA-256 is not the digest that was stamped"
        )
    return Anchor(Path(path), payload, line)


def load_anchor_history(directory):
    """Every published artifact in the public history, oldest filename first.

    Anchors and empty markers together, in the order the filenames sort — which is the order
    they were published, because the filename leads with the instant. Callers that are looking
    for a root must filter to `not entry.is_empty` first; a marker commits to no tree.
    """
    root = Path(directory)
    if not root.exists():
        raise VerificationError(f"no anchor directory at {root}")
    paths = sorted(root.rglob("*.anchor.json"))
    if not paths:
        raise VerificationError(f"no *.anchor.json files under {root}")
    return [load_anchor(path) for path in paths]


def check_receipt(anchor):
    """Offline structural check of the OpenTimestamps receipt beside the payload.

    What this proves with stdlib alone: a receipt exists, it is an OpenTimestamps detached
    timestamp file, and the digest inside it is the SHA-256 of THIS payload line rather than
    of something else. That last point is the one worth having — a well-formed receipt for a
    different digest would otherwise sit next to the payload looking like evidence.

    What this does NOT prove: that Bitcoin carries the attestation. Confirming that needs the
    OpenTimestamps client and a block source:

        ots verify <file>.anchor.json.ots

    The receipt is calendar-pending until a block includes it, so a fresh anchor legitimately
    has no Bitcoin attestation yet. That is why the timestamp this program checks precedence
    against is GitHub's commit, and OpenTimestamps is the stronger corroboration you can run
    yourself afterwards.
    """
    path = anchor.receipt_path()
    if not path.exists():
        return (False, f"no OpenTimestamps receipt at {path.name}")
    raw = path.read_bytes()
    if not raw.startswith(OTS_HEADER_MAGIC):
        return (False, f"{path.name} is not an OpenTimestamps detached timestamp file")
    body = raw[len(OTS_HEADER_MAGIC) :]
    if len(body) < _OTS_DIGEST_END or body[1:2] != OTS_OP_SHA256:
        return (False, f"{path.name} does not declare a SHA-256 file hash")
    stamped = body[2:_OTS_DIGEST_END].hex()
    if stamped != anchor.digest:
        return (
            False,
            (
                f"{path.name} stamps digest {stamped} but this payload's digest is "
                f"{anchor.digest} — the receipt is about a different payload"
            ),
        )
    return (True, f"receipt {path.name} stamps this payload's digest {stamped}")


# =====================================================================================
# 5. The third-party timestamp. The part that cannot come from us.
# =====================================================================================


def git_commit_timestamp(repo, relative_path):
    """When the commit that ADDED this file was made, according to the repository history.

    For the production medium this is GitHub's own clock: the anchor commits are created
    server-side through GitHub's API, so GitHub — not Simul8 — sets the committer date, and
    reading it here is reading a third party's statement.

    Returns None if git is unavailable or the path is untracked, and reporting nothing is the
    correct behaviour then. A verifier that fell back to a timestamp out of the payload would
    be checking our claim against itself.
    """
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "log",
                "--diff-filter=A",
                "--format=%cI",
                "--",
                str(relative_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if completed.returncode != 0:
        return None
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    # `git log` prints newest first; the commit that added the file is the last line.
    try:
        return parse_timestamp(lines[-1])
    except VerificationError:
        return None


def precedence_check(anchor, resolved_at, attested_at, attested_source):
    """Step 6: did a third party timestamp this anchor before the row was resolved?

    THE INVARIANT OF THIS FUNCTION: it never reads `anchor.payload["anchored_at"]`. That field
    is our own clock and is present in the payload for context, not for proof. If no
    third-party timestamp is available this returns undetermined, and undetermined is a
    FAILURE — not a pass with a caveat.
    """
    if attested_at is None:
        return (
            False,
            (
                f"UNDETERMINED: no third-party timestamp is available for "
                f"{anchor.path.name}. The payload's own anchored_at field is not evidence — "
                "it is our clock, and this program will not substitute it. Supply one you "
                "obtained yourself with --attested-at, or run this inside a git checkout of "
                "the anchors repository so the commit date can be read."
            ),
        )
    if resolved_at is None:
        return (
            False,
            (
                "UNDETERMINED: no resolution time given, so there is nothing to precede. "
                "Pass resolved_at in the claim file or --resolved-at."
            ),
        )
    if attested_at < resolved_at:
        return (
            True,
            (
                f"third-party timestamp {canonical_timestamp(attested_at)} "
                f"({attested_source}) precedes the resolution at "
                f"{canonical_timestamp(resolved_at)}"
            ),
        )
    return (
        False,
        (
            f"third-party timestamp {canonical_timestamp(attested_at)} ({attested_source}) "
            f"does NOT precede the resolution at {canonical_timestamp(resolved_at)}. The "
            "anchor published at or after the resolution, so this prediction was not "
            "independently verifiable ahead of its own outcome (§45(e)), and no later anchor "
            "can repair that."
        ),
    )


# =====================================================================================
# 6. The whole procedure
# =====================================================================================


def verify_claim(claim, anchors_directory, attested_at=None, resolved_at=None, out=None):
    """Run all six steps and print a transcript. Returns True only if every step passed."""
    write = (out or sys.stdout).write
    failures = []

    def step(number, title):
        write(f"\n[{number}] {title}\n")

    row = claim.get("row")
    proof = claim.get("proof")
    if not isinstance(row, dict) or not isinstance(proof, dict):
        raise VerificationError("a claim file has a 'row' object and a 'proof' object")

    if resolved_at is None and claim.get("resolved_at"):
        resolved_at = parse_timestamp(claim["resolved_at"])

    # -- step 1 -------------------------------------------------------------------
    step(1, "canonicalize the row payload (part 1 section 1)")
    payload_bytes = canonical(row["payload"])
    write(f"    {len(payload_bytes)} bytes\n")
    write(f"    sha256(canonical payload) = {sha256_hex(payload_bytes)}\n")

    # -- step 2 -------------------------------------------------------------------
    step(2, "recompute row_hash from the row's content (part 1 section 5)")
    computed = row_hash(
        row["payload"],
        row["prev_hash"],
        row["row_type"],
        row["operator_id"],
        row["created_at"],
    )
    write(f"    computed  {computed}\n")
    claimed = row.get("row_hash")
    if claimed:
        write(f"    row says  {claimed}\n")
        if claimed != computed:
            failures.append(
                "the row's stored row_hash is not the hash its own content produces. The "
                "content has changed since it was written."
            )
            write("    MISMATCH — the row's content does not produce its stored hash\n")
        else:
            write("    agree\n")
    else:
        write("    (the row did not state a hash; the computed value is used)\n")

    # -- step 3 -------------------------------------------------------------------
    step(3, "leaf_hash(row_hash) (part 1 section 6)")
    leaf = leaf_hash(computed)
    write(f"    {leaf}\n")

    # -- step 4 -------------------------------------------------------------------
    step(4, "fold the sibling path to a root (part 1 section 8)")
    path = proof.get("path") or []
    write(
        f"    leaf_index {proof.get('leaf_index')} of tree_size {proof.get('tree_size')}, "
        f"{len(path)} step(s)\n"
    )
    folded = fold(leaf, path)
    write(f"    folded root = {folded}\n")

    # -- step 5 -------------------------------------------------------------------
    step(5, "find that root in the published anchor history (part 2 section 12)")
    history = load_anchor_history(anchors_directory)
    anchors = [entry for entry in history if not entry.is_empty]
    markers = [entry for entry in history if entry.is_empty]
    write(
        f"    {len(history)} published artifact(s) read from {anchors_directory}: "
        f"{len(anchors)} anchor(s), {len(markers)} empty marker(s)\n"
    )
    if markers:
        # Reported, not hidden. An empty marker is a day the Log held no rows — neither a
        # success nor a failure, and a reader who is told only the anchor count would wonder
        # why the history has gaps it does not have.
        write(f"    {len(markers)} date(s) published no rows anchored on this date\n")

    matching = [anchor for anchor in anchors if anchor.root_hash == folded]
    if not matching:
        detail = (
            f"the folded root {folded} appears in no published anchor. Either this row was "
            "never anchored, or the proof belongs to a different tree."
        )
        if not anchors:
            detail = (
                f"the folded root {folded} appears in no published anchor, because the "
                f"history contains no anchors at all — {len(markers)} empty marker(s) and "
                "nothing else. No rows had been anchored by the last published date."
            )
        failures.append(detail)
        write("    NOT FOUND — no published anchor carries this root\n")
        _verdict(write, failures)
        return False

    anchor = matching[0]
    write(f"    found in {anchor.path.name}\n")
    write(f"    payload  {anchor.line}\n")
    write(f"    digest   {anchor.digest}\n")

    if proof.get("tree_size") is not None and int(proof["tree_size"]) != anchor.tree_size:
        failures.append(
            f"the proof is for a tree of {proof['tree_size']} rows but the anchor publishing "
            f"this root covers {anchor.tree_size}. They are not about the same tree."
        )
        write("    TREE SIZE MISMATCH\n")

    receipt_ok, receipt_detail = check_receipt(anchor)
    write(f"    {'ok  ' if receipt_ok else 'WARN'} {receipt_detail}\n")
    if not receipt_ok:
        failures.append(f"OpenTimestamps receipt: {receipt_detail}")

    # -- step 6 -------------------------------------------------------------------
    step(6, "check the third-party timestamp precedes the resolution (part 2 section 12)")
    source = "supplied with --attested-at"
    if attested_at is None:
        # Walk up to the repository root so the path handed to git is repo-relative.
        candidate = Path(anchors_directory).resolve()
        while candidate != candidate.parent and not (candidate / ".git").exists():
            candidate = candidate.parent
        if (candidate / ".git").exists():
            relative = anchor.path.resolve().relative_to(candidate)
            attested_at = git_commit_timestamp(candidate, relative)
            source = f"git commit that added {relative}"
    write(
        f"    anchored_at in the payload  {anchor.payload['anchored_at']}"
        "   <- OUR clock, NOT used for precedence\n"
    )
    precedes, detail = precedence_check(anchor, resolved_at, attested_at, source)
    write(f"    {detail}\n")
    if not precedes:
        failures.append(detail)

    _verdict(write, failures)
    return not failures


def _verdict(write, failures):
    write("\n" + "=" * 78 + "\n")
    if failures:
        write("NOT VERIFIED\n")
        for failure in failures:
            write(f"  - {failure}\n")
    else:
        write("VERIFIED\n")
        write("  the row is committed to a Merkle root that a third party timestamped\n")
        write("  before the row was resolved (Constitution §45(e)).\n")
    write("=" * 78 + "\n")


# =====================================================================================
# 7. Self-test against the vectors published in docs/VERIFY.md
# =====================================================================================

#: Roots over N rows whose hashes are sha256("row-0"), sha256("row-1"), ... in that order.
#: Copied from part 1's `vectors:tree` table, so this file can be checked against the document
#: without any Simul8 data at all. A test in the private repository asserts these are still the
#: document's values, so the two cannot drift.
TREE_VECTORS = {
    1: "76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614",
    2: "6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a",
    3: "74de35ec66294d2f81bacd715877820603c82ad9d5f6acf8635016934e13f508",
    4: "7280ad1d11858a5886a3b2d5a8b6b3f8bebd888b4cf191b8d04efa92498ec4cd",
    5: "5884da45c3524f1175e7feb32018ecf66977a31343d393694a848b5d570318e4",
    6: "980cd30ae459b5dde5c277ea7e2d0c173cbb14b00837a1c40daadc2e0233673e",
    7: "a9915a964f899075ebdb901592880158a2f43ef0544e84c89121a3330aa295b7",
    8: "9cebd0d38162339c6e36b48e486ef1980bc7d962e2e4a20abb43de46a6695a80",
    9: "5f86acf63de9738760ed045e6a5ae5010a2f79266ab9852ac39244b533cd52ef",
}

#: From part 1's `vectors:node` table.
NODE_VECTOR = "7d425e60db2e23e2a37cca55c3ebfe6c2ff2eda919f873ff5595a29a378629f6"

#: From part 1's `vectors:row-hash` table.
ROW_HASH_VECTORS = [
    (
        {},
        GENESIS_PREV_HASH,
        "declined",
        "op-1",
        "2026-07-24T10:00:00.000000Z",
        "b3b9827b56731515f135a9f3f142cdecebff0bc6b8fe9ab54e4dc56a6ed0cb0d",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        "op-1",
        "2026-07-24T10:00:00.000000Z",
        "3df194c0b92bf8f2e7efa2e7cd2f8266ad217cbe86c0aacebdd5a3a850f08521",
    ),
    (
        {"a": "1"},
        "f" * 64,
        "resolution",
        "op-2",
        "2026-11-07T18:30:00.000000Z",
        "78e066d1d45248e9ee53c732dbd51f7df8c873a8fc2be822fd6dc329e189eb33",
    ),
    (
        {"z": "1", "a": "2"},
        GENESIS_PREV_HASH,
        "void",
        "op-1",
        "2026-07-24T10:00:00.000001Z",
        "02d8fd8b7e3222a0fcd9b73a0344bd9d0c455a770c58a1f56bad757e29293337",
    ),
]

#: From part 1's `vectors:canonical` table. The supplementary-plane case is the one that
#: catches a code-point sort.
CANONICAL_VECTORS = [
    ('{"b":"2","a":"1"}', '{"a":"1","b":"2"}'),
    ('{"a":{"d":"4","c":"3"}}', '{"a":{"c":"3","d":"4"}}'),
    ('{"x":["b","a"]}', '{"x":["b","a"]}'),
    ('{"t":true,"f":false,"n":null}', '{"f":false,"n":null,"t":true}'),
    ('{"s":"a\\"b\\\\c"}', '{"s":"a\\"b\\\\c"}'),
    ('{"s":"\\u0001\\u001f"}', '{"s":"\\u0001\\u001f"}'),
    ('{"s":"na\\u00efve \\u20b9"}', '{"s":"naïve ₹"}'),
    (
        '{"\\ud800\\udc00":"supplementary","\\ufffd":"replacement"}',
        '{"\U00010000":"supplementary","�":"replacement"}',
    ),
]

#: From part 1's `vectors:timestamp` table.
TIMESTAMP_VECTORS = [
    ("2026-07-24T10:00:00Z", "2026-07-24T10:00:00.000000Z"),
    ("2026-07-24T10:00:00.5Z", "2026-07-24T10:00:00.500000Z"),
    ("2026-07-24T10:00:00.123Z", "2026-07-24T10:00:00.123000Z"),
    ("2026-07-24T10:00:00.123456Z", "2026-07-24T10:00:00.123456Z"),
    ("2026-07-24T10:00:00.123456000Z", "2026-07-24T10:00:00.123456Z"),
    ("2026-07-24T15:30:00+05:30", "2026-07-24T10:00:00.000000Z"),
]

#: From part 2's `vectors:anchor` table: the canonical published line and its SHA-256.
ANCHOR_VECTORS = [
    (
        (
            '{"anchored_at":"2026-07-25T00:00:00.000000Z","latest_row_id":'
            '"01JZZZZZZZZZZZZZZZZZZZZZZZ","ledger_schema_version":"lg_0002","root_hash":'
            '"76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614",'
            '"tree_size":"1"}'
        ),
        "c884fdcd9441c8b7bd06adab649cb9cb6fee6ddd0527f45f52d4988c00978502",
    ),
    (
        (
            '{"anchored_at":"2026-07-26T00:00:00.000000Z","latest_row_id":'
            '"01K0X9NR5N7QK8V4CZ6H2WBTMD","ledger_schema_version":"lg_0002","root_hash":'
            '"74de35ec66294d2f81bacd715877820603c82ad9d5f6acf8635016934e13f508",'
            '"tree_size":"3"}'
        ),
        "33221e828f3c124ec9a494763973d768c39d6a791d3a7e2c2486ce65c4e55079",
    ),
    (
        (
            '{"anchored_at":"2026-08-01T12:34:56.789000Z","latest_row_id":'
            '"01K1ABCDEFGHJKMNPQRSTVWXYZ","ledger_schema_version":"lg_0002","root_hash":'
            '"5f86acf63de9738760ed045e6a5ae5010a2f79266ab9852ac39244b533cd52ef",'
            '"tree_size":"9"}'
        ),
        "aef5859264b01090ed239a6d57289c8762172ab223e49af5693c1f046e98dfa2",
    ),
]

#: From part 1's `vectors:currency` table: (exponent, unit, amount, canonical), where the
#: canonical value None means the specification REFUSES the amount. A refusal is part of the
#: rule, so an implementation that accepted these would be wrong in the direction that does
#: not announce itself — it would silently produce a number for money it could not represent.
#: The currency code is deliberately absent: it is illustrative in the document and is not an
#: input here.
CURRENCY_VECTORS = [
    (2, "major_unit", "1499.00", "149900"),
    (2, "major_unit", "885.95", "88595"),
    (2, "minor_unit", "50000", "50000"),
    (2, "major_unit", "0.00", "0"),
    (0, "major_unit", "1500", "1500"),
    (0, "minor_unit", "1500", "1500"),
    (3, "major_unit", "1.234", "1234"),
    (3, "minor_unit", "1234", "1234"),
    (2, "major_unit", "-3.50", "-350"),
    (2, "major_unit", "1499.005", None),
    (0, "major_unit", "0.5", None),
    (2, "minor_unit", "50000.5", None),
    (3, "major_unit", "1.2345", None),
]

#: Empty markers (part 2 section 9). Pinned for the same reason the anchor vectors are: a
#: foreign implementation must be able to reproduce the bytes of every artifact the history
#: contains, and before the first real anchor these are the only artifacts in it.
EMPTY_MARKER_VECTORS = [
    (
        (
            '{"anchored_at":"2026-07-27T03:00:00.000000Z","ledger_schema_version":"lg_0002",'
            '"status":"empty","tree_size":"0"}'
        ),
        "a7e7012665eda4b9ca8e146ca04f9b9bdf9a7ab42ba2e34c84980f233eedeabd",
    ),
    (
        (
            '{"anchored_at":"2026-07-28T03:00:01.234567Z","ledger_schema_version":"lg_0002",'
            '"status":"empty","tree_size":"0"}'
        ),
        "681ae9ecec38e7f5beae8994515168a681164fd9fdde1b269f443aa953ed88ec",
    ),
    (
        (
            '{"anchored_at":"2026-08-01T12:34:56.789000Z","ledger_schema_version":"lg_0001",'
            '"status":"empty","tree_size":"0"}'
        ),
        "1343cd7a7c8d1e7c265cbfc67d42a5c72906f37854c2aa32e7f2c89a65b63b8a",
    ),
]


def self_test(out=None):
    """Check this file against the document's published vectors. Needs only this file."""
    write = (out or sys.stdout).write
    failures = []

    for given, expected in CANONICAL_VECTORS:
        produced = canonical(json.loads(given)).decode("utf-8")
        if produced != expected:
            failures.append(f"canonical({given}) = {produced!r}, expected {expected!r}")

    for given, expected in TIMESTAMP_VECTORS:
        produced = canonical_timestamp(given)
        if produced != expected:
            failures.append(f"timestamp {given} -> {produced}, expected {expected}")

    for exponent, unit, amount, expected in CURRENCY_VECTORS:
        try:
            produced = minor_unit_string(amount, exponent, unit)
        except VerificationError:
            produced = None
        if produced != expected:
            shown = "refused" if expected is None else repr(expected)
            failures.append(
                f"currency {amount} at exponent {exponent} as {unit} -> "
                f"{'refused' if produced is None else repr(produced)}, expected {shown}"
            )

    seed = sha256_hex(b"row-0")
    if leaf_hash(seed) != TREE_VECTORS[1]:
        failures.append("leaf_hash(sha256('row-0')) does not match vector N1/M1")
    if node_hash(seed, seed) != NODE_VECTOR:
        failures.append("node_hash does not match vector N2")

    for count, expected in sorted(TREE_VECTORS.items()):
        hashes = [sha256_hex(f"row-{index}".encode()) for index in range(count)]
        produced = merkle_root(hashes)
        if produced != expected:
            failures.append(f"root over {count} rows = {produced}, expected {expected}")

    for payload, prev, row_type, operator, created, expected in ROW_HASH_VECTORS:
        produced = row_hash(payload, prev, row_type, operator, created)
        if produced != expected:
            failures.append(f"row_hash({payload!r}) = {produced}, expected {expected}")

    for line, expected in ANCHOR_VECTORS:
        parsed = json.loads(line)
        if _render(parsed) != line:
            failures.append(f"anchor line is not canonical under this implementation: {line}")
        produced = sha256_hex(canonical(parsed))
        if produced != expected:
            failures.append(f"anchor digest {produced}, expected {expected}")

    for line, expected in EMPTY_MARKER_VECTORS:
        parsed = json.loads(line)
        if _render(parsed) != line:
            failures.append(f"empty marker is not canonical under this implementation: {line}")
        produced = sha256_hex(canonical(parsed))
        if produced != expected:
            failures.append(f"empty marker digest {produced}, expected {expected}")
        if set(parsed) != EMPTY_MARKER_KEYS:
            failures.append(f"empty marker vector has fields {sorted(parsed)}")
        if parsed.get("tree_size") != "0":
            failures.append("an empty marker vector claims a non-zero tree_size")

    try:
        canonical({"n": 1})
    except VerificationError:
        pass
    else:
        failures.append("a JSON number was canonicalized; part 1 forbids numbers in payloads")

    write(
        f"self-test: {len(CANONICAL_VECTORS)} canonical, {len(TIMESTAMP_VECTORS)} timestamp, "
        f"{len(CURRENCY_VECTORS)} currency, {len(TREE_VECTORS)} tree, "
        f"{len(ROW_HASH_VECTORS)} row-hash, {len(ANCHOR_VECTORS)} anchor, "
        f"{len(EMPTY_MARKER_VECTORS)} empty-marker vectors\n"
    )
    if failures:
        write("SELF-TEST FAILED\n")
        for failure in failures:
            write(f"  - {failure}\n")
        return False
    write("SELF-TEST PASSED — this verifier reproduces every vector in VERIFY.md\n")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify a Simul8 prediction against the published anchor history.",
        epilog="Constitution v2.4 §45(e). Procedure: VERIFY.md parts 1 and 2.",
    )
    parser.add_argument("--claim", help="JSON file holding {row, proof, resolved_at}")
    parser.add_argument("--anchors", default="anchors", help="the published anchor directory")
    parser.add_argument(
        "--attested-at",
        help="a third-party timestamp for the anchor that you obtained yourself (RFC 3339). "
        "Overrides reading the git commit date.",
    )
    parser.add_argument("--resolved-at", help="the resolution instant, if not in the claim file")
    parser.add_argument("--self-test", action="store_true", help="check against the vectors")
    parser.add_argument(
        "--history",
        action="store_true",
        help="list the published history, saying of each date whether rows were anchored",
    )
    arguments = parser.parse_args(argv)

    if arguments.self_test:
        return 0 if self_test() else 1

    if arguments.history:
        # Neither success nor failure: it reports what the public record contains. A day with
        # no rows is a fact about the Log, not a fault, and reading the history is how anyone
        # establishes when the Log actually started carrying rows.
        try:
            history = load_anchor_history(arguments.anchors)
        except VerificationError as exc:
            sys.stdout.write(f"{exc}\n")
            return 1
        anchored = sum(1 for entry in history if not entry.is_empty)
        for entry in history:
            sys.stdout.write(f"  {entry.describe()}\n")
        sys.stdout.write(
            f"{len(history)} published artifact(s): {anchored} anchor(s), "
            f"{len(history) - anchored} empty marker(s)\n"
        )
        return 0

    if not arguments.claim:
        parser.error("--claim is required unless --self-test or --history is given")

    try:
        claim = json.loads(Path(arguments.claim).read_text(encoding="utf-8"))
        attested = parse_timestamp(arguments.attested_at) if arguments.attested_at else None
        resolved = parse_timestamp(arguments.resolved_at) if arguments.resolved_at else None
        ok = verify_claim(claim, arguments.anchors, attested_at=attested, resolved_at=resolved)
    except VerificationError as exc:
        sys.stdout.write(f"NOT VERIFIED\n  - {exc}\n")
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
