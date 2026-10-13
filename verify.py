#!/usr/bin/env python3
"""Simul8 reference verifier. Stdlib only — no pip install, no network, no accounts.

    python3 verify.py --self-test
    python3 verify.py --claim claim.json --anchors anchors/ --attested-at T1 --resolved-at T2

This program answers one question, and refuses to answer it optimistically:

    Is this prediction committed to the Merkle root an anchor file states, and is a time for
    that file, obtained from outside it, BEFORE the prediction was resolved? And whose are
    the two times it compared?

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
carry nothing. So the precedence test reads a time obtained from OUTSIDE the payload — one
you supply having obtained it yourself, or else the date on the commit that added the file,
which is the repository's and not yours — and if it cannot get one it reports NOT VERIFIED
rather than falling back to ours. See `precedence_check`.

THE REPOSITORY'S DATE IS READ BY RUNNING `git` IN THE FOLDER YOU NAME WITH `--anchors`. A folder
brings its own git settings, and git can be made to run other programs from them. Name only a
clone you made yourself with `git clone`.

That refusal is the single most important behaviour here. A verifier that quietly accepted
`anchored_at` would pass every honest row, pass every dishonest one, and look identical.

THE LAST LINE IS THE VERDICT, AND THERE ARE FOUR. `VERIFIED`, exit status 0, only where every
step passed and BOTH times that are compared, the anchor's and the resolution's, came from
the person running this. `PROOF HOLDS, TIMES NOT YOUR OWN`, exit status 3, where every step
passed and the times compare but one or both came from the repository's commit or from the
claim file, which the publisher writes. `NOT JUDGED`, exit status 4, where part of the folder
named could not be opened or read on this machine and what was read does not decide the claim.
`NOT VERIFIED`, exit status 1, for everything else.
Exit status 2 means the arguments could not be read, a claim file that could not be opened or
read on this machine among them.

THE PROCEDURE (docs/VERIFY.md part 1 section 8, completed by part 2 section 12):

    1. canonicalize the row's payload           RFC 8785, and no JSON numbers ever
    2. recompute row_hash FROM THE ROW          six named members, not the row's own claim
    3. leaf_hash(row_hash)                      domain-separated, "leaf:"
    4. check the path, then fold it to a root   its steps and sides are fixed by index and size
    5. find that root in the anchor files read  the payload line, byte for byte, and its size
    6. compare the anchor's time with the       each from outside the payload, and each said
       resolution's                             to be yours, the repository's or the claim's

WHAT `--self-test` COVERS THAT `--claim` DOES NOT. The currency rule of part 1 section 1 is
implemented here and checked against the document's vectors, but it is NOT on the path a claim
takes: by the time a row is published its monetary values are already decimal strings, and
verifying the row hashes those strings. The rule matters to whoever PRODUCES them, and to you
if you want to check our arithmetic rather than only our commitment to it. It is implemented
because the document publishes vectors for it, and every vector the document publishes is one
this file must reproduce.

Steps 1-4 are part 1 and need nothing but this file. Steps 5-6 are part 2 and need the public
anchor history, which is the repository this file ships in.

The canonical form, the hashing, the tree, the proof and the reading of a published line mirror
`ledger/canonical.py`, `ledger/hashing.py`, `ledger/merkle.py`, `ledger/proof.py` and
`ledger/anchor_payload.py` in the private repository, and the reading of a receipt is mirrored
by `ledger/anchor_media.py` there. Each is a deliberate second implementation, not a shortcut:
the claim in §45(e) is that the *document* is sufficient for an outsider, and the only way to
test that claim is to write the outsider's implementation from the document and check the two
agree. `tests/constitutional/test_verify_py_end_to_end.py` runs this file against rows produced
by the frozen writer, from a clean checkout containing nothing but the public repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
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
        if any(0xD800 <= ord(character) <= 0xDFFF for character in key):
            # Refused here, by name, before the sort below tries to encode it and fails bare.
            raise VerificationError(
                "a lone surrogate has no UTF-8 encoding and therefore no canonical form, "
                "and an object key is no exception"
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
            f"a JSON number ({_cut(value)}) appeared in a payload. Every numeric quantity in a "
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
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<frac>[0-9]+))?"
    r"(?:Z|(?P<sign>[+-])(?P<offset_hour>[0-9]{2}):(?P<offset_minute>[0-9]{2}))"
)

#: Days in each month of a year that is not a leap year. February is settled by the leap rule.
_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def parse_timestamp(text):
    """Parse an RFC 3339 timestamp into an aware UTC datetime, or refuse it by name.

    WHAT IS ACCEPTED IS DECIDED HERE, by this function's own pattern and its own range checks,
    BEFORE ANY LIBRARY IS CALLED. A library's leniency in another Python version therefore
    cannot widen it. The private implementation holds the same pattern and the same checks,
    and a test runs both on one list of spellings and holds them to the same verdict and the
    same instant on each.

    Accepted, and nothing else: `YYYY-MM-DDTHH:MM:SS`, then optionally `.` and one or more
    digits, then `Z` or `+HH:MM` or `-HH:MM`. ASCII only. A year from 0001 to 9999; a month,
    day, hour, minute and second that exist (no 30 February, no hour 24, no second 60); an
    offset of 00 to 23 hours and 00 to 59 minutes; digits past the sixth of a fraction only if
    they are zeros; and an instant still within the years 0001 to 9999 once it is in UTC.
    Each refusal says which of these failed. Every refusal is one of two kinds: the spelling
    would lose information, or it would let one instant be written in a second way.
    """
    if not isinstance(text, str):
        raise VerificationError(f"a timestamp is a string, got {type(text).__name__}")
    if not text.isascii():
        # `\d` would match every script's decimal digits and `int()` reads them, so without
        # this one instant would have a second spelling in each of those scripts.
        raise VerificationError(
            f"{_cut(text)} holds a character outside ASCII. A timestamp is written in ASCII digits "
            "and letters only: another script's digits would be a second spelling of one instant"
        )

    match = _TIMESTAMP_INPUT.fullmatch(text)
    if match is None:
        raise VerificationError(
            f"{_cut(text)} is not an accepted RFC 3339 timestamp: expected "
            "YYYY-MM-DDTHH:MM:SS[.digits](Z|+HH:MM|-HH:MM), uppercase T, an offset, and at "
            "least one digit after a decimal point if there is one"
        )

    year, month, day, hour, minute, second = (
        int(match.group(name)) for name in ("year", "month", "day", "hour", "minute", "second")
    )
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = 29 if month == 2 and leap else _DAYS_IN_MONTH[(month - 1) % 12]
    offset = timedelta(0)
    problem = None
    if year == 0:
        problem = "there is no year 0000 on this clock; years run 0001 to 9999"
    elif not 1 <= month <= 12:
        problem = f"there is no month {month:02d}"
    elif not 1 <= day <= days:
        problem = f"month {month:02d} of {year:04d} has no day {day:02d}"
    elif hour > 23:
        problem = f"there is no hour {hour:02d}; hours run 00 to 23"
    elif minute > 59:
        problem = f"there is no minute {minute:02d}; minutes run 00 to 59"
    elif second > 59:
        problem = f"there is no second {second:02d}; seconds run 00 to 59, with no leap second"
    elif match.group("sign") is not None:
        offset_hour, offset_minute = int(match.group("offset_hour")), int(match.group("offset_minute"))
        if offset_hour > 23:
            problem = f"an offset has hours 00 to 23, not {offset_hour:02d}"
        elif offset_minute > 59:
            problem = f"an offset has minutes 00 to 59, not {offset_minute:02d}"
        else:
            offset = timedelta(hours=offset_hour, minutes=offset_minute)
            if match.group("sign") == "-":
                offset = -offset
    if problem is not None:
        raise VerificationError(f"{_cut(text)} names no instant: {problem}")

    frac = match.group("frac") or ""
    if len(frac) > 6:
        if set(frac[6:]) != {"0"}:
            raise VerificationError(
                f"{_cut(text)} carries sub-microsecond precision the canonical form cannot hold, "
                "and truncating it would silently change the value"
            )
        frac = frac[:6]
    microsecond = int(frac.ljust(6, "0")) if frac else 0

    try:
        return (
            datetime(year, month, day, hour, minute, second, microsecond, tzinfo=timezone.utc)
            - offset
        )
    except OverflowError as exc:
        raise VerificationError(
            f"{_cut(text)} is outside the years 0001 to 9999 once it is converted to UTC"
        ) from exc


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
# 2b. UUIDs. docs/VERIFY.md part 1 section 3.
# =====================================================================================


def canonical_uuid(value):
    """A UUID in its one form: lowercase, hyphenated 8-4-4-4-12 (part 1 section 3).

    Like the currency rule below, this is NOT on the path a claim takes: by the time a row is
    published a UUID in its payload is already a string in this form, and verifying the row
    hashes that string as it stands. It is here because the document publishes vectors for
    the rule, and every vector the document publishes is one this file must reproduce.
    """
    if not isinstance(value, str):
        raise VerificationError(f"a UUID is given as a string, got {type(value).__name__}")
    try:
        return str(uuid.UUID(value))
    except ValueError as exc:
        raise VerificationError(f"{_cut(value)} is not a UUID") from exc


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
        raise VerificationError(f"unit must be one of {list(MONEY_UNITS)}, got {_cut(unit)}")
    if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 0:
        raise VerificationError(f"exponent must be a non-negative integer, got {_cut(exponent)}")

    text = str(amount).strip()
    sign = ""
    if text[:1] in "+-":
        sign = "-" if text[0] == "-" else ""
        text = text[1:]
    if not _DECIMAL_TEXT.match(text):
        raise VerificationError(f"{_cut(amount)} is not a decimal amount")

    whole, _, frac = text.partition(".")
    # `minor_unit` is already an integer count of the minor unit, so it shifts by nothing.
    shift = exponent if unit == "major_unit" else 0

    if shift >= len(frac):
        digits = whole + frac + "0" * (shift - len(frac))
    else:
        if set(frac[shift:]) != {"0"}:
            raise VerificationError(
                f"{_cut(amount)} is finer than one minor unit at exponent {exponent}; the "
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

_HEX64 = re.compile(r"[0-9a-f]{64}")

#: The shape the Log's database holds `row_id` to: a canonical ULID, which is 26 characters of
#: Crockford base32 with the first of them 0 to 7.
_ROW_ID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")

#: The six members a row is hashed from (part 1 section 5), in the order section 1 sorts them.
#: There are no others: a row hashed from these six follows this format.
ROW_HASH_MEMBERS = ("created_at", "operator_id", "payload", "prev_hash", "row_id", "row_type")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _require_hash(value, what):
    # `fullmatch`, never `match`: with `match`, 64 hex characters and a newline pass.
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise VerificationError(f"{what} must be 64 lowercase hex characters, got {_cut(value)}")
    return value


def _require_string(value, member):
    """A hashed member that must be a string is one, or the row is refused by that name.

    `null`, `true`, a number, a list and an object all have a canonical form, so without this
    a row stating one of them would be hashed as written instead of refused.
    """
    if not isinstance(value, str):
        raise VerificationError(
            f"{member} must be a string, got {type(value).__name__}. A row is hashed from five "
            "strings and one object"
        )
    return value


def _require_row_id(value):
    if not isinstance(value, str) or not _ROW_ID.fullmatch(value):
        raise VerificationError(
            f"row_id must be a ULID as the Log holds it: 26 characters of Crockford base32, "
            f"the first of them 0 to 7. Got {_cut(value)}"
        )
    return value


def row_hashed_bytes(payload, prev_hash, row_type, operator_id, created_at, row_id):
    """The bytes a row hash covers: the canonical form of ONE object with exactly six members
    (part 1 section 5). `row_hash` is their SHA-256.

        canonical({"created_at", "operator_id", "payload", "prev_hash", "row_id", "row_type"})

    The object is built HERE, from the six values named, and from nothing else. It is never
    the claim's own `row` object, which also carries the row's stated hash. It is serialized
    by `canonical` above — section 1, the form a payload already goes through — and that form
    is one-to-one, so two different rows cannot share a preimage whatever their row types and
    operator ids are.

    Held first, each refused by the member's name:

    - `created_at`, `operator_id`, `prev_hash`, `row_id` and `row_type` are strings, and
      `payload` is an object;
    - `created_at` is put through section 2 BEFORE it enters the object, so one instant has
      one hash however it was spelled;
    - `prev_hash` is exactly 64 lowercase hex characters, and `row_id` is exactly a ULID.

    `row_type` is NOT checked against a list. A made-up row type gives a hash no anchored tree
    holds, so it cannot be passed off as a real row, and a list here would need republishing
    whenever a type is added.
    """
    if not isinstance(payload, dict):
        raise VerificationError(
            f"payload must be an object, got {type(payload).__name__}. A row is hashed from "
            "five strings and one object"
        )
    hashed = {
        "created_at": canonical_timestamp(_require_string(created_at, "created_at")),
        "operator_id": _require_string(operator_id, "operator_id"),
        "payload": payload,
        "prev_hash": _require_hash(_require_string(prev_hash, "prev_hash"), "prev_hash"),
        "row_id": _require_row_id(_require_string(row_id, "row_id")),
        "row_type": _require_string(row_type, "row_type"),
    }
    return canonical(hashed)


def row_hash(payload, prev_hash, row_type, operator_id, created_at, row_id):
    """SHA-256 over `row_hashed_bytes`, as 64 lowercase hex characters (part 1 section 5)."""
    return sha256_hex(
        row_hashed_bytes(payload, prev_hash, row_type, operator_id, created_at, row_id)
    )


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

    The rows are split at the largest power of two BELOW their number, each part is rooted
    the same way, and the two roots make one node. That is the same tree as "at a level with
    an odd number of nodes the last node is carried up unchanged": no node is ever paired with
    itself, so a root fixes the number of rows under it. A tree over one row roots at that
    row's leaf hash, with no interior node computed at all. A tree over zero rows has no root.

    The private implementation builds the tree level by level; this one splits. Two
    mechanisms agreeing on every published root says something one mechanism copied twice
    would not.
    """
    if not row_hashes:
        raise VerificationError("a tree over zero rows has no root")
    return _subtree_root([leaf_hash(each) for each in row_hashes])


def _split_point(count):
    """The largest power of two strictly below `count`, for a count of at least two.

    Read off the binary length of `count - 1`, so each level of the walk in `path_sides` costs
    the same and the whole walk is work in proportion to the tree's depth.
    """
    return 1 << ((count - 1).bit_length() - 1)


def _subtree_root(level):
    if len(level) == 1:
        return level[0]
    split = _split_point(len(level))
    return node_hash(_subtree_root(level[:split]), _subtree_root(level[split:]))


def path_sides(leaf_index, tree_size):
    """The side of every step of the proof for this leaf in a tree of this size, leaf upward.

    Read off the two numbers alone (part 1 section 8). Walking down from the root: a leaf in
    the left part has the right part's root as its sibling, on the RIGHT; a leaf in the right
    part has the left part's root on the LEFT. The walk ends at a part of one row, so a path
    is NOT one step per level: the last row of a three-row tree has one step, and a tree of
    one row has none.
    """
    sides = []
    index, size = leaf_index, tree_size
    while size > 1:
        split = _split_point(size)
        if index < split:
            sides.append("right")
            size = split
        else:
            sides.append("left")
            index -= split
            size -= split
    sides.reverse()
    return sides


#: A row id is 128 bits, so no tree has more rows than a 39-digit number can count.
_MOST_DIGITS_IN_A_COUNT = 39


def _plain_count(value, what):
    """A count as a claim file writes it: a STRING of ASCII digits in the one plain spelling.

    The spelling is the one an anchor uses for its `tree_size`: no sign, no spaces, no leading
    zero. A JSON number is refused. A claim file therefore holds no JSON number anywhere, which
    part 1 section 1 already says of everything that is hashed, and two verifiers written in
    two languages cannot read one file as two different numbers. More than 39 digits is refused
    before any arithmetic is done on it.
    """
    if not isinstance(value, str):
        raise VerificationError(
            f"{what} must be a string of digits, got {type(value).__name__}. A claim file "
            "holds no JSON number: a count is written as the anchor writes its tree_size"
        )
    if len(value) > _MOST_DIGITS_IN_A_COUNT:
        raise VerificationError(
            f"{what} has {len(value)} characters. A row id is 128 bits, so no tree has more "
            f"rows than {_MOST_DIGITS_IN_A_COUNT} digits can count"
        )
    if not _PLAIN_COUNT.fullmatch(value):
        raise VerificationError(
            f"{what} is {_cut(value)}, which is not a whole number spelled plainly: ASCII digits, "
            "no sign, no spaces, no leading zero"
        )
    return int(value)


PROOF_MEMBERS = ("leaf_index", "tree_size", "path")


def read_proof(proof):
    """A claim's proof, each member present and of its type: (leaf_index, tree_size, path).

    `leaf_index` and `tree_size` arrive as strings in the plain spelling and leave as whole
    numbers. A step is an object with exactly a `side` and a `hash`.

    A proof that leaves out its path, its index or its size is refused here. A missing path
    is NOT a tree of one row: a tree of one row states an empty path.
    """
    for member in PROOF_MEMBERS:
        if member not in proof:
            raise VerificationError(
                f"the claim's proof states no {member}. A proof states leaf_index, tree_size "
                "and path, and a claim without all three is refused"
            )
    unknown = sorted(str(member) for member in proof if member not in PROOF_MEMBERS)
    if unknown:
        raise VerificationError(
            f"the claim's proof has members {unknown}; a proof has exactly "
            f"{sorted(PROOF_MEMBERS)}"
        )
    leaf_index = _plain_count(proof["leaf_index"], "the proof's leaf_index")
    tree_size = _plain_count(proof["tree_size"], "the proof's tree_size")
    if leaf_index >= tree_size:
        raise VerificationError(
            f"the proof's leaf_index {leaf_index} is outside a tree of {tree_size} row(s). An "
            "index is below the size"
        )
    path = proof["path"]
    if not isinstance(path, list):
        raise VerificationError(
            f"the proof's path must be a list of steps, got {type(path).__name__}"
        )
    for position, step in enumerate(path):
        if not isinstance(step, dict) or sorted(step) != ["hash", "side"]:
            raise VerificationError(
                f"proof step {position} is not an object with exactly a 'side' and a 'hash'"
            )
        if step["side"] != "left" and step["side"] != "right":
            raise VerificationError(
                f"proof step {position} has side {_cut(step['side'])}; a step's side is 'left' "
                "or 'right'"
            )
        _require_hash(step["hash"], f"proof step {position}")
    return leaf_index, tree_size, path


def path_problem(leaf_index, tree_size, path):
    """Why this is not the path of that leaf in a tree of that size, or None if it is.

    The number of steps and the side of each are fixed by the two numbers. A path with a
    step more or a step fewer, or with one stated side that differs, is the path of some
    other position or of no position, whatever it folds to.
    """
    expected = path_sides(leaf_index, tree_size)
    if len(path) != len(expected):
        return (
            f"leaf {leaf_index} of a tree of {tree_size} row(s) has a path of "
            f"{len(expected)} step(s); the claim's has {len(path)}"
        )
    for position, (step, side) in enumerate(zip(path, expected)):
        if step["side"] != side:
            return (
                f"proof step {position} states its sibling is on the {step['side']}; for leaf "
                f"{leaf_index} of a tree of {tree_size} row(s) it is on the {side}"
            )
    return None


def fold(leaf, path):
    """Fold a leaf along its sibling path to a root (part 1 section 8, step 4).

    `side` is the side the SIBLING sits on. Arithmetic only: it reads no index and no size,
    so alone it says nothing of where the leaf sits. `path_problem` is what holds a path to
    its position, and `claim_verdict` runs it first.
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
                f"proof step {index} has side {_cut(side)}; a step's side is 'left' or 'right'"
            )
    return accumulator


# =====================================================================================
# 4. The published anchor payload. docs/VERIFY.md part 2 sections 9 and 12.
# =====================================================================================

ANCHOR_PAYLOAD_KEYS = frozenset(
    (
        "root_hash",
        "tree_size",
        "latest_row_id",
        "ledger_schema_version",
        "anchored_at",
        "previous_line_sha256",
    )
)

#: A quiet day's artifact. The published history carries an entry every day, and on a day the
#: Log held no rows that entry says so rather than being absent. It is NOT an anchor: it
#: commits to no tree, carries no root, and no proof can ever fold to it.
EMPTY_MARKER_KEYS = frozenset(
    ("status", "tree_size", "ledger_schema_version", "anchored_at", "previous_line_sha256")
)

#: The field by which every published line names the line published before it: the SHA-256
#: of that line's exact bytes, or JSON null on the first line ever published and on no other
#: (part 2 section 9). The one value in a published line that may be other than a string.
PREVIOUS_LINE = "previous_line_sha256"

STATUS_EMPTY = "empty"

#: A count spelled the one plain way: no sign, no spaces, no leading zero, ASCII digits only.
_PLAIN_COUNT = re.compile(r"0|[1-9][0-9]*")

OTS_HEADER_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_OP_SHA256 = b"\x08"

#: How a published file is named (part 2 section 9): the instant it stamps with the
#: punctuation taken out, a hyphen, the first characters of the SHA-256 of its own bytes, and
#: this ending.
_PAYLOAD_SUFFIX = ".anchor.json"
_DIGEST_IN_NAME = 12

#: What a copy of a published file gains in an editor, in a browser or in a checkout that
#: rewrites line endings. Each is refused by name.
_BYTE_ORDER_MARK = b"\xef\xbb\xbf"

_FETCH_UNCHANGED = (
    "A published file is its one line and not one byte more, and the SHA-256 of those bytes "
    "is what was stamped. Fetch the file again unchanged: clone the anchors repository with "
    "git and read the bytes it holds with `git cat-file blob HEAD:<path>`, or download the "
    "raw file. Do not copy its text out of a page or save it from an editor."
)


#: The most a claim file may hold. This program's own limit, with this basis: a row runs to
#: 50 to 100 KB at full voice count (SPEC-SPORTS §3.6), and a proof adds at most one step for
#: each bit of a 39-digit size. The limit stands far above both, so that it refuses only what
#: is not a claim.
MOST_CLAIM_BYTES = 16_000_000


class NotReadHere(VerificationError):
    """The operating system failed while this machine opened or read a file: a permission, an
    I/O error, a file gone between the listing and the open. A fact about the reading here,
    and never about the bytes the file holds, which were not read."""


def read_regular_file(path, most, what, limit):
    """The bytes of a regular file holding at most `most` of them, or a refusal in words.

    The file is opened without waiting, where the platform allows it, and held to being a
    REGULAR file before a byte is read: a device, a named pipe or a directory is refused by
    name, whatever its name says and wherever a link points. Then at most one byte more than
    it may hold is read, and a file that has that byte is refused. No size the file system
    reports is trusted for this: a device reports none. `what` names the file; `limit` says
    whose limit `most` is.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        handle = os.open(path, flags)
    except OSError as exc:
        raise NotReadHere(
            f"{what} could not be opened on this machine ({type(exc).__name__})"
        ) from None
    try:
        if not stat.S_ISREG(os.fstat(handle).st_mode):
            raise VerificationError(
                f"{what} is not a regular file. This program reads only a regular file: never a "
                "device, a named pipe or a directory, whatever its name and wherever a link points"
            )
        pieces = []
        left = most + 1
        while left > 0:
            piece = os.read(handle, min(left, 1 << 20))
            if not piece:
                break
            pieces.append(piece)
            left -= len(piece)
    except OSError as exc:
        raise NotReadHere(f"{what} could not be read on this machine ({type(exc).__name__})") from None
    finally:
        os.close(handle)
    raw = b"".join(pieces)
    if len(raw) > most:
        raise VerificationError(f"{what} holds more than {most:,} bytes, past {limit}")
    return raw


def shown(value):
    """Text that came from a file, a file name or an argument, made fit to print in one line.

    Every character that is not printable is written as an escape: a line break of any kind,
    a control character, a character that reorders the text around it. So nothing a claim, an
    anchor, a receipt or a file name contains can begin a new line of the transcript, and
    none of them can write a line of the verdict (part 2 section 12).
    """
    text = value if isinstance(value, str) else str(value)
    return "".join(
        character
        if character.isprintable()
        else character.encode("unicode_escape", "backslashreplace").decode("ascii")
        for character in text
    )


#: How much of a misshapen value a refusal shows: at most this many characters of it as
#: Python writes it, escaped, and its length. A choice of this program, for display only:
#: nothing is hashed or compared on it.
_MOST_CHARACTERS_SHOWN = 64


def _cut(value):
    """A value for a refusal: written as Python writes it, escaped, and cut if it is long."""
    text = shown(repr(value))
    if len(text) <= _MOST_CHARACTERS_SHOWN:
        return text
    if isinstance(value, str):
        return f"{text[:_MOST_CHARACTERS_SHOWN]}... (cut: the value is {len(value)} characters long)"
    return f"{text[:_MOST_CHARACTERS_SHOWN]}... (cut: {len(text)} characters as written)"


def copy_differences(raw):
    """What these bytes hold that a published file never does, each by name. Often nothing."""
    found = []
    if raw.startswith(_BYTE_ORDER_MARK):
        found.append("a byte-order mark at its start")
        raw = raw[len(_BYTE_ORDER_MARK) :]
    if b"\r" in raw:
        found.append("a carriage return")
    if raw != raw.lstrip():
        found.append("white space before the line")
    if raw != raw.rstrip():
        found.append("white space after the line")
    return found


class Anchor:
    """One anchor file read: its payload, its digest, and where it came from.

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
    def name(self):
        """The file's name, fit to print."""
        return shown(self.path.name)

    @property
    def is_empty(self):
        return self.payload.get("status") == STATUS_EMPTY

    @property
    def previous(self):
        """The SHA-256 of the line this one names as published before it, or None."""
        return self.payload[PREVIOUS_LINE]

    @property
    def root_hash(self):
        """The committed root. An empty marker has none, and asking is a programming error."""
        if self.is_empty:
            raise VerificationError(
                f"{self.name} is an empty marker: it records that the Log held no rows "
                "at that instant and commits to no tree, so it has no root to compare against"
            )
        return self.payload["root_hash"]

    @property
    def tree_size(self):
        return int(self.payload["tree_size"])

    @property
    def stamped_tree_size(self):
        """The number of rows this anchor stamps, read strictly. What a proof is held to.

        `int()` reads '+1', ' 3 ' and digits from other scripts as numbers. A size is the
        number spelled the one plain way, or this anchor states no size a proof can be held
        to. `load_anchor` refuses a file whose size is spelled any other way, so for a file it
        loaded this cannot fail; it stays for an `Anchor` built some other way.
        """
        text = self.payload["tree_size"]
        if not isinstance(text, str) or not _PLAIN_COUNT.fullmatch(text):
            raise VerificationError(
                f"{self.name} states tree_size {_cut(text)}, which is not a whole "
                "number spelled plainly (no sign, no spaces, no leading zero). No proof can be "
                "held to it"
            )
        return int(text)

    def describe(self):
        """One line saying which kind of artifact this is, in a reader's words."""
        if self.is_empty:
            return f"{self.name}: no rows anchored on this date"
        return f"{self.name}: anchor over {self.tree_size} row(s), root {self.root_hash}"

    def receipt_path(self):
        return Path(str(self.path) + ".ots")


#: What the anchor job writes in `ledger_schema_version`: the applied Alembic revision of the
#: Log's shared path, named `lg_` and four ASCII digits (`lg_0001` to `lg_0009` in the tree).
_LEDGER_SCHEMA_VERSION = re.compile(r"lg_[0-9]{4}")


def _longest_anchor_line():
    """The longest canonical line the format allows, in bytes, DERIVED from the fields' own
    bounds (part 2 section 9): an instant of 27 characters, a row id of 26, a revision name of
    7, a root of 64, a size of at most 39 digits and the previous line's digest of 64 (longer
    than null), every one of them ASCII that the canonical form writes without an escape. An
    empty marker's line is shorter."""
    longest = {
        "anchored_at": "9999-12-31T23:59:59.999999Z",
        "latest_row_id": "7" + "Z" * 25,
        "ledger_schema_version": "lg_9999",
        "previous_line_sha256": "f" * 64,
        "root_hash": "f" * 64,
        "tree_size": "9" * _MOST_DIGITS_IN_A_COUNT,
    }
    return len(_render(longest).encode("utf-8"))


MOST_ANCHOR_LINE_BYTES = _longest_anchor_line()


def _field_problem(payload, is_marker):
    """Why a field of a published line has the wrong shape, or None (part 2 section 9)."""
    stamped_at = payload["anchored_at"]
    try:
        one_spelling = canonical_timestamp(parse_timestamp(stamped_at))
    except VerificationError:
        one_spelling = None
    if one_spelling != stamped_at:
        return (
            f"its anchored_at is {_cut(stamped_at)}, which is not an instant in the one "
            "spelling a published line uses (part 1 section 2)"
        )
    if not _LEDGER_SCHEMA_VERSION.fullmatch(payload["ledger_schema_version"]):
        return (
            f"its ledger_schema_version is {_cut(payload['ledger_schema_version'])}, which is "
            "not a revision's name: lg_ and four ASCII digits"
        )
    previous = payload[PREVIOUS_LINE]
    if previous is not None and not _HEX64.fullmatch(previous):
        return (
            f"its previous_line_sha256 is {_cut(previous)}, which is neither 64 lowercase hex "
            "characters nor null"
        )
    size = payload["tree_size"]
    if is_marker:
        if size != "0":
            return (
                f"it is an empty marker and its tree_size is {_cut(size)}. An empty "
                'marker states no rows: its tree_size is "0"'
            )
        return None
    if not _PLAIN_COUNT.fullmatch(size) or size == "0" or len(size) > _MOST_DIGITS_IN_A_COUNT:
        return (
            f"its tree_size is {_cut(size)}. An anchor's size is a whole number spelled "
            "plainly (no sign, no spaces, no leading zero), at least 1 and of at most "
            f"{_MOST_DIGITS_IN_A_COUNT} digits"
        )
    if not _HEX64.fullmatch(payload["root_hash"]):
        return (
            f"its root_hash is {_cut(payload['root_hash'])}, which is not 64 lowercase "
            "hex characters"
        )
    if not _ROW_ID.fullmatch(payload["latest_row_id"]):
        return (
            f"its latest_row_id is {_cut(payload['latest_row_id'])}, which does not "
            "have the shape of a row_id (part 1 section 5)"
        )
    return None


def load_anchor(path):
    """Read one published file as the bytes that were stamped, and refuse anything else.

    The file is read as BYTES and must be the canonical line and not one byte more. A copy
    that gained white space, a carriage return or a byte-order mark has a different SHA-256
    from the one that was stamped, and the standard OpenTimestamps client refuses it; so does
    this. Each of the three is named, because each is what a well-meant copy does to a file.

    Re-serializing what was parsed and requiring identical bytes is what makes the rest a
    check. A line that has been reformatted, reordered, or had a number substituted for a
    decimal string still parses as JSON, which is exactly why parsing alone is not enough.

    Before any of that, the file must be a regular file, and no more than one byte past the
    longest line the format allows is read from it (`read_regular_file`). Then each field is
    held to its shape, and the file's name to its content. Every refusal is a
    `VerificationError` whose words name the file.
    """
    path = Path(path)
    name = shown(path.name)
    raw = read_regular_file(
        path, MOST_ANCHOR_LINE_BYTES, name, "the longest line the format allows"
    )
    differences = copy_differences(raw)
    if differences:
        raise VerificationError(
            f"{name} holds more than its canonical line: it holds "
            f"{' and '.join(differences)}. {_FETCH_UNCHANGED}"
        )
    def no_number(text):
        # Refused as text, never converted: every value in a published payload is a string,
        # so a number of any length is not one, and no arithmetic is done on it to say so.
        raise VerificationError(
            f"{name} holds a JSON number ({len(text)} characters long). Every value in a "
            "published payload is a string, a count among them"
        )

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            parse_int=no_number,
            parse_float=no_number,
            parse_constant=no_number,
        )
    except (ValueError, RecursionError):
        raise VerificationError(f"{name} is not JSON in UTF-8") from None
    if not isinstance(payload, dict):
        raise VerificationError(f"{name} does not contain a JSON object")
    is_marker = payload.get("status") == STATUS_EMPTY
    if is_marker:
        expected, description = EMPTY_MARKER_KEYS, "an empty marker"
    else:
        expected, description = ANCHOR_PAYLOAD_KEYS, "a published anchor payload"
    if set(payload) != expected:
        raise VerificationError(
            f"{name} has fields {shown(sorted(payload))}; {description} has exactly "
            f"{sorted(expected)}"
        )
    for key, value in payload.items():
        if key == PREVIOUS_LINE and value is None:
            continue
        if not isinstance(value, str):
            raise VerificationError(
                f"{name}: {key} is {type(value).__name__}. Every value in a published payload "
                "is a string, except that previous_line_sha256 is null on the first line"
            )
    try:
        canonical_bytes = _render(payload).encode("utf-8")
    except ValueError:
        canonical_bytes = None
    if canonical_bytes != raw:
        raise VerificationError(
            f"{name} is not in canonical form: it parses, but re-serializing it produces "
            "different bytes, so its SHA-256 is not the digest that was stamped"
        )
    problem = _field_problem(payload, is_marker)
    if problem is not None:
        raise VerificationError(f"{name} is not a well-formed publication: {problem}")
    stamped_at = payload["anchored_at"]
    named_by_content = (
        stamped_at.replace("-", "").replace(":", "").replace(".", "")
        + "-"
        + sha256_hex(raw)[:_DIGEST_IN_NAME]
        + _PAYLOAD_SUFFIX
    )
    if path.name != named_by_content:
        raise VerificationError(
            f"{name} is not the name its content gives it. A published file is named for the "
            f"instant it stamps and the first {_DIGEST_IN_NAME} characters of the SHA-256 of "
            f"its bytes, and this content belongs in a file named {named_by_content}"
        )
    return Anchor(path, payload, raw.decode("utf-8"))


def load_anchor_history(directory):
    """Every anchor file under the folder, and every file there that is not a publication.

    Returns `(entries, defects, unread)`. The entries are anchors and empty markers together, in the
    order of the instants they stamp (a file's name leads with its instant, and `load_anchor`
    holds the name to the content). Files that stamp one instant are ordered by the size
    they stamp, and only then by name. Callers that are
    looking for a root must filter to `not entry.is_empty` first; a marker commits to no
    tree.

    A defect is a file under the directory with a published file's ending that is not a
    well-formed publication: `(path, why)`. What is published stays published, so one such
    file must not make every claim unverifiable for ever. The caller decides what a defect
    means: a search for one claim's root names it and passes over it, and a reading of the
    whole history fails on it.

    `unread` is every folder under the directory that this machine could not read, and every
    regular file it could not open or read, `(path, why, kind)`, kind "folder" or "file".
    Where the failure arose decides: an operating-system failure opening or reading a folder or
    a regular file is `unread`, a fact about the reading here from which nothing about the
    published record follows; bytes that were read and are wrong are a defect. A LINK IS
    NEVER A FAILED READING: a published line is a regular file in git, so an entry named like
    one that is a symbolic link, dangling, looping or resolving, is a defect of that file.
    """
    root = Path(directory)
    if not root.exists():
        raise VerificationError(f"no anchor directory at {shown(root)}")
    found, unread = _walk(root)
    paths = sorted(found, key=lambda path: (path.name, str(path)))
    if not paths and not unread:
        raise VerificationError(f"no *{_PAYLOAD_SUFFIX} files under {shown(root)}")
    entries = []
    defects = []
    for path in paths:
        try:
            is_link = path.is_symlink()
        except OSError as exc:
            unread.append(
                (path, f"{shown(path.name)} could not be read on this machine ({type(exc).__name__})", "file")
            )
            continue
        if is_link:
            defects.append((path, f"{shown(path.name)} {IS_A_LINK}"))
            continue
        try:
            entries.append(load_anchor(path))
        except NotReadHere as exc:
            unread.append((path, shown(str(exc)), "file"))
        except VerificationError as exc:
            defects.append((path, shown(str(exc))))
        except OSError as exc:
            unread.append(
                (path, f"{shown(path.name)} could not be read on this machine ({type(exc).__name__})", "file")
            )
    # By the instant each file stamps, and files that stamp ONE instant by the size they
    # stamp, a marker first. Two files of one instant have no order of their own, and a name
    # breaks the tie by the file's digest, which says nothing about which came first; so the
    # tie is broken the way a Log grows, and a lawful history is never read as shrinking.
    entries.sort(key=_history_order)
    return entries, defects, unread


def _walk(root):
    """Every file under `root` whose name has a published file's ending, found WITHOUT
    RECURSION: an explicit stack of folders, and no link followed into a folder, so that a
    folder of any depth is walked and none can exhaust the interpreter's recursion limit. A
    folder this machine cannot read is named, `(path, why, "folder")`, and the walk goes on. A
    link named like a published file is found like any other entry, and the loader holds it
    to be a defect.

    NO LIMIT IS SET ON HOW MANY ENTRIES ARE WALKED, because the published record grows and a
    limit would be a refusal waiting to happen on it. The walk holds the folders still to visit
    and the names it found, about 0.8 KiB for each by the reviewer's measurement of 12 October
    2026, a reading of one day; a folder holding so many entries that the machine runs out of
    memory may end the program without words (docs/VERIFY.md part 2 section 12)."""
    found, unread, folders = [], [], [root]
    while folders:
        folder = folders.pop()
        try:
            with os.scandir(folder) as listing:
                for item in listing:
                    if item.is_dir(follow_symlinks=False):
                        folders.append(Path(item.path))
                    elif item.name.endswith(_PAYLOAD_SUFFIX):
                        found.append(Path(item.path))
        except OSError as exc:
            unread.append(
                (
                    folder,
                    (
                        f"the folder {shown(str(folder))} could not be read on this machine "
                        f"({type(exc).__name__})"
                    ),
                    "folder",
                )
            )
    return found, unread


def _history_order(entry):
    size = 0 if entry.is_empty else entry.tree_size
    return (entry.payload["anchored_at"], size, entry.path.name, str(entry.path))


def same_instant(entries):
    """The files that stamp an instant another file also stamps, grouped. Often none."""
    groups = {}
    for entry in entries:
        groups.setdefault(entry.payload["anchored_at"], []).append(entry)
    return [group for group in groups.values() if len(group) > 1]


#: The rules a Log's history keeps, by the names the transcript uses (part 2 section 12).
RULE_SIZES_NEVER_GO_DOWN = "SIZES NEVER GO DOWN"
RULE_ONE_SIZE_ONE_ROOT = "ONE SIZE HAS ONE ROOT"
RULE_ONE_ROOT_ONE_SIZE = "ONE ROOT HAS ONE SIZE"
RULE_NO_MARKER_AFTER_ANCHOR = "NO EMPTY MARKER FOLLOWS AN ANCHOR"
#: Held by `chain_breaks`, below, in five parts (D-S43).
RULE_ONE_CHAIN = "THE LINES READ FORM ONE CHAIN"
HISTORY_RULES = (
    RULE_SIZES_NEVER_GO_DOWN,
    RULE_ONE_SIZE_ONE_ROOT,
    RULE_ONE_ROOT_ONE_SIZE,
    RULE_NO_MARKER_AFTER_ANCHOR,
    RULE_ONE_CHAIN,
)


def history_rules_broken(entries):
    """Which of the rules a Log's history keeps this one breaks, each in words. Often none.

    The entries are in the order of the instants they stamp. A Log only grows, and a row once
    written is never changed, so across its anchors: the size never goes down; one size has
    one root; one root has one size, because a root fixes the number of rows under it; and
    no empty marker follows an anchor, because a Log that has held a row is never empty
    again.
    """
    broken = []
    previous = None
    first_of_size = {}
    first_of_root = {}
    for entry in entries:
        if entry.is_empty:
            if previous is not None:
                broken.append(
                    f"{RULE_NO_MARKER_AFTER_ANCHOR}: {entry.name} says the Log held no "
                    f"rows, after {previous.name} stamped {previous.tree_size}. A Log that has "
                    "held a row is never empty again"
                )
            continue
        size = entry.tree_size
        if previous is not None and size < previous.tree_size:
            broken.append(
                f"{RULE_SIZES_NEVER_GO_DOWN}: {entry.name} stamps {size} row(s), after "
                f"{previous.name} stamped {previous.tree_size}"
            )
        first = first_of_size.setdefault(size, entry)
        if first.root_hash != entry.root_hash:
            broken.append(
                f"{RULE_ONE_SIZE_ONE_ROOT}: {entry.name} and {first.name} both stamp {size} "
                "row(s), under different roots"
            )
        earliest = first_of_root.setdefault(entry.root_hash, entry)
        if earliest.tree_size != size:
            broken.append(
                f"{RULE_ONE_ROOT_ONE_SIZE}: {entry.name} and {earliest.name} both publish the "
                f"root {entry.root_hash}, under the sizes {size} and {earliest.tree_size}"
            )
        previous = entry
    return broken


#: The five parts of THE LINES READ FORM ONE CHAIN (part 2 section 12, D-S43), in the words
#: the transcript uses to say which part breaks.
CHAIN_ONE_FIRST = "exactly one line names nothing, and it is the earliest"
CHAIN_NAMES_A_LINE_READ = "every other line names a line read here"
CHAIN_NO_TWO_NAME_ONE = "no two lines name the same line"
CHAIN_NONE_LEFT_OUT = "no line is left out of the chain"
CHAIN_INSTANTS_GO_FORWARD = "the instants never go back along it"
CHAIN_BROKEN = "THE CHAIN IS BROKEN"
#: R5. Said by --history when part of the folder could not be read here.
CHAIN_PARTS_NOT_JUDGED = (
    f"NOT JUDGED: the parts of {RULE_ONE_CHAIN} that need every line read ({CHAIN_NAMES_A_LINE_READ}; "
    f"{CHAIN_NONE_LEFT_OUT}; some line names nothing), because the history was not read whole"
)
IF_UNCHANGED_COPY_CHAIN = (
    "If the files read here are an unchanged copy of the public repository, then the "
    "published record's chain is broken there."
)


def _chain_break(part, detail):
    return f"{RULE_ONE_CHAIN}: {part}, and {detail}"


def chain_breaks(entries, whole=True):
    """Which parts of THE LINES READ FORM ONE CHAIN the lines read break, each in words.

    Every published line names the line published immediately before it by the SHA-256 of
    that line's bytes, and the first line ever published names nothing. So among the lines
    read: exactly one names nothing, and it is the earliest; every other line names a line
    read here; no two lines name the same line; no line is left out of the chain; and the
    instants never go back along it. Two lines naming one line is a fork in the published
    record, and this is where a fork is found: here, where the whole chain is read. Often
    none breaks.

    `whole` is False when part of the folder could not be read on this machine (R5). Then the
    parts that need EVERY line read are not judged, because an unread line would make them
    break on a lawful record: that some line names nothing (the first line may be the one
    unread), that every other line names a line read here (its predecessor may be unread), and
    that no line is left out of the chain (the walk stops at an unread line). The parts that
    compare lines that were both read are judged as ever: two lines naming nothing, a line
    naming nothing that is not the earliest read, one line read twice, two lines naming one
    line, and an instant going back between a line and the line it names.
    """
    breaks = []
    if not entries:
        return breaks
    by_digest = {}
    for entry in entries:
        by_digest.setdefault(entry.digest, []).append(entry)
    for group in by_digest.values():
        if len(group) > 1:
            breaks.append(
                _chain_break(
                    CHAIN_NONE_LEFT_OUT,
                    f"one line is read more than once: {', '.join(e.name for e in group)}",
                )
            )
    firsts = [entry for entry in entries if entry.previous is None]
    earliest = min(entry.payload["anchored_at"] for entry in entries)
    if not firsts:
        if whole:  # R5: the first line may be the one this machine could not read
            breaks.append(
                _chain_break(
                    CHAIN_ONE_FIRST,
                    "no line read here names nothing, so the line the chain starts from is not "
                    "among them",
                )
            )
    elif len(firsts) > 1:
        breaks.append(
            _chain_break(
                CHAIN_ONE_FIRST,
                f"{len(firsts)} lines name nothing ({', '.join(e.name for e in firsts)}); only "
                "one line may, the one the chain starts from",
            )
        )
    elif firsts[0].payload["anchored_at"] != earliest:
        breaks.append(
            _chain_break(
                CHAIN_ONE_FIRST,
                f"{firsts[0].name} names nothing, but a line read here stamps an earlier "
                "instant",
            )
        )
    named_by = {}
    for entry in entries:
        if entry.previous is None:
            continue
        if entry.previous not in by_digest:
            if whole:
                breaks.append(
                    _chain_break(
                        CHAIN_NAMES_A_LINE_READ,
                        f"{entry.name} names {shown(entry.previous)}, which is no line read here",
                    )
                )
            continue
        named_by.setdefault(entry.previous, []).append(entry)
        # An instant going back compares two lines that were both read, so it is judged
        # whether or not the history was read whole, for every line and the line it names.
        before = by_digest[entry.previous][0]
        if entry.payload["anchored_at"] < before.payload["anchored_at"]:
            breaks.append(
                _chain_break(
                    CHAIN_INSTANTS_GO_FORWARD,
                    f"{entry.name} names {before.name} but stamps an earlier instant",
                )
            )
    for digest, group in named_by.items():
        if len(group) > 1:
            breaks.append(
                _chain_break(
                    CHAIN_NO_TWO_NAME_ONE,
                    f"{', '.join(e.name for e in group)} all name {by_digest[digest][0].name}: "
                    "the chain forks there",
                )
            )
    if len(firsts) == 1:
        current = firsts[0]
        reached = {id(current)}
        while len(named_by.get(current.digest, [])) == 1:
            following = named_by[current.digest][0]
            if id(following) in reached:
                break
            reached.add(id(following))
            current = following
        left_out = [entry for entry in entries if id(entry) not in reached]
        if left_out and whole:
            breaks.append(
                _chain_break(
                    CHAIN_NONE_LEFT_OUT,
                    f"{', '.join(e.name for e in left_out)} are not on the chain that runs from "
                    f"{firsts[0].name} to {current.name}",
                )
            )
    return breaks


def chain_back_problem(start, entries, whole=True):
    """Why the chain from `start` back to the first line breaks among the entries, or None.

    Walks from `start` to the line it names, and on, until a line that names nothing. The
    walk breaks where a line names no line read here, where it names a line that stamps a
    later instant, or where it comes round to a line it has passed. Returns `(kind, words)`:
    kind None where it holds, "broken", or "not judged" where the walk reaches a line it
    cannot find and part of the folder was not read here (`whole` False, R5): that line may
    be the one this machine could not read.
    """
    by_digest = {}
    for entry in entries:
        by_digest.setdefault(entry.digest, []).append(entry)
    current = start
    passed = set()
    while current.previous is not None:
        if current.digest in passed:
            return ("broken", f"the chain from {start.name} comes round again to {current.name}")
        passed.add(current.digest)
        found = by_digest.get(current.previous)
        if not found:
            words = f"{current.name} names {shown(current.previous)}, which is no line read here"
            return ("broken", words) if whole else ("not judged", words)
        before = found[0]
        if before.payload["anchored_at"] > current.payload["anchored_at"]:
            return ("broken", f"{current.name} names {before.name}, which stamps a later instant")
        current = before
    return (None, None)


#: The receipt beside a payload (part 2 section 12). Where a limit is the format's own it is read
#: from the reference library, opentimestamps 0.4.5, opentimestamps/core: a message and an
#: operation's result of at most 4096 bytes (op.py:40 and :59); a binary operation's argument of
#: 1 to 4096 bytes (op.py:218); an attestation's payload of at most 8192 bytes (notary.py:26); a
#: pending attestation's address of at most 1000 bytes (notary.py:165), drawn from a fixed set of
#: characters (notary.py:168); nesting at most 256 deep (timestamp.py:131).
_OTS_MOST_MESSAGE_BYTES = 4096
_OTS_MOST_ARGUMENT_BYTES = 4096
_OTS_MOST_PAYLOAD_BYTES = 8192
_OTS_MOST_ADDRESS_BYTES = 1000
_OTS_ADDRESS_CHARACTERS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:"
)
_OTS_MOST_DEPTH = 256

#: THIS PROGRAM'S OWN LIMITS. The format sets none on these three, and a hostile receipt must not
#: make the program work without bound. A count is written in at most 9 bytes, which is every
#: value below two to the sixty-third: nothing the format counts comes near that, and no reader
#: holding a count in a signed 64-bit integer could read a wider one. A receipt is at most
#: 1,000,000 bytes and holds at most 10,000 steps (operations and attestations together): these
#: two are choices, ruled for this program, with no other source.
MOST_COUNT_BYTES = 9
MOST_RECEIPT_BYTES = 1_000_000
MOST_RECEIPT_STEPS = 10_000

OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")

#: Said with every receipt this program cannot read. The standard client may read what this
#: program refuses by rule; where it does, the document says so.
UNREADABLE = "the receipt is unreadable to this program"

#: R1. Said of an entry named like a published file that is a symbolic link of any kind.
IS_A_LINK = (
    "is a symbolic link, and is not a regular file: a published line is a regular file in git, "
    "never a link, so this is a defect of the file and not a failed reading"
)
IS_A_RECEIPT_LINK = (
    "is a symbolic link, and is not a regular file: a receipt is a regular file in git, never a "
    "link, so this is a defect of the publication and not a missing receipt"
)
STANDARD_CLIENT = (
    "The standard OpenTimestamps client is the way to check it: ots verify <the .ots file>"
)


class ReceiptUnreadable(VerificationError):
    """The receipt is unreadable to this program, and why, in words."""


class ReceiptForAnotherFile(ReceiptUnreadable):
    """The receipt reads as far as its file digest, and that digest is another file's."""


def _ots_ripemd160(message):
    try:
        return hashlib.new("ripemd160", message).digest()
    except ValueError:
        raise ReceiptUnreadable(
            "it uses ripemd160, which the standard library cannot compute on this machine"
        ) from None


def _ots_keccak256(_message):
    raise ReceiptUnreadable("it uses keccak256, which the standard library cannot compute")


_OTS_UNARY = {
    0x02: ("sha1", lambda message: hashlib.sha1(message).digest()),
    0x03: ("ripemd160", _ots_ripemd160),
    0x08: ("sha256", lambda message: hashlib.sha256(message).digest()),
    0x67: ("keccak256", _ots_keccak256),
    0xF2: ("reverse", lambda message: message[::-1]),
    0xF3: ("hexlify", lambda message: message.hex().encode("ascii")),
}
_OTS_BINARY = {
    0xF0: ("append", lambda message, argument: message + argument),
    0xF1: ("prepend", lambda message, argument: argument + message),
}


class _ReceiptReader:
    def __init__(self, raw):
        self.raw = raw
        self.at = 0
        self.steps = 0
        self.longest_count = 0

    def take(self, count, what):
        if count > len(self.raw) - self.at:
            raise ReceiptUnreadable(f"it ends inside {what}")
        piece = self.raw[self.at : self.at + count]
        self.at += count
        return piece

    def count(self, what):
        """A count as the format writes it, seven bits a byte, low first: in its one shortest
        spelling, and in at most MOST_COUNT_BYTES bytes."""
        value = shift = 0
        for position in range(MOST_COUNT_BYTES):
            byte = self.take(1, what)[0]
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                if position and not byte:
                    raise ReceiptUnreadable(f"{what} is not written in its shortest form")
                self.longest_count = max(self.longest_count, position + 1)
                return value
            shift += 7
        raise ReceiptUnreadable(
            f"{what} is written in more than {MOST_COUNT_BYTES} bytes, past this program's own "
            "limit"
        )

    def sized(self, most, what, least=0):
        length = self.count(f"the length of {what}")
        if not least <= length <= most:
            raise ReceiptUnreadable(f"{what} is {length} bytes; the format allows {least} to {most}")
        return self.take(length, what)

    def step(self):
        self.steps += 1
        if self.steps > MOST_RECEIPT_STEPS:
            raise ReceiptUnreadable(
                f"it holds more than {MOST_RECEIPT_STEPS} operations and attestations, past this "
                "program's own limit"
            )


def read_receipt(raw, file_digest):
    """What a detached OpenTimestamps receipt CLAIMS, read to its last byte (part 2 section 12).

    Returns `(known, unknown, reader)`: the attestations of a kind this program knows, each a
    dict; how many of another kind were passed over; and the reader, which says how far it went.
    Raises `ReceiptUnreadable`, in words, for anything else. It fetches nothing and judges no
    block's clock: a Bitcoin attestation names a block and the value that block's Merkle root
    must have, and it is the standard client, with a block source, that checks it.
    """
    if len(raw) > MOST_RECEIPT_BYTES:
        raise ReceiptUnreadable(
            f"it is {len(raw)} bytes, past this program's own limit of {MOST_RECEIPT_BYTES}"
        )
    reader = _ReceiptReader(raw)
    if reader.take(len(OTS_HEADER_MAGIC), "its header") != OTS_HEADER_MAGIC:
        raise ReceiptUnreadable("it does not begin with the header of a detached timestamp file")
    if reader.take(1, "its version") != b"\x01":
        raise ReceiptUnreadable("its version is not 1 written as one byte")
    if reader.take(1, "its file hash") != OTS_OP_SHA256:
        raise ReceiptUnreadable("it does not declare a SHA-256 file hash")
    stamped = reader.take(32, "its file digest")
    if stamped != file_digest:
        raise ReceiptForAnotherFile(stamped.hex())
    known, unknown = [], [0]
    _ots_timestamp(reader, stamped, _OTS_MOST_DEPTH, known, unknown)
    if reader.at != len(raw):
        raise ReceiptUnreadable(f"{len(raw) - reader.at} byte(s) are left over after its end")
    if not known:
        raise ReceiptUnreadable(
            f"it holds no attestation of a kind this program knows ({unknown[0]} of another kind)"
        )
    return known, unknown[0], reader


def _ots_timestamp(reader, message, depth, known, unknown):
    if not depth:
        raise ReceiptUnreadable(f"it is nested more than {_OTS_MOST_DEPTH} deep")
    tag = reader.take(1, "a timestamp")[0]
    while tag == 0xFF:
        _ots_branch(reader, reader.take(1, "a branch")[0], message, depth, known, unknown)
        tag = reader.take(1, "a timestamp")[0]
    _ots_branch(reader, tag, message, depth, known, unknown)


def _ots_branch(reader, tag, message, depth, known, unknown):
    reader.step()
    if tag == 0x00:
        _ots_attestation(reader, message, known, unknown)
        return
    if tag in _OTS_UNARY:
        name, apply = _OTS_UNARY[tag]
        argument = None
    elif tag in _OTS_BINARY:
        name, apply = _OTS_BINARY[tag]
        argument = reader.sized(_OTS_MOST_ARGUMENT_BYTES, f"the argument of {name}", least=1)
    else:
        raise ReceiptUnreadable(f"it uses an operation this program does not know (tag {tag:#04x})")
    if len(message) > _OTS_MOST_MESSAGE_BYTES:
        raise ReceiptUnreadable(f"{name} is applied to more than {_OTS_MOST_MESSAGE_BYTES} bytes")
    result = apply(message) if argument is None else apply(message, argument)
    if not result or len(result) > _OTS_MOST_MESSAGE_BYTES:
        raise ReceiptUnreadable(
            f"{name} gives {len(result)} bytes; the format allows 1 to {_OTS_MOST_MESSAGE_BYTES}"
        )
    _ots_timestamp(reader, result, depth - 1, known, unknown)


def _ots_attestation(reader, message, known, unknown):
    kind = reader.take(8, "an attestation's kind")
    payload = _ReceiptReader(reader.sized(_OTS_MOST_PAYLOAD_BYTES, "an attestation's payload"))
    if kind == OTS_BITCOIN:
        height = payload.count("a block height")
        if payload.at != len(payload.raw):
            raise ReceiptUnreadable("a Bitcoin attestation holds bytes after its block height")
        if len(message) != 32:
            raise ReceiptUnreadable(
                f"a Bitcoin attestation stands on a message of {len(message)} bytes, not 32"
            )
        known.append({"kind": "bitcoin", "height": height, "root_as_held": message.hex()})
    elif kind == OTS_PENDING:
        address = payload.sized(_OTS_MOST_ADDRESS_BYTES, "a pending attestation's address")
        if payload.at != len(payload.raw):
            raise ReceiptUnreadable("a pending attestation holds bytes after its address")
        if any(byte not in _OTS_ADDRESS_CHARACTERS for byte in address):
            raise ReceiptUnreadable(
                "a pending attestation's address holds a character the format does not allow"
            )
        known.append({"kind": "pending", "address": address.decode("ascii")})
    else:
        unknown[0] += 1


def receipt_claims(attestation):
    """One attestation, in the words the transcript uses. It says what the receipt CLAIMS."""
    if attestation["kind"] == "bitcoin":
        held = attestation["root_as_held"]
        reverse = bytes.fromhex(held)[::-1].hex()
        return (
            f"a Bitcoin attestation at block height {attestation['height']}: that block's Merkle "
            f"root must be {held} in the order the receipt holds its bytes, which is {reverse} "
            "with the bytes reversed. This program has looked at no block"
        )
    return (
        f"a pending attestation at the calendar {attestation['address']}: nothing is attested "
        "until a block carries it"
    )


def check_receipt(anchor):
    """Read the receipt beside the payload to its end, and say what it claims.

    Returns `(ok, lines)`. The receipt must be a regular file of at most MOST_RECEIPT_BYTES
    (`read_regular_file`). What this establishes with the standard library alone: the receipt
    is an OpenTimestamps detached timestamp for THIS payload's SHA-256, every operation in it
    computes, and it holds at least one attestation of a kind this program knows. What it does
    NOT establish: that any block carries an attestation. That needs the standard client and a
    block source (`ots verify <file>.anchor.json.ots`). This program takes no time from the
    receipt: the two times it compares, and where each came from, are step 6's.
    """
    path = anchor.receipt_path()
    name = shown(path.name)
    try:
        is_link = path.is_symlink()
    except OSError as exc:
        raise NotReadHere(
            f"{name} could not be read on this machine ({type(exc).__name__})"
        ) from None
    if is_link:
        # R1: a receipt is a regular file in git, so a link here, even a dangling one, is a
        # defect of the publication and never a missing receipt or a failed reading.
        return (False, [f"{name} {IS_A_RECEIPT_LINK}"])
    if not path.exists():
        return (False, [f"no OpenTimestamps receipt at {name}"])
    try:
        raw = read_regular_file(
            path, MOST_RECEIPT_BYTES, name, "this program's own limit for a receipt"
        )
    except NotReadHere:
        raise
    except VerificationError as exc:
        return (False, [f"{UNREADABLE}: {exc}. {STANDARD_CLIENT}"])
    try:
        known, unknown, _reader = read_receipt(raw, bytes.fromhex(anchor.digest))
    except ReceiptForAnotherFile as exc:
        return (
            False,
            [
                (
                    f"{name} stamps digest {exc} but this payload's digest is {anchor.digest} — "
                    "the receipt is about a different payload"
                )
            ],
        )
    except ReceiptUnreadable as exc:
        return (False, [f"{UNREADABLE}: {name}: {exc}. {STANDARD_CLIENT}"])
    lines = [f"receipt {name} is read to its end and stamps this payload's digest {anchor.digest}"]
    lines += [f"it claims {receipt_claims(attestation)}" for attestation in known]
    if unknown:
        lines.append(f"{unknown} attestation(s) of a kind this program does not know: passed over")
    lines.append(
        "this program fetches nothing and judges no block's clock: it says what the receipt "
        f"claims, never that it is so. To finish the check: ots verify {name}"
    )
    return (True, lines)


# =====================================================================================
# 5. The two times that are compared, and where each one came from.
# =====================================================================================

#: The three last lines this program prints for a claim, and no other. Only the first is the
#: plain word, and it is printed only where BOTH times came from the person running the
#: program. The second must never begin with, or be mistaken for, the first.
VERDICT_VERIFIED = "VERIFIED"
VERDICT_TIMES_NOT_YOUR_OWN = "PROOF HOLDS, TIMES NOT YOUR OWN"
VERDICT_NOT_VERIFIED = "NOT VERIFIED"
#: The last line of a claim that could not be decided from what was read on this machine.
VERDICT_NOT_JUDGED = "NOT JUDGED"

#: The exit status that goes with each. Status 2 is the argument parser's.
EXIT_STATUS = {
    VERDICT_NOT_JUDGED: 4,
    VERDICT_VERIFIED: 0,
    VERDICT_NOT_VERIFIED: 1,
    VERDICT_TIMES_NOT_YOUR_OWN: 3,
}

#: What each source of a time is worth, said in the transcript beside the time.
WORTH_OF_YOUR_OWN = (
    "you supplied it: it is worth what the source you took it from is worth, and this "
    "program cannot check it"
)
WORTH_OF_THE_REPOSITORY = (
    "it is the repository's, not yours: a commit's date is a field of the commit, written "
    "when the commit was made. This program has checked that the commit holds exactly this "
    "file's bytes and that no later commit touched its path. It cannot tell who set the date"
)
WORTH_OF_THE_CLAIM = (
    "it is the publisher's, not yours: the claim file is written by the publisher, and this "
    "program has nothing to check that time against"
)

_COMMIT_NAME = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")


#: This program runs `git` in the folder it is pointed at, and a folder brings its own
#: `.git/config`, from which git can be made to run other programs. These switch off, for
#: the three reads below, every such setting this program's author found: the one measured
#: to run a program during these exact reads (a signature check, `log.showSignature` with
#: `gpg.program`), and the ones that run a program during other git commands. Git has no
#: switch that ignores a folder's own settings as a whole, so a setting not named here is
#: not covered. NAME ONLY A CLONE YOU MADE YOURSELF WITH `git clone`.
_GIT_NO_PROGRAMS = (
    "--no-pager",
    "--literal-pathspecs",
    "--no-replace-objects",
    "-c", "core.fsmonitor=false",
    "-c", "log.showSignature=false",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "core.hooksPath=" + os.devnull,
    "-c", "gpg.program=false",
    "-c", "gpg.ssh.program=false",
    "-c", "gpg.x509.program=false",
    "-c", "core.alternateRefsCommand=",
)  # fmt: skip

#: Said again on the two reads that could be asked to show a difference.
_GIT_SHOW_NOTHING_ELSE = ("--no-ext-diff", "--no-textconv")

#: The most time one call to git may take, in seconds. This program's own limit, with this
#: basis: each call asks git for one small thing (whether one commit touches one path, one
#: blob's size or bytes, one commit's date), and on a clone of the public repository each
#: answered in under 10 milliseconds when measured. The limit stands far above that, so that it
#: refuses only a git that is not answering. When it is reached, the transcript says so and no
#: verdict rests on what git did not answer.
GIT_SECONDS = 60

#: What `_git` returns when git did not answer within `GIT_SECONDS`.
GIT_DID_NOT_ANSWER = object()


def _git(repo, *arguments):
    """One read of the repository, as bytes; None if git could not answer; and
    `GIT_DID_NOT_ANSWER` if it did not answer within `GIT_SECONDS`."""
    environment = dict(os.environ)
    environment.update(
        GIT_PAGER="cat",
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_REPLACE_OBJECTS="1",
    )
    try:
        completed = subprocess.run(
            ["git", *_GIT_NO_PROGRAMS, "-C", str(repo), *arguments],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=GIT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return GIT_DID_NOT_ANSWER
    except (OSError, ValueError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _no_answer():
    return (
        f"git did not answer within {GIT_SECONDS} seconds, this program's own limit for one "
        "call, so the repository's date is not read and nothing here rests on it"
    )


def repository_date(anchor, anchors_directory):
    """The date on the commit that added a published file, or why that date is not used.

    Returns `(moment, where, None)` or `(None, None, reason)`.

    The date is used only if exactly one commit in the checkout's history touches the file's
    path, and that commit holds exactly the bytes this program read. A path that a later
    commit touched, or a commit holding other bytes, is refused with the reason: the date of
    a commit says nothing about bytes the commit does not hold.

    What this cannot establish is who set the date. A commit's date is a field of the commit.
    This program reads it; that is all it knows about it, and the transcript says so.

    It reads it by RUNNING `git` IN THE FOLDER IT WAS POINTED AT (see `_GIT_NO_PROGRAMS`).
    """
    top = Path(anchors_directory).resolve()
    while top != top.parent and not (top / ".git").exists():
        top = top.parent
    if not (top / ".git").exists():
        return (None, None, "the anchors are not inside a git checkout, so there is no commit")
    try:
        relative = anchor.path.resolve().relative_to(top).as_posix()
    except ValueError:
        return (None, None, f"{anchor.name} is not inside the checkout that holds the anchors")
    where = shown(relative)
    # Two commits are enough to know that more than one touches the path, so no more are
    # asked for: what git hands over here is bounded.
    listed = _git(
        top, "log", "--full-history", "--max-count=2", *_GIT_SHOW_NOTHING_ELSE, "--format=%H",
        "--", relative,
    )  # fmt: skip
    if listed is GIT_DID_NOT_ANSWER:
        return (None, None, _no_answer())
    if listed is None:
        return (None, None, "git could not read the history of this checkout")
    commits = listed.split()
    if not commits:
        return (None, None, f"no commit in this checkout's history holds {where}")
    if len(commits) > 1:
        return (
            None,
            None,
            (
                f"more than one commit in this checkout's history touches {where}. The date is "
                "used only where one commit added the file and no later commit touched its path"
            ),
        )
    commit = commits[0]
    if not _COMMIT_NAME.fullmatch(commit):
        return (None, None, "git named a commit this program could not read")
    commit = commit.decode("ascii")
    # The blob's size is read first and held to the longest line the format allows; a blob
    # over it is refused without being read.
    size = _git(top, "cat-file", "-s", f"{commit}:{relative}")
    if size is GIT_DID_NOT_ANSWER:
        return (None, None, _no_answer())
    size = (size or b"").strip()
    if not (size.isdigit() and size.isascii()):
        return (None, None, f"git could not say how many bytes the commit holds at {where}")
    if int(size) > MOST_ANCHOR_LINE_BYTES:
        return (
            None,
            None,
            (
                f"the commit that added {where} holds {int(size):,} bytes there, more than the "
                f"longest line the format allows ({MOST_ANCHOR_LINE_BYTES:,}), and they are not read"
            ),
        )
    held = _git(top, "cat-file", "blob", f"{commit}:{relative}")
    if held is GIT_DID_NOT_ANSWER:
        return (None, None, _no_answer())
    if held is None or held != anchor.line.encode("utf-8"):
        return (
            None,
            None,
            f"the commit that added {where} does not hold exactly the bytes of the file read here",
        )
    stamped = _git(top, "show", "-s", *_GIT_SHOW_NOTHING_ELSE, "--format=%cI", commit)
    if stamped is GIT_DID_NOT_ANSWER:
        return (None, None, _no_answer())
    try:
        moment = parse_timestamp((stamped or b"").decode("ascii", "replace").strip())
    except VerificationError:
        return (None, None, f"the date on the commit that added {where} could not be read")
    return (moment, f"the committer date of the git commit that added {where}", None)


def precedence_check(anchor, resolved_at, attested_at, attested_source):
    """Step 6: is the anchor's time before the resolution time?

    THE INVARIANT OF THIS FUNCTION: it never reads `anchor.payload["anchored_at"]`. That field
    is the publisher's own clock and is present in the payload for context, not for proof. If
    no time for the anchor is available this returns undetermined, and undetermined is a
    FAILURE — not a pass with a caveat.
    """
    if attested_at is None:
        return (
            False,
            (
                f"UNDETERMINED: no time is available for {anchor.name}. The payload's own "
                "anchored_at field is not evidence — it is the publisher's clock, and this "
                "program will not substitute it. Supply a time you obtained yourself with "
                "--attested-at."
            ),
        )
    if resolved_at is None:
        return (
            False,
            (
                "UNDETERMINED: no resolution time given, so there is nothing to precede. "
                "Supply one you obtained yourself with --resolved-at."
            ),
        )
    if attested_at < resolved_at:
        return (
            True,
            (
                f"the anchor's time {canonical_timestamp(attested_at)} "
                f"({attested_source}) precedes the resolution at "
                f"{canonical_timestamp(resolved_at)}"
            ),
        )
    return (
        False,
        (
            f"the anchor's time {canonical_timestamp(attested_at)} ({attested_source}) "
            f"does NOT precede the resolution at {canonical_timestamp(resolved_at)}. On "
            "these times the anchor file is at or after the resolution, so this prediction "
            "was not independently verifiable ahead of its own outcome (§45(e)), and no later "
            "anchor can repair that."
        ),
    )


# =====================================================================================
# 6. The whole procedure
# =====================================================================================


def _members_written_once(pairs):
    """One JSON object's members, or a refusal naming the key that is written twice."""
    members = {}
    for key, value in pairs:
        if key in members:
            raise VerificationError(
                f"the claim file writes the member {_cut(key)} twice in one object. A parser that "
                "keeps the last of the two would let a claim show one value to a reader and "
                "another to this program, so the claim is refused"
            )
        members[key] = value
    return members


def _no_number(text):
    """A claim file holds no JSON number anywhere, however long, so none is ever converted."""
    raise VerificationError(
        f"the claim file holds a JSON number ({len(text)} characters long). A claim holds no "
        "number anywhere: a count is a string of digits (part 2 section 12)"
    )


def read_claim(path):
    """Parse a claim file, refusing a key repeated in any object of it (part 2 section 12).

    `json.loads` alone keeps the last of two members with one name and says nothing. A claim
    could then print `"operator_id": "A"` where a reader looks and carry `"operator_id": "B"`
    further along, and this program would verify B.

    Every way a file can fail to be a claim is refused here in words: a file that cannot be
    opened or read, one that is not a regular file, one that holds more than
    `MOST_CLAIM_BYTES`, a byte-order mark, bytes that are not UTF-8, text that is not JSON,
    nesting too deep to read, a number of any length, and JSON that is not an object. A
    machine that runs out of memory may still end the program without words.
    """
    raw = read_regular_file(
        path, MOST_CLAIM_BYTES, "the claim file", "this program's own limit for a claim file"
    )
    if raw.startswith(_BYTE_ORDER_MARK):
        raise VerificationError(
            "the claim file begins with a byte-order mark. A claim file is JSON in UTF-8 with "
            "nothing before it; save it without the mark"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise VerificationError("the claim file is not UTF-8 text") from None
    try:
        claim = json.loads(
            text,
            object_pairs_hook=_members_written_once,
            parse_int=_no_number,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except RecursionError:
        raise VerificationError("the claim file is nested too deeply to be read") from None
    except ValueError:
        raise VerificationError("the claim file is not JSON") from None
    if not isinstance(claim, dict):
        raise VerificationError("the claim file is not a JSON object")
    return claim


#: The members a claim file has, and it has no other. `resolved_at` only where it states one.
CLAIM_MEMBERS = ("row", "proof", "resolved_at")

#: WHOSE RECORD IT IS. This program is pointed at a folder, and nothing it checks shows that
#: the folder is the public repository. So it says what it knows, that the anchor files it
#: read are inconsistent or that one of them is not a well-formed publication, and says of
#: the published record only what follows IF those files are an unchanged copy of it. These
#: words are provisional and the founder's to change; each is written here once.
FILE_INCONSISTENT = "the anchor file read here is inconsistent with itself"
FILES_INCONSISTENT = "the anchor files read here are inconsistent with themselves"
IF_UNCHANGED_COPY_INCONSISTENT = (
    "If the files read here are an unchanged copy of the public repository, then the "
    "published record is inconsistent with itself."
)
NOT_A_PUBLICATION = "NOT A WELL-FORMED PUBLICATION"
IF_UNCHANGED_COPY_NOT_A_PUBLICATION = (
    "If the files read here are an unchanged copy of the public repository, then the "
    "published record holds a file that is not a well-formed publication."
)
#: A folder this machine could not read. It is no defect of a publication, and the words draw
#: no conclusion about the published record.
NOT_READ_HERE = "NOT READ HERE"
NOTHING_FOLLOWS = "Nothing about the published record follows from that."
HISTORY_NOT_JUDGED = "HISTORY NOT JUDGED"
#: --history's exit status when a folder could not be read here: distinct from 1, a defect found.
EXIT_NOT_JUDGED = 4  # the same status as a claim's NOT JUDGED

IF_UNCHANGED_COPY_HISTORY_FAILS = (
    "If the files read here are an unchanged copy of the public repository, then the "
    "published record fails in the same way."
)

#: Said with each of the three checks that run once a row has been placed in the tree an
#: anchor file commits to. What they find is about that file and never about the claim.
_RECORD_NOT_CLAIM = (
    "A claim cannot cause this: the row had already been shown to be in the tree this anchor "
    "file commits to, at that index, under the file's own size. Keep the claim file and the "
    f"anchor file, and report it. {IF_UNCHANGED_COPY_INCONSISTENT}"
)


def verify_claim(claim, anchors_directory, attested_at=None, resolved_at=None, out=None):
    """Run all six steps and print a transcript. True only where the last line is `VERIFIED`.

    That is: every step passed AND both times that were compared came from the caller. The
    other two verdicts are both False here; `claim_verdict` tells them apart.
    """
    verdict = claim_verdict(claim, anchors_directory, attested_at, resolved_at, out)
    return verdict == VERDICT_VERIFIED


def claim_verdict(claim, anchors_directory, attested_at=None, resolved_at=None, out=None):
    """Run all six steps, print a transcript, and return which verdict it is.

    `attested_at` and `resolved_at` are the caller's own two times, where the caller has
    them. Where one is None the anchor's time is looked for in the repository and the
    resolution time in the claim file, and the verdict is then never the plain word.
    """
    write = (out or sys.stdout).write
    failures = []

    def step(number, title):
        write(f"\n[{number}] {title}\n")

    unknown = sorted(str(member) for member in claim if member not in CLAIM_MEMBERS)
    if unknown:
        raise VerificationError(
            f"the claim has members {unknown}. A claim has 'row', 'proof' and, where it states "
            "one, 'resolved_at', and no other member"
        )
    row = claim.get("row")
    proof = claim.get("proof")
    if not isinstance(row, dict) or not isinstance(proof, dict):
        raise VerificationError("a claim file has a 'row' object and a 'proof' object")

    stated_resolution = None
    if "resolved_at" in claim:
        # If the claim states it at all, it is a timestamp: an empty string, null or a number
        # there is refused by name, never passed over as if nothing had been stated.
        stated_resolution = parse_timestamp(claim["resolved_at"])
    resolution_is_yours = resolved_at is not None
    if resolved_at is None:
        resolved_at = stated_resolution

    # The six hashed members are read out BY NAME. The claim's `row` object is never hashed
    # itself: it also carries the row's stated hash, and a member nobody named would otherwise
    # sit in the claim looking as if the hash covered it.
    for member in ROW_HASH_MEMBERS:
        if member not in row:
            raise VerificationError(
                f"the claim's row states no {member}. A row is hashed from exactly "
                f"{list(ROW_HASH_MEMBERS)}, and a claim without all six is refused"
            )
    unhashed = sorted(str(member) for member in row if member not in (*ROW_HASH_MEMBERS, "row_hash"))
    if unhashed:
        raise VerificationError(
            f"the claim's row has members {unhashed} that the row hash does not cover. A row "
            f"has exactly {list(ROW_HASH_MEMBERS)}, and may state its row_hash"
        )
    if "row_hash" in row and (
        not isinstance(row["row_hash"], str) or not _HEX64.fullmatch(row["row_hash"])
    ):
        # If the member is there at all it is the row's hash. An empty string, null, false,
        # zero, a list or an object is not "no hash stated": it is a claim to be refused.
        raise VerificationError(
            "the claim's row states a row_hash that is not 64 lowercase hex characters (it is "
            f"{type(row['row_hash']).__name__}). A row may leave its row_hash out; if it "
            "states one, it states the hash"
        )
    leaf_index, tree_size, path = read_proof(proof)

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
        row["row_id"],
    )
    write(f"    computed  {computed}\n")
    if "row_hash" in row:
        claimed = row["row_hash"]
        write(f"    row says  {claimed}\n")
        if claimed != computed:
            failures.append(
                "the row_hash the claim states is not the hash of the six members the claim "
                "gives, so the claim file is inconsistent with itself."
            )
            write("    MISMATCH — the stated row_hash is not the hash of the six members given\n")
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
    write(f"    leaf_index {leaf_index} of tree_size {tree_size}, {len(path)} step(s)\n")
    # Before anything is folded: is this the path of THAT leaf in a tree of THAT size? A fold
    # alone cannot say. An interior node offered as a leaf folds to the root as well.
    problem = path_problem(leaf_index, tree_size, path)
    if problem is not None:
        failures.append(
            f"the proof is not a proof for the position it states: {problem}. It is refused "
            "before it is folded."
        )
        write("    PATH DOES NOT FIT ITS INDEX AND SIZE\n")
        return _verdict(write, failures)
    folded = fold(leaf, path)
    write(f"    folded root = {folded}\n")

    # -- step 5 -------------------------------------------------------------------
    step(5, "find that root in the anchor files read (part 2 section 12)")
    history, defects, unread = load_anchor_history(anchors_directory)
    for _path, why, _kind in unread:
        # The reading here failed, and that is all it says.
        write(f"    {NOT_READ_HERE}, passed over: {why}. {NOTHING_FOLLOWS}\n")
    anchors = [entry for entry in history if not entry.is_empty]
    markers = [entry for entry in history if entry.is_empty]
    write(
        f"    {len(history)} anchor file(s) read from {shown(anchors_directory)}: "
        f"{len(anchors)} anchor(s), {len(markers)} empty marker(s)\n"
    )
    if markers:
        # Reported, not hidden. An empty marker is a day the Log held no rows — neither a
        # success nor a failure, and a reader who is told only the anchor count would wonder
        # why the history has gaps it does not have.
        write(f"    {len(markers)} of them say no rows anchored on this date\n")
    for _path, why in defects:
        # Named, and passed over. A file that is not a well-formed publication does not
        # decide a claim it has nothing to do with.
        write(f"    {NOT_A_PUBLICATION}, passed over: {why}\n")
    if defects:
        write(
            f"    {len(defects)} file(s) read here are not well-formed publications. They are "
            "named above and do not decide this claim; --history holds all the files to "
            f"their rules and fails on them. {IF_UNCHANGED_COPY_NOT_A_PUBLICATION}\n"
        )

    matching = [anchor for anchor in anchors if anchor.root_hash == folded]
    if not matching and unread:
        # S5: the line may be in what this machine did not read. Saying it is absent would blame
        # the record for the reading here, so nothing is decided.
        write("    NOT FOUND among what was read here\n")
        return _not_judged(
            write,
            unread,
            f"the folded root {folded} appears in no anchor file read here, and part of the "
            "folder you named could not be read on this machine, so whether a file there "
            "carries it is not known",
        )
    if not matching:
        detail = (
            f"the folded root {folded} appears in no anchor file read here. Either this row was "
            "never anchored, or the proof belongs to a different tree."
        )
        if not anchors and not defects:
            detail = (
                f"the folded root {folded} appears in no anchor file read here, because the "
                f"files read hold no anchors at all — {len(markers)} empty marker(s) and "
                "nothing else. No rows had been anchored by the last date those files stamp."
            )
        if defects:
            detail += (
                f" {len(defects)} file(s) that are not well-formed publications were passed "
                "over in the search."
            )
        failures.append(detail)
        write("    NOT FOUND — no anchor file read here carries this root\n")
        return _verdict(write, failures)

    # Every publication that carries this root must stamp one size. A root is the root of one
    # tree, and a tree has one size; two publications that disagree are the files read here
    # contradicting each other, whichever of them a proof happens to fit.
    stamped_sizes = sorted({anchor.stamped_tree_size for anchor in matching})
    if len(stamped_sizes) > 1:
        failures.append(
            f"{FILES_INCONSISTENT}. "
            f"{len(matching)} of the files read carry the root {folded} and they stamp different "
            f"sizes ({', '.join(str(size) for size in stamped_sizes)}): "
            f"{', '.join(anchor.name for anchor in matching)}. A claim cannot cause this. "
            f"Keep the claim file and the anchor files, and report it. "
            f"{IF_UNCHANGED_COPY_INCONSISTENT}"
        )
        write("    ONE ROOT UNDER MORE THAN ONE SIZE\n")
        return _verdict(write, failures)

    # THE EARLIEST publication carrying this root is the one used. `load_anchor_history`
    # returns the files in the order of their names and a name leads with the instant its
    # file stamps, so that is `matching[0]`. A root may be published more than once (a floor
    # run after a batch run with no rows between them); the first is the one whose time is
    # the earliest evidence, and a later copy is never preferred to it.
    anchor = matching[0]
    write(f"    found in {anchor.name}\n")
    for group in same_instant(matching):
        # Y4: noted here only where it bears on the claim, when the files that carry its
        # root include two that stamp one instant. Otherwise the note is --history's.
        write(
            f"    NOTE: {len(group)} of the files carrying this root stamp the instant "
            f"{group[0].payload['anchored_at']} ({', '.join(entry.name for entry in group)}). "
            "They stamp one size, so the first of them by name is used\n"
        )
    if len(matching) > 1:
        write(
            f"    ({len(matching)} of the files read carry this root, all stamping the same size; "
            f"the earliest is used: {anchor.name}. A name leads with the instant its file "
            "stamps, so this is the first of them, and the time compared in step 6 is a time "
            "for this file)\n"
        )
    write(f"    payload  {shown(anchor.line)}\n")
    write(f"    digest   {anchor.digest}\n")
    # D-S43: whether the chain from this file back to the first line holds among the files
    # read. A break is named, and it does not decide this claim: --history reads the whole
    # chain and fails on it.
    chain_kind, broken_chain = chain_back_problem(anchor, history, whole=not unread)
    if chain_kind is None:
        write(
            f"    the chain from {anchor.name} back to the line that names nothing is "
            "unbroken among the files read\n"
        )
    elif chain_kind == "not judged":
        # R5: the line it stops at may be the one this machine could not read.
        write(
            f"    the chain from {anchor.name} back to the line that names nothing is not judged "
            f"here: {broken_chain}, and part of the folder could not be read on this machine. "
            f"{NOTHING_FOLLOWS}\n"
        )
    else:
        write(
            f"    {CHAIN_BROKEN}, passed over: {broken_chain}. It does not decide this claim; "
            f"--history holds the whole chain to its rule and fails on it. "
            f"{IF_UNCHANGED_COPY_CHAIN}\n"
        )

    # The proof's size must be the size the anchor itself stamps. Without this an honest
    # proof for one tree fits the index, length and side checks of many other sizes.
    stamped_size = stamped_sizes[0]
    if tree_size != stamped_size:
        failures.append(
            f"the proof is for a tree of {tree_size} rows but the anchor publishing "
            f"this root covers {stamped_size}. They are not about the same tree."
        )
        write("    TREE SIZE MISMATCH\n")
    else:
        # What the format makes checkable once `row_id` is hashed and the position is held
        # (part 2 section 12). By this line the row has been shown to be in the published
        # tree at this index under the anchor's own size, so a failure below is never the
        # claim's: it is the anchor file contradicting itself.
        first_row = row["prev_hash"] == GENESIS_PREV_HASH
        if first_row != (leaf_index == 0):
            failures.append(
                f"FIRST-ROW CHECK: {FILE_INCONSISTENT}. The row at "
                "index 0 carries the first row's prev_hash, 64 zeros, and no other row does. "
                f"This row is in the tree the file commits to, at index {leaf_index}, and its "
                "prev_hash is "
                f"{'' if first_row else 'not '}the first row's. {_RECORD_NOT_CLAIM}"
            )
            write("    FIRST-ROW CHECK FAILED\n")
        latest_row_id = anchor.payload["latest_row_id"]
        last_row = leaf_index == stamped_size - 1
        if last_row and row["row_id"] != latest_row_id:
            failures.append(
                f"LAST-ROW CHECK: {FILE_INCONSISTENT}. The last "
                f"row of the tree has the anchor's latest_row_id, {latest_row_id}. This row is "
                "in the tree the file commits to, at the last index, and its row_id is "
                f"{row['row_id']}. "
                f"{_RECORD_NOT_CLAIM}"
            )
            write("    LAST-ROW CHECK FAILED\n")
        if not last_row and not row["row_id"] < latest_row_id:
            failures.append(
                f"LAST-ROW CHECK: {FILE_INCONSISTENT}. Every row "
                "but the last has a row_id that sorts before the anchor's latest_row_id, "
                f"{latest_row_id}. This row is in the tree the file commits to, at index "
                f"{leaf_index} of "
                f"{stamped_size} and its row_id is {row['row_id']}. {_RECORD_NOT_CLAIM}"
            )
            write("    LAST-ROW CHECK FAILED\n")

    try:
        receipt_ok, receipt_lines = check_receipt(anchor)
    except NotReadHere as exc:
        # S4: a receipt this machine could not open or read decides nothing about the record.
        return _not_judged(
            write,
            [(anchor.receipt_path(), shown(str(exc)), "file")],
            f"the receipt beside {anchor.name} could not be read on this machine",
        )
    for line in receipt_lines:
        write(f"    {line}\n")
    if not receipt_ok:
        failures.append(f"OpenTimestamps receipt: {receipt_lines[0]}")
    claims = [
        f"{RECEIPT_CLAIMS} {line[len('it claims ') :]}"
        for line in receipt_lines
        if line.startswith("it claims ")
    ]

    # -- step 6 -------------------------------------------------------------------
    step(6, "check the anchor's time precedes the resolution (part 2 section 12)")
    write(
        f"    anchored_at in the payload  {anchor.payload['anchored_at']}"
        "   <- the publisher's clock, NOT used for precedence\n"
    )
    not_your_own = []
    whose = []

    # The anchor's time: the caller's own, or else the repository's.
    if attested_at is not None:
        whose.append(TIME_OF_ANCHOR_YOURS)
        anchor_source = "supplied with --attested-at"
        write(f"    the anchor's time      {canonical_timestamp(attested_at)}\n")
        write(f"        source: --attested-at. {WORTH_OF_YOUR_OWN}.\n")
    else:
        attested_at, anchor_source, refused = repository_date(anchor, anchors_directory)
        if attested_at is None:
            write("    the anchor's time      none\n")
            write(f"        the repository's date is not used: {refused}.\n")
        else:
            write(f"    the anchor's time      {canonical_timestamp(attested_at)}\n")
            write(f"        source: {anchor_source}. {WORTH_OF_THE_REPOSITORY}.\n")
            whose.append(f"{TIME_OF_ANCHOR_REPOSITORY} ({anchor_source})")
            not_your_own.append(
                f"the anchor's time is the repository's ({anchor_source}). Obtain a time "
                "for that file yourself and pass it with --attested-at"
            )

    # The resolution time: the caller's own, or else the claim file's.
    if resolved_at is None:
        write("    the resolution time    none\n")
    elif resolution_is_yours:
        whose.append(TIME_OF_RESOLUTION_YOURS)
        write(f"    the resolution time    {canonical_timestamp(resolved_at)}\n")
        write(f"        source: --resolved-at. {WORTH_OF_YOUR_OWN}.\n")
        if stated_resolution is not None and stated_resolution != resolved_at:
            write(
                "        (the claim file states "
                f"{canonical_timestamp(stated_resolution)}; yours is the one compared)\n"
            )
    else:
        write(f"    the resolution time    {canonical_timestamp(resolved_at)}\n")
        write(f"        source: the claim file's resolved_at. {WORTH_OF_THE_CLAIM}.\n")
        whose.append(TIME_OF_RESOLUTION_CLAIMS)
        not_your_own.append(
            "the resolution time is the publisher's (the claim file's resolved_at). Obtain "
            "the time the outcome was resolved yourself and pass it with --resolved-at"
        )

    precedes, detail = precedence_check(anchor, resolved_at, attested_at, anchor_source)
    write(f"    {detail}\n")
    if not precedes:
        failures.append(detail)

    checked = [CHECKED_LEAF, CHECKED_FOLD, CHECKED_BYTES, CHECKED_RECEIPT, *claims]
    return _verdict(write, failures, not_your_own, checked, whose)


#: The closing block of a passing verdict: what was checked, and whose each time is. Each
#: sentence is written here once. Provisional words, the founder's to change.
CHECKED_LEAF = "the row's six members hash to the leaf the proof starts from"
CHECKED_FOLD = "the proof folds to the root the anchor file states, at the index and size it gives"
CHECKED_BYTES = "the anchor file is its canonical line and not one byte more"
CHECKED_RECEIPT = "the receipt beside it is read to its end and stamps that file's SHA-256"
RECEIPT_CLAIMS = "the receipt claims"
TIME_OF_ANCHOR_YOURS = "the anchor's time is yours (--attested-at)"
TIME_OF_ANCHOR_REPOSITORY = "the anchor's time is the repository's"
TIME_OF_RESOLUTION_YOURS = "the resolution time is yours (--resolved-at)"
TIME_OF_RESOLUTION_CLAIMS = "the resolution time is the publisher's (the claim file's resolved_at)"
BOTH_TIMES_YOURS = (
    "Both times are yours. It is you who have tied that anchor file to a time, and that time is "
    "before the resolution time you gave (Constitution §45(e)). Each is worth what your source "
    "for it is worth."
)
NOT_BOTH_YOURS = "A time that is not yours was compared, so this program does not print the plain word:"


def _count_unread(unread):
    """What was not read here, counted by kind: "1 folder", "2 files", "1 folder and 1 file"."""
    counted = []
    for kind in ("folder", "file"):
        number = sum(1 for _path, _why, what in unread if what == kind)
        if number:
            counted.append(f"{number} {kind}" + ("s" if number > 1 else ""))
    return " and ".join(counted)


def _not_judged(write, unread, reason):
    """Print the closing block of a claim this machine could not decide, and return NOT JUDGED.

    Something under the folder named could not be opened or read here, and what was read does
    not decide the claim. Nothing about the published record follows, and none is said.
    """
    write("\n" + "=" * 78 + "\n")
    write(f"  - {reason}.\n")
    for _path, why, _kind in unread:
        write(f"  - {NOT_READ_HERE}: {why}\n")
    write(f"  {NOTHING_FOLLOWS} Check it again where every part of the folder can be read.\n")
    write("=" * 78 + "\n")
    write(VERDICT_NOT_JUDGED + "\n")
    return VERDICT_NOT_JUDGED


def _verdict(write, failures, not_your_own=(), checked=(), whose=()):
    """Print the closing block and return the verdict, whose word is the last line printed.

    The plain word is reached only with no failure AND no time that was not the caller's own.
    Nothing read from a claim, an anchor, a receipt or a file name is on the last line.
    """
    write("\n" + "=" * 78 + "\n")
    if failures:
        verdict = VERDICT_NOT_VERIFIED
        for failure in failures:
            write(f"  - {failure}\n")
    else:
        for sentence in checked:
            write(f"  checked: {sentence}\n")
        for sentence in whose:
            write(f"  {sentence}\n")
        if not_your_own:
            verdict = VERDICT_TIMES_NOT_YOUR_OWN
            write(f"  {NOT_BOTH_YOURS}\n")
            for line in not_your_own:
                write(f"  - {line}\n")
        else:
            verdict = VERDICT_VERIFIED
            write(f"  {BOTH_TIMES_YOURS}\n")
    write("=" * 78 + "\n")
    write(verdict + "\n")
    return verdict


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
    3: "833a0878c13c66d6a2d23acc9a250cd2b6f1c4938cd7f5f7efef288fb64391be",
    4: "7280ad1d11858a5886a3b2d5a8b6b3f8bebd888b4cf191b8d04efa92498ec4cd",
    5: "b0bd91ba932dc7e269c9bc0a3b45363e47b4669da4e1ef7264e732c97ac29807",
    6: "41f329d810a6aa9b4118cb27c4eb750a50dee51ef480060294fcbc9d2ffeebc1",
    7: "b6cfa311c4e9a8205eb325e7c85eb44707f2739e1aba72be847777fe98f7cf2b",
    8: "9cebd0d38162339c6e36b48e486ef1980bc7d962e2e4a20abb43de46a6695a80",
    9: "019019a03939e7f124b83256ba99acf4d3a7d0577096f2b92daf10cb6bc380d9",
}

#: From part 1's `vectors:node` table: N0, which is sha256("row-0") and the first row hash of
#: every tree vector above, and N2, node_hash(N0, N0). N1 is the one-row root, TREE_VECTORS[1].
SEED_VECTOR = "3c831eb5a23962a50dbffc0d4f37facd0f1171844d08d1a5cc93a04426f02393"
NODE_VECTOR = "7d425e60db2e23e2a37cca55c3ebfe6c2ff2eda919f873ff5595a29a378629f6"

#: From part 1's `vectors:row-hash` table: (payload, prev_hash, row_type, operator_id,
#: created_at, row_id, row_hash). H5 to H12 are the rows a looser serialization gets wrong: a
#: quote and a backslash, characters outside ASCII, another spelling of H2's instant (so the
#: same hash as H2), a row type on no list, keys whose UTF-16 order is not their code-point
#: order, the characters an HTML-safe writer escapes, and one letter composed (H11) and
#: decomposed (H12), which are two rows with two hashes because no string is normalised.
ROW_HASH_VECTORS = [
    (
        {},
        GENESIS_PREV_HASH,
        "declined",
        "op-1",
        "2026-07-24T10:00:00.000000Z",
        "01JZZZZZZZZZZZZZZZZZZZZZZZ",
        "15b9ee45b90802f8e50af3eebcd902a5b86ccbfcd9d9d3d2531e7bed04fa09fd",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        "op-1",
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "f2ada4a6a40b43fe220ff7c948d8610e4de2bf2be9151a76f5854be0956fc726",
    ),
    (
        {"a": "1"},
        "f" * 64,
        "resolution",
        "op-2",
        "2026-11-07T18:30:00.000000Z",
        "01K1ABCDEFGHJKMNPQRSTVWXYZ",
        "d98a86616aef951411ad1b9897600a3edf18037a4e203c042778052f4f2bcdfa",
    ),
    (
        {"z": "1", "a": "2"},
        GENESIS_PREV_HASH,
        "void",
        "op-1",
        "2026-07-24T10:00:00.000001Z",
        "01JZZZZZZZZZZZZZZZZZZZZZZZ",
        "c10a9abf5716a24e1c61eaf79d40172377b49bbccfc9f94871110d0aa4570cfe",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        'op"1\\x',
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "f08b5ccca2c5c63d4478231cae82f049ea028e15a09ab114b71d919b4b9ab4d8",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        "op-\u00e9\u20b9",
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "bc17802fd52e4860ad48daac8d929a88c02f23a63b49564b943cfb784b055ffc",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        "op-1",
        "2026-07-24T15:30:00+05:30",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "f2ada4a6a40b43fe220ff7c948d8610e4de2bf2be9151a76f5854be0956fc726",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "voided",
        "op-1",
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "1fd2b674a3390fa35c3803a6b3afba64edc945bb50053e7afcb00081d1749efa",
    ),
    (
        {"\U00010000": "supplementary", "\ufffd": "replacement"},
        GENESIS_PREV_HASH,
        "prediction",
        "op-1",
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "7c71a92deef6ee22ae52acea100034a157ff74f90ec8eaf106c1defec11bb876",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        '&<>/\x7f\u2028\u2029',
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "a5db206bfa485987c6efb5c2c9465ae16d81fcce8ff0a498f13d483b328e50e8",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        '\xe9',
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "a1e7e56418e9e84f4bdf6cef2095995cc4e3752e19c360e37d0fd78c999ce087",
    ),
    (
        {"a": "1"},
        GENESIS_PREV_HASH,
        "prediction",
        'e\u0301',
        "2026-07-24T10:00:00.000000Z",
        "01K0X9NR5N7QK8V4CZ6H2WBTMD",
        "730c8ac15f53d0036b478db2206f8203848329aefc077ba34bf5c7a40e72b901",
    ),
]

#: From part 1's `vectors:row-preimage` and `vectors:row-preimage-hex` tables: the bytes that are
#: hashed for each row vector above, in the same order, as text.
ROW_PREIMAGE_VECTORS = [
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","row_type":"declined"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-11-07T18:30:00.000000Z","operator_id":"op-2","payload":{"a":"1"},"prev_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","row_id":"01K1ABCDEFGHJKMNPQRSTVWXYZ","row_type":"resolution"}',
    '{"created_at":"2026-07-24T10:00:00.000001Z","operator_id":"op-1","payload":{"a":"2","z":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","row_type":"void"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op\\"1\\\\x","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-\xe9\u20b9","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"voided"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"\U00010000":"supplementary","\ufffd":"replacement"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"&<>/\x7f\u2028\u2029","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"\xe9","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
    '{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"e\u0301","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}',
]

#: Worked inclusion proofs over the same rows as TREE_VECTORS: (rows, leaf_index, path, root),
#: each step a (side, hash). The last row of a three-row tree has ONE step, because its leaf
#: is carried up a level unchanged; a middle row of a five-row tree; and a tree of one row,
#: whose path is empty.
PROOF_VECTORS = [
    (
        3,
        2,
        [
            ("left", "6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a"),
        ],
        "833a0878c13c66d6a2d23acc9a250cd2b6f1c4938cd7f5f7efef288fb64391be",
    ),
    (
        5,
        2,
        [
            ("right", "2fe098ebb786a6013d5f706508a0cec4341f0814e437bbc839ab487f0472d351"),
            ("left", "6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a"),
            ("right", "cac01b52850e6db4d0d3c64a995efadc1024ac2c2362dd1eb93f1d25f6e65d6b"),
        ],
        "b0bd91ba932dc7e269c9bc0a3b45363e47b4669da4e1ef7264e732c97ac29807",
    ),
    (1, 0, [], "76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614"),
]

#: From part 1's `vectors:canonical` and `vectors:canonical-hex` tables, every row of both, in
#: the document's order. The supplementary-plane case is the one that catches a code-point
#: sort. The last four are the ones a writer that escapes more than section 1 does gets wrong:
#: `&`, `<`, `>` and `/`; U+007F, U+2028 and U+2029; and one letter composed and decomposed,
#: which are two different strings because nothing is normalised.
CANONICAL_VECTORS = [
    ('{"b":"2","a":"1"}', '{"a":"1","b":"2"}'),
    ('{"a":{"d":"4","c":"3"}}', '{"a":{"c":"3","d":"4"}}'),
    ('{"x":["b","a"]}', '{"x":["b","a"]}'),
    ('{"t":true,"f":false,"n":null}', '{"f":false,"n":null,"t":true}'),
    ('{"s":"a\\"b\\\\c"}', '{"s":"a\\"b\\\\c"}'),
    ('{"s":"tab\\there"}', '{"s":"tab\\there"}'),
    ('{"s":"\\u0001\\u001f"}', '{"s":"\\u0001\\u001f"}'),
    ('{"s":""}', '{"s":""}'),
    ('{"s":"na\\u00efve \\u20b9"}', '{"s":"na\xefve \u20b9"}'),
    ('{"\\ud800\\udc00":"supplementary","\\ufffd":"replacement"}', '{"\U00010000":"supplementary","\ufffd":"replacement"}'),
    ('{"s":"&<>/"}', '{"s":"&<>/"}'),
    ('{"s":"\\u007f\\u2028\\u2029"}', '{"s":"\x7f\u2028\u2029"}'),
    ('{"s":"\\u00e9"}', '{"s":"\xe9"}'),
    ('{"s":"e\\u0301"}', '{"s":"e\u0301"}'),
]

#: From part 1's `vectors:uuid` table: (spelling, canonical form).
UUID_VECTORS = [
    ("f81d4fae-7dec-41d0-9b2a-0242ac130004", "f81d4fae-7dec-41d0-9b2a-0242ac130004"),
    ("F81D4FAE-7DEC-41D0-9B2A-0242AC130004", "f81d4fae-7dec-41d0-9b2a-0242ac130004"),
    ("{f81d4fae-7dec-41d0-9b2a-0242ac130004}", "f81d4fae-7dec-41d0-9b2a-0242ac130004"),
    ("urn:uuid:F81D4FAE-7DEC-41D0-9B2A-0242AC130004", "f81d4fae-7dec-41d0-9b2a-0242ac130004"),
    ("f81d4fae7dec41d09b2a0242ac130004", "f81d4fae-7dec-41d0-9b2a-0242ac130004"),
]

#: From part 1's `vectors:timestamp` table: (input, canonical form), where None means the
#: specification REFUSES the spelling. As with the currency table, a refusal is part of the
#: rule: an implementation that accepted one of these would be reading a second spelling of an
#: instant, or an instant that does not exist.
TIMESTAMP_VECTORS = [
    ('2026-07-24T10:00:00Z', '2026-07-24T10:00:00.000000Z'),
    ('2026-07-24T10:00:00.5Z', '2026-07-24T10:00:00.500000Z'),
    ('2026-07-24T10:00:00.123Z', '2026-07-24T10:00:00.123000Z'),
    ('2026-07-24T10:00:00.123456Z', '2026-07-24T10:00:00.123456Z'),
    ('2026-07-24T10:00:00.123456000Z', '2026-07-24T10:00:00.123456Z'),
    ('2026-07-24T15:30:00+05:30', '2026-07-24T10:00:00.000000Z'),
    ('2026-07-25T09:59:00+23:59', '2026-07-24T10:00:00.000000Z'),
    ('2026-07-24T10:00:00-00:00', '2026-07-24T10:00:00.000000Z'),
    ('2024-02-29T23:59:59.999999Z', '2024-02-29T23:59:59.999999Z'),
    ('2026-07-25T10:00:00+24:00', None),
    ('2026-07-24T10:00:00+00:60', None),
    ('2026-02-30T10:00:00Z', None),
    ('2026-02-29T10:00:00Z', None),
    ('2026-13-01T10:00:00Z', None),
    ('2026-07-24T24:00:00Z', None),
    ('2026-07-24T10:60:00Z', None),
    ('2026-07-24T10:00:60Z', None),
    ('2026-07-24T10:00:00.Z', None),
    ('2026-07-24T10:00:00.1234567Z', None),
    ('2026-07-24t10:00:00Z', None),
    ('2026-07-24T10:00:00z', None),
    ('2026-07-24 10:00:00Z', None),
    ('2026-07-24T10:00:00', None),
    ('2026-07-24T10:00:00+0530', None),
    ('0000-01-01T00:00:00Z', None),
    ('0001-01-01T00:00:00+00:01', None),
    ('9999-12-31T23:59:59-00:01', None),
    ('2026-07-24T10:00:00.\u0665Z', None),
]

#: From part 2's `vectors:anchor` table: the canonical published line and its SHA-256. The
#: three are one chain in table order (D-S43): A1 names nothing, A2 names A1, A3 names A2.
ANCHOR_VECTORS = [
    (
        (
            '{"anchored_at":"2026-07-25T00:00:00.000000Z",'
            '"latest_row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","ledger_schema_version":"lg_0002",'
            '"previous_line_sha256":null,'
            '"root_hash":"76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614",'
            '"tree_size":"1"}'
        ),
        "15001bddea0e7cfab053ab090b18af2896e3e649ac87904363fe1433005bbad6",
    ),
    (
        (
            '{"anchored_at":"2026-07-26T00:00:00.000000Z",'
            '"latest_row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","ledger_schema_version":"lg_0002",'
            '"previous_line_sha256":"15001bddea0e7cfab053ab090b18af2896e3e649ac87904363fe1433005bbad6",'
            '"root_hash":"833a0878c13c66d6a2d23acc9a250cd2b6f1c4938cd7f5f7efef288fb64391be",'
            '"tree_size":"3"}'
        ),
        "1432631b25d2bea070a420e995c3c68d19e602970876e15c1c8e78b5d6d253dd",
    ),
    (
        (
            '{"anchored_at":"2026-08-01T12:34:56.789000Z",'
            '"latest_row_id":"01K1ABCDEFGHJKMNPQRSTVWXYZ","ledger_schema_version":"lg_0002",'
            '"previous_line_sha256":"1432631b25d2bea070a420e995c3c68d19e602970876e15c1c8e78b5d6d253dd",'
            '"root_hash":"019019a03939e7f124b83256ba99acf4d3a7d0577096f2b92daf10cb6bc380d9",'
            '"tree_size":"9"}'
        ),
        "4b02f0b8759c32aef3ba63ad23908446931d633d74d418197b82f9c89c21d3ac",
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
            '"previous_line_sha256":null,"status":"empty","tree_size":"0"}'
        ),
        "5d86bd86c8da0032eb089e70542eaa52a35126083eaea30f822f46a55ea6ca71",
    ),
    (
        (
            '{"anchored_at":"2026-07-28T03:00:01.234567Z","ledger_schema_version":"lg_0002",'
            '"previous_line_sha256":"5d86bd86c8da0032eb089e70542eaa52a35126083eaea30f822f46a55ea6ca71",'
            '"status":"empty","tree_size":"0"}'
        ),
        "082b8fa7fd38f5ae2ad1142f6e14eda0b3c7fe8d7263b0ce401f53be590dc9e0",
    ),
    (
        (
            '{"anchored_at":"2026-08-01T12:34:56.789000Z","ledger_schema_version":"lg_0001",'
            '"previous_line_sha256":"082b8fa7fd38f5ae2ad1142f6e14eda0b3c7fe8d7263b0ce401f53be590dc9e0",'
            '"status":"empty","tree_size":"0"}'
        ),
        "15a127cc1faad3be0e1a70fa65325ec20f8cd5fa4bcce5157575a6c22bdf17ba",
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
        try:
            produced = canonical_timestamp(given)
        except VerificationError:
            produced = None
        if produced != expected:
            shown = "refused" if expected is None else expected
            failures.append(
                f"timestamp {given!r} -> {'refused' if produced is None else produced}, "
                f"expected {shown}"
            )

    for given, expected in UUID_VECTORS:
        produced = canonical_uuid(given)
        if produced != expected:
            failures.append(f"uuid {given} -> {produced}, expected {expected}")

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
    if seed != SEED_VECTOR:
        failures.append("sha256('row-0') does not match vector N0")
    if leaf_hash(seed) != TREE_VECTORS[1]:
        failures.append("leaf_hash(sha256('row-0')) does not match vector N1/M1")
    if node_hash(seed, seed) != NODE_VECTOR:
        failures.append("node_hash does not match vector N2")

    for count, expected in sorted(TREE_VECTORS.items()):
        hashes = [sha256_hex(f"row-{index}".encode()) for index in range(count)]
        produced = merkle_root(hashes)
        if produced != expected:
            failures.append(f"root over {count} rows = {produced}, expected {expected}")

    for payload, prev, row_type, operator, created, row_id, expected in ROW_HASH_VECTORS:
        produced = row_hash(payload, prev, row_type, operator, created, row_id)
        if produced != expected:
            failures.append(f"row_hash({payload!r}) = {produced}, expected {expected}")

    if len(ROW_PREIMAGE_VECTORS) != len(ROW_HASH_VECTORS):
        failures.append("the row vectors and their hashed bytes are not the same number")
    for vector, expected_bytes in zip(ROW_HASH_VECTORS, ROW_PREIMAGE_VECTORS):
        payload, prev, row_type, operator, created, row_id, expected = vector
        produced_bytes = row_hashed_bytes(payload, prev, row_type, operator, created, row_id)
        if produced_bytes != expected_bytes.encode("utf-8"):
            failures.append(f"the hashed bytes of the row vector {row_id}/{row_type} differ")
        if sha256_hex(expected_bytes.encode("utf-8")) != expected:
            failures.append(f"the printed hashed bytes of {row_id}/{row_type} do not hash to it")

    for count, leaf_index, steps, expected in PROOF_VECTORS:
        hashes = [sha256_hex(f"row-{index}".encode()) for index in range(count)]
        path = [{"side": side, "hash": sibling} for side, sibling in steps]
        problem = path_problem(leaf_index, count, path)
        if problem is not None:
            failures.append(f"proof vector for leaf {leaf_index} of {count}: {problem}")
        elif fold(leaf_hash(hashes[leaf_index]), path) != expected:
            failures.append(f"proof vector for leaf {leaf_index} of {count} does not fold")
        elif merkle_root(hashes) != expected:
            failures.append(f"proof vector for leaf {leaf_index} of {count} names another root")

    for line, expected in ANCHOR_VECTORS:
        parsed = json.loads(line)
        if _render(parsed) != line:
            failures.append(f"anchor line is not canonical under this implementation: {line}")
        produced = sha256_hex(canonical(parsed))
        if produced != expected:
            failures.append(f"anchor digest {produced}, expected {expected}")

    for vectors in (ANCHOR_VECTORS, EMPTY_MARKER_VECTORS):
        named = [json.loads(line).get(PREVIOUS_LINE, "absent") for line, _expected in vectors]
        if named != [None] + [expected for _line, expected in vectors[:-1]]:
            failures.append("the vectors of one table are not one chain in table order")

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
        f"{len(UUID_VECTORS)} uuid, {len(ROW_PREIMAGE_VECTORS)} row-preimage, "
        f"{len(CURRENCY_VECTORS)} currency, {len(TREE_VECTORS)} tree, "
        f"{len(ROW_HASH_VECTORS)} row-hash, {len(PROOF_VECTORS)} proof, "
        f"{len(ANCHOR_VECTORS)} anchor, "
        f"{len(EMPTY_MARKER_VECTORS)} empty-marker vectors\n"
    )
    if failures:
        write("SELF-TEST FAILED\n")
        for failure in failures:
            write(f"  - {failure}\n")
        return False
    write("SELF-TEST PASSED — this verifier reproduces every vector in VERIFY.md\n")
    return True


def _refused(reason):
    """A refusal in words: the reason, then the verdict as the last line. Exit status 1."""
    sys.stdout.write(f"  - {shown(reason)}\n{VERDICT_NOT_VERIFIED}\n")
    return EXIT_STATUS[VERDICT_NOT_VERIFIED]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Verify a Simul8 prediction against the anchor files in a folder you name.",
        epilog=(
            "Constitution v2.4 §45(e). Procedure: VERIFY.md parts 1 and 2. Exit status: 0 "
            f"{VERDICT_VERIFIED}; 3 {VERDICT_TIMES_NOT_YOUR_OWN}; 1 {VERDICT_NOT_VERIFIED}, or "
            "a failed --self-test or --history; 4 NOT JUDGED, or --history NOT JUDGED, part of the "
            "folder could not be opened or read on this machine and what was read does not decide "
            "it; 2 the arguments could not be read."
        ),
    )
    parser.add_argument("--claim", help="JSON file holding {row, proof, resolved_at}")
    parser.add_argument(
        "--anchors",
        default="anchors",
        help="the folder holding the anchor files. Without --attested-at the repository's "
        "date is read by running git in the folder you name: name only a clone you made "
        "yourself with git clone.",
    )
    parser.add_argument(
        "--attested-at",
        help="a time for the anchor that you obtained yourself (RFC 3339). Without it the "
        "date on the repository's commit is read, and the last line is then not the plain "
        "word.",
    )
    parser.add_argument(
        "--resolved-at",
        help="the time the outcome was resolved, obtained yourself (RFC 3339). Without it "
        "the claim file's is read, and the last line is then not the plain word.",
    )
    parser.add_argument("--self-test", action="store_true", help="check against the vectors")
    parser.add_argument(
        "--history",
        action="store_true",
        help="list the anchor files read and hold them to the rules a Log's history keeps",
    )
    arguments = parser.parse_args(argv)

    # Whatever the terminal's encoding, a character it cannot show is written as an escape
    # rather than ending the program.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(errors="backslashreplace")
        except (OSError, ValueError):
            pass

    if arguments.self_test:
        return 0 if self_test() else 1

    if arguments.history:
        # It reports what the public record contains, and holds it to what a Log can do. A
        # day with no rows is a fact about the Log, not a fault. A file that is not a
        # well-formed publication, or a history no Log could have produced, is a failure.
        try:
            history, defects, unread = load_anchor_history(arguments.anchors)
        except VerificationError as exc:
            sys.stdout.write(f"{shown(str(exc))}\n")
            return 1
        for _path, why, _kind in unread:
            sys.stdout.write(f"  {NOT_READ_HERE}: {why}. {NOTHING_FOLLOWS}\n")
        anchored = sum(1 for entry in history if not entry.is_empty)
        for entry in history:
            sys.stdout.write(f"  {entry.describe()}\n")
        sys.stdout.write(
            f"{len(history)} anchor file(s) read: {anchored} anchor(s), "
            f"{len(history) - anchored} empty marker(s)\n"
        )
        for group in same_instant(history):
            sys.stdout.write(
                f"  NOTE: {len(group)} files stamp the instant {group[0].payload['anchored_at']} "
                f"({', '.join(entry.name for entry in group)}). Files of one instant are "
                "listed, and held to the rules, in the order of the sizes they stamp.\n"
            )
        for _path, why in defects:
            sys.stdout.write(f"  {NOT_A_PUBLICATION}: {why}\n")
        broken = history_rules_broken(history) + chain_breaks(history, whole=not unread)
        for rule in broken:
            sys.stdout.write(f"  RULE BROKEN: {rule}\n")
        if unread:
            # R5: what needs every line read is not judged, and says so.
            sys.stdout.write(f"  {CHAIN_PARTS_NOT_JUDGED}\n")
        if defects or broken:
            # R2: a defect wins. What was read already fails, whatever else was not read.
            sys.stdout.write(
                f"  The anchor files read here do not make a history a Log could have "
                f"written. {IF_UNCHANGED_COPY_HISTORY_FAILS}\n"
            )
            if unread:
                sys.stdout.write(
                    f"  The history was not read whole: {_count_unread(unread)} under the folder "
                    "you named could not be read on this machine, and are named above.\n"
                )
            sys.stdout.write(
                f"HISTORY FAILS: {len(defects)} file(s) that are not well-formed "
                f"publications, {len(broken)} broken rule(s)\n"
            )
            return 1
        if unread:
            # Nothing read shows a defect, and the history read here is not the whole of the
            # folder named, so it is not judged: a status distinct from a defect found.
            sys.stdout.write(
                f"{HISTORY_NOT_JUDGED}: {_count_unread(unread)} under the folder you named could "
                "not be read on this machine, so the files read here are not the whole of it. "
                f"{NOTHING_FOLLOWS} Read the folder where every part of it can be read.\n"
            )
            return EXIT_NOT_JUDGED
        return 0

    if not arguments.claim:
        parser.error("--claim is required unless --self-test or --history is given")

    try:
        claim = read_claim(arguments.claim)
    except NotReadHere as exc:
        # The reader's own input, not the record: an argument that could not be read, status 2,
        # as the argument parser has it. No verdict is given.
        parser.error(shown(str(exc)))
    except VerificationError as exc:
        return _refused(str(exc))
    except RecursionError:
        return _refused("an input is nested too deeply to be read")
    try:
        attested = (
            None if arguments.attested_at is None else parse_timestamp(arguments.attested_at)
        )
        resolved = (
            None if arguments.resolved_at is None else parse_timestamp(arguments.resolved_at)
        )
        verdict = claim_verdict(claim, arguments.anchors, attested, resolved)
    except VerificationError as exc:
        return _refused(str(exc))
    except RecursionError:
        return _refused("an input is nested too deeply to be read")
    except OSError as exc:
        return _refused(f"a file could not be read ({type(exc).__name__})")
    return EXIT_STATUS[verdict]


if __name__ == "__main__":
    sys.exit(main())
