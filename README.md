# simul8-anchors

**Published Merkle roots for the Simul8 prediction ledger, and the program that checks them.**

This repository exists so that you do not have to trust us.

Simul8 keeps an append-only ledger of forecasts. Each forecast is written down *before* the
outcome is known, and every row is hashed into a Merkle tree. Periodically the root of that tree
is published here. Because the root is a commitment to every row underneath it, a root that was
published on a date proves that every row it covers already existed on that date — and could not
be changed afterwards without the root changing too.

The Simul8 Constitution v2.4 §45(e) permits presenting a forecast as *independently verifiable*
only when a published anchor covers it and that anchor's third-party timestamp precedes the
forecast's resolution. This repository is the published half of that claim.

**A privately held Merkle tree proves nothing.** We could rebuild one at any time to say
anything we liked. What makes the claim checkable is that the root was recorded somewhere we do
not control, before the outcome was known. That is what the commit history below and the
OpenTimestamps receipts are for.

## What is in here

| Path | What it is |
|---|---|
| `anchors/<year>/*.anchor.json` | one published entry — either an **anchor** (a canonical JSON line carrying the Merkle root, how many rows it covers, the last row id, the ledger schema version, and the time we built the tree) or an **empty marker** (`"status":"empty"`) on a day the Log held no rows. A date may have more than one of these files |
| `anchors/<year>/*.anchor.json.ots` | the OpenTimestamps receipt for that line's SHA-256 |
| `VERIFY.md` | the complete specification: canonical serialization, hashing, the tree, inclusion proofs, and the anchor procedure |
| `verify.py` | a dependency-free reference verifier |
| `.github/workflows/` | a scheduled check of this record. It stays idle while the record is empty and arms itself once the first entry is published; from then on it checks each day that an entry arrived and that the receipts are upgrading. It holds no credential and touches nothing of ours — that is the point of it living here |

**Nothing has been published here yet.** The ledger is not yet running, so this record is empty:
there are no entries, and a date with no file means only that publication has not begun. The first
entry will be an empty marker saying so plainly, which is how you will be able to see for yourself
exactly when we started.

**Once publication begins, every day publishes at least one entry, and often more than one**, and
from then on a date with no file means something failed rather than something being quiet. One
entry is published on a floor cadence — currently once a day — and another after each batch of new
forecasts, so several entries on one date is ordinary and is not a sign that anything went wrong or
was rewritten. More entries is more of the record committed sooner: an entry can only add coverage,
never remove it, and no entry already published is ever changed.

**What is *not* in here, and never will be:** any forecast, any resolution, any operator or
customer data, any credential. Only roots and timestamps. A Merkle root is a hash — it commits to
the rows without revealing them.

## Checking a forecast yourself

`verify.py` needs Python 3 and nothing else. No `pip install`, no network, no account.

```sh
git clone https://github.com/krishmeister/simul8-anchors
cd simul8-anchors

# 1. Confirm the verifier agrees with the published specification.
#    This uses no Simul8 data at all — it recomputes every test vector in VERIFY.md.
python3 verify.py --self-test

# 2. See what the published record contains, date by date.
python3 verify.py --history --anchors anchors/

# 3. Check an actual forecast, given the row and its inclusion proof, and the two times you
#    obtained yourself (see "The timestamp is the part that matters" below).
python3 verify.py --claim claim.json --anchors anchors/ \
    --attested-at <the anchor's time> --resolved-at <the resolution time>
```

The last line it prints is the verdict, and the exit status goes with it: `VERIFIED` (0),
`PROOF HOLDS, TIMES NOT YOUR OWN` (3), `NOT VERIFIED` (1), or `NOT JUDGED` (4) when part of
the folder you named could not be opened or read on your machine and what was read does not
decide it. Above a passing verdict it says what
was checked, and whose each of the two times is.

A `claim.json` looks like this, and is what Simul8 hands you alongside a forecast:

```json
{
  "row":   { "row_id": "...", "row_type": "prediction", "created_at": "...",
             "operator_id": "...", "payload": {...}, "prev_hash": "..." },
  "proof": { "leaf_index": "2", "tree_size": "3",
             "path": [ { "side": "left", "hash": "..." } ] },
  "resolved_at": "2026-11-07T18:30:00.000000Z"
}
```

The six members of `row` and the three members of `proof` are all required, and a claim has no
member of its own besides `row`, `proof` and `resolved_at`. `leaf_index` and `tree_size` are
written as strings of digits: a claim file holds no JSON number. `row` may also state its own
`row_hash`, which the verifier compares with the hash it computes. A claim that states any other
member, or repeats a key, is refused. The example is the last of three rows: its
path has one step, because the number of steps and the side of each are fixed by the row's index
and the size of the tree.

The verifier prints each step, so you can see where it agrees and where it does not rather than
being handed a verdict. It recomputes the row's hash **from the row's six members** — not from
the row's own claim about its hash — checks that the path is the path of that index in a tree of
that size, folds it to a root, finds that root in the anchor history here under the same tree
size, and then compares two times.

It reads only a regular file, and no more of it than it may hold: a link to a device, a named
pipe, or a file far longer than the format allows is refused by name. It reads each published
file as bytes. A copy that has gained white space, a carriage return or
a byte-order mark is not the file that was stamped, and is refused by name: fetch it again with
`git cat-file blob HEAD:<path>`, or download the raw file. A file that is not a well-formed
publication is named in the transcript and passed over when a forecast is checked. `--history`
fails on such a file, and on a history no Log could have written: sizes that go down, one size
under two roots, one root under two sizes, an empty marker after an anchor, or lines that do not
form one chain. A folder or a regular file your machine cannot open or read is a fact about the
reading here, not about the record: `--history` names it and ends "HISTORY NOT JUDGED", with exit status 4,
unless what it did read shows a defect, which fails the history. A link where a published file
should be is a defect of the record, never a failed reading.

Every published line names the line published immediately before it, in its field
`previous_line_sha256`: the SHA-256 of that line's exact bytes, or `null` on the first line ever
published and on no other. So the lines form one chain, and `--history` checks that no line was
held back and slipped in later: placed between two lines, such a line names a line another line
already names, which is a fork; placed at the end with an earlier instant, the instants go back.
The chain does not show that a line was public on its date; that rests on the times, as before. The publishing job does not read the
whole chain and does not look for a fork; `--history` does, where the whole chain is read.

`verify.py` is pointed at a folder, and nothing it checks shows that the folder is this
repository. So it speaks of the anchor files it read, and of the published record only on the
condition that those files are an unchanged copy of the public repository.

## The timestamp is the part that matters

Every anchor payload contains an `anchored_at` field. **It is not evidence, and `verify.py` will
not use it.** It is a reading of our own clock and we could have written anything in it.

`verify.py` compares two times: the anchor's, and the time the forecast's outcome was resolved.
Its last line is the plain word `VERIFIED` only when you supplied both yourself, with
`--attested-at` and `--resolved-at`. The anchor's time this repository is built to give you is
Bitcoin's:

```sh
# Bitcoin, via OpenTimestamps. Install the client from https://opentimestamps.org
ots verify anchors/2026/<file>.anchor.json.ots
```

A fresh receipt is *calendar-pending* — the calendar has committed to including the digest but no
block carries it yet — so a recent anchor may not have a Bitcoin attestation, while an older one
will. `verify.py` reads the receipt beside each anchor file to its end and says what it claims:
for a Bitcoin attestation, the block height and the value that block's Merkle root must have, in
the order the receipt holds its bytes and reversed; for a pending one, the calendar. It fetches
nothing and judges no block's clock, so it says what the receipt claims and never that it is so,
and `ots verify` finishes the check. A receipt it cannot read, it calls unreadable to this
program, and says why. The anchor job reads each receipt by the same rules before it publishes,
and publishes nothing if the read fails.

Without `--attested-at`, `verify.py` reads the date on the commit that added the file, from your
clone. It uses that date only if one commit added the file, that commit holds exactly the file's
bytes, and no later commit touched its path. A commit's date is a field of the commit, written
when the commit was made: the program can read it and cannot tell who set it. It reads that date
by running `git` in the folder you name with `--anchors`. A folder brings its own git settings,
and git can be made to run other programs from them: name only a clone you made yourself with
`git clone`. Without
`--resolved-at` it reads the `resolved_at` in the claim file, which we write. In either case, if
the proof holds and the times compare, the last line is `PROOF HOLDS, TIMES NOT YOUR OWN` and the
exit status is 3, never the plain word. The transcript says where each time came from and what
that source is worth.

If no time can be obtained for the anchor, `verify.py` reports **not verified**. It does not
fall back to ours.

## Found a discrepancy?

Open an issue here. A verifier that disagrees with us is the single most useful thing this
repository can produce, and "our implementation is right and yours is wrong" is not an argument
either of us can make from anything except `VERIFY.md` — which is why the specification, the
vectors and the verifier are all in this repository rather than described somewhere.

---

*The ledger's own source is private (Constitution §40 — it holds operator data from the first
credential onward). This repository is public by design and holds no operator data at any point
in its history.*
