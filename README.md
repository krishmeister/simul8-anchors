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

# 3. Check an actual forecast, given the row and its inclusion proof.
python3 verify.py --claim claim.json --anchors anchors/
```

A `claim.json` looks like this, and is what Simul8 hands you alongside a forecast:

```json
{
  "row":   { "payload": {...}, "prev_hash": "...", "row_type": "prediction",
             "operator_id": "...", "created_at": "..." },
  "proof": { "leaf_index": 0, "tree_size": 3,
             "path": [ { "side": "right", "hash": "..." } ] },
  "resolved_at": "2026-11-07T18:30:00.000000Z"
}
```

The verifier prints each step, so you can see where it agrees and where it does not rather than
being handed a verdict. It recomputes the row's hash **from the row's content** — not from the
row's own claim about its hash — folds the proof to a root, finds that root in the anchor history
here, and then checks the timestamp.

## The timestamp is the part that matters

Every anchor payload contains an `anchored_at` field. **It is not evidence, and `verify.py` will
not use it.** It is a reading of our own clock and we could have written anything in it.

The third-party timestamps are these, and you obtain them yourself:

```sh
# GitHub's clock. Anchor commits are created server-side through GitHub's API, so GitHub —
# not Simul8 — sets the committer date on them.
git log --diff-filter=A --format=%cI -- anchors/2026/<file>.anchor.json

# Bitcoin, via OpenTimestamps. Install the client from https://opentimestamps.org
ots verify anchors/2026/<file>.anchor.json.ots
```

A fresh receipt is *calendar-pending* — the calendar has committed to including the digest but no
block carries it yet — so a recent anchor may not have a Bitcoin attestation, while an older one
will. `verify.py` checks precedence against the commit date and tells you to run `ots verify` for
the stronger, slower confirmation.

If no third-party timestamp can be obtained, `verify.py` reports **not verified**. It does not
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
