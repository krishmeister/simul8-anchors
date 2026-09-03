# VERIFY.md — canonical form, hashing, the tree, and the anchor

**Part 1 (sections 1–8) froze at LOG pass.** **Part 2 (sections 9–13) was written at ANCHOR
pass** and appends only the anchor and timestamp layer: it supplies the fifth step section 8
names and leaves every rule above it exactly as it was. Nothing in Part 2 restates a Part 1
rule, because two statements of one rule are two rules the moment one is edited.

**Part 1 has been amended once since the freeze, under BUILD-STATE R-352 and R-353, and this
paragraph records it rather than letting the document claim it never moved.** The currency rule
of section 1 said *"integer count of paise"*; it now says *"integer count of the currency's
minor unit, per its ISO 4217 exponent"*, which is **the same rule stated for every currency**.
INR's exponent is 2, so ₹1499.00 remains `"149900"`: **no published value changes, no existing
vector moves, and an implementation written against the earlier wording still agrees with this
one on every INR amount.** The amendment adds the currency vectors section 1 had never carried
— the reason it was safe to state the rule correctly is the same reason it was urgent to pin it
— and Part 2 gains section 12a. Nothing else in either part is touched.

This document exists because of one clause. The Simul8 Constitution v2.4 §45(e) permits
presenting a prediction as independently verifiable only if an outside party can recompute the
path from that prediction to a published Merkle root. A privately held tree can be rebuilt, so
"we checked it" is not verification. Verification means **someone with none of our code and
none of our infrastructure gets the same bytes we did.**

Everything below is therefore written as a specification, not as a description of an
implementation. Where a choice existed, the choice is stated and the alternative named, so that
a reader who would have chosen differently knows to change their code rather than conclude
their arithmetic is broken.

Every rule here sits inside a hash and **cannot change silently.** Changing one invalidates
every row already written (BUILD-STATE SL-13, R-010, R-025).

The reference implementation is `ledger/canonical.py`, `ledger/hashing.py`, `ledger/merkle.py`
and `ledger/proof.py`. **The vector tables below are parsed out of this file** by
`tests/constitutional/test_verify_document.py` and checked against that code, so the document
and the implementation cannot drift apart — a stale digest in a specification is worse than no
specification.

---

## 1. Canonical JSON

**RFC 8785 (JSON Canonicalization Scheme), UTF-8, no byte-order mark.** In outline:

1. **Object keys are sorted** ascending **by UTF-16 code unit** — not by Unicode code point.
   The two orders agree for every character in the Basic Multilingual Plane and disagree above
   it, because a supplementary character is one code point but two surrogate code units. A sort
   by code point is right almost always, and almost always is not something a published root
   can rest on. Concretely: `U+10000` sorts **before** `U+FFFD`, because its first code unit is
   `U+D800`. Vector C10 is that case.
2. **Array order is preserved.** Order in an array is content, not layout.
3. **No insignificant whitespace** — none after `:`, none after `,`, none anywhere.
4. **Strings** are escaped exactly as ECMAScript `JSON.stringify` escapes them: `"` → `\"`,
   `\` → `\\`, and `U+0008 U+000C U+000A U+000D U+0009` → `\b \f \n \r \t`. Any other
   character below `U+0020` becomes `\u` and **four lowercase hex digits**. Nothing else is
   escaped — not `/`, and no non-ASCII character, which is emitted as UTF-8. A lone surrogate
   has no UTF-8 encoding and is rejected rather than escaped.
5. **`true`, `false`, `null`** are lowercase and unquoted.
6. Object keys must be strings. Anything else is rejected.

### No numbers. At all.

RFC 8785 specifies how to serialize a JSON number. **A Simul8 payload never contains one.**
Every numeric quantity in the Log is a **decimal string**, and a verifier that meets a JSON
number inside a payload should treat the row as malformed rather than canonicalize it.

Binary floating point cannot represent decimal fractions exactly, so two runs of one
computation can produce two byte strings for one value and the root stops being reproducible.
Decimal strings remove the problem at its source instead of mitigating it.

The precision a field is written at is either fixed by the registry entry or supplied by the
caller at write time; where it is unspecified **the write fails**, and it is never defaulted
(SL-13). The fixed precisions:

| Quantity | Written as | Example |
|---|---|---|
| Units, counts, tree sizes | integer; no leading zeros, no `+`, one spelling of zero | `"1842"`, `"0"`, `"-3"` |
| Currency | integer count of the currency's **minor unit**, per its ISO 4217 exponent | ₹1499.00, exponent 2 → `"149900"` |
| Probabilities, quantile levels | fixed **two** decimal places | `"0.07"`, `"1.00"` |
| Anything else | the caller's stated number of places | `"12.500"` at three places |

### Currency, and the ISO 4217 exponent

The currency row above said **paise** until this revision, and it means the same thing for INR
— exponent 2, ₹1499.00 → `"149900"`, byte for byte what it always was. "Paise" is INR-specific
and this document is implemented against by people who will not be holding rupees: JPY has no
minor unit at all and KWD divides into thousandths. The rule is stated for every currency and
no existing value moves.

Two inputs decide the conversion, and **both are supplied by the caller**:

- the **exponent** — the ISO 4217 exponent of the currency, i.e. how many decimal places its
  minor unit divides its major unit into. 2 for INR and USD, 0 for JPY, 3 for KWD;
- the **unit** the amount is already written in: `major_unit` or `minor_unit`, and nothing else.

The rule in full:

1. If the unit is `major_unit`, shift the decimal point **right by the exponent**. If it is
   `minor_unit` the amount is already an integer count of the minor unit and shifts by
   **nothing** — so at exponent 0 the two are the same operation, which is why JPY reads the
   same either way.
2. If any non-zero digit would fall past the units place, the write **fails**. Sub-minor-unit
   money is not a rounding question this specification answers, and rounding it silently would
   hide a precision decision inside a hash.
3. Render the result by the integer rule above: no leading zeros, no `+`, one spelling of zero.
   A negative amount keeps its sign.

**Both units occur in real feeds, and confusing them is a factor-of-100 error.** A storefront
may report `885.95` and a payment provider `50000`, both of them INR, meaning ₹885.95 and ₹500.
The currency code does not tell those apart, because the difference is a **unit** and not a
currency. That is why the unit is an input here rather than an assumption, and why the row that
carries a monetary quantile vector records the unit its amounts arrived in.

**The conversion consults no currency table, and yours should not either.** The reference
implementation is never given the currency code — only the exponent — so there is nothing for
it to look up. A canonicaliser that resolved a code to an exponent would have output depending
on that table's contents at hash time, and reproducing our root would then require our table at
our version. The point of this document is that you need nothing of ours. Where the exponent
comes from is an input-assembly question, answered before hashing: **the prediction row records
the exponent that was used**, so nothing re-derives it and a later revision of ISO 4217 cannot
retroactively re-interpret a row that has already been anchored.

### Vectors — currency

The `currency` column is **illustrative**: it is printed so you can check the exponent against
ISO 4217 yourself, and it is not an input to the conversion. `refused` means a conforming
implementation must **reject** the amount rather than produce a value — a refusal is part of
the specification, not an implementation detail.

<!-- vectors:currency -->
| # | currency | exponent | unit | amount | canonical |
|---|---|---|---|---|---|
| K1 | `INR` | `2` | `major_unit` | `1499.00` | `"149900"` |
| K2 | `INR` | `2` | `major_unit` | `885.95` | `"88595"` |
| K3 | `INR` | `2` | `minor_unit` | `50000` | `"50000"` |
| K4 | `INR` | `2` | `major_unit` | `0.00` | `"0"` |
| K5 | `JPY` | `0` | `major_unit` | `1500` | `"1500"` |
| K6 | `JPY` | `0` | `minor_unit` | `1500` | `"1500"` |
| K7 | `KWD` | `3` | `major_unit` | `1.234` | `"1234"` |
| K8 | `KWD` | `3` | `minor_unit` | `1234` | `"1234"` |
| K9 | `USD` | `2` | `major_unit` | `-3.50` | `"-350"` |
| K10 | `INR` | `2` | `major_unit` | `1499.005` | `refused` |
| K11 | `JPY` | `0` | `major_unit` | `0.5` | `refused` |
| K12 | `INR` | `2` | `minor_unit` | `50000.5` | `refused` |
| K13 | `KWD` | `3` | `major_unit` | `1.2345` | `refused` |
<!-- /vectors:currency -->

K2 and K3 are the pair worth reading twice: two INR amounts, one shift apart, and a hundred
times different in what they mean. K5 and K7 are the two an INR-only implementation gets wrong
in opposite directions — it multiplies the yen figure by a hundred, and it rejects the dinar
figure as too precise when the precision is exactly right.

### Vectors — canonical JSON

<!-- vectors:canonical -->
| # | input (JSON) | canonical output |
|---|---|---|
| C1 | `{"b":"2","a":"1"}` | `{"a":"1","b":"2"}` |
| C2 | `{"a":{"d":"4","c":"3"}}` | `{"a":{"c":"3","d":"4"}}` |
| C3 | `{"x":["b","a"]}` | `{"x":["b","a"]}` |
| C4 | `{"t":true,"f":false,"n":null}` | `{"f":false,"n":null,"t":true}` |
| C5 | `{"s":"a\"b\\c"}` | `{"s":"a\"b\\c"}` |
| C6 | `{"s":"tab\there"}` | `{"s":"tab\there"}` |
| C7 | `{"s":"\u0001\u001f"}` | `{"s":"\u0001\u001f"}` |
| C8 | `{"s":""}` | `{"s":""}` |
| C9 | `{"s":"na\u00efve \u20b9"}` | `{"s":"naïve ₹"}` |
| C10 | `{"\ud800\udc00":"supplementary","\ufffd":"replacement"}` | `{"𐀀":"supplementary","�":"replacement"}` |
<!-- /vectors:canonical -->

---

## 2. Timestamps

**RFC 3339, UTC, `Z` suffix, and fractional seconds always exactly six digits, zero-padded,
never truncated:**

```
2026-07-24T10:00:00.000000Z
```

Twenty-seven characters, always. The six digits are not cosmetic: unspecified trailing-zero
handling is the byte-level ambiguity most likely to make a foreign verifier fail to reproduce
our root, and §45(e)'s claim rests on byte-for-byte agreement (R-010). `Z`, never `+00:00`.

On input, zero to six fractional digits are zero-padded to six. More than six is accepted
**only if every extra digit is a zero** — dropping a zero is lossless, dropping anything else
is not, so a genuinely sub-microsecond value is rejected rather than rounded. An offset other
than `Z` is converted to UTC. A lowercase `t` or `z`, a space separator, and a missing offset
are all rejected: each admits two spellings of one instant, or names no instant at all.

**`created_at` is the database's clock and nothing else.** It is set by a trigger from `now()`
and never by a client. Local clocks are not trusted, and external time claims rest on the
published anchor (§45(e)), not on this column — a verifier should not read `created_at` as
evidence of when a row was written. The anchor carries that.

### Vectors — timestamps

<!-- vectors:timestamp -->
| # | input | canonical form |
|---|---|---|
| T1 | `2026-07-24T10:00:00Z` | `2026-07-24T10:00:00.000000Z` |
| T2 | `2026-07-24T10:00:00.5Z` | `2026-07-24T10:00:00.500000Z` |
| T3 | `2026-07-24T10:00:00.123Z` | `2026-07-24T10:00:00.123000Z` |
| T4 | `2026-07-24T10:00:00.123456Z` | `2026-07-24T10:00:00.123456Z` |
| T5 | `2026-07-24T10:00:00.123456000Z` | `2026-07-24T10:00:00.123456Z` |
| T6 | `2026-07-24T15:30:00+05:30` | `2026-07-24T10:00:00.000000Z` |
<!-- /vectors:timestamp -->

---

## 3. UUIDs

A UUID canonicalizes as its **lowercase, hyphenated 8-4-4-4-12 string** (BUILD-STATE R-025).
Uppercase, braced, URN and unhyphenated spellings all normalise to that one form before
hashing.

**A UUID rendered two ways breaks byte-for-byte root reproduction exactly as a float would.**
It is the same class of defect and it is pinned here for the same reason.

Where UUIDs appear in a payload: `freshness.sync_run_id` on every warehouse-sourced evidence
item, and `prediction_id`. `sync_run_id` is a **version 4** UUID specifically, so that the
Log's permanent content never depends on warehouse sequence state that a restore from backup
could renumber. A seeds/-sourced evidence item carries `sync_run_id: null` — there is no sync
run behind a seed entry, and minting an identifier for one would be an invented value.

### Vectors — UUIDs

<!-- vectors:uuid -->
| # | spelling | canonical form |
|---|---|---|
| U1 | `f81d4fae-7dec-41d0-9b2a-0242ac130004` | `f81d4fae-7dec-41d0-9b2a-0242ac130004` |
| U2 | `F81D4FAE-7DEC-41D0-9B2A-0242AC130004` | `f81d4fae-7dec-41d0-9b2a-0242ac130004` |
| U3 | `{f81d4fae-7dec-41d0-9b2a-0242ac130004}` | `f81d4fae-7dec-41d0-9b2a-0242ac130004` |
| U4 | `urn:uuid:F81D4FAE-7DEC-41D0-9B2A-0242AC130004` | `f81d4fae-7dec-41d0-9b2a-0242ac130004` |
| U5 | `f81d4fae7dec41d09b2a0242ac130004` | `f81d4fae-7dec-41d0-9b2a-0242ac130004` |
<!-- /vectors:uuid -->

---

## 4. The genesis constant

The `prev_hash` of the first row in the chain is **64 `0` characters**:

```
0000000000000000000000000000000000000000000000000000000000000000
```

Exactly one row can ever carry it: the column is `UNIQUE`, which is what makes a second
genesis row — and therefore a forked chain — structurally impossible rather than merely
unlikely (BUILD-STATE SL-14).

---

## 5. The row hash

```
row_hash = SHA-256(
    canonical(payload) ‖ prev_hash ‖ row_type ‖ operator_id ‖ canonical(created_at)
)
```

rendered as **64 lowercase hex characters**. `‖` is plain concatenation of the UTF-8
encodings, **with no separator, no length prefix and no delimiter of any kind.**

- `canonical(payload)` — section 1, applied to the row's `payload`.
- `prev_hash` — the previous row's `row_hash` as 64 lowercase hex characters, or the genesis
  constant for the first row.
- `row_type` — one of `prediction`, `resolution`, `amendment`, `void`, `declined`.
- `operator_id` — verbatim.
- `canonical(created_at)` — section 2. Twenty-seven characters, last.

**Why plain concatenation is unambiguous.** A verifier receives the five parts separately and
concatenates them, so it never parses the preimage. But the parse being unique is what makes
the hash a commitment to those five parts rather than to some other split of the same bytes,
so it is worth stating that it is unique: `canonical(payload)` is a JSON object, opening with
`{` and closing with its matching `}`, so its extent is fixed by its own content. `prev_hash`
is exactly 64 characters. `row_type` is drawn from a five-value set in which **no value is a
prefix of another**, so the boundary between it and `operator_id` is fixed however the operator
id begins. `canonical(created_at)` is exactly 27 characters and comes last.

### Vectors — row hash

<!-- vectors:row-hash -->
| # | payload | prev_hash | row_type | operator_id | created_at | row_hash |
|---|---|---|---|---|---|---|
| H1 | `{}` | `0000000000000000000000000000000000000000000000000000000000000000` | `declined` | `op-1` | `2026-07-24T10:00:00.000000Z` | `b3b9827b56731515f135a9f3f142cdecebff0bc6b8fe9ab54e4dc56a6ed0cb0d` |
| H2 | `{"a":"1"}` | `0000000000000000000000000000000000000000000000000000000000000000` | `prediction` | `op-1` | `2026-07-24T10:00:00.000000Z` | `3df194c0b92bf8f2e7efa2e7cd2f8266ad217cbe86c0aacebdd5a3a850f08521` |
| H3 | `{"a":"1"}` | `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | `resolution` | `op-2` | `2026-11-07T18:30:00.000000Z` | `78e066d1d45248e9ee53c732dbd51f7df8c873a8fc2be822fd6dc329e189eb33` |
| H4 | `{"z":"1","a":"2"}` | `0000000000000000000000000000000000000000000000000000000000000000` | `void` | `op-1` | `2026-07-24T10:00:00.000001Z` | `02d8fd8b7e3222a0fcd9b73a0344bd9d0c455a770c58a1f56bad757e29293337` |
<!-- /vectors:row-hash -->

---

## 6. Leaf and node hashing, domain separated

```
leaf_hash(row_hash)     = SHA-256( "leaf:" ‖ row_hash )
node_hash(left, right)  = SHA-256( "node:" ‖ left ‖ right )
```

All inputs are ASCII. `leaf:` and `node:` are the literal five-byte prefixes. `row_hash`,
`left` and `right` are each **the 64 lowercase hex characters as text — not the 32 bytes they
encode.** The row carries the hex form, so a verifier reproduces the leaf from what it can read
without a hex-decoding step it could get wrong. Output is again 64 lowercase hex characters.

The prefixes make the leaf and interior hash spaces disjoint. Without them a value could serve
as both a leaf and an interior node, and a tree of a different shape could be presented as
having the same root.

### Vectors — leaf and node

<!-- vectors:node -->
| # | expression | result |
|---|---|---|
| N0 | `sha256("row-0")` | `3c831eb5a23962a50dbffc0d4f37facd0f1171844d08d1a5cc93a04426f02393` |
| N1 | `leaf_hash(N0)` | `76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614` |
| N2 | `node_hash(N0, N0)` | `7d425e60db2e23e2a37cca55c3ebfe6c2ff2eda919f873ff5595a29a378629f6` |
<!-- /vectors:node -->

---

## 7. The tree

**Leaves are `row_hash` in `row_id` order.** `row_id` is a ULID — 26 characters of Crockford
base32, lexically time-ordered — and the writer mints each one strictly after the tip, so this
order is also the order the `prev_hash` chain runs in. Sorting is a plain byte-wise ascending
sort of those 26-character strings.

At anchor time **the whole tree is rebuilt from all rows.** That is a deliberate choice of
auditability over incrementality: at slice volumes it takes milliseconds and a
rebuild-from-scratch tree is trivially checkable. A Merkle Mountain Range is deferred until
volume demands it, and the published root format is identical either way, so that change would
be invisible to anyone reading this.

### The odd-node rule: duplicate-last

At any level with an **odd** number of nodes, the last node is paired **with itself** and
hashed as `node_hash(last, last)`. The level is then consumed in order, two at a time.

An unspecified odd-node rule is the single most common reason two correct implementations of
"a Merkle tree" produce two different roots. It is fixed here.

### Two special cases, both pinned

- **A tree over one row roots at that row's leaf hash.** No interior node is computed and no
  `node:` hashing happens at all. The alternative — hashing the lone leaf against itself — is
  equally reasonable and gives a different root, which is exactly why this says which one.
- **A tree over zero rows has no root.** There is nothing to publish, and publishing something
  would assert a Log that does not exist.

### Worked example, three rows

```
leaves:   L0 = leaf_hash(h0)    L1 = leaf_hash(h1)    L2 = leaf_hash(h2)
level 1:  N0 = node_hash(L0, L1)                      N1 = node_hash(L2, L2)   <- duplicate-last
root:          node_hash(N0, N1)
```

### Vectors — roots

The row hashes are `sha256("row-0")`, `sha256("row-1")`, … in that order, so an outside
implementation can reproduce these from nothing but this document.

<!-- vectors:tree -->
| # | rows | root |
|---|---|---|
| M1 | 1 | `76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614` |
| M2 | 2 | `6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a` |
| M3 | 3 | `74de35ec66294d2f81bacd715877820603c82ad9d5f6acf8635016934e13f508` |
| M4 | 4 | `7280ad1d11858a5886a3b2d5a8b6b3f8bebd888b4cf191b8d04efa92498ec4cd` |
| M5 | 5 | `5884da45c3524f1175e7feb32018ecf66977a31343d393694a848b5d570318e4` |
| M6 | 6 | `980cd30ae459b5dde5c277ea7e2d0c173cbb14b00837a1c40daadc2e0233673e` |
| M7 | 7 | `a9915a964f899075ebdb901592880158a2f43ef0544e84c89121a3330aa295b7` |
| M8 | 8 | `9cebd0d38162339c6e36b48e486ef1980bc7d962e2e4a20abb43de46a6695a80` |
| M9 | 9 | `5f86acf63de9738760ed045e6a5ae5010a2f79266ab9852ac39244b533cd52ef` |
<!-- /vectors:tree -->

---

## 8. Inclusion proofs, and folding

An inclusion proof for one row is:

- `leaf_index` — the row's zero-based position in `row_id` order.
- `tree_size` — the number of **rows** the tree covers. Duplicated nodes are not rows and are
  not counted.
- `path` — the sibling hashes from the leaf level upward, each tagged with the side **the
  sibling sits on**.

Verification:

1. Canonicalize the row's payload (section 1).
2. Compute `row_hash` (section 5) **from the row's content** — not from the row's own claim
   about its hash.
3. Compute `leaf_hash(row_hash)` (section 6).
4. Fold the path. Starting with the leaf hash as the accumulator, for each step in order:
   - sibling on the **left** → `accumulator = node_hash(sibling, accumulator)`
   - sibling on the **right** → `accumulator = node_hash(accumulator, sibling)`
5. The result must equal the published root.

For a leaf that is the duplicated last node of an odd level, **its sibling is itself**, and
that hash appears in the path like any other.

Step 2 is what makes this a proof about the row rather than about a hash someone handed over. A
verifier that folds the value it read out of the `row_hash` column has proved only that the
column is in the tree.

**A fifth step exists and is not specified here:** confirming the root appears in an anchor
publication whose third-party timestamp precedes the row's resolution. That needs the published
anchors and the publication medium.

---

# Part 2 — the anchor, the medium, and the timestamp

Part 1 ends one step short on purpose. It can take a row and an inclusion proof and produce a
root, and it says so: *"A fifth step exists and is not specified here: confirming the root
appears in an anchor publication whose third-party timestamp precedes the row's resolution.
That needs the published anchors and the publication medium."* This part supplies the published
anchors, the medium, and that fifth step.

The distinction it turns on is the whole reason any of this exists. Recomputing a root over our
own rows proves that our arithmetic is self-consistent and nothing else — **we can rebuild a
private tree any time we like, to say anything we like.** What makes a prediction independently
verifiable is that somebody who is not us recorded the root before the outcome was known.
Everything below is about where that record lives and how you check it yourself.

---

## 9. The published payload

One anchor publication is one **canonical JSON line** carrying five fields, plus its SHA-256:

```
{root_hash, tree_size, latest_row_id, ledger_schema_version, anchored_at}
```

| Field | Meaning |
|---|---|
| `root_hash` | the root over every row in the Log at publication time, per section 7 |
| `tree_size` | how many **rows** the tree covers; duplicated nodes are not rows |
| `latest_row_id` | the `row_id` at the tip when the tree was built |
| `ledger_schema_version` | the applied Alembic revision, e.g. `lg_0002`, so a reader of an old publication knows which schema produced it |
| `anchored_at` | when **we** built the tree — see the warning below |

The line is serialized by section 1 and the timestamp by section 2, so the keys come out sorted
ascending by UTF-16 code unit and `anchored_at` carries its six fractional digits. `tree_size`
is a **decimal string**, as section 1 requires of every numeric quantity and names tree sizes
among its examples; a publication containing a JSON number is malformed.

> **`anchored_at` is not evidence, and no verification step may use it.** It is a reading of
> our own clock, and we could have written anything in it. Section 2 already states the
> principle for the ledger's other self-reported timestamp — *"a verifier should not read
> `created_at` as evidence of when a row was written. The anchor carries that"* — and the same
> applies to the anchor's own field. What the anchor carries is the **third-party** timestamp of
> section 12, which is not in the payload at all, because a payload cannot vouch for itself.

`anchor_id` **is** the SHA-256 of the line. It is not a separate minted identifier, so an
auditor holding a resolution row's `anchor_coverage.anchor_id` can recompute it from the
published bytes and confirm the two name the same publication.

Each publication is one file. The trailing newline in the file is an ordinary text-file
convention and is **not** part of the hashed bytes — section 1 emits no insignificant
whitespace — so strip it before hashing and the digest is unchanged.

### Vectors — anchor payload

Row hashes are `sha256("row-0")`, `sha256("row-1")`, … so the roots are section 7's, and an
outside implementation can reproduce these lines and digests from this document alone.

<!-- vectors:anchor -->
| # | rows | latest_row_id | anchored_at | canonical line | SHA-256 |
|---|---|---|---|---|---|
| A1 | 1 | `01JZZZZZZZZZZZZZZZZZZZZZZZ` | `2026-07-25T00:00:00.000000Z` | `{"anchored_at":"2026-07-25T00:00:00.000000Z","latest_row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","ledger_schema_version":"lg_0002","root_hash":"76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614","tree_size":"1"}` | `c884fdcd9441c8b7bd06adab649cb9cb6fee6ddd0527f45f52d4988c00978502` |
| A2 | 3 | `01K0X9NR5N7QK8V4CZ6H2WBTMD` | `2026-07-26T00:00:00.000000Z` | `{"anchored_at":"2026-07-26T00:00:00.000000Z","latest_row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","ledger_schema_version":"lg_0002","root_hash":"74de35ec66294d2f81bacd715877820603c82ad9d5f6acf8635016934e13f508","tree_size":"3"}` | `33221e828f3c124ec9a494763973d768c39d6a791d3a7e2c2486ce65c4e55079` |
| A3 | 9 | `01K1ABCDEFGHJKMNPQRSTVWXYZ` | `2026-08-01T12:34:56.789000Z` | `{"anchored_at":"2026-08-01T12:34:56.789000Z","latest_row_id":"01K1ABCDEFGHJKMNPQRSTVWXYZ","ledger_schema_version":"lg_0002","root_hash":"5f86acf63de9738760ed045e6a5ae5010a2f79266ab9852ac39244b533cd52ef","tree_size":"9"}` | `aef5859264b01090ed239a6d57289c8762172ab223e49af5693c1f046e98dfa2` |
<!-- /vectors:anchor -->

### 9a. The empty marker — what a quiet day publishes

A day on which the Log held no rows still publishes a file. It is **not an anchor**: it commits
to no tree, carries no root, and no proof can ever fold to it. It carries four fields, and the
first of them says what it is:

```
{status, tree_size, ledger_schema_version, anchored_at}
```

| Field | Meaning |
|---|---|
| `status` | always the string `empty`. Its presence is what identifies the artifact |
| `tree_size` | always `"0"` — the Log held no rows at `anchored_at` |
| `ledger_schema_version` | as in section 9 |
| `anchored_at` | when we looked. Still our own clock, still not evidence |

**There is no `root_hash` and no `latest_row_id`, and their absence is the point.** A root over
zero rows would assert a Log that does not exist, which section 7 already forbids; a marker
makes the opposite claim — *there was nothing to anchor* — and that claim is true. The two are
different statements, and only one of them can be made honestly on a quiet day.

**Tell the two apart by reading `status`, never by noticing a field is missing.** An anchor
carries no `status` field at all, and both shapes are listed exhaustively above: an artifact
matching neither is malformed and must be rejected rather than guessed at.

**Why publish anything at all on a quiet day.** So that the public record receives an entry
every day, which makes a *gap* in the record unambiguous evidence that something failed rather
than something a reader has to interpret. It also makes the Log's **start date publicly
provable**: signed, third-party-timestamped markers running up to the first real anchor show
exactly when we began carrying rows, which is worth more than the appearance of activity. We
would rather publish "nothing happened today" than let silence be read either way.

### Vectors — empty marker

<!-- vectors:empty-marker -->
| # | anchored_at | canonical line | SHA-256 |
|---|---|---|---|
| E1 | `2026-07-27T03:00:00.000000Z` | `{"anchored_at":"2026-07-27T03:00:00.000000Z","ledger_schema_version":"lg_0002","status":"empty","tree_size":"0"}` | `a7e7012665eda4b9ca8e146ca04f9b9bdf9a7ab42ba2e34c84980f233eedeabd` |
| E2 | `2026-07-28T03:00:01.234567Z` | `{"anchored_at":"2026-07-28T03:00:01.234567Z","ledger_schema_version":"lg_0002","status":"empty","tree_size":"0"}` | `681ae9ecec38e7f5beae8994515168a681164fd9fdde1b269f443aa953ed88ec` |
| E3 | `2026-08-01T12:34:56.789000Z` | `{"anchored_at":"2026-08-01T12:34:56.789000Z","ledger_schema_version":"lg_0001","status":"empty","tree_size":"0"}` | `1343cd7a7c8d1e7c265cbfc67d42a5c72906f37854c2aa32e7f2c89a65b63b8a` |
<!-- /vectors:empty-marker -->

---

## 10. The medium, and the cadence

Two media, written by **one job**, running on a **daily floor and after each batch of new
forecasts**. Both halves are a recorded decision (BUILD-STATE D-04, delegated and minuted as
R-041), reversible by founder order.

| Medium | What it is for | What it cannot do alone |
|---|---|---|
| **`github.com/krishmeister/simul8-anchors`**, public | a human-readable, append-only public history, and an immediately available third-party timestamp | prove anything cryptographically — GitHub could in principle rewrite its own record |
| **OpenTimestamps** | a Bitcoin-anchored cryptographic timestamp of the payload digest | be available immediately — a fresh receipt is calendar-pending until a block carries it |

They fail differently, which is why they are paired rather than duplicated.

**The commit is created by GitHub, not by us, and this matters.** A commit made locally and
pushed carries a committer date taken from *our* clock — git stores it in the commit object and
GitHub preserves it verbatim. Reading that date back and calling it third-party would be
laundering our own assertion through a public place. So the anchor commit is created
**server-side through GitHub's API**, with no author or committer supplied, which leaves GitHub
to fill both from its own clock. The date you read out of the commit is therefore GitHub's
statement, not ours.

**The receipt is `<payload file>.ots`, beside its payload.** It stamps the SHA-256 of the
payload line, with no privacy nonce — the digest is of a line being published openly in the
same commit, so there is nothing to withhold, and it means the digest in the receipt is the same
value as `anchor_id`. A pending receipt is not presented as a confirmed one.

The cadence is not cosmetic, and it has two parts. Anchors publish on a **floor cadence** — today,
once a day — **and again after each batch of new forecasts is written**. A date may therefore carry
several publications, and a date on which nothing was forecast carries the floor's one.

The floor exists because anchor cadence must be strictly shorter than the shortest registry `k`
(SPEC-D2C §3.11(c)): it is what admits question types resolving in about two days, and it is what
publishes the record on a day when nothing was forecast at all. The batch trigger exists because a
forecast written an hour before its event cannot wait for tomorrow's floor run.

**What is a fault here, and what is not.** Several publications on one date is normal operation. Do
not read it as a defect, and do not read it as evidence that anything was rewritten — a published
root is never revised, and an additional publication is an additional file, never an amendment to an
existing one. **No publication on a date is still a fault**, and it is the fault the scheduled check
in `.github/workflows/` exists to report.

More anchors can only mean more coverage, never less. Each publication commits to every row written
before it, so an extra publication during a day can only move rows from *not yet covered* to
*covered*. It cannot uncover a row, it cannot narrow what an earlier root proves, and it cannot
remove your ability to check anything you could have checked before it.

**None of this changes how you check a forecast.** The procedure in sections 1 to 12 is unchanged:
canonicalize the row, compute its leaf hash, fold the sibling path to a root, and confirm that root
appears in a publication whose third-party timestamp is strictly earlier than the row's resolution.
More publications mean more roots that might carry your row. They do not change what a root is, how
it is built, or what folding one proves.

---

## 11. How a publication is made

1. Rebuild the whole tree from every row, per section 7. A Log with no rows produces **no
   anchor** — section 7 again: there would be no root to publish and publishing one would
   assert a Log that does not exist. It produces the empty marker of section 9a instead, which
   travels the remaining steps unchanged: same digest rule, same receipt, same one commit, same
   filename convention. **Each publication produces exactly one artifact**, and which of the two
   it is depends only on whether the Log held rows at the moment that tree was built. A date
   carries one artifact for each publication made on it — at least the floor's one, and one more
   for each batch of forecasts written that day (section 10). Several on a date is normal; none
   on a date is a fault.
2. Build the payload of section 9, or the marker of section 9a, and take its SHA-256.
3. Submit that digest to an OpenTimestamps calendar and keep the receipt.
4. Commit the payload line **and** the receipt to the public repository in **one** commit, so
   the medium's timestamp covers both halves at one instant.
5. Record the publication, including GitHub's commit date as the third-party timestamp.

Steps 4 and 5 are in that order deliberately, and the order decides what a crash between them
leaves behind. Publishing first can leave an anchor that is public but unrecorded: coverage
lookups then return *not covered*, resolutions defer, and nothing is ever graded against a
publication that does not exist. Recording first could leave the database claiming a publication
nobody can find — a resolution graded as covered by an anchor no outside party can reach, which
is the exact false claim this document exists to make impossible. **The failure mode is always
that we under-claim coverage, never that we over-claim it.**

---

## 12. Verifying a prediction — the fifth step

Sections 1 to 8 get you from a row to a root. Two steps remain:

5. **Find the folded root in the published history.** Read the payload files from the public
   repository. Parse each line, re-serialize it by section 1, and require the bytes to match: a
   line that has been reformatted or had a number substituted still parses as JSON but is no
   longer the artifact whose digest was stamped. **Set aside every empty marker first** — an
   artifact whose `status` is `empty` (section 9a) records a day with no rows and commits to no
   tree, so it can never carry the root you folded and must not be treated as an anchor that
   failed to match. Then, among the anchors that remain, look for one whose `root_hash` equals
   the root you folded, and check its `tree_size` equals the `tree_size` in your proof —
   otherwise the proof and the anchor are about different trees.

   A history that contains **only** empty markers is not a broken history. It says no rows had
   been anchored by the last published date, which is a fact about the Log rather than a fault
   in the record, and a verifier should say so in those words rather than reporting a generic
   failure to find the root.
6. **Check a third-party timestamp precedes the resolution.** Obtain the timestamp from outside
   the payload, by either route:

   ```
   # GitHub's own clock, from a clone of the public anchors repository
   git log --diff-filter=A --format=%cI -- anchors/2026/<file>.anchor.json

   # the Bitcoin attestation, once the receipt is confirmed
   ots verify anchors/2026/<file>.anchor.json.ots
   ```

   The prediction is independently verifiable only if that timestamp is **strictly earlier**
   than the row's resolution. If you cannot obtain a third-party timestamp, the correct outcome
   is **not verified** — not "verified, assuming ours". There is no fallback to `anchored_at`.

### The reference verifier

`verify.py` ships in the public anchors repository and implements all six steps. **Stdlib only —
no `pip install`, no network, no account.** Being able to run it without trusting us is part of
the claim.

```
python3 verify.py --self-test
python3 verify.py --history --anchors anchors/
python3 verify.py --claim claim.json --anchors anchors/
```

`--self-test` checks the verifier against every vector table in this document and needs no
Simul8 data at all: run it first, and you know the arithmetic agrees before you point it at a
row. A `claim.json` is `{"row": {...}, "proof": {...}, "resolved_at": "..."}`, where `row`
carries the five hashed parts of section 5 and `proof` carries `leaf_index`, `tree_size` and
`path` as section 8 defines them.

`--history` lists the published record and says of each date whether rows were anchored,
reporting an empty marker as **"no rows anchored on this date"**. That is neither a success nor
a failure — it is the third thing the record can say, alongside an anchor that verifies and one
that does not, and it is how you read when the Log started carrying rows.

What it proves offline: the row hashes to what the tree committed to, the proof folds to a
published root, and the receipt beside that payload stamps that payload's digest and not some
other. What it does not prove offline: that Bitcoin carries the attestation — run `ots verify`
for that. It will tell you which of these it established rather than collapsing them into one
word.

### 12a. What an anchor attests, and what it does not

You have just folded a root and found it in the published history. This section says exactly
what you have established, because reading more into an anchor than it carries is the failure
this document exists to prevent.

**What an anchor attests.** That the root existed at a time **a named third party recorded** —
GitHub's own commit date, or a Bitcoin attestation through OpenTimestamps — and therefore that
every row the tree covers was written before that time and has not changed since. That is the
Log's **integrity**, and it is the whole of what §45(e) claims.

**What an anchor does not attest: that the Log contains the rows it should.** An anchor is
produced by the anchor job, so **a run of anchors attests the anchor job's liveness, not the
ledger writer's.** A silently broken writer publishes exactly the same sequence of anchors as a
genuinely quiet day. Nothing in the published record distinguishes those two, and no amount of
anchoring will.

**The distinguishing data is already in the payload, and you can use it.** `tree_size` is one
of section 9's five fields. **Consecutive anchors whose `tree_size` has not changed mean no rows
were added between them — which is indistinguishable from a writer that has stopped.** Read a
run of unchanged sizes as *"nothing was anchored in this period"*, never as *"nothing
happened"*. The first is what the record says; the second is a claim it cannot make.

Whether we made the predictions we should have is the Log's **productivity**, and that is a
different question from its integrity. It is answered on the honesty surface, against a stated
firing cadence, and not here. An anchor is not the instrument for it and is not presented as
one.

**The set of parties whose recording counts is explicit, not implied.** Section 10 names the two
media and section 12 names the two routes to a timestamp. There is no third: an artifact
carrying a timestamp from anywhere else — including ours — is **not attested**, and
`anchored_at` is not a fallback. That set is now enumerated in our own code as a closed list,
so the internal decision about whether a publication is attested asks the same question section
12 has always asked of you. Those two answers used to be able to differ. **Where they did, the
verifier was right**, and the internal side is what changed.

---

## 13. When verification fails

A failed verification is a statement about a **claim**, not about the row. A prediction whose
covering anchor published too late is still a prediction that was made and is still graded and
published; what it may not do is claim it was independently verifiable in advance.

Internally the consequence is fixed and narrow: a resolution for an uncovered prediction is
**deferred and alerted, never voided** (SLICE-01-SPEC §3.11(b), Constitution §45(d)). Voiding is
for source-side failure — an unreachable source, a revoked feed, a disconnected operator — and a
missing anchor is *our* failure. Recording it as a void would move our own operational lapse
into a category that reads as the world's fault, and would remove it from the published
resolution rate. So it stays in, visible, as a deferral.

---

*Governed by the Simul8 Constitution v2.4 §22 and §45(e). Built to SPEC-D2C §3.2, §3.10
and §3.11(d). Constants pinned by BUILD-STATE SL-13, R-010 and R-025; the medium and cadence by
D-04 / R-041; the currency rule of section 1 and its vectors by R-127, R-131, R-132, R-133 and
R-204, ratified as R-352 and R-353, which is also the authority for section 12a's wording
(R-173). Part 1 frozen at LOG pass, Part 2 at ANCHOR pass: a change to anything in this
document is a written proposal to HQ, never a commit — this one was, and the ruling is named
above.*
