# VERIFY.md — canonical form, hashing, the tree, and the anchor

**Part 1 (sections 1–8) froze at LOG pass.** **Part 2 (sections 9–13) was written at ANCHOR
pass** and appends only the anchor and timestamp layer: it supplies the two steps section 8
names without specifying, and leaves every rule above it exactly as it was. Nothing in Part 2 restates a Part 1
rule, because two statements of one rule are two rules the moment one is edited.

**Part 1 has been amended twice since the freeze, and the next two paragraphs record it rather
than letting the document claim it never moved.** The first amendment was made under BUILD-STATE
R-352 and R-353. The currency rule
of section 1 said *"integer count of paise"*; it now says *"integer count of the currency's
minor unit, per its ISO 4217 exponent"*, which is **the same rule stated for every currency**.
INR's exponent is 2, so ₹1499.00 remains `"149900"`: **no published value changes, no existing
vector moves, and an implementation written against the earlier wording still agrees with this
one on every INR amount.** The amendment adds the currency vectors section 1 had never carried
— the reason it was safe to state the rule correctly is the same reason it was urgent to pin it
— and Part 2 gains section 12a. Nothing else in either part was touched by it.

**The second amendment changed hashed bytes, and it was made before any row had been anchored**,
under STATE-SPORTS R-S976 and R-S982. Three rules moved together. The row hash of section 5 is the hash of **one
object with six named members**, `row_id` among them, where it was five parts joined with nothing
between them. The tree of section 7 **carries the last node of an odd level up unchanged**, where
it paired that node with itself. And a proof (section 8) is **held to its index, its size and the
size the anchor stamps**, where it was only folded. Every row-hash vector moved; so did every root
over a number of rows that is not a power of two, and the two anchor vectors built on such roots.
Section 2 now says exactly which spellings of a timestamp are accepted and refuses every other,
a character outside ASCII and an offset of 24 hours among them. An implementation
written against the earlier text still agrees with this one on the canonical forms of sections 1
to 4, on the leaf and node hashes of section 6, and on every root over a number of rows that is a
power of two. It disagrees on every row hash, and on every root and every proof over any other
number of rows. Part 2 gains the checks listed under step 5 of section 12, which the new row hash
makes possible, and section 12 now says what a claim file must and must not hold.

With the same amendment, Part 2 changed what the reference verifier believes before it prints
a verdict. **Two times are compared, and the last line is the plain word only where both came
from the person running the program** (section 12, step 6): there are three verdicts where
there were two. The date on a repository's commit is no longer offered as a route equal to a
time you obtain yourself. A published file is read as bytes and must be its one line and not
one byte more, where white space around the line was once ignored (section 9). Each field of
an anchor line has a shape, and a file is held to the name its content gives it (section 9). A
file that is not a well-formed publication is named and passed over when one claim is checked,
and fails a reading of the whole history, which is also held to what a Log can do (section
12). Sections 2 and 3 now say whom they bind: whoever writes a row, and not a verifier reading
a string inside a payload. And the reference verifier speaks of the files it read, and of the
published record only on the condition that those files are an unchanged copy of it. The
receipt beside a payload is now read to its last byte by a strict reader, which refuses in words
what the format does not allow and what passes this program's own limits (section 12); every
file the program reads is bounded; and a claim file has this program's own limit, 16,000,000
bytes. And before any line was published, every
line, anchor and empty marker alike, gained a sixth field, `previous_line_sha256`, naming the
line published before it (D-S43): the anchor and empty-marker vectors moved, the longest line
the format allows grew to 347 bytes, and `--history` holds the lines it reads to one chain
(sections 9 and 12).

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

**The format carries no label, and this paragraph is all that stands in for one.** A row hashed
from the six members of section 5, and an anchor line with the six fields of section 9, follow
this document. If the format ever changes, the change will be a member that names the new format,
**added inside the hashed bytes**. Rows and lines without that member are this format for ever.
`ledger_schema_version` is the database's revision and never the format's name.

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
   escaped — not `/`, not `&`, `<` or `>`, not `U+007F`, and no non-ASCII character, `U+2028` and
   `U+2029` included, which is emitted as UTF-8 (vectors C11 and C12). A lone surrogate has no
   UTF-8 encoding and is rejected rather than escaped, wherever it stands, an object key
   included. **No string is normalised**: a letter written composed and the same letter written
   decomposed are two strings with two canonical forms (vectors C13 and C14).
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
| C11 | `{"s":"&<>/"}` | `{"s":"&<>/"}` |
<!-- /vectors:canonical -->

Three more, whose canonical output holds characters that cannot be shown safely as text
(`U+007F`, `U+2028`, `U+2029`, and a combining mark). The output is given as its UTF-8 bytes in
hex:

<!-- vectors:canonical-hex -->
| # | input (JSON) | canonical output, in hex |
|---|---|---|
| C12 | `{"s":"\u007f\u2028\u2029"}` | `7b2273223a227fe280a8e280a9227d` |
| C13 | `{"s":"\u00e9"}` | `7b2273223a22c3a9227d` |
| C14 | `{"s":"e\u0301"}` | `7b2273223a2265cc81227d` |
<!-- /vectors:canonical-hex -->

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

**Whom this section binds.** It binds whoever writes a row: an instant held as a value is
written in this one form. A verifier does not re-spell a string inside a payload. It hashes the
string as it stands (section 1: no string is normalised), so a payload written with another
spelling of the same instant is another payload, with another hash. The one string a verifier
does put into this form is the row's own `created_at`, as section 5 rules.

**What is accepted on input, and nothing else:**

```
YYYY-MM-DDTHH:MM:SS[.digits](Z|+HH:MM|-HH:MM)
```

- ASCII characters only, an uppercase `T`, and an uppercase `Z` or a numeric offset. The offset
  is required.
- A year from `0001` to `9999`, and a month, day, hour, minute and second that exist: no
  30 February, no 29 February outside a leap year, no hour `24`, no second `60`.
- An offset of `00` to `23` hours and `00` to `59` minutes, with either sign. It is converted to
  UTC, and the instant must still lie within the years `0001` to `9999` once it is.
- A fraction, if there is one, of at least one digit. Zero to six digits are zero-padded to six.
  More than six is accepted **only if every extra digit is a zero** — dropping a zero is
  lossless, dropping anything else is not, so a genuinely sub-microsecond value is refused rather
  than rounded.

**Everything else is refused.** A lowercase `t` or `z`, a space separator, a missing offset, an
offset of 24 hours or of 60 minutes, a character outside ASCII (another script's digits
included), a date or a time that does not exist: each either admits a second spelling of one
instant or names no instant at all. The refusals are vectors below, as they are for currency: an
implementation that accepts one of them reads a claim differently from this document.

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
| T7 | `2026-07-25T09:59:00+23:59` | `2026-07-24T10:00:00.000000Z` |
| T8 | `2026-07-24T10:00:00-00:00` | `2026-07-24T10:00:00.000000Z` |
| T9 | `2024-02-29T23:59:59.999999Z` | `2024-02-29T23:59:59.999999Z` |
| T10 | `2026-07-25T10:00:00+24:00` | `refused` |
| T11 | `2026-07-24T10:00:00+00:60` | `refused` |
| T12 | `2026-02-30T10:00:00Z` | `refused` |
| T13 | `2026-02-29T10:00:00Z` | `refused` |
| T14 | `2026-13-01T10:00:00Z` | `refused` |
| T15 | `2026-07-24T24:00:00Z` | `refused` |
| T16 | `2026-07-24T10:60:00Z` | `refused` |
| T17 | `2026-07-24T10:00:60Z` | `refused` |
| T18 | `2026-07-24T10:00:00.Z` | `refused` |
| T19 | `2026-07-24T10:00:00.1234567Z` | `refused` |
| T20 | `2026-07-24t10:00:00Z` | `refused` |
| T21 | `2026-07-24T10:00:00z` | `refused` |
| T22 | `2026-07-24 10:00:00Z` | `refused` |
| T23 | `2026-07-24T10:00:00` | `refused` |
| T24 | `2026-07-24T10:00:00+0530` | `refused` |
| T25 | `0000-01-01T00:00:00Z` | `refused` |
| T26 | `0001-01-01T00:00:00+00:01` | `refused` |
| T27 | `9999-12-31T23:59:59-00:01` | `refused` |
| T28 | `2026-07-24T10:00:00.٥Z` | `refused` |
<!-- /vectors:timestamp -->

---

## 3. UUIDs

A UUID canonicalizes as its **lowercase, hyphenated 8-4-4-4-12 string** (BUILD-STATE R-025).
Whoever writes a row puts a UUID held as a value into that one form before it is hashed,
whether it arrived in uppercase, braced, as a URN or unhyphenated.

**A UUID rendered two ways breaks byte-for-byte root reproduction exactly as a float would.**
It is the same class of defect and it is pinned here for the same reason.

**Whom this section binds.** The rule binds the writer, wherever a payload holds a UUID. A
verifier does not re-spell a UUID it finds as a string inside a payload: it hashes the string as
it stands (section 1: no string is normalised), so the same UUID written in capitals is another
payload, with another hash. `freshness.sync_run_id` on a warehouse-sourced
evidence item and `prediction_id` are two examples, not a complete list. `sync_run_id` is a **version 4** UUID specifically, so that the
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
row_hash = SHA-256( canonical( {
    "created_at":  created_at,
    "operator_id": operator_id,
    "payload":     payload,
    "prev_hash":   prev_hash,
    "row_id":      row_id,
    "row_type":    row_type
} ) )
```

rendered as **64 lowercase hex characters**. The hashed bytes are the canonical form of section 1
applied to **one JSON object with exactly these six members** and no other.

- `created_at` — the row's instant, as a string in the one form of section 2: twenty-seven
  characters. **It is put into that form before it enters the object**, so one instant has one
  hash however it was handed over. Vector H7 is H2's row with the instant spelled another way, and
  it has H2's hash.
- `operator_id` — a string, verbatim. Section 1 escapes it as it escapes any string.
- `payload` — the row's payload, a JSON object, as it is. Its canonical form stands whole inside
  the hashed bytes.
- `prev_hash` — the previous row's `row_hash` as exactly 64 lowercase hex characters, or the
  genesis constant for the first row.
- `row_id` — the row's identifier: a ULID, exactly 26 characters of Crockford base32 (the digits,
  and the capital letters without `I`, `L`, `O` and `U`), the first of them `0` to `7`.
- `row_type` — a string. The Log writes `prediction`, `resolution`, `amendment`, `void` or
  `declined`.

**Five of the six are strings and `payload` is an object. Anything else is malformed.** `null`,
`true`, a number, a list, or an object where a string belongs each have a canonical form, so an
implementation that did not refuse them would hash them as written. Refuse the row instead.
"Exactly" means the whole string: 64 hex characters followed by a newline are not a `prev_hash`.

**Build the object from the six members, by name.** Do not hash a row object as it was handed to
you. It may also carry the row's own `row_hash`, or a member nobody defined, and neither is under
the hash.

**A verifier does not check `row_type` against a list.** A row type that is on no list gives a
hash no anchored tree holds, so it cannot be passed off as a real row (vector H8), and a list
written here would be wrong the day a type is added.

**Why one object, and not the parts joined end to end.** The canonical form of section 1 is
one-to-one: escaping can be undone, keys are unique and sorted, and no number appears. So two
different rows cannot produce the same hashed bytes, whatever their row types and operator ids
are, and nothing rests on one value not being the beginning of another. The members sort as
`created_at`, `operator_id`, `payload`, `prev_hash`, `row_id`, `row_type`, which is therefore the
order they stand in inside the hashed bytes.

**This is section 1's form and not a JSON library's sorted-keys output.** A library's writer can
differ from section 1 in ways that each change the hash. These are the ones we know of, and the
list may not be complete: a space written after `:` and `,`; characters outside ASCII escaped
where section 1 writes them as UTF-8 (H6); keys sorted by code point where section 1 sorts by
UTF-16 code unit (H9); and `&`, `<`, `>`, `/`, `U+007F`, `U+2028` or `U+2029` escaped where
section 1 writes each as itself (H10). A writer may also normalise a string, which section 1 never
does (H11, H12).

### Vectors — row hash

Each row is JSON text: the six members as one JSON object. A character outside printable ASCII
is written here as a `\u` escape, which any JSON parser reads back to the character. What is
hashed is section 1's form of the row and never this text. H5's `operator_id` is the six
characters `o`, `p`, `"`, `1`, `\`, `x`.

<!-- vectors:row-hash -->
| # | row (JSON) | row_hash |
|---|---|---|
| H1 | `{"row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","row_type":"declined","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `15b9ee45b90802f8e50af3eebcd902a5b86ccbfcd9d9d3d2531e7bed04fa09fd` |
| H2 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `f2ada4a6a40b43fe220ff7c948d8610e4de2bf2be9151a76f5854be0956fc726` |
| H3 | `{"row_id":"01K1ABCDEFGHJKMNPQRSTVWXYZ","row_type":"resolution","created_at":"2026-11-07T18:30:00.000000Z","operator_id":"op-2","payload":{"a":"1"},"prev_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}` | `d98a86616aef951411ad1b9897600a3edf18037a4e203c042778052f4f2bcdfa` |
| H4 | `{"row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","row_type":"void","created_at":"2026-07-24T10:00:00.000001Z","operator_id":"op-1","payload":{"z":"1","a":"2"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `c10a9abf5716a24e1c61eaf79d40172377b49bbccfc9f94871110d0aa4570cfe` |
| H5 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op\"1\\x","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `f08b5ccca2c5c63d4478231cae82f049ea028e15a09ab114b71d919b4b9ab4d8` |
| H6 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-\u00e9\u20b9","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `bc17802fd52e4860ad48daac8d929a88c02f23a63b49564b943cfb784b055ffc` |
| H7 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T15:30:00+05:30","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `f2ada4a6a40b43fe220ff7c948d8610e4de2bf2be9151a76f5854be0956fc726` |
| H8 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"voided","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `1fd2b674a3390fa35c3803a6b3afba64edc945bb50053e7afcb00081d1749efa` |
| H9 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"\ud800\udc00":"supplementary","\ufffd":"replacement"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `7c71a92deef6ee22ae52acea100034a157ff74f90ec8eaf106c1defec11bb876` |
| H10 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"&<>/\u007f\u2028\u2029","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `a5db206bfa485987c6efb5c2c9465ae16d81fcce8ff0a498f13d483b328e50e8` |
| H11 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"\u00e9","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `a1e7e56418e9e84f4bdf6cef2095995cc4e3752e19c360e37d0fd78c999ce087` |
| H12 | `{"row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction","created_at":"2026-07-24T10:00:00.000000Z","operator_id":"e\u0301","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000"}` | `730c8ac15f53d0036b478db2206f8203848329aefc077ba34bf5c7a40e72b901` |
<!-- /vectors:row-hash -->

H5 to H12 are H2's row with one thing changed. H5 and H6 change `operator_id`: a quote and a
backslash, then two characters outside ASCII. H7 spells the same instant another way, so its hash
is H2's. H8 has a `row_type` that is on no list. H9 has a payload whose two keys, `U+10000` and
`U+FFFD`, sort one way by UTF-16 code unit and the other way by code point (section 1, vector C10).
H10's `operator_id` is seven characters a writer made safe for HTML would escape and section 1
does not: `&`, `<`, `>`, `/`, `U+007F`, `U+2028`, `U+2029`. H11 and H12 are one letter written
composed (`U+00E9`) and decomposed (`U+0065 U+0301`): the same to the eye, and two rows with two
hashes, because no string is normalised.

**The bytes that are hashed**, for each vector above, so that an implementation with a different
hash can find the byte at which it parts company:

<!-- vectors:row-preimage -->
| # | hashed bytes |
|---|---|
| H1 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","row_type":"declined"}` |
| H2 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}` |
| H3 | `{"created_at":"2026-11-07T18:30:00.000000Z","operator_id":"op-2","payload":{"a":"1"},"prev_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","row_id":"01K1ABCDEFGHJKMNPQRSTVWXYZ","row_type":"resolution"}` |
| H4 | `{"created_at":"2026-07-24T10:00:00.000001Z","operator_id":"op-1","payload":{"a":"2","z":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","row_type":"void"}` |
| H5 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op\"1\\x","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}` |
| H6 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-é₹","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}` |
| H7 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}` |
| H8 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"a":"1"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"voided"}` |
| H9 | `{"created_at":"2026-07-24T10:00:00.000000Z","operator_id":"op-1","payload":{"𐀀":"supplementary","�":"replacement"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","row_type":"prediction"}` |
<!-- /vectors:row-preimage -->

The hashed bytes of H10, H11 and H12 hold characters that cannot be shown safely as text, so they
are given in hex:

<!-- vectors:row-preimage-hex -->
| # | hashed bytes, in hex |
|---|---|
| H10 | `7b22637265617465645f6174223a22323032362d30372d32345431303a30303a30302e3030303030305a222c226f70657261746f725f6964223a22263c3e2f7fe280a8e280a9222c227061796c6f6164223a7b2261223a2231227d2c22707265765f68617368223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c22726f775f6964223a2230314b3058394e52354e37514b385634435a3648325742544d44222c22726f775f74797065223a2270726564696374696f6e227d` |
| H11 | `7b22637265617465645f6174223a22323032362d30372d32345431303a30303a30302e3030303030305a222c226f70657261746f725f6964223a22c3a9222c227061796c6f6164223a7b2261223a2231227d2c22707265765f68617368223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c22726f775f6964223a2230314b3058394e52354e37514b385634435a3648325742544d44222c22726f775f74797065223a2270726564696374696f6e227d` |
| H12 | `7b22637265617465645f6174223a22323032362d30372d32345431303a30303a30302e3030303030305a222c226f70657261746f725f6964223a2265cc81222c227061796c6f6164223a7b2261223a2231227d2c22707265765f68617368223a2230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c22726f775f6964223a2230314b3058394e52354e37514b385634435a3648325742544d44222c22726f775f74797065223a2270726564696374696f6e227d` |
<!-- /vectors:row-preimage-hex -->

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
volume demands it. It would publish the same root if its peaks are joined right to left, the
older peak as the left child, with the node hash of section 6 and nothing else mixed in: joined
that way its root is this section's root at every size we have tried, from 1 to 131 rows. Joined
left to right it is a different root at every one of those sizes that has three or more peaks, and
the same root at the rest. Nothing is claimed here of any other construction.

### The odd-node rule: carried up, never paired with itself

At any level with an **odd** number of nodes, the last node is **carried up unchanged** to the
level above. It is not hashed at that level, and it is **never paired with itself**. The nodes
before it are consumed in order, two at a time.

This is the shape of the Merkle tree of RFC 6962 section 2.1, stated level by level. That section
states it by splitting: split the rows at the largest power of two smaller than their number, root
each part the same way, and make one node of the two roots. The two statements give the same tree.
**Only the shape is that tree's.** The leaf and node hashes are section 6's, not the RFC's.

Because no node is ever paired with itself, **a root fixes the number of rows under it**: three
rows, and four rows whose fourth repeats the third, have different roots.

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
level 1:  N0 = node_hash(L0, L1)                      L2                       <- carried up unchanged
root:          node_hash(N0, L2)
```

And five rows, where the fifth leaf is carried up twice:

```
leaves:   L0    L1    L2    L3    L4
level 1:  N0 = node_hash(L0, L1)    N1 = node_hash(L2, L3)    L4
level 2:  N2 = node_hash(N0, N1)                              L4
root:          node_hash(N2, L4)
```

### Vectors — roots

The row hashes are `sha256("row-0")`, `sha256("row-1")`, … in that order, so an outside
implementation can reproduce these from nothing but this document.

<!-- vectors:tree -->
| # | rows | root |
|---|---|---|
| M1 | 1 | `76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614` |
| M2 | 2 | `6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a` |
| M3 | 3 | `833a0878c13c66d6a2d23acc9a250cd2b6f1c4938cd7f5f7efef288fb64391be` |
| M4 | 4 | `7280ad1d11858a5886a3b2d5a8b6b3f8bebd888b4cf191b8d04efa92498ec4cd` |
| M5 | 5 | `b0bd91ba932dc7e269c9bc0a3b45363e47b4669da4e1ef7264e732c97ac29807` |
| M6 | 6 | `41f329d810a6aa9b4118cb27c4eb750a50dee51ef480060294fcbc9d2ffeebc1` |
| M7 | 7 | `b6cfa311c4e9a8205eb325e7c85eb44707f2739e1aba72be847777fe98f7cf2b` |
| M8 | 8 | `9cebd0d38162339c6e36b48e486ef1980bc7d962e2e4a20abb43de46a6695a80` |
| M9 | 9 | `019019a03939e7f124b83256ba99acf4d3a7d0577096f2b92daf10cb6bc380d9` |
<!-- /vectors:tree -->

---

## 8. Inclusion proofs, and folding

An inclusion proof for one row has three members, and **all three are required**:

- `leaf_index` — the row's zero-based position in `row_id` order.
- `tree_size` — the number of **rows** the tree covers.
- `path` — the sibling hashes from the leaf level upward, each tagged with the side **the
  sibling sits on**. A level at which the node is carried up (section 7) contributes **no step**,
  so a path is not one step per level: the last row of a three-row tree has one step, and a tree
  of one row has an empty path.

`leaf_index` and `tree_size` are whole numbers, with `leaf_index` at least zero and below
`tree_size`. **In a claim file each is written as a string**, in the one plain spelling an anchor
uses for its size (section 9): ASCII digits, no sign, no spaces, no leading zero. A JSON number
there is refused. So a claim file holds no JSON number anywhere, and two verifiers written in two
languages cannot read one file as two numbers. An index or a size of more than 39 digits is
refused before any arithmetic: a row's identifier is 128 bits, so there are not that many rows.

Each step of `path` is an object with exactly two members: `side`, which is `left` or `right`,
and `hash`. A step with any other member is refused.

A proof that leaves out its path, its index or its size is not a proof. In particular, a missing
path is not the empty path of a one-row tree.

Verification:

1. Canonicalize the row's payload (section 1).
2. Compute `row_hash` (section 5) **from the row's content** — not from the row's own claim
   about its hash.
3. Compute `leaf_hash(row_hash)` (section 6).
4. **Check the path against the index and the size, then fold it.** The number of steps, and the
   side of each, are fixed by `leaf_index` and `tree_size` alone. From the leaf upward:

   ```
   index = leaf_index
   last  = tree_size - 1
   while last > 0:
       if index is odd:        one step, its sibling on the LEFT
       else if index < last:   one step, its sibling on the RIGHT
       else:                   no step: this node is carried up
       index = index // 2
       last  = last // 2
   ```

   A path with a step more or a step fewer than that, or with one step whose stated side differs,
   is refused before anything is folded. So is a step whose hash is not exactly 64 lowercase hex
   characters. Then, starting with the leaf hash as the accumulator, for each step in order:
   - sibling on the **left** → `accumulator = node_hash(sibling, accumulator)`
   - sibling on the **right** → `accumulator = node_hash(accumulator, sibling)`

The result of step 4 is the root this proof commits the row to. Whether that root was published,
and under which size, is step 5, which section 12 gives.

**The fold alone says nothing about position.** It reads neither number, so one path folds to one
root whatever index is claimed for it, and an interior node offered in place of a leaf folds to the
root as well. The check in step 4 is what makes a proof a statement about one row, at one
position, in a tree of one size. And that size is worth checking against only once it is the
published one (step 5): an honest path for one tree has the step count and the sides of positions
in many trees of other sizes.

Step 2 is what makes this a proof about the row rather than about a hash someone handed over. A
verifier that folds the value it read out of the `row_hash` column has proved only that the
column is in the tree.

### Vectors — inclusion proofs

Over the rows of section 7's roots: the row hashes are `sha256("row-0")`, `sha256("row-1")`, … in
that order. `path` is JSON text, its steps from the leaf upward.

<!-- vectors:proof -->
| # | rows | leaf_index | path | root |
|---|---|---|---|---|
| P1 | 3 | 2 | `[{"side":"left","hash":"6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a"}]` | `833a0878c13c66d6a2d23acc9a250cd2b6f1c4938cd7f5f7efef288fb64391be` |
| P2 | 5 | 2 | `[{"side":"right","hash":"2fe098ebb786a6013d5f706508a0cec4341f0814e437bbc839ab487f0472d351"},{"side":"left","hash":"6763907dbfd9216a8ac83e77318d14094d067713a4380f6cf09982363e287b8a"},{"side":"right","hash":"cac01b52850e6db4d0d3c64a995efadc1024ac2c2362dd1eb93f1d25f6e65d6b"}]` | `b0bd91ba932dc7e269c9bc0a3b45363e47b4669da4e1ef7264e732c97ac29807` |
| P3 | 1 | 0 | `[]` | `76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614` |
<!-- /vectors:proof -->

P1 is the last row of a three-row tree. It has one step and not two, because its leaf is carried up
a level unchanged; that one sibling is the node over the first two rows, which is root M2. P2 is a
middle row of a five-row tree. P3 is a tree of one row: the path is empty and the root, M1, is the
row's leaf hash.

**Two more steps exist and are not specified here:** step 5, finding that root in an anchor
publication under the same `tree_size`; and step 6, confirming that the publication's third-party
timestamp precedes the row's resolution. They need the published anchors and the publication
medium, and section 12 gives them.

---

# Part 2 — the anchor, the medium, and the timestamp

Part 1 ends two steps short on purpose. It can take a row and an inclusion proof and produce a
root, and it says so: *"Two more steps exist and are not specified here"*. This part supplies the
published anchors, the medium, and those two steps.

The distinction it turns on is the whole reason any of this exists. Recomputing a root over our
own rows proves that our arithmetic is self-consistent and nothing else — **we can rebuild a
private tree any time we like, to say anything we like.** What makes a prediction independently
verifiable is that somebody who is not us recorded the root before the outcome was known.
Everything below is about where that record lives and how you check it yourself.

---

## 9. The published payload

One anchor publication is one **canonical JSON line** carrying six fields, plus its SHA-256:

```
{root_hash, tree_size, latest_row_id, ledger_schema_version, anchored_at, previous_line_sha256}
```

| Field | Meaning |
|---|---|
| `root_hash` | the root over every row in the Log at publication time, per section 7 |
| `tree_size` | how many **rows** the tree covers |
| `latest_row_id` | the `row_id` of the last row the tree covers: its last leaf |
| `ledger_schema_version` | the applied Alembic revision, e.g. `lg_0002`, so a reader of an old publication knows which schema produced it |
| `anchored_at` | when **we** built the tree — see the warning below |
| `previous_line_sha256` | the SHA-256 of the exact bytes of the line published immediately before this one, anchor or empty marker, as 64 lowercase hex characters: the digest that line's own receipt stamps. `null` on the first line ever published, and on no other (D-S43) |

The line is serialized by section 1 and the timestamp by section 2, so the keys come out sorted
ascending by UTF-16 code unit and `anchored_at` carries its six fractional digits. `tree_size`
is a **decimal string**, as section 1 requires of every numeric quantity and names tree sizes
among its examples; a publication containing a JSON number is malformed. Every value in a
published line is a string, with one exception: `previous_line_sha256` is JSON `null` on the
first line ever published, and on no other line.

> **`anchored_at` is not evidence, and no verification step may use it.** It is a reading of
> our own clock, and we could have written anything in it. Section 2 already states the
> principle for the ledger's other self-reported timestamp — *"a verifier should not read
> `created_at` as evidence of when a row was written. The anchor carries that"* — and the same
> applies to the anchor's own field. What the anchor carries is the **third-party** timestamp of
> section 12, which is not in the payload at all, because a payload cannot vouch for itself.

`anchor_id` **is** the SHA-256 of the line. It is not a separate minted identifier, so an
auditor holding a resolution row's `anchor_coverage.anchor_id` can recompute it from the
published bytes and confirm the two name the same publication.

Each publication is one file, and the file's bytes **are** the hashed bytes: the line of
section 1 and nothing after it, with no trailing newline. The SHA-256 of the file as published
is therefore the `anchor_id` and the digest its OpenTimestamps receipt stamps, which is what
lets the standard client check the receipt against the file with nothing stripped (section
12). A copy that has gained anything is a different file with a different SHA-256, and neither
reader accepts it. `verify.py` reads the file as bytes and refuses a copy that holds white
space before or after the line, a carriage return or a byte-order mark, saying which. The
standard OpenTimestamps client hashes the whole file, so it refuses such a copy too. Fetch the
file unchanged: clone the repository with git and read the bytes it holds with
`git cat-file blob HEAD:<path>`, or download the raw file. Do not copy its text out of a page
or save it from an editor.

Each field has a shape, and a file that breaks one is not a well-formed publication.
`root_hash` is 64 lowercase hex characters. `tree_size` is a whole number spelled plainly (no
sign, no spaces, no leading zero), at least 1 and of at most 39 digits. `latest_row_id` has the
shape of a `row_id` (section 5). `anchored_at` is in the one spelling of section 2.
`ledger_schema_version` is a revision's name: `lg_` and four ASCII digits, the name the anchor
job reads from the Log's applied Alembic revision. `previous_line_sha256` is 64 lowercase hex
characters, or `null`. The file is
named for its content: `anchored_at` with its hyphens, colons and full stop taken out, a
hyphen, the first 12 hex characters of the file's SHA-256, and `.anchor.json`. Vector A1 below
is the file `20260725T000000000000Z-15001bddea0e.anchor.json`. `verify.py` holds the name to the
content, and the order of the names is then the order of the instants the files stamp.

**The longest line the format allows is 347 bytes**, derived from the fields' own bounds: the
braces and five commas, 7 bytes; and for each field its name and its value, each in quotes, with
a colon between, the value at its longest: `anchored_at` 27 characters, `latest_row_id` 26,
`ledger_schema_version` 7, `root_hash` 64, `tree_size` 39 and `previous_line_sha256` 64 (its
`null`, unquoted, is shorter). None of them holds a character the canonical form escapes. An
empty marker's line is shorter. `verify.py` reads at most one byte more than that from an anchor
file, and refuses a file that holds more.

**Each line names the one published before it, so the lines form one chain** (D-S43). The first
line ever published names nothing; every later line, anchor or empty marker, names the line
published immediately before it by the SHA-256 of that line's bytes. What this lets you check
that a single line does not: that no line was held back and slipped in later. A line added
afterwards cannot join the chain without breaking it: placed between two lines, it names a line
another line already names, which is a fork; placed at the end with an earlier instant, the
instants go back along the chain. `--history` holds the lines it reads to that rule (section
12). What it does not let you check: that a line was public on its date. A chain can be written
in one sitting; that a line existed by a time rests on the times of section 12, as before. The
publishing job finds the line a new line names from one listing of the repository's tree, as the
published line whose name carries the latest instant, and reads that one file; it refuses to
publish if two names carry one instant. It does not read the whole chain and does not look for a
fork: a fork is found where the whole chain is read, by `--history`.

### Vectors — anchor payload

Row hashes are `sha256("row-0")`, `sha256("row-1")`, … so the roots are section 7's, and an
outside implementation can reproduce these lines and digests from this document alone. The three
lines are one chain in table order: A1 names nothing, A2 names A1 and A3 names A2.

<!-- vectors:anchor -->
| # | rows | latest_row_id | anchored_at | canonical line | SHA-256 |
|---|---|---|---|---|---|
| A1 | 1 | `01JZZZZZZZZZZZZZZZZZZZZZZZ` | `2026-07-25T00:00:00.000000Z` | `{"anchored_at":"2026-07-25T00:00:00.000000Z","latest_row_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ","ledger_schema_version":"lg_0002","previous_line_sha256":null,"root_hash":"76af063ba4aacba62a2611d4e33688d6e617557266c40a47a5c73f9814390614","tree_size":"1"}` | `15001bddea0e7cfab053ab090b18af2896e3e649ac87904363fe1433005bbad6` |
| A2 | 3 | `01K0X9NR5N7QK8V4CZ6H2WBTMD` | `2026-07-26T00:00:00.000000Z` | `{"anchored_at":"2026-07-26T00:00:00.000000Z","latest_row_id":"01K0X9NR5N7QK8V4CZ6H2WBTMD","ledger_schema_version":"lg_0002","previous_line_sha256":"15001bddea0e7cfab053ab090b18af2896e3e649ac87904363fe1433005bbad6","root_hash":"833a0878c13c66d6a2d23acc9a250cd2b6f1c4938cd7f5f7efef288fb64391be","tree_size":"3"}` | `1432631b25d2bea070a420e995c3c68d19e602970876e15c1c8e78b5d6d253dd` |
| A3 | 9 | `01K1ABCDEFGHJKMNPQRSTVWXYZ` | `2026-08-01T12:34:56.789000Z` | `{"anchored_at":"2026-08-01T12:34:56.789000Z","latest_row_id":"01K1ABCDEFGHJKMNPQRSTVWXYZ","ledger_schema_version":"lg_0002","previous_line_sha256":"1432631b25d2bea070a420e995c3c68d19e602970876e15c1c8e78b5d6d253dd","root_hash":"019019a03939e7f124b83256ba99acf4d3a7d0577096f2b92daf10cb6bc380d9","tree_size":"9"}` | `4b02f0b8759c32aef3ba63ad23908446931d633d74d418197b82f9c89c21d3ac` |
<!-- /vectors:anchor -->

### 9a. The empty marker — what a quiet day publishes

A day on which the Log held no rows still publishes a file. It is **not an anchor**: it commits
to no tree, carries no root, and no proof can ever fold to it. It carries five fields, and the
first of them says what it is:

```
{status, tree_size, ledger_schema_version, anchored_at, previous_line_sha256}
```

| Field | Meaning |
|---|---|
| `status` | always the string `empty`. Its presence is what identifies the artifact |
| `tree_size` | always `"0"` — the Log held no rows at `anchored_at` |
| `ledger_schema_version` | as in section 9 |
| `anchored_at` | when we looked. Still our own clock, still not evidence |
| `previous_line_sha256` | as in section 9: a marker names the line published before it like any other line, and is `null` only if it is the first line ever published |

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

The three markers are one chain in table order: E1 names nothing, E2 names E1 and E3 names E2.

<!-- vectors:empty-marker -->
| # | anchored_at | canonical line | SHA-256 |
|---|---|---|---|
| E1 | `2026-07-27T03:00:00.000000Z` | `{"anchored_at":"2026-07-27T03:00:00.000000Z","ledger_schema_version":"lg_0002","previous_line_sha256":null,"status":"empty","tree_size":"0"}` | `5d86bd86c8da0032eb089e70542eaa52a35126083eaea30f822f46a55ea6ca71` |
| E2 | `2026-07-28T03:00:01.234567Z` | `{"anchored_at":"2026-07-28T03:00:01.234567Z","ledger_schema_version":"lg_0002","previous_line_sha256":"5d86bd86c8da0032eb089e70542eaa52a35126083eaea30f822f46a55ea6ca71","status":"empty","tree_size":"0"}` | `082b8fa7fd38f5ae2ad1142f6e14eda0b3c7fe8d7263b0ce401f53be590dc9e0` |
| E3 | `2026-08-01T12:34:56.789000Z` | `{"anchored_at":"2026-08-01T12:34:56.789000Z","ledger_schema_version":"lg_0001","previous_line_sha256":"082b8fa7fd38f5ae2ad1142f6e14eda0b3c7fe8d7263b0ce401f53be590dc9e0","status":"empty","tree_size":"0"}` | `15a127cc1faad3be0e1a70fa65325ec20f8cd5fa4bcce5157575a6c22bdf17ba` |
<!-- /vectors:empty-marker -->

---

## 10. The medium, and the cadence

Two media, written by **one job**, running on a **daily floor and after each batch of new
forecasts**. Both halves are a recorded decision (BUILD-STATE D-04, delegated and minuted as
R-041), reversible by founder order.

| Medium | What it is for | What it cannot do alone |
|---|---|---|
| **`github.com/krishmeister/simul8-anchors`**, public | a human-readable, append-only public history, and a date on each commit, available immediately | prove anything cryptographically, or show a reader who set a commit's date — GitHub could in principle rewrite its own record |
| **OpenTimestamps** | a Bitcoin-anchored cryptographic timestamp of the payload digest | be available immediately — a fresh receipt is calendar-pending until a block carries it |

They fail differently, which is why they are paired rather than duplicated.

**A commit's date is a field of the commit, and this matters.** A commit made locally and
pushed carries a committer date taken from the clock, or the choice, of whoever made it — git
stores it in the commit object and the repository preserves it verbatim. The anchor job creates
its commit **through GitHub's API**, and sends no author, no committer and no date with it. A
reader holding a clone cannot see that in the commit, and neither can `verify.py`: it can read
the date, check that the commit holds exactly the file's bytes, and check that no later commit
touched the file's path. It cannot tell who set the date. So the date on a commit is the
repository's word and not a time you obtained yourself, and section 12 treats it so.

**The receipt is `<payload file>.ots`, beside its payload.** It stamps the SHA-256 of the
payload line, with no privacy nonce — the digest is of a line being published openly in the
same commit, so there is nothing to withhold, and it means the digest in the receipt is the same
value as `anchor_id`. A pending receipt is not presented as a confirmed one. The anchor job reads
the receipt it is about to publish by the rules the reference verifier reads it by (section 12),
and publishes nothing if the read fails.

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
5. Record the publication, with the committer date the medium returned for the commit.

Steps 4 and 5 are in that order deliberately, and the order decides what a crash between them
leaves behind. Publishing first can leave an anchor that is public but unrecorded: coverage
lookups then return *not covered*, resolutions defer, and nothing is ever graded against a
publication that does not exist. Recording first could leave the database claiming a publication
nobody can find — a resolution graded as covered by an anchor no outside party can reach, which
is the exact false claim this document exists to make impossible. **The failure mode is always
that we under-claim coverage, never that we over-claim it.**

---

## 12. Verifying a prediction — steps 5 and 6

Sections 1 to 8 get you from a row to a root. Two steps remain:

5. **Find the folded root in the published history.** Read the payload files from the public
   repository, as bytes. A file is the canonical line and not one byte more (section 9). Parse
   it, re-serialize it by section 1, and require the bytes to match: a line that has been
   reformatted or had a number substituted still parses as JSON but is no longer the artifact
   whose digest was stamped. Hold each field to its shape and the file's name to its content
   (section 9). **A file that fails any of this is not a well-formed publication. Name it, and
   pass over it:** what is published stays published, so one such file must not decide a claim
   it has nothing to do with, or make every later claim unverifiable. What you have shown is
   that a file in the folder you read is not a well-formed publication. If your files are an
   unchanged copy of the public repository, then the published record holds such a file.
   **Set aside every empty marker first** — an
   artifact whose `status` is `empty` (section 9a) records a day with no rows and commits to no
   tree, so it can never carry the root you folded and must not be treated as an anchor that
   failed to match. Then, among the anchors that remain, look for one whose `root_hash` equals
   the root you folded. Where several publications carry that root, they must all stamp the same
   `tree_size`: if they do not, the anchor files you read are inconsistent with themselves, and
   the claim is refused. If those files are an unchanged copy of the public repository, then the
   published record is inconsistent with itself. If they agree, the earliest of them is the
   one to use — the first by name, since a name leads with the instant its file stamps — and the
   time of step 6 is a time for that file. Its `tree_size` must be a whole number spelled the one
   plain way — no sign, no spaces, no leading zero — and must equal the `tree_size` in your proof. Otherwise the proof and
   the anchor are about different trees, and the position check of section 8 was made against a
   size nobody published.

   Three more checks follow, which the row hash of section 5 and the position check of section 8
   make possible. By the time they run, the row has been shown to be in the tree the anchor file
   commits to, at that index, under the file's own size. **So a failure of one of them is not the
   claim's doing: it means the anchor file you read is inconsistent with itself.** If your files
   are an unchanged copy of the public repository, then the published record is inconsistent
   with itself. The claim is still refused. Keep the claim file and the anchor file, and report
   it:
   - the row at index 0 carries the first row's `prev_hash` (section 4), and no other row does;
   - the last row of the tree, at index `tree_size` − 1, has the anchor's `latest_row_id` as its
     `row_id`;
   - every other row's `row_id` sorts before the anchor's `latest_row_id`.

   A history that contains **only** empty markers is not a broken history. It says no rows had
   been anchored by the last published date, which is a fact about the Log rather than a fault
   in the record, and a verifier should say so in those words rather than reporting a generic
   failure to find the root.
6. **Compare two times: the anchor's, and the resolution's.** The prediction is independently
   verifiable only if the anchor's time is **strictly earlier** than the row's resolution.
   Neither time is in the payload, and each has a source:

   - **The anchor's time.** A time for that file that you obtained yourself, passed with
     `--attested-at`. The Bitcoin attestation is the one this record is built to give you, once
     the receipt is confirmed:

     ```
     ots verify anchors/2026/<file>.anchor.json.ots
     ```

     Without one, `verify.py` reads the date on the commit that added the file, from the clone it
     is run in. That date is the repository's, not yours. It is used only if exactly one commit
     in the clone's history touches the file's path and that commit holds exactly the file's
     bytes; a path a later commit touched, or a commit holding other bytes, is refused with the
     reason. The program cannot tell who set the date (section 10). It reads the date by running
     `git` in the folder you name with `--anchors`. A folder brings its own git settings, and git
     can be made to run other programs from them: name only a clone you made yourself with
     `git clone`.
   - **The resolution time.** The time the outcome was resolved, obtained yourself and passed
     with `--resolved-at`. Without one, `verify.py` reads `resolved_at` from the claim file,
     which the publisher writes and which the program has nothing to check against.

   The transcript says, for each of the two, which source was used and what that source is
   worth. **Its last line is the verdict, and there are four:**

   | last line | exit status | when |
   |---|---|---|
   | `VERIFIED` | 0 | every step passed, and **both** times are your own |
   | `PROOF HOLDS, TIMES NOT YOUR OWN` | 3 | every step passed and the times compare, but one or both are the repository's or the claim file's |
   | `NOT VERIFIED` | 1 | anything else |
   | `NOT JUDGED` | 4 | part of the folder you named, a folder or a regular file, could not be opened or read on your machine, and what was read does not decide the claim: the root is in no file read, or the receipt beside the file it is in could not be read. Nothing about the published record is concluded |

   Above a passing verdict the transcript says what was checked and whose each time is: the
   row's six members hash to the leaf the proof starts from; the proof folds to the root the
   anchor file states, at the index and size it gives; the anchor file is its canonical line and
   not one byte more; the receipt beside it is read to its end and stamps that file's SHA-256,
   and what it claims; and each of the two
   times is either yours or the repository's or the publisher's. When both times are yours, the
   transcript says that it is you who have tied that anchor file to a time, and that the time is
   before the resolution time you gave: that is what the plain word says, and all it says.

   Exit status 2 means the arguments could not be read, and a claim file your machine could not
   open or read is one of them: it is your own input, not the record, and no verdict is given.
   If no time can be had for the anchor,
   the correct outcome is **not verified** — not "verified, assuming ours". There is no fallback
   to `anchored_at`.

### The reference verifier

`verify.py` ships in the public anchors repository and implements all six steps. **Stdlib only —
no `pip install`, no network, no account.** Being able to run it without trusting us is part of
the claim.

```
python3 verify.py --self-test
python3 verify.py --history --anchors anchors/
python3 verify.py --claim claim.json --anchors anchors/ \
    --attested-at <the anchor's time> --resolved-at <the resolution time>
```

`--self-test` checks the verifier against every vector table in this document and needs no
Simul8 data at all: run it first, and you know the arithmetic agrees before you point it at a
row. A `claim.json` is `{"row": {...}, "proof": {...}, "resolved_at": "..."}` and has no other
member. `resolved_at` may be left out; if it is there, it is a timestamp of section 2. `row`
carries the six hashed members of section 5, `row_id` among them, and may also state its
`row_hash`: if it does, that is exactly 64 lowercase hex characters, and anything else there is
refused. `proof` carries `leaf_index`, `tree_size` and `path` as section 8 defines them, the first
two as strings. All six members and all three parts of the proof are required. A `row`, a `proof`
or a step with any other member is refused. So is a claim file in which a JSON object repeats a
key: a parser that keeps the last of the two would let a claim show one value to a reader and
another to the program. A claim file holds no JSON number anywhere.

No input ends the program any other way than in words, with one exception: a machine that runs
out of memory. There the operating system may end the program without words. Every file it
reads, an anchor file, a
receipt or a claim file, must be a regular file: a device, a named pipe or a directory is refused
with the words "is not a regular file", whatever its name and wherever a link points. It reads
at most one byte more than the file may hold, and refuses a file that holds more: the longest
line the format allows for an anchor file (section 9), 1,000,000 bytes for a receipt, and
16,000,000 bytes for a claim file. No size the file system reports is trusted for this. The
folder named with `--anchors` is walked without recursion and without following a link into a
folder, so a folder of any depth is walked, and a folder or a regular file your machine cannot
open or read is named "NOT READ HERE". Where the failure arises decides: in the opening or the
reading it is a failed reading here; in bytes that were read it is a defect of the file. A link is
never a failed reading: a published line and its receipt are regular files in git, so a symbolic
link named like one, dangling, looping or resolving, is a defect of that file. No
limit is set on how many entries the walk holds, because the published record grows and a limit
would be a refusal waiting to happen on it; it holds about 0.8 KiB for each folder or matching
file, by a reviewer's measurement of 12 October 2026, a reading of one day. A folder holding so
many entries that the machine runs out of memory may therefore end the program without words.
What git
is asked is bounded too: no more than two commits are asked for, a blob's size is read before
the blob, and a blob longer than the longest line the format allows is refused without being
read.

A claim file is at most 16,000,000 bytes. This limit is this program's own. Its basis: a row runs
to 50 to 100 KB at full voice count (SPEC-SPORTS §3.6), and a proof adds at most one step for each
bit of a 39-digit size; the limit stands far above both, so that it refuses only what is not a
claim. A claim past it is unreadable to this program.

A call to `git` may take at most 60 seconds. This limit is this program's own. Its basis: each
call asks git for one small thing, whether one commit touches one path, one blob's size or bytes,
or one commit's date, and on a clone of the public repository each answered in under 10
milliseconds when measured; the limit stands far above that, so that it refuses only a git that
is not answering. When it is reached the transcript says so, the repository's date is not read,
and no verdict rests on what git did not answer.

A claim file that is not UTF-8, is not
JSON, is not a JSON object, begins with a byte-order mark, is nested too deeply to read, or
holds a number of any length is refused, with exit status 1. Everything the transcript prints
from a claim, an anchor, a receipt or a file name is either held to its shape first or printed
with every character that is not printable written as an escape, so none of them can begin a
line of the transcript or write a line of the verdict.

`--history` lists the anchor files it read and says of each date whether rows were anchored,
reporting an empty marker as **"no rows anchored on this date"**. That is neither a success nor
a failure — it is the third thing the record can say, alongside an anchor that verifies and one
that does not, and it is how you read when the Log started carrying rows. `--history` also holds
the files to what a Log can do, and fails, with exit status 1, saying which rule is broken. A
folder or a regular file under the folder you name that your machine cannot open or read is not
one of these: it is named "NOT READ HERE", and nothing about the published record is concluded
from it. A defect wins: if what was read shows a defect, or breaks a rule between lines that were
read, the history fails, with exit status 1, and the transcript says it was not read whole. The
parts of THE LINES READ FORM ONE CHAIN that need every line read (every other line names a line
read here; no line is left out of the chain; some line names nothing) are then not judged, and
the transcript says so, because a line not read here would break them on a lawful record. Only
where nothing read shows a defect, `--history` ends "HISTORY NOT JUDGED" with exit status 4, because the files read are not the
whole of the folder and the history is neither passed nor failed. It fails on: a
file that is not a well-formed publication; sizes that go down; one size under two roots; one
root under two sizes; an empty marker after an anchor, because a Log that has held a row is
never empty again; and lines that do not form one chain. That last rule, THE LINES READ FORM ONE
CHAIN, has five parts, and the transcript says which part breaks: exactly one line names nothing,
and it is the earliest; every other line names a line read here; no two lines name the same
line; no line is left out of the chain; and the instants never go back along it. The files are
taken in the order of the instants they stamp. Where two files stamp one instant the transcript
says so, and they are taken in the order of the sizes they stamp, so that a history a Log could
have written is never read as sizes going down. With `--claim`, the transcript says whether the
chain from the anchor file whose time it compared back to the first line is unbroken among the
files read. A break is named, with what it means if the files are an unchanged copy of the
public repository, and it does not decide the claim: `--history` fails on it. Where part of the
folder could not be read on your machine and the walk back reaches a line it cannot find, the
chain is said to be not judged there, not broken: that line may be the one not read.

`verify.py` is pointed at a folder, and nothing it checks shows that the folder is the public
repository. So it speaks of the anchor files it read, and of the published record only on the
condition that those files are an unchanged copy of the public repository.

What it checks offline: the row's six members hash to the leaf the proof starts from; the proof
folds to the root an anchor file states, at the index and size it gives; the anchor file is its
canonical line and not one byte more; and the receipt beside it is read to its end, stamps that
file's SHA-256 and not some other, and holds at least one attestation of a kind it knows. It
says what the receipt claims, never that it is so: for a Bitcoin attestation, the block height
and the value that block's Merkle root must have, printed in the order the receipt holds its
bytes and again with the bytes reversed; for a pending one, the calendar's address. It fetches
nothing and judges no block's clock. What it does not check offline: that Bitcoin carries the
attestation — run `ots verify` for that. It will tell you which of these it established rather
than collapsing them into one word.

**A receipt is read to its last byte.** Its header; its version, 1, written as one byte; its
declared file hash, SHA-256; and the 32-byte digest, which must be the SHA-256 of the anchor file
beside it. Then the whole timestamp as OpenTimestamps writes it: every operation applied, every
attestation found, and no byte left over. An attestation of a kind the program does not know is
passed over and counted, and at least one must be of a kind it knows, a pending one or a Bitcoin
one. A Bitcoin attestation must stand on a 32-byte message. A pending attestation's address is
printed only from the characters the format allows.

`verify.py` refuses by rule, and says why in words: a declared file hash that is not SHA-256; an
operation it does not know, or cannot compute with the standard library on the machine it runs
on (keccak256 everywhere, ripemd160 where the machine lacks it); a receipt whose only
attestations are of kinds it does not know; a Bitcoin attestation on a message that is not 32
bytes; a version written in more than one byte; a count not written in its shortest form; bytes
left over; anything past a limit. Each is
refused with the words "the receipt is unreadable to this program", and the standard client is
the way to check it (`ots verify`). The standard client may still read some of these: the
reference library, opentimestamps 0.4.5, read a version written in two bytes, a receipt whose
only attestation is of a kind it does not know, a Bitcoin attestation on a 33-byte message, a
receipt that uses keccak256, and one that declares another file hash; and the reference library
does not refuse a count that is not written in its shortest form.

The format's own limits, as read in that library's `opentimestamps/core`: a message and an
operation's result of at most 4096 bytes (`op.py`, lines 40 and 59); an operation's argument of 1
to 4096 bytes (`op.py`, line 218); an attestation's payload of at most 8192 bytes (`notary.py`,
line 26); a pending attestation's address of at most 1000 bytes (`notary.py`, line 165), from a
fixed set of characters (`notary.py`, line 168); nesting at most 256 deep (`timestamp.py`, line
131).

A receipt is at most 1,000,000 bytes. The format sets no limit on a receipt's size; this one is
this program's own. The largest receipt the tree keeps is 3,812 bytes.

A count is written in at most 9 bytes. The format sets no limit on how many bytes a count is
written in; this one is this program's own. The longest count in the receipts the tree keeps is
written in 2 bytes. Nine bytes hold every value below two to the sixty-third: nothing the format
counts comes near that, and no reader that holds a count in a signed 64-bit integer could read a
wider one.

A receipt holds at most 10,000 steps, operations and attestations together. The format sets no
limit on how many; this one is this program's own. The most in a receipt the tree keeps is 41.
The first and the third of these limits are choices, ruled for this program, with no other
source.

### 12a. What an anchor attests, and what it does not

You have just folded a root and found it in the published history. This section says exactly
what you have established, because reading more into an anchor than it carries is the failure
this document exists to prevent.

**What an anchor attests.** That the root existed at a time **a named third party recorded** —
a Bitcoin attestation through OpenTimestamps, which you can confirm yourself, or the date on the
repository's commit, which is the repository's word and is worth less (section 12, step 6) — and
therefore that
every row the tree covers was written before that time and has not changed since. That is the
Log's **integrity**, and it is the whole of what §45(e) claims.

**What an anchor does not attest: that the Log contains the rows it should.** An anchor is
produced by the anchor job, so **a run of anchors attests the anchor job's liveness, not the
ledger writer's.** A silently broken writer publishes exactly the same sequence of anchors as a
genuinely quiet day. Nothing in the published record distinguishes those two, and no amount of
anchoring will.

**The distinguishing data is already in the payload, and you can use it.** `tree_size` is one
of section 9's six fields. **Consecutive anchors whose `tree_size` has not changed mean no rows
were added between them — which is indistinguishable from a writer that has stopped.** Read a
run of unchanged sizes as *"nothing was anchored in this period"*, never as *"nothing
happened"*. The first is what the record says; the second is a claim it cannot make.

Whether we made the predictions we should have is the Log's **productivity**, and that is a
different question from its integrity. It is answered on the honesty surface, against a stated
firing cadence, and not here. An anchor is not the instrument for it and is not presented as
one.

**The set of parties whose recording counts is explicit, not implied.** Section 10 names the two
media and section 12 says what a time from each is worth to you. There is no third: an artifact
carrying a timestamp from anywhere else — including ours — is **not attested**, and
`anchored_at` is not a fallback. That set is enumerated in our own code as a closed list, which
the internal decision about whether a publication is attested reads. That decision and the
verifier do not ask the same question: the internal decision accepts the committer date the
medium returned for a commit made through GitHub's API, and `verify.py` prints the plain word
only on times you supplied yourself. **Where the two differ, the verifier is the stricter.**

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
and §3.11(d), except that the row hash of section 5, the odd-node rule of section 7 and the proof
check of section 8 are the second amendment's (STATE-SPORTS R-S976 and R-S982) and no longer
SPEC-D2C's. Constants pinned by BUILD-STATE SL-13, R-010 and R-025; the medium and cadence by
D-04 / R-041; the currency rule of section 1 and its vectors by R-127, R-131, R-132, R-133 and
R-204, ratified as R-352 and R-353, which is also the authority for section 12a's wording
(R-173). Part 1 frozen at LOG pass, Part 2 at ANCHOR pass: a change to anything in this
document is a written proposal to HQ, never a commit. The two amendments are recorded at the
top.*
