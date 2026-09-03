#!/usr/bin/env python3
"""The anchor watchdog's check. Published to simul8-anchors as .github/workflows/watchdog.py.

BUILD-STATE R-067, implementing R-062 mechanism (2).

It answers one question — **did the public record receive its entry for this date** — by
looking at the published files and nothing else. It knows no hostname of ours, holds no
credential of ours, and imports none of our code. The handful of constants it needs are
restated here rather than imported, and that duplication is deliberate: a watchdog that shares
a module with the thing it watches fails at the same time as the thing it watches.

It also reports OpenTimestamps receipts that have not upgraded (R-057(e), moved here by
R-067(c)). An un-upgraded receipt is an ABSENCE — nothing failed, something simply never
arrived — which is exactly the class of problem in-band alerting cannot see.

WHAT COUNTS AS TODAY'S ENTRY. Every day publishes AT LEAST ONE artifact, and may publish
several: publication runs on a floor cadence and again after each batch of new forecasts. Each
artifact is an anchor when the Log held rows, or an empty marker when it did not. All are named
`anchors/<YYYY>/<YYYYMMDD>T<time>Z-<digest>.anchor.json`, so the check is a date-prefix glob
and needs no knowledge of the digest, the root, or our internals. THE CHECK IS FOR PRESENCE,
NOT FOR COUNT — a date with two or five artifacts is sound, and only a date with none is not.

WHY AN EMPTY HISTORY IS NOT AN ALERT. Until the first artifact is published there is nothing to
be absent, and a watchdog that fires every day before the system has started publishing trains
its reader to ignore it — the precise failure this mechanism exists to avoid. So it stays idle
until the record contains at least one artifact, and arms itself from then on. The stated cost:
if publication never begins at all, this never fires. That is a known state nobody needs a
watchdog to discover.

Stdlib only, and no network: it reads the checkout it is handed. Exits 0 when the record is
sound, 1 when it is not, after writing `watchdog-report.md` for the issue body.
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ANCHOR_DIRECTORY = Path("anchors")
REPORT = Path("watchdog-report.md")

#: Restated, not imported. See the module docstring — sharing a constant with the publisher
#: would couple the watchdog to the thing it watches.
OTS_BITCOIN_ATTESTATION_TAG = b"\x05\x88\x96\x0d\x73\xd7\x19\x01"

#: R-057(e), with the basis it was ruled on: Bitcoin blocks average ~10 minutes and
#: OpenTimestamps calendars typically confirm within hours, so a receipt still pending after a
#: day is already anomalous, and after three days something is wrong rather than slow.
UPGRADE_WARN_AFTER = timedelta(hours=24)
UPGRADE_INCIDENT_AFTER = timedelta(hours=72)

#: `20260728T030012123456Z-abc123def456.anchor.json`
_ARTIFACT = re.compile(r"^(\d{8})T(\d{6})(\d{6})Z-[0-9a-f]+\.anchor\.json$")


def published_artifacts(root=ANCHOR_DIRECTORY):
    """Every published payload file, oldest filename first. Filenames sort chronologically."""
    if not root.exists():
        return []
    return sorted(root.rglob("*.anchor.json"))


def artifact_instant(path):
    """The instant in an artifact's filename, or None if the name is not one of ours.

    This is our own clock, recorded in the name at publication. For deciding whether a
    RECEIPT has had time to upgrade that is the right clock and the only one available
    offline — it is an operational staleness question, not a claim about anything.
    """
    match = _ARTIFACT.match(path.name)
    if not match:
        return None
    day, clock, micros = match.groups()
    return datetime(
        int(day[0:4]), int(day[4:6]), int(day[6:8]),
        int(clock[0:2]), int(clock[2:4]), int(clock[4:6]),
        int(micros), tzinfo=timezone.utc,
    )


def entry_for_date(day, artifacts):
    """The artifacts published on a given UTC date, by filename prefix."""
    prefix = day.strftime("%Y%m%d") + "T"
    return [path for path in artifacts if path.name.startswith(prefix)]


def stale_receipts(artifacts, now):
    """Receipts that have not carried a Bitcoin attestation for longer than they should.

    Reads bytes and looks for the attestation tag. A receipt that is merely calendar-pending
    is normal for hours and suspicious for a day; this reports it rather than deciding it.
    """
    warnings, incidents, missing = [], [], []
    for payload in artifacts:
        receipt = payload.with_name(payload.name + ".ots")
        published = artifact_instant(payload)
        if not receipt.exists():
            missing.append(receipt.name)
            continue
        if OTS_BITCOIN_ATTESTATION_TAG in receipt.read_bytes():
            continue
        if published is None:
            continue
        age = now - published
        if age >= UPGRADE_INCIDENT_AFTER:
            incidents.append((receipt.name, age))
        elif age >= UPGRADE_WARN_AFTER:
            warnings.append((receipt.name, age))
    return warnings, incidents, missing


def check(now, root=ANCHOR_DIRECTORY):
    """Returns (ok, report_lines). Pure: everything it needs is an argument."""
    lines = [
        "# anchor watchdog",
        "",
        f"Checked at `{now.strftime('%Y-%m-%dT%H:%M:%SZ')}` against the published record.",
        "",
    ]
    artifacts = published_artifacts(root)

    if not artifacts:
        lines += [
            "**Idle — nothing has been published yet.**",
            "",
            (
                "The record contains no artifacts, so there is nothing that could be missing. "
                "The watchdog arms itself once the first anchor or empty marker is published."
            ),
        ]
        return True, lines

    today = entry_for_date(now, artifacts)
    ok = True

    if today:
        names = ", ".join(f"`{path.name}`" for path in today)
        lines += [f"Today's entry is present: {names}.", ""]
    else:
        ok = False
        newest = artifacts[-1]
        lines += [
            f"## No artifact for {now.strftime('%Y-%m-%d')}",
            "",
            (
                "The public record did not receive an artifact for this date, and it "
                "should have received at least one. Publication runs on a floor cadence — "
                "today, once a day — and again after each batch of new forecasts, so a date "
                "normally carries one artifact or several: an anchor when the Log held rows, "
                "an empty marker when it did not. Several on a date is normal and is not what "
                "this report is about. NONE is the fault, and it means the anchor job did not "
                "complete. Nothing already published has changed — every artifact and every "
                "root already in this repository still verifies exactly as before, by the "
                "unchanged procedure in VERIFY.md. What is missing is a new artifact for this "
                "date, and until it appears any forecast resolving after it is NOT covered "
                "and must not be treated as independently verifiable."
            ),
            "",
            f"The most recent published artifact is `{newest.name}`.",
            "",
            (
                "This check runs outside our infrastructure on purpose, so it cannot tell you "
                "*why*. Likely causes, in the order worth checking: the worker is not running, "
                "its database or GitHub credential is missing or expired, or the job raised "
                "before it could record anything."
            ),
            "",
        ]

    warnings, incidents, missing = stale_receipts(artifacts, now)
    if missing:
        ok = False
        lines += [
            "## Payloads published without a receipt",
            "",
            (
                "Both media travel in one commit, so a payload with no `.ots` beside it means "
                "a publication completed only halfway."
            ),
            "",
        ]
        lines += [f"- `{name}`" for name in missing] + [""]
    if incidents:
        ok = False
        lines += [
            f"## Receipts still not Bitcoin-attested after {UPGRADE_INCIDENT_AFTER}",
            "",
        ]
        lines += [f"- `{name}` — pending for {age}" for name, age in incidents] + [""]
    if warnings:
        lines += [
            f"## Receipts still pending after {UPGRADE_WARN_AFTER} (warning)",
            "",
            "Calendars usually confirm within hours. Not yet an incident.",
            "",
        ]
        lines += [f"- `{name}` — pending for {age}" for name, age in warnings] + [""]

    if ok:
        lines += ["No problems found."]
    return ok, lines


def main():
    override = os.environ.get("WATCHDOG_DATE", "").strip()
    if override:
        now = datetime.strptime(override, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        now = datetime.now(timezone.utc)

    ok, lines = check(now)
    report = "\n".join(lines) + "\n"
    REPORT.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
