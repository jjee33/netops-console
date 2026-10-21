# Device history, scan comparison and result explanations

What these features show, where the data comes from, and where they stop.

## The rule they follow

Every entry is a record something else wrote when it happened. The console
does not poll, sample or interpolate. **Between two scans nothing is known, so
nothing is shown.** If you want fresher history, run a scan; nothing runs on
its own.

| Source | Written when | Holds |
|---|---|---|
| Scan observation | A discovery scan finishes | Per device: whether it answered, and the address, MAC, hostname, vendor and open ports *that scan* returned |
| Diagnostic result | You run a check | Status, output, latency and loss |
| Action execution | You run an action | Status and the redacted command |
| Change event | You change something | Who, when, from where, and what changed |

## Device history

Open a device, then **History** (`/devices/{id}/history`).

**Scan coverage** counts the scans that covered the device's address and how
many it answered. **Timeline** lists only transitions:

- **First recorded** — the first scan that saw it, with what it saw.
- **Changed** — something differs from the previous sighting: IP address, MAC,
  hostname, vendor, or open ports.
- **Did not answer** — a known device inside the scanned range was silent. Listed
  once per silent spell, not once per scan.
- **Answered again** — back after silence, compared with the last time it was
  *seen*, so a change made while it was away still shows.

A scan that saw exactly what the previous one saw adds no row; it shows up in
the coverage counts instead. Diagnostics, actions and your own edits appear in
the same timeline.

For a long-lived device, the page reads the most recent 100 records of each
kind. If any kind has more, the whole timeline stops at the oldest record shown
for that kind, so it never shows a gap where checks or scans are missing. The
page says when this happens. The coverage counts always cover the full
history, and the oldest scan shown is compared with the scan before it, so it
is never reported as a first sighting.

### Reading it correctly

- **"Ports not compared"** means one of the two scans ran without port
  detection. It never means the ports closed.
- **"Hostname: nas.lan → not reported"** means that scan's reverse lookup
  returned no name. The device's stored hostname is kept; the timeline records
  what the scan actually saw.
- **"Did not answer"** is an inference: the device's address is inside the
  range and it did not respond. It may be off, asleep, filtering probes, or on a
  new address. If it moved, the next scan finds it by MAC and records the
  address change.

## Scan reports and comparison

Every row in **Discovery → History** links to a report
(`/discovery/runs/{id}/report`): each host the scan recorded, and each known
device in the range that did not answer.

**Compare two scans** (`/discovery/compare`) defaults to the two most recent
scans of the same range. It sorts hosts into four groups: new, no longer
answering, outside the later scan's range, and changed. It matches hosts by the
identity resolved at scan time, MAC first and then address, so a device that
moved shows as *changed*, not as one host gone and another new.

## Result explanations

Diagnostic results and scan reports can carry a short explanation: what the
result most likely means, the evidence it is based on, plausible causes, and
the next check to run. These are fixed rules over the stored output, not a
model, so the same output always gets the same explanation.

Several fire on runs that report **success**, because the status misleads:

| Result | Why status is not enough |
|---|---|
| DNS lookup with an empty answer | `dig` exits 0 for a name that does not exist |
| TCP port test showing `closed` or `filtered` | an nmap connect test exits 0 either way |
| ARP entry with no output | the read succeeded; the table is just empty |
| A scan that found hosts but no MAC addresses | the symptom of running without host networking, otherwise visible only as empty columns |

An explanation names likely causes, never *the* cause. Treat it as a starting
point for troubleshooting.

## The change log

Device edits and removal, SSH host key trust and revocation, credential
create, delete, assign and unassign, action create, enable, disable and delete,
and settings changes all write a row. They appear under **Audit → Changes** and
on the affected device's timeline. A credential appears by name and username
only. Revoking a host key used to erase the only record of who had trusted it;
the change log keeps it.

## Retention and size

Scan observations follow the same **retention days** setting as diagnostic and
action history, and are pruned after each scan. That setting is therefore also
how far back device history reaches. Each scan writes one small row per device
in its range, with no output blob. Run summaries and the change log are kept
indefinitely, like discovery runs always have been.

## Upgrading from an earlier version

Scans run before this version recorded only summary counts. Their reports and
comparisons say *"recorded before per-host scan history existed"* rather than
showing an empty scan. History starts with the first scan after the upgrade.
