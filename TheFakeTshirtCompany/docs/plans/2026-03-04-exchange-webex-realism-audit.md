# Exchange & Webex Realism Audit — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix realism issues in Exchange message trace and Webex (TA + API) generators — improve subject diversity, fix correlation gaps, correct geographic assumptions, remove unrealistic patterns.

**Architecture:** Exchange generator (`generate_exchange.py`) produces `ms:o365:reporting:messagetrace` events. Webex TA (`generate_webex_ta.py`) produces `cisco:webex:meetings:history:*` records. Webex API (`generate_webex_api.py`) produces REST API format across 5 sourcetypes. All three consume the shared `meeting_schedule.py`. Fixes target data realism without changing Splunk config (field names, sourcetypes unchanged).

**Tech Stack:** Python 3.8+ stdlib only. Splunk TA-FAKE-TSHRT.

---

## Findings Summary

| ID | Finding | Severity | Generator | Evidence |
|----|---------|----------|-----------|----------|
| F1 | Only 10 internal email subject lines | Critical | Exchange | 33,819 events across 10 subjects (~3,400 each) |
| F2 | Only 3 outbound recipient name prefixes | High | Exchange | 77 unique recipients: `contact@`, `info@`, `orders@` × 11 domains |
| F3 | Calendar invite/response subject mismatch | High | Exchange | Invites: "Meeting Invite: All Hands - Link", Responses: "Accepted: All Hands" (no room) |
| F4 | Flat overnight email volume | Medium | Exchange | Hours 0-5 all exactly 904 events, hours 19-21 all exactly 1812 |
| F5 | Weekend email ratio 1.3% | Medium | Exchange | 377/day weekend vs 11,595/day weekday — too low |
| F6 | All meetings use America/New_York timezone | High | Webex API | 2,321 meetings all Eastern, even ATL/AUS (Central) |
| F7 | Server regions uniformly distributed | Medium | Webex API | Perfect 20% split across 5 regions including Tokyo for US company |
| F8 | Call Direction always ORIGINATING | Medium | Webex API | 1,259 calls, 100% ORIGINATING, no TERMINATING leg |
| F9 | Call answer rate 90% | Low | Webex API | Real enterprise: 65-75% |
| F10 | International calls always 0 | Low | Webex TA | totalCallOutInternational hardcoded to 0 |
| F11 | Baseline calendar events duplicate meeting invites | Low | Exchange | Baseline generates 6% calendar invites + 5% responses PLUS meeting_schedule generates its own set |

---

## What's Already Good (No Changes Needed)

- Meeting ID correlation: 2,321 shared UUIDs across TA + API (99.9% match)
- Ghost meeting handling: 10.6% ghost rate, consistent `duration=0` (TA) / `state=missed` (API)
- Exchange hourly volume curve: correct peak at 10-11 AM, lunch dip, evening taper
- SPF/DKIM/DMARC on inbound: 85% pass rate is realistic
- Calendar invite count proportional to meeting schedule
- Attendee join/leave variance: ±3-5 min realistic
- Quality sample counts match meeting durations

---

## Task 1: Expand Internal Email Subject Pool

**Files:**
- Modify: `bin/shared/company.py:1703-1709`

**Problem:** 10 subjects repeated ~3,400× each across 33,819 internal emails. Immediately recognizable as synthetic.

**Step 1: Replace EMAIL_SUBJECTS_INTERNAL with 60+ diverse subjects**

Replace the 10-item list at `company.py:1703` with a categorized pool of 60+ realistic business email subjects. Include:

```python
EMAIL_SUBJECTS_INTERNAL = [
    # Replies and follow-ups (prefix with RE:/FW:)
    "RE: Q4 Budget Review", "RE: Action Items from Yesterday",
    "RE: Updated Timeline", "RE: Feedback Needed", "RE: Quick Follow-up",
    "FW: Updated Policy Document", "FW: Customer Feedback",
    "FW: Vendor Proposal", "FW: Conference Room Changes",
    "FW: New Hire Onboarding Checklist",
    # Direct questions
    "Quick Question", "Question about the deployment",
    "Can you review this?", "Need your input",
    "Thoughts on this approach?", "Available for a quick call?",
    # Meeting related
    "Meeting Notes - Project Sync", "Agenda for Tomorrow",
    "Recap: Sprint Retro", "Pre-read for Thursday",
    "Notes from today's standup", "Follow-up from 1:1",
    # Status and updates
    "Weekly Status Update", "EOD Update",
    "Release Notes v2.14", "Deployment Complete",
    "Incident Resolved - API Latency", "Change Request #4521",
    # Social/HR
    "Team Lunch Friday?", "Happy Hour This Week",
    "Out of Office: Back Monday", "Birthday Celebration - Break Room",
    "Welcome New Team Member", "Parking Lot Update",
    # Project specific
    "RE: Migration Plan Review", "RE: API Design Feedback",
    "Database Maintenance Window", "Test Results - Sprint 14",
    "Code Review Request", "PR #342 Ready for Merge",
    "Staging Environment Down", "SSL Cert Renewal Reminder",
    # Administrative
    "RE: Invoice Approval Needed", "Expense Report - January",
    "PTO Request - Feb 10-14", "Equipment Request",
    "VPN Access Request", "Badge Access Update",
    "RE: Headcount Planning", "RE: Q1 OKR Draft",
    # Customer/vendor
    "RE: Customer Escalation - ACME Corp",
    "Vendor Contract Renewal", "RFP Response Draft",
    "Partner Integration Update", "Support Ticket Escalation",
    # IT/Operations
    "Password Expiry Reminder", "Software License Audit",
    "Backup Job Failed - MON-ATL-01", "Firewall Rule Change Request",
    "New Laptop Provisioning", "MFA Token Reset",
    # General
    "FYI - Updated Org Chart", "Shared Drive Permissions",
    "Documentation Updated", "New Process - Effective Monday",
    "Reminder: Timesheet Due", "Building Maintenance Notice",
]
```

**Step 2: Verify**

Run: `python3 bin/main_generate.py --sources=exchange --days=1 --test --quiet`

Check: `python3 -c "import json; from collections import Counter; c=Counter(); [c.update([json.loads(l).get('Subject','')]) for l in open('bin/output/tmp/cloud/microsoft/exchange_message_trace.json')]; print(f'Unique subjects: {len(c)}'); print('Max repeats:', c.most_common(1)[0][1])"`

Expected: 50+ unique subjects, max repeats < 300 per subject per day.

**Step 3: Commit**
```
git add bin/shared/company.py
git commit -m "fix(exchange): Expand internal email subjects from 10 to 60+"
```

---

## Task 2: Diversify Outbound Recipient Addresses

**Files:**
- Modify: `bin/generators/generate_exchange.py:221-249` (outbound_message function)
- Modify: `bin/shared/company.py:1693-1701` (EXTERNAL_MAIL_DOMAINS, PARTNER_DOMAINS)

**Problem:** Only 3 prefixes (`contact@`, `info@`, `orders@`) × 11 domains = 77 combos. Real outbound has diverse personal names.

**Step 1: Add realistic name-based recipients**

In `generate_exchange.py` outbound_message(), replace the generic prefix selection with a mix:

```python
# 60% personal names, 40% generic prefixes
if random.random() < 0.6:
    first = random.choice(["james", "sarah", "michael", "jennifer", "david", "lisa",
                           "robert", "maria", "william", "amanda", "chris", "emily",
                           "brian", "rachel", "kevin", "nicole", "jason", "ashley",
                           "mark", "laura", "daniel", "karen", "andrew", "megan"])
    last = random.choice(["wilson", "anderson", "thomas", "jackson", "white", "harris",
                          "martin", "garcia", "martinez", "robinson", "clark", "lewis",
                          "lee", "walker", "hall", "allen", "young", "king",
                          "wright", "scott", "green", "baker", "adams", "nelson"])
    sep = random.choice([".", "_", ""])
    recipient = f"{first}{sep}{last}@{domain}"
else:
    prefix = random.choice(["contact", "info", "sales", "support", "orders",
                            "billing", "procurement", "hr", "accounts", "enquiries"])
    recipient = f"{prefix}@{domain}"
```

**Step 2: Verify**

Run exchange generator, check unique outbound recipients > 500.

**Step 3: Commit**
```
git commit -m "fix(exchange): Diversify outbound recipient addresses with personal names"
```

---

## Task 3: Fix Calendar Invite-Response Subject Correlation

**Files:**
- Modify: `bin/generators/generate_exchange.py:686` (response subject)

**Problem:** Invites include room: `"Meeting Invite: All Hands - Link"`. Responses omit room: `"Accepted: All Hands"`. Cannot correlate in Splunk by subject.

**Step 1: Include room in response subject**

At line 686, change:
```python
subject = f"{response_type}: {meeting.meeting_title}"
```
to:
```python
room_info = f" - {meeting.room}" if meeting.room else ""
subject = f"{response_type}: {meeting.meeting_title}{room_info}"
```

Also add `MeetingRoom` field to response event (line 708, it's missing):
```python
"MeetingRoom": meeting.room,
"MeetingLocation": meeting.location_code,
```

**Step 2: Verify**

Run exchange generator, check that response subjects include room names.

**Step 3: Commit**
```
git commit -m "fix(exchange): Include room name in calendar response subjects for correlation"
```

---

## Task 4: Remove Duplicate Baseline Calendar Events

**Files:**
- Modify: `bin/generators/generate_exchange.py:711-775` (generate_baseline_hour)

**Problem:** The baseline hour generation produces 6% calendar invites + 5% calendar responses as random, non-correlated events. Meanwhile, `generate_meeting_emails_for_day()` already produces properly correlated invites+responses from the meeting schedule. The baseline calendar events are unrealistic noise — they reference generic meeting types with no actual meeting backing them.

**Step 1: Redirect baseline calendar budget to other event types**

In `generate_baseline_hour()`, replace the 6% calendar invite and 5% calendar response allocation with additional internal (5%) and inbound (3%) and distribution list (3%) events:

Change distribution from:
```
34% Internal, 19% Inbound, 14% Outbound, 8% DL, 7% System, 6% Calendar, 5% Calendar-Response, 3% Failed, 2% OOO, 1% Spam
```
to:
```
39% Internal, 22% Inbound, 14% Outbound, 11% DL, 7% System, 3% Failed, 2% OOO, 1% Spam
```

Remove the `calendar_invite()` and `calendar_response()` calls from the baseline hour event selection. All calendar events now come exclusively from the meeting schedule integration.

**Step 2: Verify**

Run exchange generator, confirm:
- Calendar events come only from meeting schedule (SourceContext=Calendar has MeetingRoom field)
- No orphaned calendar invites without matching meetings
- Total event count similar (±5%)

**Step 3: Commit**
```
git commit -m "fix(exchange): Remove duplicate baseline calendar events, all calendar from meeting schedule"
```

---

## Task 5: Fix Overnight Volume Flatness

**Files:**
- Modify: `bin/generators/generate_exchange.py` (main generation loop, ~line 862)

**Problem:** Hours 0-5 all produce exactly 904 events (identical). Hours 19-21 all produce 1812 (identical). Real email volume has gradual variation even at night — not step functions.

**Step 1: Add per-hour noise to overnight periods**

After computing `hour_events` from `calc_natural_events()`, apply a ±20% random variation:

```python
hour_events = calc_natural_events(base_events_per_peak_hour, start_date, day, hour, "email")
# Add per-hour noise to prevent identical counts across low-activity hours
hour_noise = random.Random(hash(f"exchange:{start_date}:{day}:{hour}")).gauss(1.0, 0.15)
hour_events = max(1, int(hour_events * max(0.7, min(1.3, hour_noise))))
```

**Step 2: Verify**

Run exchange generator 1 day, check that midnight hours show varied counts (not identical).

**Step 3: Commit**
```
git commit -m "fix(exchange): Add per-hour volume noise to prevent flat overnight counts"
```

---

## Task 6: Fix Weekend Email Volume

**Files:**
- Modify: `bin/generators/generate_exchange.py` (weekend handling, ~line 841+)

**Problem:** Weekend produces only 1.3% of total volume (377/day). Expected 3-5% from system notifications, auto-replies, and automated processes.

**Step 1: Investigate root cause**

Check if the issue is in `calc_natural_events()` or in the generator itself. The "email" traffic type in `time_utils.py` may have a very aggressive weekend multiplier.

If the weekend multiplier for "email" is set to something like 0.03 (3%), increase it to `0.08` (8% of weekday peak). This would produce ~900 events/day on weekends (8% × 11,500) which is realistic for automated systems + a few people checking email.

**Step 2: Verify**

Run 7-day generation, check weekend/weekday ratio is 5-10%.

**Step 3: Commit**
```
git commit -m "fix(exchange): Increase weekend email volume from 1.3% to ~8%"
```

---

## Task 7: Fix Webex API Meeting Timezone

**Files:**
- Modify: `bin/generators/generate_webex_api.py:195` (hardcoded timezone)

**Problem:** All 2,321 meetings use `America/New_York`. Atlanta and Austin are Central time.

**Step 1: Map timezone from meeting location**

```python
LOCATION_TIMEZONES = {
    "BOS": "America/New_York",
    "ATL": "America/New_York",   # Atlanta is Eastern
    "AUS": "America/Chicago",    # Austin is Central
}
```

Note: Atlanta is actually Eastern Time (ET), same as Boston. Only Austin is Central. Fix the timezone lookup to use meeting.location_code:

```python
timezone = LOCATION_TIMEZONES.get(meeting.location_code, "America/New_York")
```

For cross-site meetings, use the organizer's location timezone.

**Step 2: Verify**

Run webex_api generator, check timezone distribution shows both Eastern and Central.

**Step 3: Commit**
```
git commit -m "fix(webex_api): Use location-based timezone instead of hardcoded Eastern"
```

---

## Task 8: Fix Webex API Server Region Distribution

**Files:**
- Modify: `bin/generators/generate_webex_api.py` (quality record generation, serverRegion field)

**Problem:** Perfect 20% uniform split across San Jose, Chicago, London, Frankfurt, Tokyo. US-based company should route primarily to US data centers.

**Step 1: Weight server regions by participant location**

```python
# US participants → 85% US regions, 15% international
US_REGION_WEIGHTS = {
    "San Jose, USA": 45,
    "Chicago, USA": 40,
    "London, UK": 7,
    "Frankfurt, DE": 5,
    "Tokyo, JP": 3,
}

# External participants → more international
EXTERNAL_REGION_WEIGHTS = {
    "San Jose, USA": 25,
    "Chicago, USA": 20,
    "London, UK": 25,
    "Frankfurt, DE": 20,
    "Tokyo, JP": 10,
}
```

Select weights based on whether participant email is internal or external.

**Step 2: Verify**

Run webex_api, check San Jose + Chicago > 70%.

**Step 3: Commit**
```
git commit -m "fix(webex_api): Weight server regions by participant location (US-heavy)"
```

---

## Task 9: Add TERMINATING Call Direction

**Files:**
- Modify: `bin/generators/generate_webex_api.py` (call history generation)

**Problem:** All 1,259 calls have `Direction: "ORIGINATING"`. Real CDR data produces a TERMINATING record for the receiving party.

**Step 1: Generate both call legs**

For each call, generate:
1. **ORIGINATING** record (caller side) — existing behavior
2. **TERMINATING** record (callee side) — new

The TERMINATING record swaps caller/callee fields:
- `Calling line ID` → becomes the called party name
- `Called line ID` → becomes the caller name
- `Direction` = `"TERMINATING"`
- Same `Correlation ID` to link both legs
- `User` field = called party's email

**Step 2: Also fix answer rate**

Change from 90% to 75% success rate:
```python
answered = random.random() < 0.75  # Was 0.90
```

**Step 3: Verify**

Run webex_api, check Direction distribution ~50/50 ORIGINATING/TERMINATING.

**Step 4: Commit**
```
git commit -m "fix(webex_api): Add TERMINATING call legs, reduce answer rate to 75%"
```

---

## Task 10: Add International Call Support

**Files:**
- Modify: `bin/generators/generate_webex_ta.py` (meeting usage record, totalCallOutInternational)

**Problem:** `totalCallOutInternational` is always 0. A company with external meeting participants would have occasional international calls.

**Step 1: Add small international call probability**

In the meeting usage record creation, change:
```python
"totalCallOutInternational": "0",
```
to:
```python
"totalCallOutInternational": str(random.choice([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])),  # ~10% chance
```

Only when meeting has external participants, increase to ~20%:
```python
has_external = any(not e.endswith("@theFakeTshirtCompany.com") for e in meeting.participants)
intl_calls = random.randint(0, 1) if has_external and random.random() < 0.2 else 0
"totalCallOutInternational": str(intl_calls),
```

**Step 2: Verify**

Run webex_ta, check totalCallOutInternational has some non-zero values.

**Step 3: Commit**
```
git commit -m "fix(webex_ta): Add occasional international call-out for external meetings"
```

---

## Task 11: Full Regression Test

**Step 1: Generate all sources**
```bash
python3 bin/main_generate.py --all --days=14 --scenarios=all --test --quiet
```

**Step 2: Verify fixes from output files**

```bash
# F1: Subject diversity (expect 50+ unique)
python3 -c "import json; from collections import Counter; c=Counter(); [c.update([json.loads(l)['Subject']]) for l in open('bin/output/tmp/cloud/microsoft/exchange_message_trace.json') if json.loads(l).get('SourceContext')=='Internal']; print(f'Unique internal subjects: {len(c)}, Max repeats: {c.most_common(1)[0][1]}')"

# F2: Outbound recipients (expect 500+)
python3 -c "import json; s=set(); [s.add(json.loads(l)['RecipientAddress']) for l in open('bin/output/tmp/cloud/microsoft/exchange_message_trace.json') if json.loads(l).get('Directionality')=='Outbound']; print(f'Unique outbound recipients: {len(s)}')"

# F3: Calendar response subjects include room
python3 -c "import json; [print(json.loads(l)['Subject']) for i, l in enumerate(open('bin/output/tmp/cloud/microsoft/exchange_message_trace.json')) if json.loads(l).get('SourceContext')=='Calendar-Response' and i < 5]"

# F4: Overnight variation (expect different counts per hour)
python3 -c "import json; from collections import Counter; h=Counter(); [h.update([json.loads(l)['Received'].split('T')[1][:2]]) for l in open('bin/output/tmp/cloud/microsoft/exchange_message_trace.json')]; [print(f'{k}:00 = {h[k]}') for k in sorted(h) if int(k) < 6]"

# F6: Timezone (expect both Eastern and Central)
python3 -c "import json; from collections import Counter; t=Counter(); [t.update([json.loads(l).get('timezone','')]) for l in open('bin/output/tmp/cloud/webex/webex_api_meetings.json')]; [print(f'{k}: {v}') for k, v in t.most_common()]"

# F7: Server regions (expect US-heavy)
python3 -c "import json; from collections import Counter; r=Counter(); [r.update([json.loads(l).get('serverRegion','')]) for l in open('bin/output/tmp/cloud/webex/webex_api_meeting_qualities.json')]; [print(f'{k}: {v}') for k, v in r.most_common()]"

# F8: Call directions (expect ORIGINATING + TERMINATING)
python3 -c "import json; from collections import Counter; d=Counter(); [d.update([json.loads(l).get('Direction','')]) for l in open('bin/output/tmp/cloud/webex/webex_api_call_history.json')]; [print(f'{k}: {v}') for k, v in d.most_common()]"
```

**Step 3: Commit**
```
git commit -m "test: Verify Exchange + Webex realism audit fixes"
```

---

## Task 12: Update CHANGEHISTORY.md

**Files:**
- Modify: `docs/CHANGEHISTORY.md`

Document all changes with:
- Date/time UTC
- All affected files
- Summary of 11 findings and fixes
- Verification results from regression test

---

## Verification Matrix

| Finding | Verification Query | Pass Criteria |
|---------|-------------------|---------------|
| F1: Subject diversity | Count unique internal subjects | > 50 unique |
| F2: Outbound recipients | Count unique outbound recipients | > 500 unique |
| F3: Calendar correlation | Compare invite/response subjects | Room name present in both |
| F4: Overnight flatness | Compare hour 0-5 event counts | No identical adjacent hours |
| F5: Weekend volume | Weekend/total ratio | 5-10% |
| F6: Timezone | Count unique timezones | 2+ timezones |
| F7: Server regions | Region distribution | US regions > 70% |
| F8: Call direction | Direction distribution | Both ORIGINATING + TERMINATING |
| F9: Answer rate | NoAnswer / total ratio | ~25% |
| F10: International calls | Non-zero totalCallOutInternational | Some > 0 |
| F11: Baseline calendar | SourceContext=Calendar without MeetingRoom | 0 orphaned |
