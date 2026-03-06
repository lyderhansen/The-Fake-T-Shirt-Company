# Meraki Realism Audit — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 9 realism issues in the Meraki generator covering firewall rules, port distribution, event volumes, field completeness, and typos.

**Architecture:** All changes are in `bin/generators/generate_meraki.py`. No new files needed. Most fixes are localized to event builder functions and the baseline generation functions.

**Tech Stack:** Python 3.8+ (stdlib only)

---

## Findings Summary

| # | Finding | Severity | Impact |
|---|---------|----------|--------|
| F1 | MX firewall uses only 2 ACL patterns ("allow all" / "deny all") | High | Unrealistic — real Meraki MX has named L3/L7 firewall rules |
| F2 | MX firewall destination ports are uniformly distributed | High | 443/80/53 should dominate; SSH/RDP/SMTP should be rare outbound |
| F3 | "Firewall flow denyed" typo in description | Medium | Grammatically incorrect — should be "denied" |
| F4 | MX URL events use single hardcoded user agent | Medium | Every URL event has identical UA string |
| F5 | MR association events missing `ssidName` field | Medium | Real Meraki events include both ssidNumber and ssidName |
| F6 | Switch health events dominate at 49.6% of all Meraki events (1.18M) | High | Drowns out wireless, camera, sensor events in dashboards |
| F7 | MR access point event volume too low (0.7% of all Meraki) | Medium | Only 17K wireless events for 36 APs / 175 users over 14 days |
| F8 | MX URL destination IP is random, unrelated to URL domain | Low | Minor inconsistency — dst should loosely match URL service |
| F9 | Camera weekend motion still ~57% of weekday | Low | Empty offices should have much less motion on weekends |

---

### Task 1: Fix MX Firewall ACL Patterns (F1)

**Files:**
- Modify: `bin/generators/generate_meraki.py:724-759` (mx_firewall_event function)
- Modify: `bin/generators/generate_meraki.py:2469-2488` (firewall generation in generate_mx_baseline_hour)

**What to change:**

Replace the static `"allow all"` / `"deny all"` pattern assignment (line 733) with realistic named firewall rule patterns that match the traffic type.

Add a `FIREWALL_RULES` constant near the top of the file (after `MERAKI_SSIDS`):

```python
# Realistic L3/L7 firewall rule patterns matching Meraki Dashboard format
MX_FIREWALL_RULES = {
    # Allow rules by destination port
    443: {"pattern": "Allow HTTPS outbound", "policy": "allow"},
    80: {"pattern": "Allow HTTP outbound", "policy": "allow"},
    53: {"pattern": "Allow DNS", "policy": "allow"},
    8080: {"pattern": "Allow web proxy", "policy": "allow"},
    25: {"pattern": "Allow SMTP relay", "policy": "allow"},
    587: {"pattern": "Allow SMTP submission", "policy": "allow"},
    # Cross-site / internal
    445: {"pattern": "Allow SMB to DC", "policy": "allow"},
    389: {"pattern": "Allow LDAP to DC", "policy": "allow"},
    636: {"pattern": "Allow LDAPS to DC", "policy": "allow"},
    88: {"pattern": "Allow Kerberos to DC", "policy": "allow"},
    135: {"pattern": "Allow RPC to DC", "policy": "allow"},
    1433: {"pattern": "Allow SQL to DB", "policy": "allow"},
    # Deny rules
    "deny_ssh": {"pattern": "Deny SSH outbound", "policy": "deny"},
    "deny_rdp": {"pattern": "Deny RDP outbound", "policy": "deny"},
    "deny_default": {"pattern": "Default deny", "policy": "deny"},
}
```

In `mx_firewall_event()`, change line 733 from:
```python
pattern = "allow all" if action == "allow" else "deny all"
```
to accept pattern as a parameter and use it directly.

In `generate_mx_baseline_hour()` firewall block (lines 2469-2488), look up the pattern from the port/action:
```python
if action == "allow":
    rule = MX_FIREWALL_RULES.get(dport, {"pattern": "Allow all", "policy": "allow"})
else:
    if dport == 22:
        rule = MX_FIREWALL_RULES["deny_ssh"]
    elif dport == 3389:
        rule = MX_FIREWALL_RULES["deny_rdp"]
    else:
        rule = MX_FIREWALL_RULES["deny_default"]
pattern = rule["pattern"]
```

Pass `pattern` to `mx_firewall_event()`.

---

### Task 2: Fix Destination Port Distribution (F2)

**Files:**
- Modify: `bin/generators/generate_meraki.py:2481-2483` (dport selection in firewall baseline)

**What to change:**

Replace the uniform `random.choice()` with weighted `random.choices()`:

For external traffic (line 2483), change from:
```python
dport = random.choice([80, 443, 53, 8080, 3389, 22, 25, 587])
```
to:
```python
dport = random.choices(
    [443, 80, 53, 8080, 25, 587, 22, 3389],
    weights=[50, 15, 12, 8, 5, 4, 3, 3]
)[0]
```

Also adjust the deny probability to be port-aware: SSH (22) and RDP (3389) outbound should be denied more often (~60% deny), while HTTPS should rarely be denied:
```python
if dport in (22, 3389):
    action = "deny" if random.random() < 0.6 else "allow"
elif dport in (25, 587):
    action = "deny" if random.random() < 0.15 else "allow"
else:
    action = "allow" if random.random() < 0.98 else "deny"
```

---

### Task 3: Fix "denyed" Typo (F3)

**Files:**
- Modify: `bin/generators/generate_meraki.py:739`

**What to change:**

Line 739 currently generates `"Firewall flow denyed"` via `f"Firewall flow {action}ed"`.

Change to explicit mapping:
```python
desc_action = "allowed" if action == "allow" else "denied"
# ...
"description": f"Firewall flow {desc_action}",
```

---

### Task 4: Diversify URL Event User Agents (F4)

**Files:**
- Modify: `bin/generators/generate_meraki.py:762-768` (mx_url_event default agent)
- Modify: `bin/generators/generate_meraki.py:2490-2505` (URL generation)

**What to change:**

Add a `USER_AGENTS` constant:
```python
MX_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]
```

In the URL generation block (line 2505), pass a random agent:
```python
agent = random.choice(MX_USER_AGENTS)
events.append(mx_url_event(ts, mx_device, src_ip, src_port, dst_ip, dst_port, mac, url, agent=agent))
```

Also diversify the URL list with more realistic business URLs (expand from 7 to ~20).

---

### Task 5: Add ssidName to MR Association Events (F5)

**Files:**
- Modify: `bin/generators/generate_meraki.py:1340-1374` (mr_association_event)
- Modify: `bin/generators/generate_meraki.py:2671-2675` (association generation)

**What to change:**

In `mr_association_event()`, add `ssid_name` parameter and include it in the event:
```python
def mr_association_event(ts, device, client_mac, ssid, channel, rssi,
                         radio=1, vap=0, aid=None, client_ip=None,
                         ssid_name=None,  # NEW
                         location=None, demo_id=None):
```

Add to event dict:
```python
if ssid_name:
    event["ssidName"] = ssid_name
```

In the generation block (line 2672-2675), pass the SSID name:
```python
events.append(mr_association_event(
    ts, ap, client_mac, ssid_info["name"], channel, rssi, radio, ssid_info["vap"],
    client_ip=client_ip, ssid_name=ssid_info["name"]
))
```

---

### Task 6: Reduce Switch Health Volume (F6)

**Files:**
- Modify: `bin/generators/generate_meraki.py` — the `generate_ms_port_health()` call site

**What to change:**

The switch health generates 1.18M events (49.6% of all Meraki) because it reports every port on every switch every 5 minutes. Two approaches to reduce volume:

**Option A (recommended): Only report ports that changed status**

Instead of reporting all 48 ports every interval, track port states and only report:
- Changed ports (status flipped since last interval)
- A small random sample of unchanged ports (~10%) as health confirmation
- Always report uplink ports

This would reduce volume by ~80-90% while keeping the same data pattern.

**Option B: Increase polling interval**

Change default interval from 5 to 15 minutes. This reduces volume by 67% (from 12 to 4 samples/hour).

**Implement Option A:**

Add port state tracking per switch per day. At the start of each hour, determine which ports are connected based on the same business-hours logic. Report:
- First interval of the day: all ports (baseline)
- Subsequent intervals: only changed ports + 10% random sample + uplinks
- Transitional hours (8-9 AM arrival, 17-18 PM departure): more status changes

Expected reduction: ~1.18M → ~200K events (still the largest sourcetype, but not 50% of all events).

---

### Task 7: Increase MR Wireless Event Volume (F7)

**Files:**
- Modify: `bin/generators/generate_meraki.py` — the MR events_per_hour calculation in the main generation loop

**What to change:**

Currently generating ~1,224 MR events/day across 36 APs. That's 34 events per AP per day, which is unrealistically low.

A real office AP handles 10-30 clients roaming in/out throughout the day. With associations, disassociations, 802.1X auth, and other events, a busy AP should generate 20-50 events/hour during business hours.

Find where `events_per_hour` is calculated for MR and increase the base volume. Look at the main loop's MR scaling — likely need to multiply the base MR event count by 3-5x.

Target: ~50-80K MR events over 14 days (~4,000-5,700/day).

---

### Task 8: Diversify MX URL Destinations (F8)

**Files:**
- Modify: `bin/generators/generate_meraki.py:2496-2504` (URL list and dst_ip generation)

**What to change:**

Expand the URL list and loosely match dst IP ranges to known services. Create a mapping of URL domains to representative IP ranges:

```python
MX_URL_DESTINATIONS = [
    {"url": "https://www.google.com/search?q={}", "dst_range": "142.250.", "port": 443, "weight": 15},
    {"url": "https://www.microsoft.com/en-us/", "dst_range": "13.107.", "port": 443, "weight": 10},
    {"url": "https://login.microsoftonline.com/", "dst_range": "20.190.", "port": 443, "weight": 8},
    {"url": "https://github.com/", "dst_range": "140.82.", "port": 443, "weight": 5},
    {"url": "https://slack.com/", "dst_range": "54.239.", "port": 443, "weight": 8},
    {"url": "https://app.webex.com/", "dst_range": "170.72.", "port": 443, "weight": 6},
    {"url": "https://outlook.office365.com/", "dst_range": "52.96.", "port": 443, "weight": 10},
    {"url": "https://cdn.shopify.com/assets/{}", "dst_range": "23.227.", "port": 443, "weight": 5},
    {"url": "https://api.salesforce.com/", "dst_range": "136.147.", "port": 443, "weight": 4},
    {"url": "https://www.amazon.com/", "dst_range": "54.239.", "port": 443, "weight": 4},
    {"url": "http://www.example{}.com/page", "dst_range": None, "port": 80, "weight": 10},
    {"url": "https://cdn.example.com/assets/{}", "dst_range": None, "port": 443, "weight": 8},
    {"url": "https://jira.atlassian.net/", "dst_range": "104.192.", "port": 443, "weight": 5},
    {"url": "https://docs.google.com/", "dst_range": "142.250.", "port": 443, "weight": 5},
]
```

When `dst_range` is provided, generate the dst IP using that prefix + random octets.

---

### Task 9: Reduce Weekend Camera Motion (F9)

**Files:**
- Modify: `bin/generators/generate_meraki.py` — camera motion generation for weekends

**What to change:**

In `generate_meeting_room_cameras_hour()` and the general camera baseline function, reduce weekend motion events. Currently weekend motion is ~57% of weekday.

For meeting room cameras on weekends with no meetings, motion should be very rare (cleaning staff, security patrol):
- Weekday with meeting: 2-4 motion events/hour (current)
- Weekday without meeting: 0-1 motion events/hour
- Weekend: 0-1 motion events per 4 hours (significantly reduced)

Find the baseline camera generation and add weekend scaling.

---

## Verification

After implementing all tasks, run:

```bash
# Full generation test
python3 bin/main_generate.py --sources=meraki --days=14 --scenarios=all --test --quiet

# Verify in Splunk after indexing:
# F1: Check firewall patterns - should see named rules
index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" type=firewall | spath eventData.pattern | stats count by eventData.pattern | sort -count

# F2: Check port distribution - 443 should dominate
index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" type=firewall | spath eventData.dport | stats count by eventData.dport | sort -count

# F3: Check typo fix
index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" type=firewall | stats count by description

# F5: Check ssidName present
index=fake_tshrt sourcetype="FAKE:meraki:accesspoints" type=association | spath ssidName | stats count by ssidName

# F6: Check volume ratio
index=fake_tshrt sourcetype="FAKE:meraki:*" | stats count by sourcetype | sort -count

# F7: Check MR volume increase
index=fake_tshrt sourcetype="FAKE:meraki:accesspoints" | stats count
```

## Expected Impact

- **F1**: 2 patterns → ~15 realistic named firewall rules
- **F2**: Flat distribution → 443 at 50%, realistic traffic profile
- **F3**: "denyed" → "denied"
- **F4**: 1 user agent → 6 diverse browser UAs
- **F5**: Missing ssidName → present on all association events
- **F6**: 1.18M switch health → ~200-300K (no longer dominates)
- **F7**: 17K MR events → ~50-80K (proportional to user count)
- **F8**: Random dst IPs → service-matched IP ranges
- **F9**: 57% weekend camera motion → ~15% of weekday
