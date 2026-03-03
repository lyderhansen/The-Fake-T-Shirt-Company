# Cisco ASA Generator Realism Audit

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix logical flaws and realism issues in `generate_asa.py` so the synthetic ASA logs match what a real Cisco ASA 5525-X would actually produce.

**Architecture:** The ASA generator produces syslog events for FW-EDGE-01 (perimeter firewall). Issues were found via Splunk data analysis and comparison with official Splunk_TA_cisco-asa field extraction regexes. Fixes are isolated to `generate_asa.py` with minor changes to `company.py`.

**Tech Stack:** Python 3.8+ (stdlib only), Splunk SPL for verification

---

## Findings Summary

| # | Issue | Severity | Category |
|---|-------|----------|----------|
| F1 | NAT addresses identical to real addresses in 302013/302014 | **Critical** | Format realism |
| F2 | 41 phantom DMZ IPs (only WEB-01/02 exist) | **Critical** | Network accuracy |
| F3 | "inbound" direction on inside->inside traffic | **High** | Protocol accuracy |
| F4 | External scans target `inside` zone IPs directly | **High** | Firewall logic |
| F5 | 585 zero-duration sessions with >0 bytes | **Medium** | Data consistency |
| F6 | CID reuse within same day (900K range wrapping) | **Medium** | Correlation |
| F7 | Only 4 teardown reasons (real ASA has more) | **Low** | Variety |
| F8 | DNS always to external resolvers (no internal DC DNS) | **Low** | Network accuracy |

---

## Finding Details

### F1: NAT Addresses Identical to Real Addresses (CRITICAL)

**Problem:** Every 302013 Built event shows parenthetical NAT addresses identical to the real addresses:
```
Built outbound TCP connection 180355
  for inside:10.20.30.96/49529 (10.20.30.96/49529)     <-- same!
  to outside:54.239.28.85/80 (54.239.28.85/80)          <-- same!
```

**Real ASA behavior:** The parenthetical addresses show the **post-NAT** (translated) addresses. For outbound traffic with dynamic PAT:
```
Built outbound TCP connection 180355
  for inside:10.20.30.96/49529 (203.0.113.5/49529)      <-- NAT'd to public IP
  to outside:54.239.28.85/80 (54.239.28.85/80)           <-- dest unchanged
```

For inbound traffic to DMZ with static NAT:
```
Built inbound TCP connection 340136
  for outside:174.63.88.98/59400 (174.63.88.98/59400)    <-- src unchanged
  to dmz:172.16.1.10/443 (203.0.113.50/443)              <-- shows public VIP
```

**Impact:** Anyone familiar with ASA logs will immediately see that NAT is not functioning. The 305011/305012 NAT events exist separately but are disconnected from the 302013/302014 events. Splunk fields `src_translated_ip`, `dest_translated_ip` are always identical to `src_ip`, `dest_ip`, making NAT correlation dashboards useless.

**Fix:**
- Outbound (inside->outside): Set `src_translated_ip` to a PAT address from 203.0.113.{1-10} pool
- Inbound to DMZ (outside->dmz): Set `dest_translated_ip` to public VIP (203.0.113.50 for WEB-01, 203.0.113.51 for WEB-02)
- Inside->inside, dmz->inside: Keep same (no NAT -- identity NAT shows same addresses, which is correct)

---

### F2: 41 Phantom DMZ IPs (CRITICAL)

**Problem:** Registry-driven web sessions produce 41 unique DMZ destination IPs (172.16.1.10 through 172.16.1.50). Only WEB-01 (172.16.1.10) and WEB-02 (172.16.1.11) actually exist in the DMZ.

**Data evidence:**
- WEB-01/02: ~3,750 sessions each (correct -- from `asa_web_session()`)
- 172.16.1.12-50: ~200 sessions each (wrong -- from registry-driven sessions)

**Root cause:** The access log generator (`generate_access.py`) assigns random DMZ IPs to sessions in the order registry, and `asa_web_session_from_registry()` uses those IPs verbatim without clamping to valid servers.

**Fix:** In `asa_web_session_from_registry()`, map any `dst` IP in the 172.16.1.x range to either WEB-01 (172.16.1.10) or WEB-02 (172.16.1.11) using a hash of the session for deterministic distribution. Alternatively, fix the access log generator to only use valid DMZ IPs.

---

### F3: "inbound" Direction on inside->inside Traffic (HIGH)

**Problem:** 9,067 events show `Built inbound TCP connection` for traffic between two `inside` interfaces:
```
Built inbound TCP connection 339748
  for inside:10.30.30.90/50934 (10.30.30.90/50934)
  to inside:10.10.20.11/88 (10.10.20.11/88)
```

**Real ASA behavior:** For same-security-level traffic, the ASA does NOT use "inbound" or "outbound". It shows the direction relative to the **initiating** interface. For inside-to-inside traffic (when `same-security-traffic permit inter-interface` is configured), the correct format is:
```
Built TCP connection 339748
  for inside:10.30.30.90/50934 (10.30.30.90/50934)
  to inside:10.10.20.11/88 (10.10.20.11/88)
```

No direction keyword when src and dst are on the same security level.

Similarly, `inside->management` (376 events) should not say "inbound".

**Affected traffic types:** DC traffic, site-to-site, backup, new server traffic -- any inside->inside flow.

**Fix:** In Built event formatting, omit direction when `src_zone == dst_zone` or when both zones are equal security level (inside=100, management=100).

---

### F4: External Scans Target `inside` Zone Directly (HIGH)

**Problem:** Deny events (106023) for external scans show the destination as `inside:10.x.x.x`:
```
Deny tcp src outside:91.231.58.2/48143 dst inside:10.30.30.78/110
```

**Real ASA behavior:** An external attacker cannot directly reach internal 10.x.x.x addresses. The ASA would deny the packet at the **outside** interface. The denied destination would be either:
1. The **public IP** of the firewall (203.0.113.1) if port-scanning the perimeter
2. A **DMZ IP** (172.16.1.x) if targeting DMZ services
3. The ASA's outside interface IP itself

An external host scanning port 110 on 10.30.30.78 is impossible -- that IP is not routable from the internet.

**Fix:** External scan deny events should target:
- 60% public IPs (203.0.113.{1-10} NAT pool + 203.0.113.50/51 VIPs) with `dst outside:` zone
- 30% DMZ IPs (172.16.1.10/11) with `dst dmz:` zone
- 10% the ASA's own outside interface (203.0.113.1) with `dst outside:` zone

---

### F5: Zero-Duration Sessions with >0 Bytes (MEDIUM)

**Problem:** 585 teardown events show `duration 0:0:0` but have up to 49,952 bytes transferred. Transferring 50KB in exactly 0 seconds is unrealistic.

**Fix:** If `bytes > 0`, ensure `duration >= 1` second minimum. Quick connections (small API calls) can be 1s, but 0s with data is a data inconsistency.

---

### F6: CID Reuse Within Same Day (MEDIUM)

**Problem:** Connection IDs like 160880 appear in 4 events (2 Built + 2 Teardown) within the same day but for **different sessions** (different src IPs). This breaks Built/Teardown correlation in Splunk.

**Evidence:** CID 160880 used for session from 98.148.55.99 at 23:16 AND session from 76.169.44.61 at 23:42.

**Root cause:** Likely from multiple generation runs loading data into the same Splunk index. The CID counter resets on each generator invocation. Could also be CID range (900K) wrapping during high-volume generation with registry sessions.

**Fix:** Two options:
- (a) Expand CID range from 900K to 9M (1,000,000-9,999,999) to prevent wrapping
- (b) Include a date-based offset in the CID seed so different runs produce different ranges
- Note: If caused by stale Splunk data, this is an indexing issue, not a generator bug. Verify by running fresh generation into a clean index.

---

### F7: Only 4 Teardown Reasons (LOW)

**Problem:** Only 4 teardown reasons: `TCP FINs`, `TCP Reset-I`, `TCP Reset-O`, `idle timeout`.

**Real ASA:** Additional common reasons include:
- `SYN Timeout` (half-open connection timeout)
- `RESET-I from inspect` (inspection engine reset)
- `Flow deleted by inspection` (application inspection teardown)
- `Uauth Deny` (auth failure)

**Fix:** Add 2-3 more reasons with low probability (5% combined): `SYN Timeout` (2%), `Flow deleted by inspection` (2%), `Uauth Deny` (1%).

---

### F8: DNS Always to External Resolvers (LOW)

**Problem:** All DNS queries go to 8.8.8.8 or 1.1.1.1. In reality, internal clients use domain controllers as DNS resolvers (10.10.20.10/11, 10.20.20.10), which then forward externally.

**Impact:** Minor -- the DC traffic function already generates internal DNS on port 53. But the `asa_dns_query()` function should reflect that SOME DNS goes to internal DCs and only external DNS (from DCs themselves) goes to 8.8.8.8/1.1.1.1.

**Fix:** Split DNS traffic:
- 70% internal->DC DNS (10.10.20.10/11 or 10.20.20.10) on `inside->inside`
- 30% DC->external DNS (8.8.8.8/1.1.1.1) on `inside->outside` (DCs forwarding)

---

## Implementation Tasks

### Task 1: Fix NAT Addresses in Built/Teardown Events (F1)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_asa.py`
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/shared/company.py` (add NAT VIP constants)

**Step 1: Add NAT constants to company.py**

Add public VIP mappings for DMZ servers:
```python
# NAT/PAT configuration
ASA_NAT_POOL = [f"203.0.113.{i}" for i in range(1, 11)]  # Dynamic PAT pool
ASA_STATIC_NAT = {
    "172.16.1.10": "203.0.113.50",   # WEB-01 public VIP
    "172.16.1.11": "203.0.113.51",   # WEB-02 public VIP
}
```

**Step 2: Update `asa_tcp_session()` for outbound NAT**

For outbound (inside->outside) connections, the source gets PAT'd:
- `src_translated_ip` = deterministic PAT address from `ASA_NAT_POOL` (hash of src_ip)
- `src_translated_port` = same as `src_port` (PAT preserves port when possible)
- `dest_translated_ip` = same as `dest_ip` (no DNAT on outbound)

**Step 3: Update `asa_web_session()` and `asa_web_session_from_registry()` for inbound static NAT**

For inbound (outside->dmz) connections, the destination shows the public VIP:
- `src_translated_ip` = same as `src_ip` (external source unchanged)
- `dest_translated_ip` = `ASA_STATIC_NAT[dest_ip]` (172.16.1.10 -> 203.0.113.50)

**Step 4: Update Built event format string**

Change the format from:
```python
f"for {src_zone}:{src_ip}/{sp} ({src_ip}/{sp}) to {dst_zone}:{dst_ip}/{dp} ({dst_ip}/{dp})"
```
To:
```python
f"for {src_zone}:{src_ip}/{sp} ({src_nat_ip}/{sp_nat}) to {dst_zone}:{dst_ip}/{dp} ({dst_nat_ip}/{dp_nat})"
```

**Step 5: Verify in Splunk**

Run: `python3 bin/main_generate.py --sources=asa --days=2 --scenarios=none`

Then check:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302013 src_interface=inside dest_interface=outside
| head 10
| table src_ip, src_translated_ip, dest_ip, dest_translated_ip
```
Expected: `src_translated_ip` shows 203.0.113.x, `dest_translated_ip` = `dest_ip`

```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302013 src_interface=outside dest_interface=dmz
| head 10
| table src_ip, src_translated_ip, dest_ip, dest_translated_ip
```
Expected: `dest_translated_ip` shows 203.0.113.50/51

**Step 6: Commit**
```bash
git add bin/generators/generate_asa.py bin/shared/company.py
git commit -m "fix(asa): Add realistic NAT addresses to Built/Teardown events"
```

---

### Task 2: Fix Phantom DMZ IPs (F2)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_asa.py`

**Step 1: Clamp registry DMZ IPs to valid servers**

In `asa_web_session_from_registry()`, replace:
```python
dst_ip = session["dst"]
```
With:
```python
raw_dst = session.get("dst", "172.16.1.10")
if raw_dst.startswith("172.16.1."):
    dst_ip = random.choice(["172.16.1.10", "172.16.1.11"])  # WEB-01 or WEB-02 only
else:
    dst_ip = raw_dst
```

Use `hash(session.get("ip",""))` for deterministic server selection if preferred.

**Step 2: Verify**

Run: `python3 bin/main_generate.py --sources=access,asa --days=2 --scenarios=none`

Then:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302013 dest_interface=dmz
| stats dc(dest_ip) as unique_dmz_ips, values(dest_ip) as dmz_ips
```
Expected: `unique_dmz_ips=2`, `dmz_ips=["172.16.1.10","172.16.1.11"]`

**Step 3: Commit**
```bash
git add bin/generators/generate_asa.py
git commit -m "fix(asa): Clamp registry DMZ destinations to WEB-01/02 only"
```

---

### Task 3: Fix Direction Label on Same-Zone Traffic (F3)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_asa.py`

**Step 1: Update Built event direction logic**

Find the Built event formatting and change direction selection:
- If `src_zone == dst_zone` (e.g. inside->inside): omit direction keyword entirely
- If `src_zone` has lower security than `dst_zone` (outside->dmz, outside->inside): use "inbound"
- If `src_zone` has higher security than `dst_zone` (inside->outside, dmz->outside): use "outbound"
- If `dmz->inside`: use "inbound" (lower to higher security)

Security levels: outside=0, dmz=50, inside=100, management=100

```python
ZONE_SECURITY = {"outside": 0, "dmz": 50, "inside": 100, "management": 100}

def get_direction(src_zone, dst_zone):
    src_sec = ZONE_SECURITY.get(src_zone, 0)
    dst_sec = ZONE_SECURITY.get(dst_zone, 0)
    if src_sec == dst_sec:
        return ""  # No direction for same security level
    elif src_sec < dst_sec:
        return "inbound "
    else:
        return "outbound "
```

**Step 2: Update all functions that generate 302013 events**

Apply `get_direction()` in:
- `asa_tcp_session()`
- `asa_web_session()`
- `asa_web_session_from_registry()`
- `asa_internal_app_traffic()`
- `asa_dc_traffic()`
- `asa_site_to_site()`
- `asa_backup_traffic()`
- `asa_new_server_traffic()`

**Step 3: Verify**

```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302013
| rex "Built (?<dir_word>\w+)? ?TCP"
| eval zone_pair=src_interface."->".dest_interface
| stats count by dir_word, zone_pair
```
Expected: inside->inside shows empty direction, outside->dmz shows "inbound", inside->outside shows "outbound"

**Step 4: Commit**
```bash
git add bin/generators/generate_asa.py
git commit -m "fix(asa): Remove direction label from same-security-level traffic"
```

---

### Task 4: Fix External Scan Deny Destinations (F4)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_asa.py`

**Step 1: Update `asa_deny_external()` destination logic**

Replace internal IP targets with public-facing targets:
```python
def asa_deny_external(...):
    src_ip = get_world_ip()
    # External scans can only reach public-facing addresses
    target_type = random.random()
    if target_type < 0.60:
        # Scanning NAT pool / public IPs
        dst_ip = random.choice(ASA_NAT_POOL + ["203.0.113.50", "203.0.113.51"])
        dst_zone = "outside"
    elif target_type < 0.90:
        # Scanning DMZ servers (visible through firewall)
        dst_ip = random.choice(["172.16.1.10", "172.16.1.11"])
        dst_zone = "dmz"
    else:
        # Scanning ASA outside interface
        dst_ip = "203.0.113.1"
        dst_zone = "outside"
    dst_port = random.choice(ASA_SCAN_PORTS)
    acl = random.choice(ASA_EXT_ACLS)
```

**Step 2: Verify**

```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=106023 src_interface=outside
| rex "dst (?<dst_zone_raw>\w+):(?<dst_ip_raw>[^/]+)"
| stats count by dst_zone_raw
| eval pct=round(count/sum(count)*100,1)
```
Expected: ~60% outside (public IPs), ~30% dmz, ~10% outside (ASA interface). Zero `inside` zone targets.

**Step 3: Commit**
```bash
git add bin/generators/generate_asa.py
git commit -m "fix(asa): External scans target public/DMZ IPs, not internal addresses"
```

---

### Task 5: Fix Zero-Duration Sessions (F5)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_asa.py`

**Step 1: Ensure minimum 1-second duration when bytes > 0**

Find all Teardown event generation points and add:
```python
if bytes_val > 0 and duration_secs == 0:
    duration_secs = 1
```

This applies to:
- `asa_tcp_session()`
- `asa_web_session()`
- `asa_web_session_from_registry()`
- `asa_dns_query()`
- Any other function producing Teardown events

**Step 2: Verify**

```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302014
| rex "duration (?<d_h>\d+):(?<d_m>\d+):(?<d_s>\d+) bytes (?<bv>\d+)"
| eval dur=(d_h*3600)+(d_m*60)+d_s
| where dur=0 AND bv>0
| stats count
```
Expected: 0

**Step 3: Commit**
```bash
git add bin/generators/generate_asa.py
git commit -m "fix(asa): Ensure minimum 1s duration for sessions with data transfer"
```

---

### Task 6: Expand Teardown Reasons (F7)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/shared/company.py`

**Step 1: Add more teardown reasons**

Update `ASA_TEARDOWN_REASONS` to include weighted selection:
```python
ASA_TEARDOWN_REASONS = [
    "TCP FINs",                     # Normal close (most common)
    "TCP Reset-I",                  # Reset from inside
    "TCP Reset-O",                  # Reset from outside
    "idle timeout",                 # Idle connection reaped
    "SYN Timeout",                  # Half-open timeout
    "Flow deleted by inspection",   # App inspection teardown
]
```

Consider weighted selection in the generator:
```python
TEARDOWN_WEIGHTS = [40, 20, 15, 15, 7, 3]  # TCP FINs most common
reason = random.choices(ASA_TEARDOWN_REASONS, weights=TEARDOWN_WEIGHTS, k=1)[0]
```

**Step 2: Commit**
```bash
git add bin/shared/company.py bin/generators/generate_asa.py
git commit -m "fix(asa): Add SYN Timeout and inspection teardown reasons"
```

---

### Task 7: Fix DNS Resolution Path (F8)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_asa.py`

**Step 1: Split DNS traffic realistically**

Update `asa_dns_query()`:
```python
def asa_dns_query(...):
    if random.random() < 0.70:
        # Internal client -> DC (internal DNS resolver)
        src_ip = get_random_user().ip_address
        src_zone = "inside"
        dst_ip = random.choice(["10.10.20.10", "10.10.20.11", "10.20.20.10"])
        dst_zone = "inside"
    else:
        # DC -> external DNS (forwarding query)
        src_ip = random.choice(["10.10.20.10", "10.10.20.11", "10.20.20.10"])
        src_zone = "inside"
        dst_ip = random.choice(["8.8.8.8", "1.1.1.1"])
        dst_zone = "outside"
```

**Step 2: Verify**

```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302015
| stats count by src_interface, dest_interface
```
Expected: ~70% inside->inside, ~30% inside->outside

**Step 3: Commit**
```bash
git add bin/generators/generate_asa.py
git commit -m "fix(asa): Split DNS traffic between internal DCs and external resolvers"
```

---

### Task 8: Investigate and Fix CID Reuse (F6)

**Files:**
- Modify: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/shared/config.py`

**Step 1: Determine root cause**

First check if CID reuse is from stale Splunk data:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=302013
| rex "Built \w+ TCP connection (?<cid>\d+)"
| stats min(_time) as first, max(_time) as last, count by cid
| where count > 1
| head 5
```

If CIDs appear in different date ranges, it's stale data. If same day, it's counter wrapping.

**Step 2: Expand CID range (if wrapping)**

In `config.py`, change:
```python
_cid_counter += 1
return 100000 + (_cid_counter % 900000)
```
To:
```python
_cid_counter += 1
return 1000000 + (_cid_counter % 9000000)  # 1M-9.99M range
```

**Step 3: Verify**

After clean generation + index clear:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id IN (302013,302014)
| rex "(?:Built|Teardown) (?:\w+ )?TCP connection (?<cid>\d+)"
| stats count by cid
| where count > 2
| stats count as duplicates
```
Expected: 0 duplicates

**Step 4: Commit**
```bash
git add bin/shared/config.py
git commit -m "fix(asa): Expand CID range to 9M to prevent wrapping on 14-day runs"
```

---

### Task 9: Full Regression Test + Splunk Verification

**Step 1: Generate fresh data**
```bash
python3 bin/main_generate.py --all --days=14 --scenarios=all
```

**Step 2: Verify all fixes in Splunk**

| Check | SPL | Expected |
|-------|-----|----------|
| NAT outbound | `message_id=302013 src_interface=inside dest_interface=outside \| table src_ip, src_translated_ip` | Different IPs |
| NAT inbound | `message_id=302013 src_interface=outside dest_interface=dmz \| table dest_ip, dest_translated_ip` | dest_translated = 203.0.113.50/51 |
| DMZ IPs | `message_id=302013 dest_interface=dmz \| stats dc(dest_ip)` | 2 |
| Direction | `message_id=302013 src_interface=inside dest_interface=inside \| rex "Built (?<dir>\w+)" \| stats count by dir` | No "inbound" |
| Scan targets | `message_id=106023 src_interface=outside \| stats count by dest_interface` | 0 inside |
| Duration | `message_id=302014 \| where duration=0 AND bytes>0 \| stats count` | 0 |
| CID pairs | `message_id IN (302013,302014) \| stats count by session_id \| where count>2 \| stats count` | 0 |
| Teardown reasons | `message_id=302014 \| stats count by reason` | 6 distinct |
| DNS split | `message_id=302015 \| stats count by dest_interface` | Mix of inside + outside |

**Step 3: Update CHANGEHISTORY.md**

**Step 4: Final commit**
```bash
git add -A
git commit -m "docs: Add ASA realism audit verification results to CHANGEHISTORY"
```

---

## Task Dependencies

```
Task 1 (NAT) ──┐
Task 2 (DMZ) ──┤
Task 3 (Dir) ──┤
Task 4 (Scan) ─┼──► Task 9 (Regression)
Task 5 (Dur) ──┤
Task 6 (Reasons)┤
Task 7 (DNS) ──┤
Task 8 (CID) ──┘
```

Tasks 1-8 are independent and can be done in any order (or in parallel).
Task 9 depends on all others completing first.

---

## Out of Scope

- **Access log generator DMZ IP assignment**: F2 is fixed in ASA by clamping. A deeper fix in `generate_access.py` to use correct server IPs is a separate task.
- **Correlating 305011 NAT events with 302013 sessions**: The separate NAT events should ideally share the same CID or timestamp as the corresponding connection. This is a larger refactor.
- **Adding more message IDs**: The current 30 message IDs are sufficient. Adding more (e.g., IPS events 400xxx, failover details) is enhancement, not a fix.
