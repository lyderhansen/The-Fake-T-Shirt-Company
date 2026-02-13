# Cisco Catalyst Switches

IOS-XE syslog events from Catalyst 9300 distribution switches across 3 locations, covering interface status, 802.1X authentication, spanning tree, and system events.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `cisco:ios` |
| Format | Syslog (RFC 3164 with PRI) |
| Output File | `output/network/cisco_catalyst/cisco_catalyst_syslog.log` |
| Volume | ~3000 events/day |
| Devices | 3 switches |

---

## Device Inventory

| Switch | Model | Location | IP | Role |
|--------|-------|----------|-----|------|
| CAT-BOS-DIST-01 | C9300-48UXM | Boston | 10.10.10.30 | Primary distribution |
| CAT-BOS-DIST-02 | C9300-48UXM | Boston | 10.10.10.31 | Secondary distribution |
| CAT-ATL-DIST-01 | C9300-48UXM | Atlanta | 10.20.10.30 | Atlanta distribution |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `hostname` | Switch name | `CAT-BOS-DIST-01` |
| `facility` | IOS facility | `LINEPROTO`, `DOT1X`, `STP` |
| `severity` | Syslog severity | `5` (notice) |
| `mnemonic` | Event mnemonic | `UPDOWN`, `SUCCESS`, `TCHANGE` |
| `interface` | Port reference | `GigabitEthernet1/0/12` |
| `client_mac` | Client MAC (802.1X) | `aa:bb:cc:dd:ee:ff` |
| `demo_id` | Scenario tag | `exfil` |

---

## Event Types

| Facility-Mnemonic | Severity | Description |
|-------------------|----------|-------------|
| `LINEPROTO-5-UPDOWN` | Notice | Interface state change (up/down) |
| `DOT1X-5-SUCCESS` | Notice | 802.1X authentication success |
| `DOT1X-5-FAIL` | Notice | 802.1X authentication failure |
| `STP-5-TCHANGE` | Notice | Spanning tree topology change |
| `STP-6-ROOTCHANGE` | Info | STP root bridge change |
| `SYS-5-CONFIG_I` | Notice | Configuration change |
| `SYS-6-LOGGINGHOST_STARTSTOP` | Info | Syslog connection status |
| `STACK-5-SWITCH_STATUS` | Notice | Stack member status |

---

## Example Events

### Interface Up/Down
```
<189>12345: CAT-BOS-DIST-01: Jan  5 2026 14:25:12.100: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/15, changed state to up
```

### 802.1X Authentication Success
```
<189>12346: CAT-BOS-DIST-01: Jan  5 2026 14:23:45.326: %DOT1X-5-SUCCESS: Authentication successful for client (aa:bb:cc:dd:ee:ff) on Interface GigabitEthernet1/0/12 AuditSessionID 0a1b2c3d
```

### STP Topology Change
```
<189>12400: CAT-BOS-DIST-01: Jan  7 2026 10:18:30.500: %STP-5-TCHANGE: Topology change on VLAN 10 GigabitEthernet1/0/24 demo_id=firewall_misconfig
```

---

## Use Cases

### 1. Interface flapping detection
```spl
index=fake_tshrt sourcetype="FAKE:cisco:ios" "LINEPROTO-5-UPDOWN"
| rex "Interface (?<interface>\S+)"
| stats count by host, interface
| where count > 4
| sort - count
```

### 2. 802.1X authentication failures
```spl
index=fake_tshrt sourcetype="FAKE:cisco:ios" "DOT1X-5-FAIL"
| stats count by host
| sort - count
```

### 3. Spanning tree changes
```spl
index=fake_tshrt sourcetype="FAKE:cisco:ios" "STP-5-TCHANGE"
| timechart span=1h count by host
```

### 4. After-hours port activity (exfil)
```spl
index=fake_tshrt sourcetype="FAKE:cisco:ios" "DOT1X-5-SUCCESS" demo_id=exfil
| where date_hour >= 20 OR date_hour <= 5
| table _time, host, interface, client_mac
```

### 5. DDoS uplink impact
```spl
index=fake_tshrt sourcetype="FAKE:cisco:ios" "LINEPROTO-5-UPDOWN" demo_id=ddos_attack
| table _time, host, interface
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 5-7 | MAC flap events (lateral movement), after-hours 802.1X auth |
| **ddos_attack** | 17-18 | Uplink interface flapping from traffic saturation |
| **firewall_misconfig** | 6 | STP topology changes from network instability |

---

## Talking Points

**Exfil:**
> "Look at the Catalyst logs during the lateral movement phase. You see MAC address flapping -- the attacker's device is moving between ports. Then after-hours 802.1X authentications that don't match normal employee patterns."

**DDoS:**
> "During the DDoS attack, the uplinks to the Catalyst distribution switches start flapping from the traffic volume. This cascades into STP recalculations across the campus."

---

## Related Sources

- [Cisco ASA](cisco_asa.md) - Perimeter firewall
- [Meraki](meraki.md) - SD-WAN and wireless
- [Cisco ACI](aci.md) - Data center fabric
- [Catalyst Center](catalyst_center.md) - Network assurance

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | [Cisco Catalyst Add-on for Splunk](https://splunkbase.splunk.com/app/7538) |
| **Ingestion** | Syslog (UDP/TCP) to Splunk or [SC4S](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/) |
| **Real sourcetype** | `cisco:ios` -- matches our generator exactly |
