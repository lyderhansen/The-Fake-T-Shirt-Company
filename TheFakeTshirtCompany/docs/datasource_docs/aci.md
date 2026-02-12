# Cisco ACI

Application Centric Infrastructure logs from the Boston data center fabric, covering faults, events, and audit trails from APIC and leaf/spine switches.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `cisco:aci:fault`, `cisco:aci:event`, `cisco:aci:audit` |
| Format | JSON (APIC REST API format) |
| Output Files | `output/network/cisco_aci/cisco_aci_fault.json`, `_event.json`, `_audit.json` |
| Volume | Faults: ~500-1000/day, Events: ~2000-3500/day, Audits: ~30-50/day |

---

## Fabric Architecture

| Role | Device | Model | Location |
|------|--------|-------|----------|
| Spine | SPINE-BOS-01/02 | N9K-C9336C-FX2 | Boston DC |
| Leaf | LEAF-BOS-01/02/03/04 | N9K-C93180YC-FX | Boston DC |
| Spine | SPINE-ATL-01 | N9K-C9336C-FX2 | Atlanta DC |
| Leaf | LEAF-ATL-01/02 | N9K-C93180YC-FX | Atlanta DC |
| APIC | APIC-BOS-01 | APIC-L3 | Boston (shared) |

---

## Output Types

### Faults (faultInst)
| Field | Description | Example |
|-------|-------------|---------|
| `dn` | Distinguished name | `topology/pod-1/node-201/sys/phys-[eth1/12]/...` |
| `code` | Fault code | `F0546` |
| `severity` | Fault severity | `warning`, `critical`, `info` |
| `descr` | Description | `Port is down, reason: link-failure` |
| `created` | Timestamp | `2026-01-05T14:23:45.000+00:00` |
| `demo_id` | Scenario tag | `exfil` |

### Events (eventRecord)
| Field | Description | Example |
|-------|-------------|---------|
| `code` | Event code | `E4210150` |
| `descr` | Description | `Endpoint learned on node 201` |
| `severity` | Event severity | `info` |

### Audits (aaaModLR)
| Field | Description | Example |
|-------|-------------|---------|
| `descr` | Change description | `Tenant TShirtCo-Prod modified` |
| `user` | Admin user | `admin` |

---

## Example Events

### Fault - Port Down
```json
{"faultInst": {"attributes": {"dn": "topology/pod-1/node-201/sys/phys-[eth1/12]/phys/fault-F0546", "code": "F0546", "severity": "warning", "descr": "Port is down, reason:link-failure", "created": "2026-01-05T14:23:45.000+00:00"}}}
```

### Event - Endpoint Learned
```json
{"eventRecord": {"attributes": {"code": "E4210150", "descr": "Endpoint aa:bb:cc:dd:ee:ff learned on node 201 interface eth1/12", "severity": "info"}}}
```

### Audit - Configuration Change
```json
{"aaaModLR": {"attributes": {"descr": "Tenant TShirtCo-Prod modified", "user": "admin"}}}
```

---

## Use Cases

### 1. Critical fabric faults
```spl
index=network sourcetype="cisco:aci:fault" severity="critical" OR severity="major"
| table _time, code, severity, descr
| sort - _time
```

### 2. Endpoint anomalies (exfil)
```spl
index=network sourcetype="cisco:aci:event" demo_id=exfil
| stats count by descr
| sort - count
```

### 3. DDoS fabric impact
```spl
index=network sourcetype="cisco:aci:fault" demo_id=ddos_attack
| timechart span=1h count by severity
```

### 4. Configuration audit trail
```spl
index=network sourcetype="cisco:aci:audit"
| table _time, user, descr
| sort _time
```

### 5. CPU runaway downstream effects
```spl
index=network sourcetype="cisco:aci:fault" demo_id=cpu_runaway
| table _time, descr, severity
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 5-7 | Endpoint anomaly faults, contract deny events |
| **ddos_attack** | 17-18 | Border leaf high CPU faults, interface errors |
| **cpu_runaway** | 10-11 | EPG-DBServers health score drops |

---

## Talking Points

**Fabric visibility:**
> "ACI gives us the data center perspective. When the exfil attacker moves laterally, ACI sees endpoint anomalies -- MAC addresses appearing on unexpected leaf ports. The contract deny events show traffic being blocked between security zones."

**DDoS:**
> "During the DDoS, the border leaf switches handling WEB-01 traffic show elevated CPU. ACI faults correlate with the ASA and Meraki events to paint the full picture."

---

## Related Sources

- [Catalyst](catalyst.md) - Campus network switches
- [Catalyst Center](catalyst_center.md) - Network assurance
- [Cisco ASA](cisco_asa.md) - Perimeter firewall
- [Meraki](meraki.md) - SD-WAN and branch
