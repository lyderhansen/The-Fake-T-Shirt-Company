# Cisco Catalyst Center

Network assurance data from Catalyst Center (formerly DNA Center), providing device health scores, network health, client health, and detected issues for the campus network.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `cisco:catalyst:devicehealth`, `cisco:catalyst:networkhealth`, `cisco:catalyst:clienthealth`, `cisco:catalyst:issue` |
| Format | JSON (Assurance API v2 format) |
| Output Files | `output/cloud/catalyst_center/catalyst_center_*.json` |
| Volume | Device: ~864/day, Network: ~576/day, Client: ~100/day, Issues: ~10-30/day |

---

## Managed Devices

| Switch | Model | Location | IP |
|--------|-------|----------|-----|
| CAT-BOS-DIST-01 | C9300-48UXM | Boston | 10.10.10.30 |
| CAT-BOS-DIST-02 | C9300-48UXM | Boston | 10.10.10.31 |
| CAT-ATL-DIST-01 | C9300-48UXM | Atlanta | 10.20.10.30 |

Polling interval: 5 minutes (288 polls/day per device).

---

## Data Types

### Device Health
| Field | Description | Example |
|-------|-------------|---------|
| `name` | Device name | `CAT-BOS-DIST-01` |
| `overallHealth` | Health score (0-10) | `10` |
| `cpuUtilization` | CPU % | `25.3` |
| `memoryUtilization` | Memory % | `42.1` |
| `reachabilityHealth` | Status | `REACHABLE` |
| `demo_id` | Scenario tag | `ddos_attack` |

### Network Health
| Field | Description | Example |
|-------|-------------|---------|
| `healthScore` | Site health (0-100) | `100` |
| `totalCount` | Devices in site | `2` |
| `goodCount` | Healthy devices | `2` |
| `badCount` | Unhealthy devices | `0` |

### Client Health
| Field | Description | Example |
|-------|-------------|---------|
| `healthScore` | Client health (0-100) | `95` |
| `totalClients` | Connected clients | `45` |
| `wiredClients` | Wired count | `30` |
| `wirelessClients` | Wireless count | `15` |

### Issues
| Field | Description | Example |
|-------|-------------|---------|
| `issueId` | Unique issue ID | `AWf2-issue-0042` |
| `issueName` | Issue type | `network_device_high_cpu` |
| `issueDescription` | Details | `High CPU on CAT-BOS-DIST-01` |
| `issueSeverity` | Severity level | `HIGH`, `MEDIUM`, `LOW` |

---

## Example Events

### Device Health - Normal
```json
{"name": "CAT-BOS-DIST-01", "model": "C9300-48UXM", "ipAddress": "10.10.10.30", "overallHealth": 10, "cpuUtilization": 25.3, "memoryUtilization": 42.1, "reachabilityHealth": "REACHABLE", "timestamp": "2026-01-05T14:00:00.000Z"}
```

### Device Health - DDoS Degraded
```json
{"name": "CAT-BOS-DIST-01", "model": "C9300-48UXM", "ipAddress": "10.10.10.30", "overallHealth": 4, "cpuUtilization": 78.5, "memoryUtilization": 65.2, "reachabilityHealth": "REACHABLE", "timestamp": "2026-01-18T09:00:00.000Z", "demo_id": "ddos_attack"}
```

### Issue - High CPU
```json
{"issueId": "AWf2-issue-0042", "issueName": "network_device_high_cpu", "issueDescription": "High CPU utilization detected on CAT-BOS-DIST-01 during DDoS event", "issueSeverity": "HIGH", "demo_id": "ddos_attack"}
```

---

## Use Cases

### 1. Device health over time
```spl
index=fake_tshrt sourcetype="FAKE:cisco:catalyst:devicehealth"
| timechart span=1h avg(overallHealth) by name
```

### 2. Network health by site
```spl
index=fake_tshrt sourcetype="FAKE:cisco:catalyst:networkhealth"
| timechart span=1h avg(healthScore) by site
```

### 3. High-severity issues
```spl
index=fake_tshrt sourcetype="FAKE:cisco:catalyst:issue" issueSeverity="HIGH"
| table _time, issueName, issueDescription, issueSeverity
| sort - _time
```

### 4. DDoS impact on network health
```spl
index=fake_tshrt sourcetype="FAKE:cisco:catalyst:devicehealth" demo_id=ddos_attack
| timechart span=30m avg(cpuUtilization) AS cpu, avg(overallHealth) AS health by name
```

### 5. CPU runaway correlation
```spl
index=fake_tshrt sourcetype="FAKE:cisco:catalyst:issue" demo_id=cpu_runaway
| table _time, issueDescription, issueSeverity
```

### 6. Client health trends
```spl
index=fake_tshrt sourcetype="FAKE:cisco:catalyst:clienthealth"
| timechart span=1h avg(healthScore) AS client_health
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **ddos_attack** | 17-18 | Device: elevated CPU, degraded health. Network: BOS score drops. Issues: high CPU, interface errors |
| **cpu_runaway** | 10-11 | Device: CPU ramp on SQL traffic path. Issues: high CPU detected |
| **memory_leak** | 6-9 | Client health: BOS client score degrades as WEB-01 slows |

---

## Talking Points

**Network assurance:**
> "Catalyst Center gives the network team a single pane of glass. During the DDoS attack, watch the device health scores drop from 10 to 4 as CPU spikes. The issues API automatically detects 'high CPU' and creates alerts."

**Cross-correlation:**
> "The beauty is correlating Catalyst Center with the Meraki SD-WAN events and ASA logs. When device health drops, you can pivot to the ASA to see why -- it's the DDoS traffic overwhelming the uplinks."

---

## Related Sources

- [Catalyst](catalyst.md) - Switch syslog events
- [Cisco ACI](aci.md) - Data center fabric health
- [Meraki](meraki.md) - SD-WAN health and failover
- [Perfmon](perfmon.md) - Server performance metrics
