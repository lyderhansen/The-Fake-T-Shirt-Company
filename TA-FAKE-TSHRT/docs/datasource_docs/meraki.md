# Cisco Meraki

Multi-site SD-WAN and network infrastructure including security appliances (MX), access points (MR), switches (MS), cameras (MV), and sensors (MT).

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `cisco:meraki:*` |
| Format | JSON (Dashboard API) |
| Output Files | `output/network/meraki_*.log` |
| Volume | 1000s events/day |

---

## Device Inventory

### MX Security Appliances (SD-WAN)
| Device | Model | Location | Role |
|--------|-------|----------|------|
| MX-BOS-01 | MX450 | Boston | Primary (HA) |
| MX-BOS-02 | MX450 | Boston | Secondary (HA) |
| MX-ATL-01 | MX250 | Atlanta | Primary |
| MX-AUS-01 | MX85 | Austin | Primary |

### MR Access Points (36 total)
| Location | Count | Areas |
|----------|-------|-------|
| Boston | 16 | 3 floors: Reception, Finance, Exec, Engineering |
| Atlanta | 12 | 2 floors: IT Ops, NOC, Training |
| Austin | 8 | Sales, Engineering, Demo Lab |

### MS Switches (11 total)
| Location | Core | Access |
|----------|------|--------|
| Boston | 2x MS425-32 | 3x MS225-48 |
| Atlanta | 2x MS425-32 | 2x MS225-48 |
| Austin | - | 2x MS225-24 |

### MV Cameras (19 total)
| Location | Indoor | Outdoor |
|----------|--------|---------|
| Boston | 8 | 2 |
| Atlanta | 6 | - |
| Austin | 3 | - |

### MT Sensors (14 total)
| Type | Model | Use |
|------|-------|-----|
| Temperature | MT10 | Server rooms |
| Humidity | MT11 | Data centers |
| Door | MT20 | Secure areas |
| Water Leak | MT14 | DC floors |

---

## Event Types by Device

### MX Firewall Events
| Type | Description |
|------|-------------|
| `firewall` | Allow/deny decisions |
| `urls` | URL filtering |
| `security_event` | IDS/IPS alerts |
| `vpn` | VPN tunnel events |
| `sd_wan_events` | SD-WAN health |
| `sd_wan_failover` | WAN failover |

### MR Wireless Events
| Type | Description |
|------|-------------|
| `association` | Client connects |
| `disassociation` | Client disconnects |
| `802.1X auth` | Enterprise auth |
| `WPA auth` | PSK auth |
| `rogue_ap` | Rogue AP detected |

### MS Switch Events
| Type | Description |
|------|-------------|
| `port_status_change` | Port up/down |
| `spanning_tree` | STP events |
| `port_auth` | 802.1X port auth |

### MV Camera Events
| Type | Description |
|------|-------------|
| `motion_detection` | Motion detected |
| `person_detection` | Person detected |
| `analytics` | People count |
| `health_status` | Camera health |

### MT Sensor Events
| Type | Description |
|------|-------------|
| `temperature` | Temp reading |
| `humidity` | Humidity reading |
| `door_open` | Door opened |
| `door_close` | Door closed |
| `water_leak` | Leak detected |

---

## Key Fields

### Common Fields
| Field | Description |
|-------|-------------|
| `deviceName` | Device identifier |
| `ts` | Unix timestamp |
| `eventType` | Event type |
| `demo_id` | Scenario tag |

### MX Firewall Fields
| Field | Description |
|-------|-------------|
| `srcMac` | Source MAC |
| `destIp` | Destination IP |
| `protocol` | Protocol |
| `destPort` | Destination port |
| `action` | allow/deny |
| `policy` | Applied policy |

### MR Wireless Fields
| Field | Description |
|-------|-------------|
| `clientMac` | Client MAC |
| `ssid` | Network SSID |
| `channel` | WiFi channel |
| `rssi` | Signal strength |
| `vap` | Virtual AP |

### MT Sensor Fields
| Field | Description |
|-------|-------------|
| `sensorType` | Sensor type |
| `value` | Reading value |
| `unit` | Measurement unit |
| `alertLevel` | Alert threshold |

---

## Example Events

### MX Firewall Allow
```json
{
  "deviceName": "MX-BOS-01",
  "ts": 1735689600,
  "eventType": "firewall",
  "srcMac": "AA:BB:CC:DD:EE:FF",
  "srcIp": "10.10.30.55",
  "destIp": "8.8.8.8",
  "protocol": "tcp",
  "destPort": 443,
  "action": "allow",
  "policy": "allow all"
}
```

### MX IDS Alert (Ransomware)
```json
{
  "deviceName": "MX-AUS-01",
  "ts": 1736352720,
  "eventType": "security_event",
  "signature": "ET TROJAN Emotet CnC Beacon",
  "srcIp": "10.30.30.20",
  "destIp": "194.26.29.42",
  "action": "block",
  "severity": "critical",
  "demo_id": "ransomware_attempt"
}
```

### MX Client Isolation
```json
{
  "deviceName": "MX-AUS-01",
  "ts": 1736352900,
  "eventType": "client_isolated",
  "clientMac": "11:22:33:44:55:66",
  "clientIp": "10.30.30.20",
  "reason": "IDS threat detected",
  "demo_id": "ransomware_attempt"
}
```

### MR Client Association
```json
{
  "deviceName": "AP-BOS-1F-01",
  "ts": 1735689600,
  "eventType": "association",
  "clientMac": "11:22:33:44:55:66",
  "ssid": "FakeTShirtCo-Corp",
  "channel": 36,
  "rssi": -55,
  "vap": 0
}
```

### MS Port Status Change
```json
{
  "deviceName": "MS-BOS-CORE-01",
  "ts": 1735689600,
  "eventType": "port_status_change",
  "port": 24,
  "status": "up",
  "speed": 1000
}
```

### MV Person Detection
```json
{
  "deviceName": "CAM-BOS-LOBBY-01",
  "ts": 1735689600,
  "eventType": "person_detection",
  "detections": 3,
  "confidence": 95,
  "zone": "entrance"
}
```

### MT Temperature Reading
```json
{
  "deviceName": "MT-BOS-DC-01",
  "ts": 1735689600,
  "eventType": "temperature",
  "sensorType": "temperature",
  "value": 22.5,
  "unit": "°C",
  "alertLevel": "normal"
}
```

### MT Door Open
```json
{
  "deviceName": "MT-BOS-SERVERROOM-01",
  "ts": 1735689600,
  "eventType": "door_open",
  "sensorType": "door",
  "previousState": "closed",
  "duration_seconds": 0
}
```

---

## SSIDs

| SSID | Auth | Use |
|------|------|-----|
| FakeTShirtCo-Corp | 802.1X | Corporate devices |
| FakeTShirtCo-Guest | PSK | Guest network |
| FakeTShirtCo-IoT | PSK | IoT devices |

---

## Use Cases

### 1. Wireless Client Tracking
Track client connections across APs:
```spl
index=network sourcetype=cisco:meraki:* eventType=association
| stats count, values(deviceName) AS aps by clientMac
| sort - count
```

### 2. IDS Alert Analysis
Review security events:
```spl
index=network sourcetype=cisco:meraki:* eventType=security_event
| stats count by signature, severity, action
| sort - count
```

### 3. Meeting Room Correlation
Combine camera + sensor + Webex:
```spl
index=network sourcetype=cisco:meraki:*
  (eventType=person_detection OR eventType=door_open OR eventType=temperature)
| eval room=case(
    match(deviceName, "CAMBRIDGE"), "Cambridge",
    match(deviceName, "FANEUIL"), "Faneuil",
    true(), deviceName
)
| timechart span=5m avg(value) AS temp, sum(detections) AS people by room
```

### 4. Ransomware Detection Timeline
Full ransomware kill chain:
```spl
index=network sourcetype=cisco:meraki:* demo_id=ransomware_attempt
| sort _time
| table _time, deviceName, eventType, action, signature
```

### 5. Temperature Anomalies
Monitor DC temperatures:
```spl
index=network sourcetype=cisco:meraki:* eventType=temperature
| where value > 25
| stats latest(value) AS temp, latest(_time) AS last_seen by deviceName
| sort - temp
```

### 6. SD-WAN Health
Monitor WAN link status:
```spl
index=network sourcetype=cisco:meraki:* eventType IN ("sd_wan_events", "sd_wan_failover")
| timechart span=1h count by eventType
```

---

## Scenario Integration

| Scenario | Device | Events |
|----------|--------|--------|
| **ransomware_attempt** | MX-AUS-01 | IDS alert, client isolation |

---

## Talking Points

**Ransomware Response:**
> "Watch the kill chain: First the IDS detects the Emotet beacon to Russia. Within 3 minutes, the MX automatically isolates the client. The user can't spread laterally because the network has already contained them."

**Meeting Room Analytics:**
> "Combining MT sensors with MV cameras gives us real-time occupancy. The door opens 2-5 minutes before each meeting, temperature rises with people count, and MV confirms the headcount."

**Wireless Coverage:**
> "RSSI values tell us signal strength. Below -70 dBm means poor coverage - users will have connection issues. We can map this across the floor plan."

---

## Related Sources

- [Webex Devices](webex_devices.md) - Meeting room correlation
- [Cisco ASA](cisco_asa.md) - Perimeter firewall
- [ServiceNow](servicenow.md) - Network incidents

