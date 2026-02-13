# The FAKE T-Shirt Company — Floor Plans

Physical layout for all office locations with room assignments, network equipment, and device placement.

---

## Location Overview

| Location | Code | Address | Floors | Employees | Type |
|----------|------|---------|--------|-----------|------|
| Boston, MA | BOS | 125 One Financial Center | 3 | ~93 | Headquarters |
| Atlanta, GA | ATL | 400 Peachtree Center | 2 | ~43 | IT / Regional Hub |
| Austin, TX | AUS | 200 Congress Ave | 1 | ~39 | Sales / Engineering |

---

## IP Addressing

| Location | Mgmt | Servers | Users | WiFi | IoT/Sensor | Camera |
|----------|------|---------|-------|------|------------|--------|
| Boston | 10.10.10.x | 10.10.20.x | 10.10.30.x | 10.10.40.x | 10.10.60.x | 10.10.70.x |
| Atlanta | 10.20.10.x | 10.20.20.x | 10.20.30.x | 10.20.40.x | 10.20.60.x | 10.20.70.x |
| Austin | 10.30.10.x | - | 10.30.30.x | 10.30.40.x | 10.30.60.x | 10.30.70.x |

DMZ (Boston): 172.16.1.0/24

---

## Network Architecture

```
                            INTERNET
                               |
                       +---------------+
                       | FW-EDGE-01    |  Cisco ASA 5525-X
                       | (Perimeter)   |  ALL external traffic
                       +-------+-------+
                               |
                +--------------+--------------+
                |              |              |
           +----+----+   +----+----+   +----+----+
           |  DMZ    |   |         |   |         |
           | WEB-01  |   |         |   |         |
           | WEB-02  |   |         |   |         |
           +---------+   |         |   |         |
                |         |         |   |         |
           +----+----+   +----+----+   +----+----+
           | BOSTON   |   | ATLANTA |   | AUSTIN  |
           | MX-BOS  |   | MX-ATL  |   | MX-AUS  |
           | -01/-02 |   | -01     |   | -01     |
           | MX450HA |   | MX250   |   | MX85    |
           +---------+   +---------+   +---------+
                |              |              |
                +----- AutoVPN Full Mesh -----+
```

### Firewall Hierarchy

| Layer | Device | Role |
|-------|--------|------|
| **Perimeter** | FW-EDGE-01 (ASA 5525-X) | All external traffic, DMZ, IDS/IPS |
| **SD-WAN Hub** | MX-BOS-01/02 (HA) | Boston internal, AutoVPN concentrator |
| **SD-WAN Spokes** | MX-ATL-01, MX-AUS-01 | Branch offices, internal segmentation |

**Key:** ASA sees ALL external traffic (exfil, C2, attacks). Meraki MX handles internal/SD-WAN routing.

---

# Boston HQ — 125 One Financial Center

## Equipment Summary

| Type | Count | Model | Device Names |
|------|-------|-------|-------------|
| MX Firewall | 2 | MX450 (HA) | MX-BOS-01, MX-BOS-02 |
| MS Core Switch | 2 | MS425-32 | MS-BOS-CORE-01, MS-BOS-CORE-02 |
| MS Access Switch | 3 | MS225-48 | MS-BOS-1F-IDF1, MS-BOS-2F-IDF1, MS-BOS-3F-IDF1 |
| MR Access Point | 16 | MR46 | AP-BOS-1F-01 through AP-BOS-3F-06 |
| MV Camera | 10 | MV12, MV72 | CAM-BOS-* |
| MT Sensor | 6 | MT10, MT11, MT20 | MT-BOS-* |
| Webex | 10 | Various | WEBEX-BOS-* |

---

### Floor 1 — Lobby / Operations / Shipping

```
+------------------+------------------------+------------------+
| Elevator Lobby   |                        | Stairs A & B     |
| (3 elevators)    |                        |                  |
+------------------+------------------------+------------------+
| Reception        | Main Lobby             | Security         |
| AP-BOS-1F-01     | AP-BOS-1F-02           | CAM-BOS-1F-01    |
|                  | Seating / waiting area | Badge reader     |
+------------------+------------------------+------------------+
| "Peach" (6)      | Operations Center      | Break Room       |
| Visitor meeting  | 5 operator desks       | Kitchen          |
| Desk Pro         | AP-BOS-1F-03           | AP-BOS-1F-05     |
+------------------+------------------------+------------------+
| "Toad" (4)       | Shipping / Receiving   | Server Room      |
| Visitor meeting  | Packing stations       | [IDF-BOS-1F]     |
| Room Kit Mini    | AP-BOS-1F-04           | MS-BOS-1F-IDF1   |
+------------------+------------------------+------------------+
| Loading Dock / Parking                                       |
| CAM-BOS-EXT-01 (West)          CAM-BOS-EXT-02 (East)        |
+--------------------------------------------------------------+
```

#### Room Equipment

| Room | Type | Cap | Webex Device | APs | Cameras | Sensors | Switches |
|------|------|-----|-------------|-----|---------|---------|----------|
| Reception | Lobby | - | - | AP-BOS-1F-01 | - | - | - |
| Main Lobby | Common | - | - | AP-BOS-1F-02 | - | - | - |
| Security | Utility | - | - | - | CAM-BOS-1F-01 | - | - |
| "Peach" | Visitor Mtg | 6 | WEBEX-BOS-1F-PEACH (Desk Pro) | - | MV-BOS-1F-PEACH | MT-BOS-1F-DOOR-PEACH, MT-BOS-1F-TEMP-PEACH | - |
| "Toad" | Visitor Mtg | 4 | WEBEX-BOS-1F-TOAD (Room Kit Mini) | - | - | MT-BOS-1F-DOOR-TOAD | - |
| Operations Center | Workspace | - | - | AP-BOS-1F-03 | - | - | - |
| Break Room | Common | - | - | AP-BOS-1F-05 | - | - | - |
| Shipping / Receiving | Workspace | - | - | AP-BOS-1F-04 | - | - | - |
| Server Room (IDF) | Infra | - | - | - | CAM-BOS-1F-03 | MT-BOS-1F-TEMP-01, MT-BOS-1F-DOOR-01 | MS-BOS-1F-IDF1 (48-port) |
| Loading Dock | Exterior | - | - | - | CAM-BOS-EXT-01, CAM-BOS-EXT-02 | - | - |

---

### Floor 2 — Finance / Marketing / HR

```
+------------------+------------------------+------------------+
| Elevator Lobby   |                        | Stairs A & B     |
+------------------+------------------------+------------------+
| CFO Office       | Open Office - Finance  | "Zelda" (12)     |
| (Private)        | ~20 staff              | Conference       |
|                  | AP-BOS-2F-01/02        | Room Kit         |
+------------------+------------------------+------------------+
| "Mario" (10)     | Open Office - Mktg     | "Samus" (8)      |
| Conference       | ~12 staff              | Conference       |
| Room Kit         | AP-BOS-2F-03           | Room Kit         |
+------------------+------------------------+------------------+
| HR Department    | Wellness Room          | Break Room       |
| ~6 staff         | Quiet zone             | Cafeteria        |
| AP-BOS-2F-04     |                        | AP-BOS-2F-05     |
+------------------+----------+-------------+------------------+
|                  | IDF-BOS-2F             |                  |
|                  | MS-BOS-2F-IDF1         |                  |
+------------------+------------------------+------------------+
```

#### Room Equipment

| Room | Type | Cap | Webex Device | APs | Cameras | Sensors | Switches |
|------|------|-----|-------------|-----|---------|---------|----------|
| CFO Office | Private | - | - | - | - | - | - |
| Open Office Finance | Workspace | - | - | AP-BOS-2F-01, AP-BOS-2F-02 | - | - | - |
| "Zelda" | Conference | 12 | WEBEX-BOS-2F-ZELDA (Room Kit + Board 55) | - | - | MT-BOS-2F-DOOR-ZELDA, MT-BOS-2F-TEMP-ZELDA | - |
| "Mario" | Conference | 10 | WEBEX-BOS-2F-MARIO (Room Kit) | - | - | MT-BOS-2F-DOOR-MARIO, MT-BOS-2F-TEMP-MARIO | - |
| "Samus" | Conference | 8 | WEBEX-BOS-2F-SAMUS (Room Kit) | - | - | MT-BOS-2F-DOOR-SAMUS, MT-BOS-2F-TEMP-SAMUS | - |
| Open Office Marketing | Workspace | - | - | AP-BOS-2F-03 | - | - | - |
| HR Department | Workspace | - | - | AP-BOS-2F-04 | - | - | - |
| Wellness Room | Quiet | - | - | - | - | - | - |
| Break Room / Cafeteria | Common | - | - | AP-BOS-2F-05 | - | - | - |
| IDF-BOS-2F | Infra | - | - | - | - | - | MS-BOS-2F-IDF1 (48-port) |

#### Key Personnel — Floor 2

| Name | Role | Desk | IP | Notes |
|------|------|------|-----|-------|
| Alex Miller | Sr. Financial Analyst | 2F-55 | 10.10.30.55 | **Primary target** (exfil scenario) |
| Sarah Wilson | CFO | Private office | 10.10.30.12 | Finance leadership |

---

### Floor 3 — Executive / Engineering / Legal

```
+------------------+------------------------+------------------+
| Elevator Lobby   |  Executive Reception   | Stairs A & B     |
|                  |  AP-BOS-3F-01          |                  |
+------------------+------------------------+------------------+
| Exec Assistant   | Boardroom "Link" (20)  | CEO Office       |
| Area             | Room Kit Pro           | John Smith       |
|                  | + Board 85 Pro         | AP-BOS-3F-02     |
+------------------+------------------------+------------------+
| Legal Dept       | Open Office - Eng      | "Sonic" (8)      |
| ~6 staff         | ~20 staff              | Collab/Lab       |
| AP-BOS-3F-05     | AP-BOS-3F-03/04        | Board 55         |
+------------------+------------------------+------------------+
| "Yoshi" (6)      | Primary MDF            | Break Room       |
| Huddle           | Core switches, FW      | AP-BOS-3F-06     |
| Room Kit Mini    | MX-BOS-01/02 (HA)      |                  |
+------------------+------------------------+------------------+
| "Kirby" (4)      | "Luigi" (8)            | CTO Office       |
| Huddle (!)       | Conference             | Mike Johnson     |
| Desk Pro         | Room Kit               |                  |
+------------------+------------------------+------------------+
```

**(!) Kirby = Problem room** — WiFi congestion, old equipment

#### Room Equipment

| Room | Type | Cap | Webex Device | APs | Cameras | Sensors | Switches |
|------|------|-----|-------------|-----|---------|---------|----------|
| Executive Reception | Lobby | - | - | AP-BOS-3F-01 | - | - | - |
| CEO Office | Private | - | - | AP-BOS-3F-02 | - | - | - |
| "Link" | Boardroom | 20 | WEBEX-BOS-3F-LINK (Room Kit Pro + Board 85 Pro) | - | MV-BOS-3F-LINK | MT-BOS-3F-DOOR-LINK, MT-BOS-3F-TEMP-LINK | - |
| "Luigi" | Conference | 8 | WEBEX-BOS-3F-LUIGI (Room Kit) | - | - | MT-BOS-3F-DOOR-LUIGI, MT-BOS-3F-TEMP-LUIGI | - |
| "Kirby" | Huddle | 4 | WEBEX-BOS-3F-KIRBY (Desk Pro) | - | - | MT-BOS-3F-DOOR-KIRBY, MT-BOS-3F-TEMP-KIRBY | - |
| "Yoshi" | Huddle | 6 | WEBEX-BOS-3F-YOSHI (Room Kit Mini) | - | - | MT-BOS-3F-DOOR-YOSHI, MT-BOS-3F-TEMP-YOSHI | - |
| "Sonic" | Lab | 8 | WEBEX-BOS-3F-SONIC (Board 55) | - | MV-BOS-3F-SONIC | MT-BOS-3F-DOOR-SONIC, MT-BOS-3F-TEMP-SONIC | - |
| Open Office Engineering | Workspace | - | - | AP-BOS-3F-03, AP-BOS-3F-04 | - | - | - |
| Legal Department | Workspace | - | - | AP-BOS-3F-05 | - | - | - |
| Break Room | Common | - | - | AP-BOS-3F-06 | - | - | - |
| Primary MDF | Infra | - | - | - | CAM-BOS-3F-03, CAM-BOS-3F-04 | MT-BOS-MDF-TEMP-01, MT-BOS-MDF-HUMID-01, MT-BOS-MDF-DOOR-01 | MS-BOS-CORE-01/02, MS-BOS-3F-IDF1 |
| Boardroom corridor | Corridor | - | - | - | CAM-BOS-3F-01, CAM-BOS-3F-02 | - | - |
| CTO Office | Private | - | - | - | - | - | - |

#### Key Personnel — Floor 3

| Name | Role | Notes |
|------|------|-------|
| John Smith | CEO | Corner office |
| Sarah Wilson | CFO | Private office |
| Mike Johnson | CTO | Private office |

---

# Atlanta Hub — 400 Peachtree Center

## Equipment Summary

| Type | Count | Model | Device Names |
|------|-------|-------|-------------|
| MX Firewall | 1 | MX250 | MX-ATL-01 |
| MS Core Switch | 2 | MS425-32 | MS-ATL-DC-01, MS-ATL-DC-02 |
| MS Access Switch | 2 | MS225-48 | MS-ATL-1F-IDF1, MS-ATL-2F-IDF1 |
| MR Access Point | 12 | MR46 | AP-ATL-1F-01 through AP-ATL-2F-06 |
| MV Camera | 11 | MV12, MV32, MV72 | CAM-ATL-* |
| MT Sensor | 8 | MT10, MT11, MT20 | MT-ATL-* |
| Webex | 7 | Various | WEBEX-ATL-* |

---

### Floor 1 — IT Operations / Data Center

```
+------------------+------------------------+------------------+
| Elevator Lobby   |                        | Stairs A & B     |
| (2 elevators)    |                        |                  |
+------------------+------------------------+------------------+
| Reception        | IT Operations Center   | "Ryu" (6)        |
| AP-ATL-1F-01     | ~15 IT staff           | NOC briefing     |
| CAM-ATL-1F-01    | AP-ATL-1F-02/03        | Room Kit         |
+------------------+------------------------+------------------+
| "Kratos" (8)     | Data Center [DC-ATL]   | Staging Area     |
| Conference       | Rack rows, cooling     | Equipment prep   |
| Room Kit         | CAM-ATL-DC-01..04      | AP-ATL-1F-05     |
+------------------+------------------------+------------------+
| Break Room       | Storage / Warehouse    | IDF-ATL-1F       |
| AP-ATL-1F-06     |                        | MS-ATL-1F-IDF1   |
|                  |                        | CAM-ATL-1F-05    |
+------------------+------------------------+------------------+
```

#### Room Equipment

| Room | Type | Cap | Webex Device | APs | Cameras | Sensors | Switches |
|------|------|-----|-------------|-----|---------|---------|----------|
| Reception | Lobby | - | - | AP-ATL-1F-01 | CAM-ATL-1F-01 | - | - |
| IT Operations Center | Workspace | - | - | AP-ATL-1F-02, AP-ATL-1F-03 | - | - | - |
| "Ryu" | Operations | 6 | WEBEX-ATL-1F-RYU (Room Kit) | - | MV-ATL-1F-RYU | MT-ATL-1F-DOOR-RYU, MT-ATL-1F-TEMP-RYU | - |
| "Kratos" | Conference | 8 | WEBEX-ATL-1F-KRATOS (Room Kit) | - | - | MT-ATL-1F-DOOR-KRATOS, MT-ATL-1F-TEMP-KRATOS | - |
| Data Center | Infra | - | - | - | CAM-ATL-DC-01 through 04 | MT-ATL-DC-TEMP-01..04, MT-ATL-DC-HUMID-01..02, MT-ATL-DC-DOOR-01 | MS-ATL-DC-01/02 (core) |
| Staging Area | Workspace | - | - | AP-ATL-1F-05 | - | - | - |
| Break Room | Common | - | - | AP-ATL-1F-06 | - | - | - |
| Storage / Warehouse | Utility | - | - | - | - | - | - |
| IDF-ATL-1F | Infra | - | - | - | CAM-ATL-1F-05 | - | MS-ATL-1F-IDF1 (48-port) |

#### Key Personnel — Floor 1

| Name | Role | Desk | IP | Notes |
|------|------|------|-----|-------|
| Jessica Brown | IT Administrator | 1F-15 | 10.20.30.15 | **Initial compromise** (exfil scenario) |
| David Robinson | IT Manager | - | - | - |
| Samuel Wright | IT Security Analyst | - | - | - |

---

### Floor 2 — Engineering / Sales / Marketing

```
+------------------+------------------------+------------------+
| Elevator Lobby   |                        | Stairs A & B     |
+------------------+------------------------+------------------+
| "Chief" (10)     | Open Office - Eng      | "Megaman" (4)    |
| Conference       | ~8 staff               | Huddle           |
| Room Kit         | AP-ATL-2F-01/02        | Desk Pro         |
| + Board 55       |                        |                  |
+------------------+------------------------+------------------+
| HR / Operations  | Open Office - Sales    | Phone Booths     |
| HR ~3, Ops ~3    | Sales ~5, Mktg ~5      | (4 booths)       |
| AP-ATL-2F-03     | AP-ATL-2F-04           | AP-ATL-2F-05     |
+------------------+------------------------+------------------+
| Wellness Room    | Break Room             | "Lara" (8)       |
| Quiet zone       | Kitchen                | Collab/Lab       |
|                  | AP-ATL-2F-06           | Board 55         |
+---------+--------+------------------------+------------------+
| "Cortana" (16) (!)                        | "Pikachu" (4)    |
| Training room - Room Kit Pro              | Huddle           |
|                                           | Desk Pro         |
+-------------------------------------------+------------------+
| IDF-ATL-2F                                                   |
| MS-ATL-2F-IDF1 (48-port)                                    |
+--------------------------------------------------------------+
```

**(!) Cortana = Problem room** — Bandwidth limited, echo issues

#### Room Equipment

| Room | Type | Cap | Webex Device | APs | Cameras | Sensors | Switches |
|------|------|-----|-------------|-----|---------|---------|----------|
| "Cortana" | Training | 16 | WEBEX-ATL-2F-CORTANA (Room Kit Pro) | - | MV-ATL-2F-CORTANA | MT-ATL-2F-DOOR-CORTANA, MT-ATL-2F-TEMP-CORTANA | - |
| "Chief" | Conference | 10 | WEBEX-ATL-2F-CHIEF (Room Kit + Board 55) | - | - | MT-ATL-2F-DOOR-CHIEF, MT-ATL-2F-TEMP-CHIEF | - |
| "Megaman" | Huddle | 4 | WEBEX-ATL-2F-MEGAMAN (Desk Pro) | - | - | MT-ATL-2F-DOOR-MEGAMAN, MT-ATL-2F-TEMP-MEGAMAN | - |
| "Pikachu" | Huddle | 4 | WEBEX-ATL-2F-PIKACHU (Desk Pro) | - | - | MT-ATL-2F-DOOR-PIKACHU | - |
| "Lara" | Lab | 8 | WEBEX-ATL-2F-LARA (Board 55) | - | - | MT-ATL-2F-DOOR-LARA, MT-ATL-2F-TEMP-LARA | - |
| Open Office Engineering | Workspace | - | - | AP-ATL-2F-01, AP-ATL-2F-02 | - | - | - |
| Open Office Sales/Mktg | Workspace | - | - | AP-ATL-2F-04 | - | - | - |
| HR / Operations | Workspace | - | - | AP-ATL-2F-03 | - | - | - |
| Phone Booths (4) | Utility | - | - | AP-ATL-2F-05 | - | - | - |
| Wellness Room | Quiet | - | - | - | - | - | - |
| Break Room | Common | - | - | AP-ATL-2F-06 | - | - | - |
| IDF-ATL-2F | Infra | - | - | - | - | - | MS-ATL-2F-IDF1 (48-port) |

---

# Austin Office — 200 Congress Ave

## Equipment Summary

| Type | Count | Model | Device Names |
|------|-------|-------|-------------|
| MX Firewall | 1 | MX85 | MX-AUS-01 |
| MS Switch | 2 | MS250-48, MS225-24 | MS-AUS-01, MS-AUS-02 |
| MR Access Point | 8 | MR46 | AP-AUS-1F-01 through AP-AUS-1F-08 |
| MV Camera | 4 | MV12, MV72 | CAM-AUS-* |
| MT Sensor | 2 | MT10, MT20 | MT-AUS-* |
| Webex | 4 | Various | WEBEX-AUS-* |

---

### Floor 1 — Sales / Engineering

```
+------------------+------------------------+------------------+
| Reception        | Open Office - Sales    | "Doom" (12)      |
| AP-AUS-1F-01     | ~15 staff              | Main conference  |
| CAM-AUS-1F-01    | AP-AUS-1F-02/03        | Room Kit         |
|                  |                        | + Board 55       |
+------------------+------------------------+------------------+
| "Fox" (6)        | Open Office - Eng      | "Jett" (8)       |
| Huddle           | ~12 staff              | Demo Lab         |
| Room Kit Mini    | AP-AUS-1F-04/05        | Room Kit         |
+------------------+------------------------+------------------+
| "Crash" (8)      | Game Room / Recharge   | Phone Booths     |
| Conference       | Billiards, foosball    | (3 booths)       |
| Room Kit         | AP-AUS-1F-08           | AP-AUS-1F-07     |
+------------------+------------------------+------------------+
| Break Room       | Server Room            | Parking          |
| Kitchen          | MS-AUS-01/02           | CAM-AUS-EXT-01   |
| AP-AUS-1F-06     | CAM-AUS-1F-02          | CAM-AUS-EXT-02   |
|                  | MX-AUS-01              |                  |
+------------------+------------------------+------------------+
```

#### Room Equipment

| Room | Type | Cap | Webex Device | APs | Cameras | Sensors | Switches |
|------|------|-----|-------------|-----|---------|---------|----------|
| Reception | Lobby | - | - | AP-AUS-1F-01 | CAM-AUS-1F-01 | - | - |
| Open Office Sales | Workspace | - | - | AP-AUS-1F-02, AP-AUS-1F-03 | - | - | - |
| Open Office Engineering | Workspace | - | - | AP-AUS-1F-04, AP-AUS-1F-05 | - | - | - |
| "Doom" | Conference | 12 | WEBEX-AUS-1F-DOOM (Room Kit + Board 55) | - | - | MT-AUS-1F-DOOR-DOOM, MT-AUS-1F-TEMP-DOOM | - |
| "Fox" | Huddle | 6 | WEBEX-AUS-1F-FOX (Room Kit Mini) | - | - | MT-AUS-1F-DOOR-FOX | - |
| "Jett" | Demo Lab | 8 | WEBEX-AUS-1F-JETT (Room Kit) | - | MV-AUS-1F-JETT | MT-AUS-1F-DOOR-JETT, MT-AUS-1F-TEMP-JETT | - |
| "Crash" | Conference | 8 | WEBEX-AUS-1F-CRASH (Room Kit) | - | - | MT-AUS-1F-DOOR-CRASH, MT-AUS-1F-TEMP-CRASH | - |
| Game Room | Common | - | - | AP-AUS-1F-08 | - | - | - |
| Phone Booths (3) | Utility | - | - | AP-AUS-1F-07 | - | - | - |
| Break Room | Common | - | - | AP-AUS-1F-06 | - | - | - |
| Server Room | Infra | - | - | - | CAM-AUS-1F-02 | MT-AUS-TEMP-01, MT-AUS-DOOR-01 | MS-AUS-01, MS-AUS-02 |
| Parking | Exterior | - | - | - | CAM-AUS-EXT-01, CAM-AUS-EXT-02 | - | - |

#### Key Personnel — Austin

| Name | Role | Notes |
|------|------|-------|
| Zoey Collins | Sales Manager | - |
| Taylor Campbell | Regional Sales Director | - |
| Amelia Collins | Lead Engineer | - |

---

# Meeting Room Summary (All Locations)

| Location | Room | Floor | Cap | Webex Device | Model | Quality | Notes |
|----------|------|-------|-----|-------------|-------|---------|-------|
| **BOS** | Link | 3 | 20 | WEBEX-BOS-3F-LINK | Room Kit Pro + Board 85 Pro | Premium | Executive boardroom |
| | Zelda | 2 | 12 | WEBEX-BOS-2F-ZELDA | Room Kit + Board 55 | Normal | Finance floor |
| | Mario | 2 | 10 | WEBEX-BOS-2F-MARIO | Room Kit | Normal | General conference |
| | Samus | 2 | 8 | WEBEX-BOS-2F-SAMUS | Room Kit | Normal | Marketing team |
| | Luigi | 3 | 8 | WEBEX-BOS-3F-LUIGI | Room Kit | Normal | Engineering meetings |
| | Sonic | 3 | 8 | WEBEX-BOS-3F-SONIC | Board 55 | Premium | Collaboration/whiteboard |
| | Peach | 1 | 6 | WEBEX-BOS-1F-PEACH | Desk Pro | Normal | Visitor room |
| | Yoshi | 3 | 6 | WEBEX-BOS-3F-YOSHI | Room Kit Mini | Normal | Quick meetings |
| | Kirby | 3 | 4 | WEBEX-BOS-3F-KIRBY | Desk Pro | **Problem** | WiFi congestion, old equipment |
| | Toad | 1 | 4 | WEBEX-BOS-1F-TOAD | Room Kit Mini | Normal | Visitor room |
| **ATL** | Cortana | 2 | 16 | WEBEX-ATL-2F-CORTANA | Room Kit Pro | **Problem** | Bandwidth limited, echo issues |
| | Chief | 2 | 10 | WEBEX-ATL-2F-CHIEF | Room Kit + Board 55 | Normal | Gets warm in afternoon |
| | Kratos | 1 | 8 | WEBEX-ATL-1F-KRATOS | Room Kit | Normal | IT operations conference |
| | Lara | 2 | 8 | WEBEX-ATL-2F-LARA | Board 55 | Normal | Innovation/brainstorming |
| | Ryu | 1 | 6 | WEBEX-ATL-1F-RYU | Room Kit | Premium | NOC briefing room |
| | Pikachu | 2 | 4 | WEBEX-ATL-2F-PIKACHU | Desk Pro | Normal | Quick meetings |
| | Megaman | 2 | 4 | WEBEX-ATL-2F-MEGAMAN | Desk Pro | Normal | Engineering huddle |
| **AUS** | Doom | 1 | 12 | WEBEX-AUS-1F-DOOM | Room Kit + Board 55 | Normal | Very hot in afternoon sun |
| | Crash | 1 | 8 | WEBEX-AUS-1F-CRASH | Room Kit | Normal | Sales/engineering |
| | Jett | 1 | 8 | WEBEX-AUS-1F-JETT | Room Kit | Premium | Demo lab |
| | Fox | 1 | 6 | WEBEX-AUS-1F-FOX | Room Kit Mini | Normal | Sales team |

**Total: 21 rooms** (Boston 10, Atlanta 7, Austin 4)

---

# SSID Configuration

| SSID | Authentication | VLAN | Sites | Purpose |
|------|---------------|------|-------|---------|
| FakeTShirtCo-Corp | 802.1X (RADIUS) | 40 | All | Employee wireless |
| FakeTShirtCo-Guest | WPA2-PSK + Captive Portal | 80 | All | Guest access |
| FakeTShirtCo-IoT | WPA2-PSK | 60 | All | IoT devices, sensors |
| FakeTShirtCo-Voice | 802.1X | 50 | All | Webex devices, phones |

---

# Server Infrastructure

## Boston HQ (Primary Data Center)

| Hostname | IP | Role | OS |
|----------|-----|------|-----|
| DC-BOS-01 | 10.10.20.10 | Domain Controller | Windows Server 2022 |
| DC-BOS-02 | 10.10.20.11 | Domain Controller | Windows Server 2022 |
| FILE-BOS-01 | 10.10.20.20 | File Server | Windows Server 2022 |
| SQL-PROD-01 | 10.10.20.30 | SQL Database | Windows Server 2022 |
| APP-BOS-01 | 10.10.20.40 | Application Server | Windows Server 2022 |
| WEB-01 | 172.16.1.10 | Web Server (DMZ) | Ubuntu 22.04 |
| WEB-02 | 172.16.1.11 | Web Server (DMZ) | Ubuntu 22.04 |

## Atlanta Hub (Secondary Data Center)

| Hostname | IP | Role | OS |
|----------|-----|------|-----|
| DC-ATL-01 | 10.20.20.10 | Domain Controller (Replica) | Windows Server 2022 |
| BACKUP-ATL-01 | 10.20.20.20 | Backup Server (Veeam) | Windows Server 2022 |
| MON-ATL-01 | 10.20.20.30 | Monitoring (Splunk) | Ubuntu 22.04 |
| DEV-ATL-01 | 10.20.20.40 | Dev/Test | Ubuntu 22.04 |
| DEV-ATL-02 | 10.20.20.41 | Dev/Test | Ubuntu 22.04 |

## Austin Office

No local servers (cloud-first approach, uses Atlanta/Boston resources).
