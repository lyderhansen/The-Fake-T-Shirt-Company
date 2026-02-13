# Webex Room Devices

Cisco Webex collaboration device events from 21 meeting rooms across 3 locations.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `cisco:webex:events` |
| Format | JSON |
| Output File | `output/cloud/webex_events.log` |
| Volume | 50-200 events/day |
| Rooms | 21 meeting rooms |

---

## Device Inventory

### Boston (10 rooms)
| Room | Device ID | Model | Capacity |
|------|-----------|-------|----------|
| Link | WEBEX-BOS-3F-LINK | Room Kit Pro + Board 85 Pro | 20 |
| Zelda | WEBEX-BOS-2F-ZELDA | Room Kit + Board 55 | 12 |
| Mario | WEBEX-BOS-2F-MARIO | Room Kit | 10 |
| Samus | WEBEX-BOS-2F-SAMUS | Room Kit | 8 |
| Luigi | WEBEX-BOS-3F-LUIGI | Room Kit | 8 |
| Kirby | WEBEX-BOS-3F-KIRBY | Desk Pro | 4 |
| Yoshi | WEBEX-BOS-3F-YOSHI | Room Kit Mini | 6 |
| Peach | WEBEX-BOS-1F-PEACH | Desk Pro | 6 |
| Toad | WEBEX-BOS-1F-TOAD | Room Kit Mini | 4 |
| Sonic | WEBEX-BOS-3F-SONIC | Board 55 | 8 |

### Atlanta (7 rooms)
| Room | Device ID | Model | Capacity |
|------|-----------|-------|----------|
| Cortana | WEBEX-ATL-2F-CORTANA | Room Kit Pro | 16 |
| Chief | WEBEX-ATL-2F-CHIEF | Room Kit + Board 55 | 10 |
| Kratos | WEBEX-ATL-1F-KRATOS | Room Kit | 8 |
| Ryu | WEBEX-ATL-1F-RYU | Room Kit | 6 |
| Pikachu | WEBEX-ATL-2F-PIKACHU | Desk Pro | 4 |
| Megaman | WEBEX-ATL-2F-MEGAMAN | Desk Pro | 4 |
| Lara | WEBEX-ATL-2F-LARA | Board 55 | 8 |

### Austin (4 rooms)
| Room | Device ID | Model | Capacity |
|------|-----------|-------|----------|
| Doom | WEBEX-AUS-1F-DOOM | Room Kit + Board 55 | 12 |
| Crash | WEBEX-AUS-1F-CRASH | Room Kit | 8 |
| Jett | WEBEX-AUS-1F-JETT | Room Kit | 8 |
| Fox | WEBEX-AUS-1F-FOX | Room Kit Mini | 6 |

---

## Event Types

| Type | Description |
|------|-------------|
| `meeting_started` | Meeting begins |
| `participant_joined` | User joins meeting |
| `participant_left` | User leaves meeting |
| `meeting_ended` | Meeting concludes |
| `quality_metrics` | Audio/video quality data |
| `device_health` | Device status update |
| `room_analytics` | Occupancy data |
| `wireless_share` | Screen sharing started |

---

## Key Fields

### Meeting Events
| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | ISO 8601 time | `2026-01-05T14:00:00Z` |
| `event_type` | Event type | `meeting_started` |
| `device_id` | Device identifier | `WEBEX-BOS-3F-LINK` |
| `device_model` | Hardware model | `Room Kit Pro` |
| `location` | Site | `Boston HQ` |
| `location_code` | Site code | `BOS` |
| `room` | Room name | `Link` |
| `meeting_id` | Meeting identifier | `123-456-789` |
| `organizer` | Meeting host | `john.smith@theFakeTshirtCompany.com` |
| `meeting_title` | Meeting name | `Board Meeting` |
| `participant_email` | Participant | `alex.miller@theFakeTshirtCompany.com` |
| `participant_count` | Attendee count | `8` |
| `demo_id` | Scenario tag | `exfil` |

### Quality Metrics
| Field | Description | Example |
|-------|-------------|---------|
| `audio.mos_score` | Audio MOS (1-5) | `4.2` |
| `audio.packet_loss_pct` | Audio loss % | `0.5` |
| `video.packet_loss_pct` | Video loss % | `1.2` |
| `network.jitter_ms` | Network jitter | `15` |
| `network.latency_ms` | Network latency | `45` |

### Device Health
| Field | Description | Example |
|-------|-------------|---------|
| `cpu_usage_pct` | CPU usage | `35` |
| `memory_usage_pct` | Memory usage | `42` |
| `peripheral_status` | Peripherals | `all_ok` |

### Room Analytics
| Field | Description | Example |
|-------|-------------|---------|
| `people_count` | Detected occupants | `6` |
| `ambient_noise_db` | Noise level | `42` |
| `room_temperature_c` | Temperature | `22.5` |

---

## Example Events

### Meeting Started
```json
{
  "timestamp": "2026-01-05T14:00:00Z",
  "event_type": "meeting_started",
  "device_id": "WEBEX-BOS-3F-LINK",
  "device_model": "Room Kit Pro",
  "location": "Boston HQ",
  "location_code": "BOS",
  "room": "Link",
  "meeting_id": "123-456-789",
  "organizer": "john.smith@theFakeTshirtCompany.com",
  "meeting_title": "Board Meeting",
  "scheduled_duration_min": 60
}
```

### Participant Joined
```json
{
  "timestamp": "2026-01-05T14:02:00Z",
  "event_type": "participant_joined",
  "device_id": "WEBEX-BOS-3F-LINK",
  "room": "Link",
  "meeting_id": "123-456-789",
  "participant_email": "alex.miller@theFakeTshirtCompany.com",
  "participant_name": "Alex Miller",
  "join_method": "room_device",
  "participant_count": 5
}
```

### Quality Metrics
```json
{
  "timestamp": "2026-01-05T14:30:00Z",
  "event_type": "quality_metrics",
  "device_id": "WEBEX-BOS-3F-KIRBY",
  "room": "Kirby",
  "meeting_id": "987-654-321",
  "audio": {
    "mos_score": 3.2,
    "packet_loss_pct": 2.5,
    "echo_detected": false
  },
  "video": {
    "packet_loss_pct": 4.1,
    "resolution": "720p"
  },
  "network": {
    "jitter_ms": 45,
    "latency_ms": 120,
    "bandwidth_mbps": 2.5
  },
  "quality_issue": "wifi_congestion"
}
```

### Room Analytics
```json
{
  "timestamp": "2026-01-05T14:15:00Z",
  "event_type": "room_analytics",
  "device_id": "WEBEX-BOS-3F-LINK",
  "room": "Link",
  "people_count": 8,
  "ambient_noise_db": 45,
  "room_temperature_c": 23.5,
  "air_quality": "good"
}
```

### Meeting Ended
```json
{
  "timestamp": "2026-01-05T15:00:00Z",
  "event_type": "meeting_ended",
  "device_id": "WEBEX-BOS-3F-LINK",
  "room": "Link",
  "meeting_id": "123-456-789",
  "actual_duration_min": 60,
  "total_participants": 12,
  "peak_participants": 10
}
```

---

## Problem Rooms

| Room | Issues | Symptoms |
|------|--------|----------|
| **Kirby** (BOS) | wifi_congestion, old_equipment | Low MOS, high jitter |
| **Cortana** (ATL) | bandwidth_limited, echo_issues | Video loss, echo |

### Problem Room Quality
```json
{
  "room": "Kirby",
  "quality_issue": "wifi_congestion",
  "audio": {"mos_score": 3.2},
  "video": {"packet_loss_pct": 4.5},
  "network": {"jitter_ms": 55}
}
```

---

## Meeting Variations

| Type | Frequency | Description |
|------|-----------|-------------|
| Normal | 75% | Standard meeting flow |
| Ghost (no-show) | 15% | Booked but no one joins |
| Walk-in | 10% | Unbooked room usage |
| Late start | 20% | Starts 5-15 min late |
| Overfilled | 5% | More than capacity |

---

## Use Cases

### 1. Meeting Volume Analysis
Track meeting patterns:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="meeting_started"
| timechart span=1h count by location_code
```

### 2. Room Utilization
Find busiest rooms:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="meeting_started"
| stats count AS meetings, sum(actual_duration_min) AS total_minutes by room
| eval hours = round(total_minutes / 60, 1)
| sort - hours
```

### 3. Quality Issues
Identify problematic meetings:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="quality_metrics"
| where audio.mos_score < 3.5 OR video.packet_loss_pct > 3
| table _time, room, audio.mos_score, video.packet_loss_pct, quality_issue
```

### 4. Problem Room Trends
Track specific room issues:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="quality_metrics"
  room IN ("Kirby", "Cortana")
| timechart span=1d avg(audio.mos_score) by room
```

### 5. Ghost Meeting Detection
Find no-shows:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:events"
| transaction meeting_id maxspan=2h
| where NOT match(_raw, "participant_joined")
| table meeting_id, room, organizer
```

### 6. Participant Analysis
Track meeting participation:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="participant_joined"
| stats count AS meetings_attended by participant_email
| sort - meetings_attended
```

---

## Sensor Correlation

Webex events correlate with Meraki MT sensors:

```
-5 min   Door opens (MT)         First arrival
-3 min   Person detected (MV)    Camera sees movement
-2 min   Temp begins rising      Body heat
 0 min   meeting_started         Webex event
+5 min   people_count: 6         Room analytics
+10 min  Temp +1.5°C             Stabilizes
+60 min  meeting_ended           Webex event
+62 min  Door opens              Exit
+75 min  Temp drops              Room cools
```

---

## Scenario Integration

| Scenario | Activity |
|----------|----------|
| **exfil** | Meetings tagged with compromised users (jessica.brown, alex.miller) |

---

## Talking Points

**Room Utilization:**
> "Link is our most-used room - 6+ hours of meetings daily. But look at ghost meetings - 15% of bookings are no-shows. That's wasted capacity."

**Quality Issues:**
> "Kirby consistently shows poor audio quality. MOS scores below 3.5, high jitter. This room is near a busy AP - WiFi congestion is the culprit."

**Sensor Correlation:**
> "Watch the temperature: it starts rising 2 minutes before the meeting starts as people enter. During a 10-person meeting, the room temperature increases by 2-3 degrees."

**Problem Rooms:**
> "We have two problem rooms flagged for AV issues. Cortana has echo problems - bad acoustics. Kirby has old equipment. These need IT attention."

---

## Related Sources

- [Webex Meetings TA](webex_meetings.md) - Meeting history details
- [Webex API](webex_api.md) - Admin and quality data
- [Meraki MT](meraki.md) - Sensor correlation

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | None (no dedicated TA for Webex device telemetry) |
| **Ingestion** | Custom webhook/xAPI integration to HEC, or Webex Control Hub export |
| **Real sourcetype** | `cisco:webex:events` -- custom format for device telemetry |

