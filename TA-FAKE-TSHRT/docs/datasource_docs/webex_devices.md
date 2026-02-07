# Webex Room Devices

Cisco Webex collaboration device events from 17 meeting rooms across 3 locations.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `cisco:webex:events` |
| Format | JSON |
| Output File | `output/cloud/webex_events.log` |
| Volume | 50-200 events/day |
| Rooms | 17 meeting rooms |

---

## Device Inventory

### Boston (7 rooms)
| Room | Device ID | Model | Capacity |
|------|-----------|-------|----------|
| Cambridge | WEBEX-BOS-CAMBRIDGE | Room Kit Pro + Board 85 Pro | 20 |
| Faneuil | WEBEX-BOS-FANEUIL | Room Kit + Board 55 | 12 |
| Quincy | WEBEX-BOS-QUINCY | Room Kit | 8 |
| North End | WEBEX-BOS-NORTHEND | Desk Pro | 4 |
| Back Bay | WEBEX-BOS-BACKBAY | Room Kit Mini | 6 |
| Harbor | WEBEX-BOS-HARBOR | Desk Pro | 6 |
| Beacon | WEBEX-BOS-BEACON | Room Kit Mini | 4 |

### Atlanta (6 rooms)
| Room | Device ID | Model | Capacity |
|------|-----------|-------|----------|
| Peachtree | WEBEX-ATL-PEACHTREE | Room Kit Pro | 16 |
| Midtown | WEBEX-ATL-MIDTOWN | Room Kit + Board 55 | 10 |
| NOC | WEBEX-ATL-NOC | Room Kit | 6 |
| Buckhead | WEBEX-ATL-BUCKHEAD | Desk Pro | 4 |
| Decatur | WEBEX-ATL-DECATUR | Desk Pro | 4 |
| Innovation Lab | WEBEX-ATL-INNOVATION | Board 55 | 8 |

### Austin (3 rooms)
| Room | Device ID | Model | Capacity |
|------|-----------|-------|----------|
| Congress | WEBEX-AUS-CONGRESS | Room Kit + Board 55 | 12 |
| 6th Street | WEBEX-AUS-6THSTREET | Room Kit Mini | 6 |
| Live Oak | WEBEX-AUS-LIVEOAK | Room Kit | 8 |

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
| `device_id` | Device identifier | `WEBEX-BOS-CAMBRIDGE` |
| `device_model` | Hardware model | `Room Kit Pro` |
| `location` | Site | `Boston HQ` |
| `location_code` | Site code | `BOS` |
| `room` | Room name | `Cambridge` |
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
  "device_id": "WEBEX-BOS-CAMBRIDGE",
  "device_model": "Room Kit Pro",
  "location": "Boston HQ",
  "location_code": "BOS",
  "room": "Cambridge",
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
  "device_id": "WEBEX-BOS-CAMBRIDGE",
  "room": "Cambridge",
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
  "device_id": "WEBEX-BOS-NORTHEND",
  "room": "North End",
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
  "device_id": "WEBEX-BOS-CAMBRIDGE",
  "room": "Cambridge",
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
  "device_id": "WEBEX-BOS-CAMBRIDGE",
  "room": "Cambridge",
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
| **North End** (BOS) | wifi_congestion, old_equipment | Low MOS, high jitter |
| **Peachtree** (ATL) | bandwidth_limited, echo_issues | Video loss, echo |

### Problem Room Quality
```json
{
  "room": "North End",
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
index=cloud sourcetype="cisco:webex:events" event_type="meeting_started"
| timechart span=1h count by location_code
```

### 2. Room Utilization
Find busiest rooms:
```spl
index=cloud sourcetype="cisco:webex:events" event_type="meeting_started"
| stats count AS meetings, sum(actual_duration_min) AS total_minutes by room
| eval hours = round(total_minutes / 60, 1)
| sort - hours
```

### 3. Quality Issues
Identify problematic meetings:
```spl
index=cloud sourcetype="cisco:webex:events" event_type="quality_metrics"
| where audio.mos_score < 3.5 OR video.packet_loss_pct > 3
| table _time, room, audio.mos_score, video.packet_loss_pct, quality_issue
```

### 4. Problem Room Trends
Track specific room issues:
```spl
index=cloud sourcetype="cisco:webex:events" event_type="quality_metrics"
  room IN ("North End", "Peachtree")
| timechart span=1d avg(audio.mos_score) by room
```

### 5. Ghost Meeting Detection
Find no-shows:
```spl
index=cloud sourcetype="cisco:webex:events"
| transaction meeting_id maxspan=2h
| where NOT match(_raw, "participant_joined")
| table meeting_id, room, organizer
```

### 6. Participant Analysis
Track meeting participation:
```spl
index=cloud sourcetype="cisco:webex:events" event_type="participant_joined"
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
> "Cambridge is our most-used room - 6+ hours of meetings daily. But look at ghost meetings - 15% of bookings are no-shows. That's wasted capacity."

**Quality Issues:**
> "North End consistently shows poor audio quality. MOS scores below 3.5, high jitter. This room is near a busy AP - WiFi congestion is the culprit."

**Sensor Correlation:**
> "Watch the temperature: it starts rising 2 minutes before the meeting starts as people enter. During a 10-person meeting, the room temperature increases by 2-3 degrees."

**Problem Rooms:**
> "We have two problem rooms flagged for AV issues. Peachtree has echo problems - bad acoustics. North End has old equipment. These need IT attention."

---

## Related Sources

- [Webex Meetings TA](webex_meetings.md) - Meeting history details
- [Webex API](webex_api.md) - Admin and quality data
- [Meraki MT](meraki.md) - Sensor correlation

