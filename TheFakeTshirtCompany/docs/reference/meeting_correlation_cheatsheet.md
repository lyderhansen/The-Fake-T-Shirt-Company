# Meeting Correlation Cheat Sheet

Quick reference for tracing meetings across all correlated data sources in Splunk.

## How Correlation Works

```
Phase 1: generate_webex.py populates shared meeting_schedule
    |
    v
Phase 2 (parallel):
    generate_webex_ta.py  --> reads shared schedule --> webex_ta_meetingusage.json + webex_ta_attendee.json
    generate_webex_api.py --> reads shared schedule --> webex_api_meetings.json + quality/audit files
    generate_exchange.py  --> reads shared schedule --> exchange calendar invite emails
    generate_meraki.py    --> reads shared schedule --> MT door/temp sensors + MV cameras
```

All five generators produce events for the **exact same meetings** with matching titles, times, hosts, and participants.

## Correlation Fields

| Source | Sourcetype | Meeting Title Field | Host/Organizer Field | Time Field |
|--------|-----------|--------------------|--------------------|-----------|
| Webex Events | `cisco:webex:events` | `meeting_title` | `organizer` | `timestamp` |
| Webex TA | `cisco:webex:meetings:history:meetingusagehistory` | `confName` | `hostName` / `hostEmail` | `meetingStartTime` |
| Webex API | `cisco:webex:meetings` | `title` | `hostDisplayName` / `hostEmail` | `start` |
| Exchange | `ms:o365:reporting:messagetrace` | `Subject` (format: `Meeting Invite: {title} - {room}`) | `SenderAddress` | `Received` |
| Meraki MT | `meraki:mt` | N/A (correlate by room/time) | N/A | syslog timestamp |
| Meraki MV | `meraki:mv` | N/A (correlate by room/time) | N/A | syslog timestamp |

## Room-to-Device Mapping

### Boston HQ (10 rooms)

| Room | Floor | Webex Device | Door Sensor | Temp Sensor | Camera | Cap | Notes |
|------|-------|-------------|-------------|-------------|--------|-----|-------|
| Link | 3 | WEBEX-BOS-3F-LINK | MT-BOS-3F-DOOR-LINK | MT-BOS-3F-TEMP-LINK | MV-BOS-3F-LINK | 20 | Boardroom. Sun: South +4C (1-5pm) |
| Zelda | 2 | WEBEX-BOS-2F-ZELDA | MT-BOS-2F-DOOR-ZELDA | MT-BOS-2F-TEMP-ZELDA | -- | 12 | |
| Samus | 2 | WEBEX-BOS-2F-SAMUS | MT-BOS-2F-DOOR-SAMUS | MT-BOS-2F-TEMP-SAMUS | -- | 8 | Sun: East +2C (8-11am) |
| Kirby | 3 | WEBEX-BOS-3F-KIRBY | MT-BOS-3F-DOOR-KIRBY | MT-BOS-3F-TEMP-KIRBY | -- | 4 | **Problem room**: WiFi congestion, old equipment. Sun: West +2.5C (3-6pm). After-hours: Days 3+7 |
| Yoshi | 3 | WEBEX-BOS-3F-YOSHI | MT-BOS-3F-DOOR-YOSHI | MT-BOS-3F-TEMP-YOSHI | -- | 6 | After-hours: Days 3+7 |
| Sonic | 3 | WEBEX-BOS-3F-SONIC | MT-BOS-3F-DOOR-SONIC | MT-BOS-3F-TEMP-SONIC | MV-BOS-3F-SONIC | 8 | Lab |
| Peach | 1 | WEBEX-BOS-1F-PEACH | MT-BOS-1F-DOOR-PEACH | MT-BOS-1F-TEMP-PEACH | MV-BOS-1F-PEACH | 6 | Visitor room. Sun: East +1.5C (8-10am) |
| Toad | 1 | WEBEX-BOS-1F-TOAD | MT-BOS-1F-DOOR-TOAD | -- | -- | 4 | Visitor room |
| Mario | 2 | WEBEX-BOS-2F-MARIO | MT-BOS-2F-DOOR-MARIO | MT-BOS-2F-TEMP-MARIO | -- | 10 | |
| Luigi | 3 | WEBEX-BOS-3F-LUIGI | MT-BOS-3F-DOOR-LUIGI | MT-BOS-3F-TEMP-LUIGI | -- | 8 | |

### Atlanta Hub (7 rooms)

| Room | Floor | Webex Device | Door Sensor | Temp Sensor | Camera | Cap | Notes |
|------|-------|-------------|-------------|-------------|--------|-----|-------|
| Cortana | 2 | WEBEX-ATL-2F-CORTANA | MT-ATL-2F-DOOR-CORTANA | MT-ATL-2F-TEMP-CORTANA | MV-ATL-2F-CORTANA | 16 | **Problem room**: Bandwidth limited, echo issues. Sun: West +3C (2-6pm) |
| Chief | 2 | WEBEX-ATL-2F-CHIEF | MT-ATL-2F-DOOR-CHIEF | MT-ATL-2F-TEMP-CHIEF | -- | 10 | Sun: West +3.5C (2-6pm) |
| Ryu | 1 | WEBEX-ATL-1F-RYU | MT-ATL-1F-DOOR-RYU | MT-ATL-1F-TEMP-RYU | MV-ATL-1F-RYU | 6 | Operations |
| Pikachu | 2 | WEBEX-ATL-2F-PIKACHU | MT-ATL-2F-DOOR-PIKACHU | -- | -- | 4 | After-hours: Days 3+7. Sun: South +2C (11am-3pm) |
| Megaman | 2 | WEBEX-ATL-2F-MEGAMAN | MT-ATL-2F-DOOR-MEGAMAN | MT-ATL-2F-TEMP-MEGAMAN | -- | 4 | |
| Lara | 2 | WEBEX-ATL-2F-LARA | MT-ATL-2F-DOOR-LARA | MT-ATL-2F-TEMP-LARA | -- | 8 | Lab. Sun: East +1.5C (8-11am) |
| Kratos | 1 | WEBEX-ATL-1F-KRATOS | MT-ATL-1F-DOOR-KRATOS | MT-ATL-1F-TEMP-KRATOS | -- | 8 | |

### Austin Office (4 rooms)

| Room | Floor | Webex Device | Door Sensor | Temp Sensor | Camera | Cap | Notes |
|------|-------|-------------|-------------|-------------|--------|-----|-------|
| Doom | 1 | WEBEX-AUS-1F-DOOM | MT-AUS-1F-DOOR-DOOM | MT-AUS-1F-TEMP-DOOM | -- | 12 | Sun: Southwest +5C (12-5pm) -- hottest room |
| Fox | 1 | WEBEX-AUS-1F-FOX | MT-AUS-1F-DOOR-FOX | -- | -- | 6 | |
| Jett | 1 | WEBEX-AUS-1F-JETT | MT-AUS-1F-DOOR-JETT | MT-AUS-1F-TEMP-JETT | MV-AUS-1F-JETT | 8 | Demo room. Sun: East +2C (8-11am) |
| Crash | 1 | WEBEX-AUS-1F-CRASH | MT-AUS-1F-DOOR-CRASH | MT-AUS-1F-TEMP-CRASH | -- | 8 | |

## Meeting Behavior Patterns

| Pattern | Probability | What to Look For |
|---------|------------|------------------|
| Ghost (no-show) | ~15% | Calendar invite sent, no Webex events, no sensor activity |
| Walk-in (unbooked) | ~10% | Door/camera activity WITHOUT matching Webex events |
| Late start | ~20% | Meeting starts 5-15 min after scheduled time |
| Overfilled | ~5% | More participants than room capacity |
| After-hours | Days 3+7 | Rooms Yoshi, Kirby (BOS), Pikachu (ATL) -- 20:00-23:00 |

## Sample SPL Queries

### Trace a Single Meeting Across All Sources

```spl
| Search for a specific meeting title on a specific day
index=fake_tshrt earliest="01/05/2026:00:00:00" latest="01/05/2026:23:59:59"
  (sourcetype="FAKE:cisco:webex:events" event_type="meeting_started" meeting_title="Team Standup")
  OR (sourcetype="FAKE:cisco:webex:meetings:history:meetingusagehistory" confName="Team Standup")
  OR (sourcetype="FAKE:cisco:webex:meetings" title="Team Standup")
  OR (sourcetype="FAKE:ms:o365:reporting:messagetrace" Subject="Meeting Invite: Team Standup*")
| stats count by sourcetype
```

### Correlate Meeting with Room Sensors

```spl
| Given a room name (e.g., Zelda) and time window, find all related events
index=fake_tshrt earliest="01/05/2026:09:00:00" latest="01/05/2026:11:00:00"
  (sourcetype="FAKE:cisco:webex:events" device_id="WEBEX-BOS-2F-ZELDA")
  OR (sourcetype="FAKE:meraki:mt" sensor_name="MT-BOS-2F-*-ZELDA")
  OR (sourcetype="FAKE:meraki:mv" camera_name="MV-BOS-2F-*")
| sort _time
| table _time sourcetype event_type
```

### Find Problem Room Quality Issues

```spl
| Kirby and Cortana have known quality issues
index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="quality_metrics"
  (device_id="WEBEX-BOS-3F-KIRBY" OR device_id="WEBEX-ATL-2F-CORTANA")
| where 'audio.mos_score' < 3.5 OR 'video.packet_loss_pct' > 3
| stats count avg(audio.mos_score) as avg_mos avg(video.packet_loss_pct) as avg_loss by device_id
```

### Ghost Meeting Detection

```spl
| Meetings with calendar invites but no actual Webex start event
index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace" Subject="Meeting Invite:*"
| rex field=Subject "Meeting Invite: (?<meeting_title>[^-]+)"
| join type=left meeting_title
  [search index=fake_tshrt sourcetype="FAKE:cisco:webex:events" event_type="meeting_started"
   | rename meeting_title as meeting_title]
| where isnull(event_type)
```

### After-Hours Activity Detection

```spl
| Sensor activity between 20:00-23:00 on Days 3 and 7
index=fake_tshrt sourcetype="FAKE:meraki:mt"
  (sensor_name="MT-BOS-3F-DOOR-YOSHI" OR sensor_name="MT-BOS-3F-DOOR-KIRBY" OR sensor_name="MT-ATL-2F-DOOR-PIKACHU")
  date_hour>=20 date_hour<23
| timechart count by sensor_name
```

### Temperature Anomaly in Sunny Rooms

```spl
| Compare temperature in sunny rooms (Link, Chief, Doom) during sun hours
index=fake_tshrt sourcetype="FAKE:meraki:mt" metric_type="temperature"
  (sensor_name="MT-BOS-3F-TEMP-LINK" OR sensor_name="MT-ATL-2F-TEMP-CHIEF" OR sensor_name="MT-AUS-1F-TEMP-DOOM")
| timechart avg(temperature) by sensor_name
```

## Meeting Types

All 15 meeting types used across all Webex generators:

| Meeting Type | Duration | Participants | Notes |
|-------------|----------|-------------|-------|
| Team Standup | 15 min | 3-8 | Recurring |
| Project Review | 60 min | 4-12 | |
| Sprint Planning | 120 min | 5-15 | Recurring |
| 1:1 Meeting | 30 min | 2 | Recurring |
| All Hands | 60 min | 20-50 | Recurring, large rooms only |
| Training Session | 90 min | 6-16 | |
| Client Call | 45 min | 2-6 | External participants (20%) |
| Budget Review | 60 min | 3-8 | |
| Design Review | 45 min | 3-10 | |
| Interview | 60 min | 2-5 | External participants (20%) |
| Vendor Meeting | 60 min | 3-8 | External participants (20%) |
| Board Meeting | 120 min | 6-15 | Recurring |
| Executive Sync | 30 min | 2-6 | Recurring |
| Tech Deep Dive | 90 min | 3-8 | |
| Sales Pipeline | 60 min | 4-10 | Recurring |

## Exchange Email Subject Patterns

| Pattern | Example | Description |
|---------|---------|-------------|
| `Meeting Invite: {title} - {room}` | `Meeting Invite: Team Standup - Zelda` | Calendar invite from organizer |
| `Accepted: {title}` | `Accepted: Team Standup` | Participant accepted |
| `Tentative: {title}` | `Tentative: Sprint Planning` | Participant tentatively accepted |
| `Declined: {title}` | `Declined: Budget Review` | Participant declined |
