# Webex Meetings TA

Webex meeting history and attendee data in the Splunk TA for Cisco Webex Meetings format, providing meeting usage records and per-attendee details.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `cisco:webex:meetings:history:meetingusagehistory`, `cisco:webex:meetings:history:meetingattendeehistory` |
| Format | JSON |
| Output Files | `output/cloud/webex/webex_ta_meetingusage.json`, `webex_ta_attendee.json` |
| Volume | Usage: ~20-40/day, Attendees: ~100-300/day |
| Site URL | theFakeTshirtCompany.webex.com |

---

## Data Types

### Meeting Usage History
| Field | Description | Example |
|-------|-------------|---------|
| `confID` | Conference ID | `123456789` |
| `confName` | Meeting title | `Team Standup` |
| `meetingKey` | Meeting key | `987654321` |
| `hostName` | Host display name | `John Smith` |
| `hostEmail` | Host email | `john.smith@theTshirtCompany.com` |
| `meetingStartTime` | Start time | `01/05/2026 09:00:00` |
| `meetingEndTime` | End time | `01/05/2026 09:20:00` |
| `duration` | Duration (minutes) | `20` |
| `totalParticipants` | Attendee count | `8` |
| `peakAttendee` | Peak concurrent | `8` |
| `meetingType` | Meeting type | `MC` (Meeting Center) |
| `demo_id` | Scenario tag | `exfil` |

### Meeting Attendee History
| Field | Description | Example |
|-------|-------------|---------|
| `confID` | Conference ID (join key) | `123456789` |
| `attendeeName` | Attendee name | `Alex Miller` |
| `attendeeEmail` | Attendee email | `alex.miller@theTshirtCompany.com` |
| `joinTime` | Join timestamp | `01/05/2026 08:58:00` |
| `leaveTime` | Leave timestamp | `01/05/2026 09:22:00` |
| `duration` | Minutes in meeting | `24` |
| `ipAddress` | Client IP | `10.10.30.55` |
| `clientType` | Client software | `Webex Desktop` |
| `clientOS` | Operating system | `Windows 10` |
| `participantType` | Role | `HOST`, `ATTENDEE` |
| `demo_id` | Scenario tag | `exfil` |

---

## Example Events

### Meeting Usage Record
```json
{"confID": "123456789", "confName": "Team Standup", "meetingKey": "987654321", "hostName": "John Smith", "hostEmail": "john.smith@theTshirtCompany.com", "hostWebExID": "john.smith", "meetingStartTime": "01/05/2026 09:00:00", "meetingEndTime": "01/05/2026 09:20:00", "duration": "20", "totalParticipants": "8", "peakAttendee": "8", "meetingType": "MC", "siteUrl": "theFakeTshirtCompany.webex.com"}
```

### Attendee Record
```json
{"confID": "123456789", "confName": "Team Standup", "attendeeName": "Alex Miller", "attendeeEmail": "alex.miller@theTshirtCompany.com", "joinTime": "01/05/2026 08:58:00", "leaveTime": "01/05/2026 09:22:00", "duration": "24", "ipAddress": "10.10.30.55", "clientType": "Webex Desktop", "clientOS": "Windows 10", "participantType": "ATTENDEE"}
```

---

## Use Cases

### 1. Meeting frequency by host
```spl
index=cloud sourcetype="cisco:webex:meetings:history:meetingusagehistory"
| stats count by hostName
| sort - count
```

### 2. Average meeting duration
```spl
index=cloud sourcetype="cisco:webex:meetings:history:meetingusagehistory"
| stats avg(duration) AS avg_minutes, count AS meetings
| eval avg_minutes = round(avg_minutes, 1)
```

### 3. Attendee participation rates
```spl
index=cloud sourcetype="cisco:webex:meetings:history:meetingattendeehistory"
| stats count AS meetings_attended by attendeeName
| sort - meetings_attended
```

### 4. Client platform distribution
```spl
index=cloud sourcetype="cisco:webex:meetings:history:meetingattendeehistory"
| stats count by clientType, clientOS
| sort - count
```

### 5. Exfil user meeting activity
```spl
index=cloud sourcetype="cisco:webex:meetings:history:meetingattendeehistory"
  (attendeeEmail="alex.miller@*" OR attendeeEmail="jessica.brown@*")
| table _time, confName, attendeeName, ipAddress, duration
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 0-13 | Meetings hosted by or attended by jessica.brown/alex.miller get demo_id tag |

---

## Timestamp Format

Note: This generator uses `MM/DD/YYYY HH:MM:SS` format (Webex TA convention), different from the ISO 8601 format used by the Webex API generator.

---

## Talking Points

**Collaboration analytics:**
> "The Webex TA data shows meeting patterns across the organization. You can see who's meeting with whom, how often, and from where. During the exfil scenario, correlate jessica.brown's meeting attendance with her lateral movement activity."

**User behavior baseline:**
> "Meeting data helps establish normal user behavior. If an account suddenly stops attending meetings while generating suspicious network traffic, that's a red flag worth investigating."

---

## Related Sources

- [Webex API](webex_api.md) - Real-time meeting events and quality metrics
- [Webex Devices](webex_devices.md) - Room device telemetry and room analytics
- [Entra ID](entraid.md) - User identity correlation
