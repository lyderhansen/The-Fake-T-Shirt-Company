# Webex Meetings TA

Webex Meetings history from the Splunk Technical Add-on format.

---

Based on TA: [ta-cisco-webex-meetings-add-on-for-splunk](https://github.com/splunk/ta-cisco-webex-meetings-add-on-for-splunk)
## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `cisco:webex:meetings:history:meetingusagehistory`, `cisco:webex:meetings:history:meetingattendeehistory` |
| Format | JSON |
| Output File | `output/cloud/webex_meetings.log` |
| Volume | 100-200 events/day |

---

## Event Types

### Meeting Usage History
One event per meeting with summary data.

### Meeting Attendee History
One event per attendee per meeting with individual participation details.

---

## Meeting Usage Fields

| Field | Description | Example |
|-------|-------------|---------|
| `MeetingName` | Meeting title | `Weekly Team Sync` |
| `MeetingNumber` | Meeting ID | `123456789` |
| `MeetingStartTime` | Start time | `01/05/2026 09:00:00` |
| `MeetingEndTime` | End time | `01/05/2026 09:45:00` |
| `Duration` | Duration (minutes) | `45` |
| `TotalAttendees` | Attendee count | `8` |
| `OrganizerEmail` | Host email | `john.smith@theFakeTshirtCompany.com` |
| `OrganizerName` | Host name | `John Smith` |
| `HostKey` | Host identifier | `host-001` |
| `MeetingType` | Meeting type | `MC`, `TC`, `EC`, `SC` |
| `SiteURL` | Webex site | `theFakeTshirtCompany.webex.com` |
| `AudioType` | Audio connection | `VoIP`, `PSTN`, `BOTH` |
| `RecordingPresent` | Was it recorded? | `Yes`, `No` |

---

## Meeting Types

| Code | Description |
|------|-------------|
| `MC` | Meeting Center (standard) |
| `TC` | Training Center |
| `EC` | Event Center |
| `SC` | Support Center |

---

## Attendee History Fields

| Field | Description | Example |
|-------|-------------|---------|
| `MeetingNumber` | Meeting ID | `123456789` |
| `MeetingName` | Meeting title | `Weekly Team Sync` |
| `UserName` | Attendee name | `Alex Miller` |
| `UserEmail` | Attendee email | `alex.miller@theFakeTshirtCompany.com` |
| `JoinTime` | Join timestamp | `01/05/2026 09:00:15` |
| `LeaveTime` | Leave timestamp | `01/05/2026 09:45:10` |
| `Duration` | Attendance (min) | `45` |
| `ClientOS` | Operating system | `Windows 11`, `macOS 14` |
| `ClientType` | Client used | `Webex Desktop`, `Mobile`, `Browser` |
| `ParticipantRole` | Role | `Organizer`, `Presenter`, `Attendee` |

---

## Client Types

| Type | Description |
|------|-------------|
| `Webex Desktop` | Desktop application |
| `Webex Mobile` | iOS/Android app |
| `Browser` | Web client |
| `Room Device` | Room Kit, Board, etc. |
| `PSTN` | Phone dial-in |

---

## Example Events

### Meeting Usage History
```json
{
  "sourcetype": "cisco:webex:meetings:history:meetingusagehistory",
  "MeetingName": "Q4 Planning Session",
  "MeetingNumber": "123456789",
  "MeetingStartTime": "01/05/2026 14:00:00",
  "MeetingEndTime": "01/05/2026 15:30:00",
  "Duration": "90",
  "TotalAttendees": "12",
  "OrganizerEmail": "sarah.wilson@theFakeTshirtCompany.com",
  "OrganizerName": "Sarah Wilson",
  "MeetingType": "MC",
  "SiteURL": "theFakeTshirtCompany.webex.com",
  "AudioType": "VoIP",
  "RecordingPresent": "Yes"
}
```

### Attendee History
```json
{
  "sourcetype": "cisco:webex:meetings:history:meetingattendeehistory",
  "MeetingNumber": "123456789",
  "MeetingName": "Q4 Planning Session",
  "UserName": "Alex Miller",
  "UserEmail": "alex.miller@theFakeTshirtCompany.com",
  "JoinTime": "01/05/2026 14:02:00",
  "LeaveTime": "01/05/2026 15:30:00",
  "Duration": "88",
  "ClientOS": "Windows 11",
  "ClientType": "Webex Desktop",
  "ParticipantRole": "Attendee"
}
```

### PSTN Attendee
```json
{
  "sourcetype": "cisco:webex:meetings:history:meetingattendeehistory",
  "MeetingNumber": "123456789",
  "UserName": "External Partner",
  "UserEmail": "partner@external.com",
  "JoinTime": "01/05/2026 14:05:00",
  "LeaveTime": "01/05/2026 15:00:00",
  "Duration": "55",
  "ClientType": "PSTN",
  "ParticipantRole": "Attendee"
}
```

### Room Device Attendee
```json
{
  "sourcetype": "cisco:webex:meetings:history:meetingattendeehistory",
  "MeetingNumber": "123456789",
  "UserName": "Link Room",
  "UserEmail": "link-room@theFakeTshirtCompany.com",
  "JoinTime": "01/05/2026 13:58:00",
  "LeaveTime": "01/05/2026 15:30:00",
  "Duration": "92",
  "ClientType": "Room Device",
  "ParticipantRole": "Presenter"
}
```

---

## Use Cases

### 1. Meeting Volume Trends
Track meeting patterns:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingusagehistory"
| timechart span=1d count AS meetings, sum(TotalAttendees) AS total_attendees
```

### 2. Organizer Activity
Find most active meeting hosts:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingusagehistory"
| stats count AS meetings, sum(Duration) AS total_minutes by OrganizerEmail
| eval hours = round(total_minutes / 60, 1)
| sort - meetings
```

### 3. Meeting Duration Analysis
Analyze meeting lengths:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingusagehistory"
| stats count by Duration
| eval duration_bucket = case(
    Duration <= 15, "Quick (≤15 min)",
    Duration <= 30, "Short (16-30 min)",
    Duration <= 60, "Standard (31-60 min)",
    true(), "Long (>60 min)"
)
| stats sum(count) by duration_bucket
```

### 4. Client Type Distribution
See how people join:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingattendeehistory"
| stats count by ClientType
| sort - count
```

### 5. Late Joiners
Find participants who join late:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingattendeehistory"
| rex field=JoinTime "(?<join_time>\d{2}:\d{2}:\d{2})$"
| rex field=MeetingStartTime "(?<start_time>\d{2}:\d{2}:\d{2})$"
| eval late_seconds = strptime(join_time, "%H:%M:%S") - strptime(start_time, "%H:%M:%S")
| where late_seconds > 300
| stats count by UserEmail
| sort - count
```

### 6. Recording Compliance
Track recorded meetings:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingusagehistory"
| stats count AS total,
        count(eval(RecordingPresent="Yes")) AS recorded
| eval recording_pct = round(recorded / total * 100, 1)
```

### 7. External Participants
Find meetings with external attendees:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingattendeehistory"
  NOT UserEmail="*@theFakeTshirtCompany.com"
| stats dc(MeetingNumber) AS meetings, dc(UserEmail) AS unique_externals
```

---

## Meeting Templates

Common meeting types generated:

| Template | Duration | Attendees | Frequency |
|----------|----------|-----------|-----------|
| Daily Standup | 15 min | 5-8 | Daily |
| 1:1 Meeting | 30 min | 2 | Weekly |
| Team Sync | 45-60 min | 6-12 | Weekly |
| Project Review | 60-90 min | 8-15 | Bi-weekly |
| All-Hands | 60 min | 20+ | Monthly |
| Training | 90-120 min | 10-30 | As needed |

---

## Talking Points

**Meeting Culture:**
> "We average 15-20 meetings per day across the organization. Most are under 60 minutes, but notice the long-tail of 90+ minute meetings."

**Client Adoption:**
> "70% of participants use Webex Desktop, 15% mobile, and 10% room devices. PSTN dial-in is only 5% - VoIP adoption is strong."

**Organizer Patterns:**
> "Some people are meeting-heavy. The top 10 organizers account for 40% of all meetings. That might indicate collaboration or might indicate too many meetings."

**Recording Compliance:**
> "Only 30% of meetings are recorded. If there's a policy requiring recording for certain meeting types, we're not hitting it."

---

## Related Sources

- [Webex Devices](webex_devices.md) - Real-time device events
- [Webex API](webex_api.md) - Admin and quality data

