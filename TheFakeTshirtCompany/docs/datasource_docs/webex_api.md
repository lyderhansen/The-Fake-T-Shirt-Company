# Webex REST API

Webex REST API events including meetings, admin audit, security events, and quality metrics.

---
Based upon TA: [ta_cisco_webex_add_on_for_splunk/releases/tag/v1.3.1](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk/releases/tag/v1.3.1) - 
[git](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk)

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `cisco:webex:meetings`, `cisco:webex:admin:audit:events`, `cisco:webex:security:audit:events`, `cisco:webex:meeting:qualities`, `cisco:webex:call:detailed_history` |
| Format | JSON |
| Output File | `output/cloud/webex_api.log` |
| Volume | 100-300 events/day |

---

## Event Types

| Sourcetype | Description |
|------------|-------------|
| `cisco:webex:meetings` | Scheduled/completed meetings |
| `cisco:webex:admin:audit:events` | Admin actions |
| `cisco:webex:security:audit:events` | Login/logout events |
| `cisco:webex:meeting:qualities` | Quality metrics |
| `cisco:webex:call:detailed_history` | Call detail records |

---

## Meetings

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Meeting UUID | `uuid-123-456` |
| `title` | Meeting title | `Board Meeting` |
| `start` | Start time (ISO 8601) | `2026-01-05T14:00:00Z` |
| `end` | End time (ISO 8601) | `2026-01-05T15:00:00Z` |
| `organizer.email` | Host email | `john.smith@theFakeTshirtCompany.com` |
| `organizer.displayName` | Host name | `John Smith` |
| `attendees` | Attendee list | `["alex@...", "sarah@..."]` |
| `status` | Meeting status | `ACTIVE`, `COMPLETED`, `CANCELLED` |
| `isRecurring` | Recurring flag | `true`, `false` |
| `recurrence` | Recurrence pattern | `WEEKLY` |

### Example Event
```json
{
  "sourcetype": "cisco:webex:meetings",
  "id": "uuid-123-456-789",
  "title": "Q4 Strategy Review",
  "start": "2026-01-05T14:00:00Z",
  "end": "2026-01-05T15:30:00Z",
  "organizer": {
    "email": "sarah.wilson@theFakeTshirtCompany.com",
    "displayName": "Sarah Wilson"
  },
  "attendees": [
    "john.smith@theFakeTshirtCompany.com",
    "alex.miller@theFakeTshirtCompany.com",
    "mike.johnson@theFakeTshirtCompany.com"
  ],
  "status": "COMPLETED",
  "isRecurring": false,
  "location": "Link Room"
}
```

---

## Admin Audit Events

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Event ID | `event-001` |
| `timestamp` | ISO 8601 time | `2026-01-05T14:23:45Z` |
| `category` | Event category | `USERS`, `GROUPS`, `MEETINGS` |
| `action` | Action taken | `Created`, `Updated`, `Deleted` |
| `admin.email` | Admin who acted | `it.admin@theFakeTshirtCompany.com` |
| `admin.displayName` | Admin name | `IT Admin` |
| `resource.name` | Affected resource | `new.user@theFakeTshirtCompany.com` |
| `resource.type` | Resource type | `User`, `Group`, `Policy` |

### Categories

| Category | Description |
|----------|-------------|
| `USERS` | User management |
| `GROUPS` | Group management |
| `MEETINGS` | Meeting settings |
| `COMPLIANCE` | Compliance policies |
| `DEVICES` | Device management |

### Example Event
```json
{
  "sourcetype": "cisco:webex:admin:audit:events",
  "id": "audit-001",
  "timestamp": "2026-01-05T09:30:00Z",
  "category": "USERS",
  "action": "Created user",
  "admin": {
    "email": "hr.admin@theFakeTshirtCompany.com",
    "displayName": "HR Admin"
  },
  "resource": {
    "name": "new.employee@theFakeTshirtCompany.com",
    "type": "User"
  },
  "details": {
    "firstName": "New",
    "lastName": "Employee",
    "licenses": ["Webex Meetings", "Webex Calling"]
  }
}
```

---

## Security Audit Events

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Event ID | `login-001` |
| `timestamp` | ISO 8601 time | `2026-01-05T08:00:00Z` |
| `category` | Always `SECURITY` | `SECURITY` |
| `action` | Login/logout | `User login`, `User logout` |
| `user.email` | User email | `alex.miller@theFakeTshirtCompany.com` |
| `user.displayName` | User name | `Alex Miller` |
| `ipAddress` | Source IP | `10.10.30.55` |
| `userAgent` | Client info | `Webex Desktop/43.1.0` |
| `location` | Geo location | `Boston, MA` |

### Example Events

#### Login
```json
{
  "sourcetype": "cisco:webex:security:audit:events",
  "id": "login-001",
  "timestamp": "2026-01-05T08:00:00Z",
  "category": "SECURITY",
  "action": "User login",
  "user": {
    "email": "alex.miller@theFakeTshirtCompany.com",
    "displayName": "Alex Miller"
  },
  "ipAddress": "10.10.30.55",
  "userAgent": "Webex Desktop/43.1.0 (Windows)",
  "location": "Boston, MA",
  "result": "SUCCESS"
}
```

#### Logout
```json
{
  "sourcetype": "cisco:webex:security:audit:events",
  "id": "logout-001",
  "timestamp": "2026-01-05T17:30:00Z",
  "category": "SECURITY",
  "action": "User logout",
  "user": {
    "email": "alex.miller@theFakeTshirtCompany.com"
  },
  "sessionDuration": "9h 30m"
}
```

---

## Meeting Quality

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `meetingId` | Meeting UUID | `uuid-123-456` |
| `timestamp` | ISO 8601 time | `2026-01-05T14:30:00Z` |
| `audioQuality` | Quality rating | `Excellent`, `Good`, `Fair`, `Poor` |
| `audioMOS` | MOS score (1-5) | `4.2` |
| `videoQuality` | Video rating | `Good` |
| `videoLossPct` | Packet loss % | `1.5` |
| `jitterMs` | Network jitter | `25` |
| `latencyMs` | Network latency | `45` |
| `bandwidthMbps` | Bandwidth used | `3.5` |

### Example Event
```json
{
  "sourcetype": "cisco:webex:meeting:qualities",
  "meetingId": "uuid-123-456",
  "timestamp": "2026-01-05T14:30:00Z",
  "audioQuality": "Good",
  "audioMOS": 4.1,
  "videoQuality": "Good",
  "videoLossPct": 1.2,
  "jitterMs": 20,
  "latencyMs": 40,
  "bandwidthMbps": 3.2,
  "participants": 8,
  "duration": 30
}
```

---

## Call Detail Records

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `callId` | Call UUID | `call-001` |
| `startTime` | Start time | `2026-01-05T14:00:00Z` |
| `endTime` | End time | `2026-01-05T14:15:00Z` |
| `duration` | Duration (seconds) | `900` |
| `caller.email` | Caller email | `alex.miller@theFakeTshirtCompany.com` |
| `callee.email` | Called party | `sarah.wilson@theFakeTshirtCompany.com` |
| `callType` | Call type | `INTERNAL`, `EXTERNAL`, `PSTN` |
| `result` | Call result | `ANSWERED`, `NO_ANSWER`, `BUSY` |

### Example Event
```json
{
  "sourcetype": "cisco:webex:call:detailed_history",
  "callId": "call-001",
  "startTime": "2026-01-05T14:00:00Z",
  "endTime": "2026-01-05T14:12:30Z",
  "duration": 750,
  "caller": {
    "email": "alex.miller@theFakeTshirtCompany.com",
    "displayName": "Alex Miller",
    "extension": "1055"
  },
  "callee": {
    "email": "sarah.wilson@theFakeTshirtCompany.com",
    "displayName": "Sarah Wilson",
    "extension": "1012"
  },
  "callType": "INTERNAL",
  "result": "ANSWERED"
}
```

---

## Use Cases

### 1. User Provisioning Audit
Track user management:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:admin:audit:events" category="USERS"
| table _time, action, admin.email, resource.name
| sort _time
```

### 2. Login Pattern Analysis
Find suspicious login times:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:security:audit:events" action="User login"
| eval hour = strftime(_time, "%H")
| where hour < 6 OR hour > 22
| table _time, user.email, ipAddress, location
```

### 3. Meeting Quality Trends
Monitor quality over time:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meeting:qualities"
| timechart span=1d avg(audioMOS) AS avg_mos, avg(videoLossPct) AS avg_loss
```

### 4. Poor Quality Meetings
Find problematic meetings:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meeting:qualities"
| where audioMOS < 3.5 OR videoLossPct > 5
| table _time, meetingId, audioMOS, videoLossPct, jitterMs
```

### 5. Call Volume Analysis
Track calling patterns:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:call:detailed_history"
| timechart span=1h count by callType
```

### 6. Admin Activity Summary
Summarize admin actions:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:admin:audit:events"
| stats count by admin.email, category, action
| sort - count
```

---

## Talking Points

**User Management:**
> "We can track every user provisioning action - who created accounts, assigned licenses, or modified settings. Full audit trail for compliance."

**Security Monitoring:**
> "Login events show time, location, and IP. Combined with Entra ID, we can correlate Webex access with overall identity posture."

**Quality Assurance:**
> "Meeting quality metrics give us MOS scores and packet loss. If users complain about call quality, we have objective data to investigate."

**Admin Accountability:**
> "Every admin action is logged with the admin's identity. Policy changes, user deletions, license assignments - all tracked."

---

## Related Sources

- [Webex Devices](webex_devices.md) - Real-time device events
- [Webex Meetings TA](webex_meetings.md) - Meeting history
- [Entra ID](entraid.md) - Identity correlation

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | [Webex Add-on for Splunk](https://splunkbase.splunk.com/app/8365) |
| **Ingestion** | Webex REST API polling |
| **Real sourcetypes** | `cisco:webex:meetings`, `cisco:webex:admin:audit:events`, `cisco:webex:meeting:qualities`, etc. |

