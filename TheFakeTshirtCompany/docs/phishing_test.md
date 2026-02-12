# Phishing Test Scenario

IT Security runs an authorized phishing awareness campaign across all 175 employees after the real exfil incident, using a KnowBe4-style simulation platform.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 3 days |
| Category | Attack (authorized simulation) |
| demo_id | `phishing_test` |
| Days | 21-23 |
| Impact | 31% click rate, 10% credential submission |

---

## Key Personnel

### Campaign Operator
| Attribute | Value |
|-----------|-------|
| Name | Ashley Griffin |
| Role | Security Analyst |
| Username | ashley.griffin |
| Email | ashley.griffin@theFakeTshirtCompany.com |
| IP | 10.10.30.168 |

### Simulation Platform
| Attribute | Value |
|-----------|-------|
| Sender | noreply@security-training.thefaketshirtcompany.com |
| Landing page | phishsim.knowbe4.com |
| Platform IP | 52.25.138.42 (AWS) |

---

## Timeline - Day 21 (Campaign Launch)

| Time | Event | Description |
|------|-------|-------------|
| **09:00** | Wave 1 | ~93 phishing emails sent to Boston employees |
| **10:00** | Wave 2 | ~43 phishing emails sent to Atlanta employees |
| **11:00** | Wave 3 | ~39 phishing emails sent to Austin employees |
| **12:00+** | First clicks | Employees start clicking the phishing link |

## Timeline - Days 21-22 (User Responses)

| Response | Count | Rate | Description |
|----------|-------|------|-------------|
| Clicked link | ~55 | 31% | Visited the fake login page |
| Submitted credentials | ~18 | 10% | Entered username/password |
| Reported to IT | ~35 | 20% | Forwarded to security team |
| Ignored/deleted | ~67 | 39% | No interaction |

## Timeline - Day 23 (Results)

| Time | Event | Description |
|------|-------|-------------|
| **10:00** | Results compiled | Campaign metrics gathered |
| **11:00** | Training emails | Mandatory training assigned to all clickers |

---

## Phishing Email Details

**Subject:** Action Required: Your Microsoft 365 password expires in 24 hours

**Lure:** Password expiration urgency targeting Microsoft 365 credentials. The simulated phishing page mimics a Microsoft login portal.

**Landing URL:** `https://phishsim.knowbe4.com/auth/faketshirtco/login`

---

## Timeline Visualization

```
Day 21                              Day 22                    Day 23
09:00  10:00  11:00  12:00                                    10:00  11:00
  |      |      |      |                                        |      |
  v      v      v      v                                        v      v
 BOS -> ATL -> AUS -> CLICKS START ------- RESPONSES -------> RESULTS -> TRAINING
 (~93)  (~43)  (~39)    |                     |                  |
                     31% click             20% report        Mandatory
                     10% creds             to IT             for clickers
```

---

## Response Breakdown by Location

| Location | Employees | Emails | Expected Clicks | Expected Creds |
|----------|-----------|--------|-----------------|----------------|
| Boston | ~93 | Wave 1 (09:00) | ~29 | ~9 |
| Atlanta | ~43 | Wave 2 (10:00) | ~13 | ~4 |
| Austin | ~39 | Wave 3 (11:00) | ~12 | ~4 |
| **Total** | **~175** | **~175** | **~55** | **~18** |

---

## Affected Log Sources

| Source | Events | Description |
|--------|--------|-------------|
| **Exchange** | Phishing emails sent, training emails | Message trace for all campaign emails |
| **Entra ID** | Sign-in attempts to phishing page | Failed MFA, suspicious sign-in from sim platform |
| **WinEventLog** | Browser process creation | Employees opening phishing link in browser |
| **Office Audit** | SafeLinks click events | URL click tracking via M365 Safe Links |
| **ServiceNow** | Campaign tracking incidents | Campaign creation, results documentation |
| **Secure Access** | DNS/proxy for phishing domain | DNS resolution and web proxy logs for sim URL |

---

## Logs to Look For

### Exchange - Campaign emails
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace" demo_id=phishing_test
| stats count by SenderAddress, Subject
```

### Exchange - All phishing emails with recipients
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace" demo_id=phishing_test
  SenderAddress="noreply@security-training*"
| timechart span=1h count
```

### Entra ID - Credential submissions
```spl
index=cloud sourcetype="azure:aad:signin" demo_id=phishing_test
| table _time, userPrincipalName, status.errorCode, ipAddress, location.city
```

### WinEventLog - Link clicks (browser launches)
```spl
index=windows sourcetype=WinEventLog demo_id=phishing_test
| table _time, ComputerName, user, NewProcessName
```

### Secure Access - DNS/proxy for phishing domain
```spl
index=cloud sourcetype="cisco:umbrella:dns" demo_id=phishing_test
| stats count by domain, response
```

### Office Audit - SafeLinks clicks
```spl
index=cloud sourcetype="o365:management:activity" demo_id=phishing_test
| search Operation="SafeLinksClick*"
| table _time, UserId, Url
```

### Full campaign timeline
```spl
index=* demo_id=phishing_test
| timechart span=1h count by sourcetype
```

### Click rate analysis
```spl
index=* demo_id=phishing_test
| stats dc(user) AS unique_users by sourcetype
| sort - unique_users
```

---

## Narrative Context

This scenario is deliberately placed **after** the exfil incident (Days 1-14). The timeline tells a story:

1. **Days 1-14**: Real APT exfiltration occurs undetected
2. **Days 15-20**: (Implied) Incident discovered, response begins
3. **Days 21-23**: IT Security runs phishing awareness campaign as remediation

The phishing simulation email mimics the same technique used in the real attack (credential phishing), making the campaign directly relevant to the incident.

---

## Talking Points

**Setup:**
> "After the exfil incident, IT Security decides to test how vulnerable the workforce really is. Ashley Griffin sets up a KnowBe4 phishing simulation targeting all 175 employees."

**Campaign:**
> "The emails go out in three waves -- Boston at 9 AM, Atlanta at 10, Austin at 11. The lure is a classic password expiration notice for Microsoft 365. Within hours, clicks start rolling in."

**Results:**
> "31% click rate, 10% actually submit credentials. These are industry-average numbers for a first-time phishing test. The good news: 20% reported the email to IT, showing some security awareness."

**Cross-correlation:**
> "Look at the Entra ID sign-in logs -- you can see attempted authentications against the KnowBe4 simulation page. The Secure Access DNS logs show who resolved the phishing domain. Exchange has the full email trail. Every source tells part of the story."

**Lesson:**
> "This ties the whole demo together. The real attack succeeded because someone clicked a phishing link (jessica.brown on Day 4). The simulation proves it could happen again -- 55 employees clicked the test phishing email. Security awareness training isn't optional."
