# Microsoft Entra ID (Azure AD)

Sign-in logs, audit logs, and risk detection events for 175 employees and 5 service principals across the theFakeTshirtCompany.com tenant. The richest identity source in the project with 35+ event types across 3 scenarios.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `azure:aad:signin`, `azure:aad:audit` |
| Format | JSON (NDJSON) |
| Output Files | `output/cloud/entraid/entraid_signin.json`, `entraid_audit.json` |
| Volume | ~1,200-1,500 events/day (sign-ins + SP + audit + risk) |
| Tenant | theFakeTshirtCompany.com |
| Tenant ID | af23e456-7890-1234-5678-abcdef012345 |

---

## Key Fields

### Sign-in Events

| Field | Description | Example |
|-------|-------------|---------|
| `properties.userPrincipalName` | User identity | `alex.miller@theFakeTshirtCompany.com` |
| `properties.ipAddress` | Source IP | `10.10.30.55` |
| `properties.status.errorCode` | Result code (0=success) | `0`, `50126`, `53003` |
| `properties.status.failureReason` | Error description | `Invalid username or password` |
| `properties.appDisplayName` | Target application | `Microsoft Office 365 Portal` |
| `properties.mfaDetail.authMethod` | MFA method used | `Microsoft Authenticator` |
| `properties.mfaDetail.authDetail` | MFA detail | `Notification approved` |
| `properties.conditionalAccessStatus` | CA result | `success`, `failure`, `notApplied` |
| `properties.deviceDetail.operatingSystem` | Client OS | `Windows 11` |
| `properties.clientAppUsed` | Client type | `Browser`, `Mobile Apps and Desktop clients` |
| `properties.location.city` | GeoIP city | `Boston` |
| `properties.location.countryOrRegion` | GeoIP country | `US`, `DE` |
| `properties.riskLevelAggregated` | Overall risk | `none`, `low`, `medium`, `high` |
| `properties.riskState` | Risk status | `none`, `atRisk`, `confirmedCompromised` |
| `properties.isInteractive` | Interactive login | `true`, `false` |
| `callerIpAddress` | Alternative IP field | `10.10.30.55` |
| `correlationId` | Session correlation | UUID |
| `demo_id` | Scenario tag | `exfil` |

### Audit Events

| Field | Description | Example |
|-------|-------------|---------|
| `properties.activityDisplayName` | Operation | `Add member to group` |
| `properties.category` | Audit category | `UserManagement`, `GroupManagement` |
| `properties.result` | Outcome | `success`, `failure` |
| `properties.loggedByService` | Service source | `Core Directory`, `Self-service Password Management` |
| `properties.initiatedBy.user.userPrincipalName` | Admin identity | `it.admin@theFakeTshirtCompany.com` |
| `properties.targetResources[].displayName` | Target | User/group/app name |
| `properties.targetResources[].modifiedProperties` | Changed attributes | Old/new values |

---

## Sign-in Event Types

### Interactive Sign-ins (35/peak hour)

**Success rate:** 95% | **Failure rate:** 5%

**MFA Methods (weighted distribution):**

| Method | Weight | Auth Detail |
|--------|--------|-------------|
| Microsoft Authenticator | 35% | Notification approved |
| Previously satisfied | 20% | MFA satisfied by claim in token |
| Phone call | 15% | Call answered |
| FIDO2 security key | 15% | Security key verified |
| TOTP verification code | 15% | Code verified |

**Client Profiles (platform-correlated):**

| Platform | Client | Weight |
|----------|--------|--------|
| Windows 11 | Chrome 120.0 | 25% |
| Windows 11 | Edge 120.0 | 15% |
| Windows 10 | Chrome 120.0 | 10% |
| Windows 10 | Edge 120.0 | 5% |
| macOS | Chrome 120.0 | 10% |
| macOS | Safari 17.2 | 8% |
| Windows 11 | Desktop client | 10% |
| macOS | Desktop client | 5% |
| iOS | Mobile app | 3% |
| Android | Mobile app | 2% |

### Failed Sign-in Error Codes

| Code | Description | Context |
|------|-------------|---------|
| 50126 | Invalid username or password | Most common failure, spray noise |
| 50076 | MFA required but not completed | User didn't finish MFA |
| 50074 | Strong authentication required | Step-up auth needed |
| 53003 | Blocked by Conditional Access | Policy enforcement |
| 50053 | Account is locked | Brute force protection (Day 10) |
| 50058 | Silent sign-in interrupted | Session expired |
| 70011 | Invalid scope | App misconfiguration |

### Service Principal Sign-ins (10-20/hour, constant 24/7)

| Service Principal | Source IP | Resource | Auth Method |
|-------------------|-----------|----------|-------------|
| SAP S/4HANA Connector | 10.10.20.60 | Microsoft Graph | Client secret |
| Veeam Backup Agent | 10.20.20.20 | Azure Storage | Client secret |
| Splunk Cloud Forwarder | 10.20.20.30 | Microsoft Graph | Client secret |
| GitHub Actions CI/CD | 10.20.20.30 | Azure DevOps | Client secret |
| Nagios Monitoring Agent | 10.20.20.30 | Microsoft Graph | Client secret |

**SP success rate:** ~83% | SP error codes: 7000215 (invalid secret), 7000222 (expired cert)

### Password Spray Noise (~6 events/day)

25% chance per hour from random world IPs:

| Origin | IP Range | Target Users |
|--------|---------|--------------|
| Moscow | 45.155.x.x | admin, ceo, finance, hr |
| Beijing | 103.21.x.x | it.support, john.smith |
| Sao Paulo | 186.90.x.x | jane.doe, test |
| Mumbai | 102.67.x.x | (random selection) |
| Ashburn | 37.19.x.x | |
| Frankfurt | 91.231.x.x | |
| Paris | 5.44.x.x | |

All fail with error 50126 from non-compliant Android 13 devices.

### Account Lockout (Day 10)

3 consecutive lockout events (error 50053) at 09:10-09:12 for a random user.

---

## Audit Event Types

### User Management

| Operation | Frequency | Details |
|-----------|-----------|---------|
| Update user | 1-3/day | JobTitle, Department, Manager, MobilePhone, OfficeLocation |
| Reset password | 1-2/day | Admin-initiated via helpdesk |
| User registered security info | Occasional | MFA enrollment |
| Admin deleted authentication method | Rare | MFA bypass indicator |
| Confirm user compromised | Scenario only | Identity Protection action |

### Group Management

| Operation | Frequency | Split |
|-----------|-----------|-------|
| Add member to group | 2-4/day | 75% of group changes |
| Remove member from group | 2-4/day | 25% of group changes |

### Application Management

| Operation | Frequency | Details |
|-----------|-----------|---------|
| Assign app role to user | Every 3-5 days | License assignments |
| Add application | Rare/scenario | New app registration |
| Add service principal credentials | Rare/scenario | Secret rotation |
| Consent to application | Rare/scenario | OAuth consent grant |
| Update certificate | Every ~10 days | Certificate rotation |

### Role Management

| Operation | Frequency |
|-----------|-----------|
| Add member to directory role | Every 5-7 days |
| Remove member from directory role | Every 5-7 days |

### Self-Service Password Reset (SSPR)

5-10 flows per day during business hours (08:00-17:00), 70% success rate.

**Verification steps** (each tracked individually):

| Step | Audit Name |
|------|-----------|
| Email verification | Self-service password reset flow activity progress |
| Mobile app notification | Self-service password reset flow activity progress |
| Mobile app code | Self-service password reset flow activity progress |
| Office phone verification | Self-service password reset flow activity progress |
| Security questions | Self-service password reset flow activity progress |
| Reset completion | Reset password (self-service) |

### Policy Management

| Operation | Frequency |
|-----------|-----------|
| Update conditional access policy | Weekly (day % 7 == 1) |

---

## Risk Detection Events (1-3/day baseline)

| Risk Type | Description |
|-----------|-------------|
| unfamiliarFeatures | Sign-in with unfamiliar properties |
| anonymizedIPAddress | Sign-in from anonymous IP address |
| impossibleTravel | Impossible travel detected |
| maliciousIPAddress | Sign-in from known malicious IP |
| suspiciousBrowser | Suspicious browser fingerprint |
| passwordSpray | Password spray attack detected |
| leakedCredentials | Leaked credentials found in dark web |

**Risk levels:** low, medium, high
**Risk states:** atRisk, confirmedSafe, remediated, dismissed

---

## Admin Accounts

| Account | Role | Share of Admin Actions |
|---------|------|----------------------|
| it.admin | IT Admin | 50% |
| helpdesk | Helpdesk Admin | 33% |
| ad.sync | AD Connect Sync | 17% |
| sec.admin | Security Admin | Scenario-specific |
| mike.johnson | CTO | Occasional |
| jessica.brown | IT Admin | Exfil (compromised) |

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 4 | Jessica Brown clicks phishing link (initial compromise) |
| **exfil** | 4-14 | Jessica Brown sign-ins tagged `demo_id=exfil` |
| **exfil** | 5-14 | Alex Miller credentials stolen, sign-ins tagged |
| **exfil** | 5-14 | Threat IP (185.220.101.42) sign-in attempts (failed + successful) |
| **exfil** | 5-14 | Conditional Access blocks on suspicious sign-ins (error 53003) |
| **exfil** | 5-14 | Risk detections: impossibleTravel, maliciousIPAddress, unfamiliarFeatures |
| **exfil** | 8-10 | Audit: app creation, role assignments, consent grants (privilege escalation) |
| **ransomware_attempt** | 8-9 | Brooklyn White unusual sign-in patterns |
| **phishing_test** | 21-23 | Simulated credential submissions (all employees) |

### Exfil Attack Pattern in Entra ID

```
Day 4:   Jessica Brown clicks phishing link (initial access from ATL)
Day 4+:  Jessica's sign-ins tagged demo_id=exfil
Day 5:   Alex Miller credentials compromised
Day 5+:  Threat IP (185.220.101.42, Frankfurt) sign-in attempts as Alex
         Some blocked by CA (53003), some succeed with stolen session
Day 5-7: Risk detections: impossibleTravel, unfamiliarFeatures
Day 8:   Audit: new application registered (persistence)
Day 8:   Audit: service principal credentials added
Day 9:   Audit: directory role assignment (privilege escalation)
Day 10:  Account lockout events (3x error 50053)
Day 10+: Risk detections escalate: maliciousIPAddress, passwordSpray
Day 11-14: Continued exfil-phase sign-ins from threat IP
```

---

## Use Cases

### 1. Compromised user sign-in timeline
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin"
    properties.userPrincipalName="alex.miller@theFakeTshirtCompany.com"
| eval status=if('properties.status.errorCode'="0", "success", "failed")
| timechart span=1h count by status
```

### 2. Threat actor IP activity
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin"
    callerIpAddress="185.220.101.42"
| table _time, properties.userPrincipalName, properties.status.errorCode,
    properties.status.failureReason, properties.conditionalAccessStatus
| sort _time
```

### 3. MFA method distribution
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin" properties.status.errorCode=0
| stats count by properties.mfaDetail.authMethod
| sort - count
```

### 4. Password spray detection
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin" properties.status.errorCode=50126
| eval src_country=mvindex(split('properties.location.countryOrRegion', ","), 0)
| stats dc(properties.userPrincipalName) AS targets,
    values(properties.userPrincipalName) AS users
    by callerIpAddress, src_country
| where targets > 3
| sort - targets
```

### 5. Conditional Access blocks
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin"
    properties.status.errorCode=53003
| table _time, properties.userPrincipalName, callerIpAddress,
    properties.appDisplayName, properties.location.city
| sort _time
```

### 6. Privilege escalation audit trail
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:audit"
    properties.activityDisplayName IN ("Add member to role", "Add application",
    "Consent to application", "Add service principal credentials")
| table _time, properties.activityDisplayName,
    properties.initiatedBy.user.userPrincipalName,
    properties.targetResources{}.displayName, demo_id
| sort _time
```

### 7. Risk detection timeline
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin" OR sourcetype="FAKE:azure:aad:audit"
    properties.riskEventType=*
| table _time, properties.riskEventType, properties.riskLevel,
    properties.userPrincipalName, properties.ipAddress
| sort _time
```

### 8. Service principal health
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin"
    properties.isInteractive=false properties.servicePrincipalName=*
| eval status=if('properties.status.errorCode'="0", "success", "failed")
| stats count by properties.appDisplayName, status
| sort properties.appDisplayName
```

### 9. SSPR flow analysis
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:audit"
    properties.activityDisplayName="Self-service password reset flow*"
| table _time, properties.targetResources{}.userPrincipalName,
    properties.activityDisplayName, properties.result
| sort _time
```

### 10. Account lockout events
```spl
index=fake_tshrt sourcetype="FAKE:azure:aad:signin"
    properties.status.errorCode=50053
| table _time, properties.userPrincipalName, callerIpAddress,
    properties.status.failureReason
```

---

## Talking Points

**Identity is the new perimeter:**
> "Look at the exfil timeline in Entra ID. Day 4, Jessica clicks the phish. Day 5, Alex's credentials are compromised. By Day 8, the attacker is creating applications and granting themselves directory roles -- all through identity, no network exploit needed."

**MFA isn't foolproof:**
> "The attacker gets past MFA. How? We see an impossibleTravel risk -- Alex signs in from Boston and Frankfurt within 30 minutes. But the attacker has a stolen session token. MFA doesn't re-challenge on token replay."

**Conditional Access as detection:**
> "CA policies block some attempts -- error 53003. But the attacker adapts, switching to apps not covered by the same policy. The blocks tell you someone is probing your policies."

**Service principals are blind spots:**
> "Five SPs authenticate 24/7 -- SAP, Veeam, Splunk, GitHub, Nagios. 360+ non-interactive sign-ins per day nobody reviews. When the attacker creates a new SP on Day 8, it blends right into this noise."

**Spray noise as cover:**
> "~6 spray attempts per day from Moscow, Beijing, Sao Paulo. Background internet noise. The attacker's Frankfurt IP looks like just another spray. Correlate the spray failures with the successful sign-ins to see the pattern."

---

## Related Sources

- [AWS CloudTrail](aws_cloudtrail.md) - Multi-cloud identity correlation
- [GCP Audit](gcp_audit.md) - GCP service account activity
- [WinEventLog](wineventlog.md) - Windows auth events (4624/4625)
- [Sysmon](sysmon.md) - Process-level credential access
- [Cisco Secure Access](secure_access.md) - DNS/proxy identity-based access
- [Exchange](exchange.md) - Phishing delivery correlation
- [Office Audit](office_audit.md) - M365 activity correlation

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | [Splunk Add-on for MS Cloud Services](https://splunkbase.splunk.com/app/3110) (current) / [MS Azure Add-on](https://splunkbase.splunk.com/app/3757) (legacy) |
| **Ingestion** | Azure Event Hubs (recommended) or Microsoft Graph API (legacy) |
| **Real sourcetypes** | Current: `azure:monitor:aad`. Legacy: `azure:aad:signin`, `azure:aad:audit` (our choice) |

See [REFERENCES.md](REFERENCES.md#note-4-microsoft-entra-id) for details.
