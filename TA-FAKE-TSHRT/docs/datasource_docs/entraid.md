# Microsoft Entra ID (Azure AD)

Identity and access management logs including sign-ins and audit events.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `azure:aad:signin`, `azure:aad:audit` |
| Format | JSON |
| Output Files | `output/cloud/entraid_signin.log`, `output/cloud/entraid_audit.log` |
| Volume | 200-500 sign-ins/day, 20-50 audit events/day |
| Tenant | theFakeTshirtCompany.com |

---

## Sign-In Events

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `createdDateTime` | ISO 8601 timestamp | `2026-01-05T14:23:45Z` |
| `userPrincipalName` | User email | `alex.miller@theFakeTshirtCompany.com` |
| `status.errorCode` | Result code | `0` (success), `50126` (bad password) |
| `status.failureReason` | Error description | `Invalid username or password` |
| `clientAppUsed` | Application type | `Browser`, `Mobile Apps`, `Desktop client` |
| `deviceDetail.operatingSystem` | Client OS | `Windows 11`, `iOS 17` |
| `location.city` | Geo location | `Boston`, `Frankfurt` |
| `location.countryOrRegion` | Country | `US`, `DE` |
| `ipAddress` | Source IP | `10.10.30.55` |
| `riskLevel` | Risk assessment | `low`, `medium`, `high` |
| `riskState` | Risk status | `none`, `atRisk`, `confirmedCompromised` |
| `conditionalAccessStatus` | CA result | `success`, `failure` |
| `mfaDetail.authMethod` | MFA method | `Authenticator app`, `Phone call` |
| `demo_id` | Scenario tag | `exfil` |

### Common Error Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `50126` | Invalid username or password |
| `50053` | Account locked |
| `50057` | Account disabled |
| `50074` | MFA required |
| `50076` | MFA not completed |
| `53003` | Blocked by Conditional Access |

### Example Events

#### Successful Sign-In
```json
{
  "createdDateTime": "2026-01-05T08:15:00Z",
  "userPrincipalName": "alex.miller@theFakeTshirtCompany.com",
  "status": {
    "errorCode": 0,
    "failureReason": null
  },
  "clientAppUsed": "Browser",
  "deviceDetail": {
    "operatingSystem": "Windows 11",
    "browser": "Chrome 120"
  },
  "location": {
    "city": "Boston",
    "countryOrRegion": "US"
  },
  "ipAddress": "10.10.30.55",
  "riskLevel": "low",
  "riskState": "none",
  "conditionalAccessStatus": "success",
  "mfaDetail": {
    "authMethod": "Authenticator app"
  }
}
```

#### Suspicious Sign-In (Exfil)
```json
{
  "createdDateTime": "2026-01-04T14:30:00Z",
  "userPrincipalName": "jessica.brown@theFakeTshirtCompany.com",
  "status": {
    "errorCode": 0,
    "failureReason": null
  },
  "clientAppUsed": "Browser",
  "location": {
    "city": "Frankfurt",
    "countryOrRegion": "DE"
  },
  "ipAddress": "185.220.101.42",
  "riskLevel": "high",
  "riskState": "atRisk",
  "demo_id": "exfil"
}
```

#### Failed Sign-In (Brute Force)
```json
{
  "createdDateTime": "2026-01-03T22:45:00Z",
  "userPrincipalName": "admin@theFakeTshirtCompany.com",
  "status": {
    "errorCode": 50126,
    "failureReason": "Invalid username or password"
  },
  "ipAddress": "45.33.32.156",
  "location": {
    "city": "Unknown",
    "countryOrRegion": "CN"
  },
  "riskLevel": "medium"
}
```

---

## Audit Events

### Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `createdDateTime` | ISO 8601 timestamp | `2026-01-05T14:23:45Z` |
| `operationType` | Operation type | `Create`, `Update`, `Delete` |
| `result` | Result | `Success`, `Failure` |
| `category` | Audit category | `UserManagement`, `GroupManagement` |
| `activityDisplayName` | Action description | `Add user`, `Update user` |
| `targetDisplayName` | Affected resource | `new.user@company.com` |
| `initiatedBy.user.userPrincipalName` | Admin user | `it.admin@company.com` |
| `demo_id` | Scenario tag | `exfil` |

### Common Categories

| Category | Description |
|----------|-------------|
| `UserManagement` | User create/update/delete |
| `GroupManagement` | Group membership changes |
| `PolicyUpdate` | Conditional Access changes |
| `ApplicationManagement` | App registrations |
| `RoleManagement` | Role assignments |

### Example Events

#### User Created
```json
{
  "createdDateTime": "2026-01-05T09:00:00Z",
  "operationType": "Create",
  "result": "Success",
  "category": "UserManagement",
  "activityDisplayName": "Add user",
  "targetDisplayName": "new.employee@theFakeTshirtCompany.com",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "hr.admin@theFakeTshirtCompany.com"
    }
  }
}
```

#### Password Reset
```json
{
  "createdDateTime": "2026-01-06T10:30:00Z",
  "operationType": "Update",
  "result": "Success",
  "category": "UserManagement",
  "activityDisplayName": "Reset user password",
  "targetDisplayName": "jessica.brown@theFakeTshirtCompany.com",
  "initiatedBy": {
    "user": {
      "userPrincipalName": "helpdesk@theFakeTshirtCompany.com"
    }
  }
}
```

#### MFA Registration
```json
{
  "createdDateTime": "2026-01-05T11:15:00Z",
  "operationType": "Create",
  "result": "Success",
  "category": "UserManagement",
  "activityDisplayName": "User registered security info",
  "targetDisplayName": "alex.miller@theFakeTshirtCompany.com",
  "additionalDetails": {
    "authMethod": "Microsoft Authenticator"
  }
}
```

---

## Use Cases

### 1. Impossible Travel Detection
Find sign-ins from multiple locations:
```spl
index=cloud sourcetype="azure:aad:signin" status.errorCode=0
| stats earliest(_time) AS first, latest(_time) AS last,
        values(location.city) AS cities,
        dc(location.city) AS city_count
    by userPrincipalName
| where city_count > 1
| eval time_diff_hours = (last - first) / 3600
| where time_diff_hours < 2
```

### 2. Compromised Account Detection
Find high-risk sign-ins:
```spl
index=cloud sourcetype="azure:aad:signin"
  (riskLevel="high" OR riskState="atRisk" OR riskState="confirmedCompromised")
| table _time, userPrincipalName, ipAddress, location.city, riskLevel, riskState
```

### 3. Failed Sign-In Analysis
Track authentication failures:
```spl
index=cloud sourcetype="azure:aad:signin" status.errorCode!=0
| stats count by userPrincipalName, status.errorCode, status.failureReason
| sort - count
```

### 4. MFA Coverage
Check MFA usage:
```spl
index=cloud sourcetype="azure:aad:signin" status.errorCode=0
| stats count AS total,
        count(eval(isnotnull(mfaDetail.authMethod))) AS with_mfa
    by userPrincipalName
| eval mfa_pct = round(with_mfa / total * 100, 1)
| sort - mfa_pct
```

### 5. Admin Activity Audit
Track privileged actions:
```spl
index=cloud sourcetype="azure:aad:audit"
  category IN ("UserManagement", "GroupManagement", "RoleManagement")
| table _time, activityDisplayName, targetDisplayName, initiatedBy.user.userPrincipalName
| sort _time
```

### 6. Exfil User Timeline
Track compromised user activity:
```spl
index=cloud sourcetype="azure:aad:signin"
  userPrincipalName IN ("jessica.brown@theFakeTshirtCompany.com", "alex.miller@theFakeTshirtCompany.com")
  demo_id=exfil
| timechart span=1d count by userPrincipalName
```

---

## Scenario Integration

| Scenario | User | Activity |
|----------|------|----------|
| **exfil** | jessica.brown | Day 4: Suspicious login from Germany |
| **exfil** | alex.miller | Day 5-14: Credential use by attacker |
| **ransomware** | brooklyn.white | Day 8: Normal then suspicious activity |

---

## Attack Indicators

### Exfil Scenario Timeline
```
Day 1-3:  Normal sign-ins from Atlanta (jessica.brown)
Day 4:    Sign-in from Frankfurt, Germany - SUSPICIOUS
Day 4+:   Attacker using jessica.brown credentials
Day 5:    alex.miller credentials compromised
Day 5-14: Both accounts used from suspicious IPs
```

### Signs of Compromise
- Sign-in from unexpected country
- Multiple failed attempts then success
- Off-hours authentication
- New device/browser suddenly
- High risk score

---

## Talking Points

**Impossible Travel:**
> "Jessica signs in from Atlanta at 10:00 AM, then from Frankfurt at 10:30 AM. That's impossible travel - nobody flies across the Atlantic in 30 minutes. This is our first indicator of compromise."

**Risk Scoring:**
> "Entra ID automatically flagged this as high risk. The combination of new location, new device, and unusual time triggered the alert."

**Credential Theft:**
> "After jessica.brown is compromised, we see alex.miller's account being used from the same suspicious IPs. The attacker is moving laterally through our organization."

**MFA Matters:**
> "Notice that the attacker bypassed MFA. This suggests either phishing that captured the MFA token, or the attacker accessed from a device that was already MFA-trusted."

---

## Related Sources

- [Exchange](exchange.md) - Email correlation
- [AWS CloudTrail](aws_cloudtrail.md) - Cloud access with same identity
- [WinEventLog](wineventlog.md) - On-prem logon correlation

