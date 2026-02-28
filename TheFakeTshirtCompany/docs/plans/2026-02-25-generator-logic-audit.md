# Generator Logic & Correlation Audit Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Systematically audit all remaining generators for logical correctness, cross-generator correlation, and vendor format realism — then fix every issue found.

**Architecture:** Run each generator in test mode (3-day, all scenarios), inspect output for logical/format issues, verify cross-generator correlation by comparing shared fields (IPs, users, timestamps, session IDs) across output files. Fixes go directly into generator code, verified by re-running.

**Tech Stack:** Python 3.8+ (stdlib only), bash for output inspection, `main_generate.py --test` for generation runs.

---

## Approach

**Priority order:** Generators are grouped by correlation risk — those with the most cross-generator dependencies come first. Each task follows the same pattern:

1. Read the generator code completely
2. Run it in test mode (3-day, relevant scenarios)
3. Inspect output for format/logic/correlation issues
4. Cross-reference with vendor documentation (web search)
5. Fix all issues found
6. Re-run and verify
7. Commit

**Key correlation checks applied to EVERY generator:**
- Do employee IPs match `company.py` assignments?
- Do hostnames match `company.py` server definitions?
- Do scenario events appear on correct days/hours?
- Does `demo_id` field appear correctly (not corrupting adjacent fields)?
- Do timestamps use the correct `time_utils.py` formatter?
- Are volume patterns realistic (hourly curve, weekend factor, Monday boost)?

---

## Phase 1: Order Pipeline (Critical Correlation Chain)

The access → orders → servicebus → sap chain is the backbone of retail data correlation. A bug here breaks 4 generators.

### Task 1: Audit generate_access.py (887 lines)

**Files:**
- Read: `bin/generators/generate_access.py`
- Read: `bin/shared/products.py` (product catalog referenced in sessions)
- Read: `bin/shared/config.py` (ORDER_SEQUENCE, output paths)
- Inspect: `bin/output/tmp/web/access_combined.log` (after test run)
- Inspect: `bin/output/tmp/web/order_registry.json` (NDJSON output)

**Step 1: Read generator code end-to-end**

Focus areas:
- Apache Combined Log format: `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`
- Session flow: browse → add-to-cart → checkout → order confirmation
- `order_registry.json` NDJSON format: verify all fields (session_id, tshirtcid, customer_id, order_id, items, total, timestamp)
- Customer IP generation: verify `get_customer_ip()` determinism
- VIP customer weighting (top 5% = 30% of orders)
- Abandoned cart rate and its realism
- Scenario error injection: verify error rates match scenario severity

**Step 2: Run 3-day test with all scenarios**

```bash
cd TheFakeTshirtCompany/TA-FAKE-TSHRT
python3 bin/main_generate.py --sources=access --days=3 --scenarios=all --test --quiet
```

**Step 3: Inspect output format**

Check Apache Combined format compliance:
```bash
head -20 bin/output/tmp/web/access_combined.log
```

Verify:
- IP format: `NNN.NNN.NNN.NNN` (no IPv6 unless intentional)
- Timestamp: `[DD/Mon/YYYY:HH:MM:SS +0000]`
- HTTP method/path: realistic e-commerce URLs (`/products/`, `/cart/`, `/checkout/`)
- Status codes: 200, 301, 302, 404, 500, 502, 503
- Response size: realistic byte counts (not 0 for 200 responses)
- User-agent: realistic browser strings
- Referer: logical flow (google → homepage → products → cart)

Check order_registry.json:
```bash
head -5 bin/output/tmp/web/order_registry.json | python3 -m json.tool
```

Verify each record has: `session_id`, `tshirtcid`, `customer_id`, `order_id`, `items`, `total`, `timestamp`, `customer_ip`

**Step 4: Cross-reference with vendor format**

Web search: "Apache Combined Log Format specification"
Verify our format matches the standard exactly.

**Step 5: Check scenario correlation**

```bash
grep "demo_id" bin/output/tmp/web/access_combined.log | head -20
```

Verify:
- `demo_id` appears as a custom log field (not breaking Apache format)
- Scenario days match: memory_leak (Days 7-10), cpu_runaway (Days 11-12), ddos (Days 18-19), firewall_misconfig (Day 6), certificate_expiry (Day 13), dead_letter_pricing (Day 16)
- Error rates escalate/de-escalate with scenario intensity

**Step 6: Fix all issues found, re-run, verify**

**Step 7: Commit**

```bash
git add bin/generators/generate_access.py
git commit -m "Access Generator Realism Audit (N fixes)"
```

---

### Task 2: Audit generate_orders.py (647 lines)

**Files:**
- Read: `bin/generators/generate_orders.py`
- Inspect: `bin/output/tmp/retail/orders.log` (after test run)

**Step 1: Read generator code end-to-end**

Focus areas:
- order_registry.json parsing: verify NDJSON line-by-line read
- Order detail enrichment: items, quantities, prices, shipping, tax
- Payment processing: success/failure rates (5-7% failure realistic?)
- Fraud detection injection
- Region-based tax calculation (US states, EU VAT, Norway MVA)
- `dead_letter_pricing` scenario: wrong price injection logic
- Customer region distribution (70% US, 20% EU, 10% NO)

**Step 2: Run dependent chain**

```bash
python3 bin/main_generate.py --sources=access,orders --days=3 --scenarios=all --test --quiet
```

**Step 3: Correlation check — orders ↔ access**

Verify:
- Every order_id in orders.log exists in order_registry.json
- Customer IDs match between order_registry and orders.log
- Order timestamps are AFTER the corresponding access log checkout timestamp
- Item counts and totals are consistent

```bash
# Count orders in each file
wc -l bin/output/tmp/web/order_registry.json
grep -c "order_id" bin/output/tmp/retail/orders.log
```

**Step 4: Check dead_letter_pricing scenario**

On Day 16 (if running enough days): verify wrong prices appear in orders, demo_id=dead_letter_pricing is set, prices differ from products.py catalog.

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

### Task 3: Audit generate_servicebus.py (629 lines)

**Files:**
- Read: `bin/generators/generate_servicebus.py`
- Inspect: `bin/output/tmp/servicebus/servicebus.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- Azure ServiceBus JSON format compliance
- 5-event lifecycle per order: OrderCreated → PaymentProcessed → InventoryReserved → ShipmentCreated → ShipmentDispatched
- Timing delays between events (0-5s, 2-10s, 1-4h, 4-24h)
- Dead-letter queue baseline (0.5%) and scenario injection (25-60%)
- MessageId, SequenceNumber uniqueness
- TopicName/QueueName naming conventions
- ContentType, Label, TTL fields

**Step 2: Run dependent chain**

```bash
python3 bin/main_generate.py --sources=access,servicebus --days=3 --scenarios=all --test --quiet
```

**Step 3: Correlation check — servicebus ↔ access**

Verify:
- Every order_id in servicebus events exists in order_registry.json
- OrderCreated timestamp is close to (but after) the access log checkout time
- Event sequence is strictly ordered: Created < Payment < Inventory < Shipment < Dispatched
- No out-of-order events within a single order lifecycle

**Step 4: Cross-reference with Azure ServiceBus format**

Web search: "Azure Service Bus message format JSON properties"
Verify field names: `MessageId`, `SequenceNumber`, `EnqueuedTimeUtc`, `DeliveryCount`, `TimeToLive`, `ContentType`

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

### Task 4: Audit generate_sap.py (932 lines)

**Files:**
- Read: `bin/generators/generate_sap.py`
- Inspect: `bin/output/tmp/erp/sap_audit.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- SAP Security Audit Log pipe-delimited format
- Transaction code mapping by department (Finance→FI tcodes, Sales→SD tcodes, etc.)
- Order correlation via tshirtcid from order_registry.json
- VA01 (sales order) → VL01N (delivery) → VF01 (billing) lifecycle
- Batch job events (SM37) — realistic scheduling
- User-to-SAP-role mapping consistency with company.py departments

**Step 2: Run full retail chain**

```bash
python3 bin/main_generate.py --sources=access,orders,servicebus,sap --days=3 --scenarios=all --test --quiet
```

**Step 3: Correlation check — sap ↔ access**

Verify:
- tshirtcid values in SAP VA01/VL01N/VF01 events match order_registry.json
- SAP order events occur AFTER the web checkout (not before — this was a known bug, fixed 2026-02-15)
- Department-based tcode distribution is realistic

**Step 4: Cross-reference with SAP audit log format**

Web search: "SAP Security Audit Log SM20 format fields"
Verify: date, time, user, tcode, report, message class, message number, variable data

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

## Phase 2: Cloud Generators (AWS + GCP)

### Task 5: Audit generate_aws.py (930 lines)

**Files:**
- Read: `bin/generators/generate_aws.py`
- Inspect: `bin/output/tmp/cloud/aws/cloudtrail.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- CloudTrail JSON record structure (eventVersion, eventTime, eventSource, eventName, etc.)
- IAM user vs assumed-role events
- AWS service coverage: EC2, S3, IAM, Lambda, CloudWatch, RDS, SNS, SQS
- Error injection: AccessDenied, ResourceNotFound rates
- Exfil scenario: S3 GetObject/PutObject from threat actor, IAM backdoor user creation
- sourceIPAddress: should be employee office IP or VPN IP, not random
- userIdentity structure: type, arn, accountId, accessKeyId, principalId

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=aws --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

```bash
head -3 bin/output/tmp/cloud/aws/cloudtrail.log | python3 -m json.tool
```

Cross-reference with: "AWS CloudTrail record format JSON schema"

Key fields to verify:
- `eventVersion`: should be "1.08" or "1.09"
- `userIdentity.type`: "IAMUser", "AssumedRole", "Root"
- `userIdentity.arn`: must match `arn:aws:iam::123456789012:user/{username}`
- `sourceIPAddress`: employee IP from company.py, or AWS service IP
- `requestParameters`: realistic for each eventName
- `responseElements`: appropriate for success/failure
- `errorCode`/`errorMessage`: only on failures

**Step 4: Correlation check**

- Verify `sourceIPAddress` matches company.py employee IPs
- Verify `userIdentity.accessKeyId` matches company.py `aws_access_key_id`
- Verify scenario events use correct threat actor IP (185.220.101.42)

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

### Task 6: Audit generate_aws_guardduty.py (665 lines)

**Files:**
- Read: `bin/generators/generate_aws_guardduty.py`
- Inspect: `bin/output/tmp/cloud/aws/guardduty.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- GuardDuty finding JSON format
- Finding types: Recon, UnauthorizedAccess, Exfiltration, CryptoCurrency, etc.
- Severity levels (1.0-8.9 scale): Low (1-3.9), Medium (4-6.9), High (7-8.9)
- Resource details: instance-id, access-key, s3-bucket
- Action details: networkConnectionAction, awsApiCallAction, dnsRequestAction
- Exfil scenario: findings should reference threat actor IP and compromised user

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=aws_guardduty --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "AWS GuardDuty finding format JSON"

Key fields: `schemaVersion`, `id`, `type`, `severity`, `resource`, `service.action`, `service.count`

**Step 4: Fix all issues, re-run, verify**

**Step 5: Commit**

---

### Task 7: Audit generate_aws_billing.py (371 lines)

**Files:**
- Read: `bin/generators/generate_aws_billing.py`
- Inspect: `bin/output/tmp/cloud/aws/billing.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- AWS Cost and Usage Report (CUR) CSV format
- Column structure (19 simplified columns of standard 125)
- Service cost distribution: EC2, S3, RDS, Lambda, CloudWatch
- DDoS scenario: 4x cost spike on Days 18-19
- Exfil scenario: 1.5x S3 cost on Days 11-13
- Tax/shipping calculations by region

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=aws_billing --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "AWS CUR CSV column names"

**Step 4: Fix all issues, re-run, verify**

**Step 5: Commit**

---

### Task 8: Audit generate_gcp.py (888 lines)

**Files:**
- Read: `bin/generators/generate_gcp.py`
- Inspect: `bin/output/tmp/cloud/gcp/`

**Step 1: Read generator code end-to-end**

Focus areas:
- GCP Audit Log JSON format (protoPayload structure)
- Two log types: admin_activity vs data_access
- Service coverage: compute, storage, iam, bigquery, cloudsql
- sourceIP correlation with company.py employee IPs
- principalEmail format: `{username}@theTshirtCompany.com`
- Exfil scenario: storage.objects.get/create operations from compromised user
- cpu_runaway scenario: GCP monitoring events

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=gcp --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "GCP Cloud Audit Logs format protoPayload"

Key fields: `protoPayload.@type`, `protoPayload.methodName`, `protoPayload.resourceName`, `protoPayload.authenticationInfo.principalEmail`, `resource.type`, `resource.labels`

**Step 4: Correlation check**

- Verify `authenticationInfo.principalEmail` matches company.py emails
- Verify `callerIp` matches company.py employee IPs
- Verify exfil events use correct compromised user and threat actor

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

## Phase 3: Collaboration & Email

### Task 9: Audit generate_exchange.py (894 lines)

**Files:**
- Read: `bin/generators/generate_exchange.py`
- Inspect: `bin/output/tmp/cloud/microsoft/exchange_messagetrace.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- Exchange MessageTrace JSON format
- Email flow: internal, inbound (external→internal), outbound (internal→external)
- Sender/recipient correlation with company.py employees
- SPF/DKIM/DMARC result fields
- Exfil scenario: phishing emails, auto-forwarding rules
- Ransomware scenario: malicious attachment delivery
- Phishing test scenario: simulated phishing waves by location
- connectorId and sourceContext fields

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=exchange --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "Exchange Online MessageTrace PowerShell output format"

Key fields: `MessageTraceId`, `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, `FromIP`, `ToIP`, `Size`, `MessageId`

**Step 4: Correlation check**

- Verify sender/recipient email addresses match `{username}@theTshirtCompany.com` format
- Verify FromIP for internal senders matches company.py employee IPs
- Verify phishing_test wave timing: Boston (09:00), Atlanta (10:00), Austin (11:00)

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

### Task 10: Audit generate_office_audit.py (944 lines)

**Files:**
- Read: `bin/generators/generate_office_audit.py`
- Inspect: `bin/output/tmp/cloud/microsoft/office365_audit.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- O365 Unified Audit Log JSON format
- RecordType values: 6 (SharePoint file ops), 7 (SharePoint sharing), 25 (Teams)
- Workload distribution: SharePoint, OneDrive, Teams, Exchange
- ClientIP correlation with company.py employee IPs
- UserAgent strings: realistic browser/Teams client strings
- Exfil scenario: suspicious SharePoint/OneDrive file access by alex.miller
- Ransomware scenario: rapid file access by brooklyn.white
- Department-based access control (Finance users access Finance sites, etc.)

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=office_audit --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "Office 365 Management Activity API AuditRecord schema"

Key fields: `CreationTime`, `Id`, `Operation`, `OrganizationId`, `RecordType`, `UserKey`, `UserType`, `Workload`, `ClientIP`, `ObjectId`

**Step 4: Fix all issues, re-run, verify**

**Step 5: Commit**

---

### Task 11: Audit generate_webex.py (1324 lines)

**Files:**
- Read: `bin/generators/generate_webex.py`
- Read: `bin/shared/meeting_schedule.py`
- Inspect: `bin/output/tmp/cloud/webex/`

**Step 1: Read generator code end-to-end**

Focus areas:
- Webex event JSON format
- Meeting lifecycle: scheduled → started → participant_joined → ended
- Device events: health_status, quality metrics (audioMos, videoPacketLoss, jitter)
- Problem rooms: Kirby (wifi/codec issues), Cortana (bandwidth/echo)
- Sunny rooms: Link, Chief, Doom (always good quality)
- Meeting schedule population for meraki consumption
- Room device model correlation with company.py room definitions
- Exfil scenario: jessica.brown and alex.miller meeting activity

**Step 2: Run test (with meraki to check schedule correlation)**

```bash
python3 bin/main_generate.py --sources=webex,meraki --days=3 --scenarios=all --test --quiet
```

**Step 3: Correlation check — webex ↔ meraki**

Verify:
- Meraki door sensor events occur 2-5 min before meeting start times
- Meraki temperature events correlate with meeting duration
- Room names match between generators

**Step 4: Fix all issues, re-run, verify**

**Step 5: Commit**

---

### Task 12: Audit generate_webex_ta.py (804 lines) + generate_webex_api.py (785 lines)

**Files:**
- Read: `bin/generators/generate_webex_ta.py`
- Read: `bin/generators/generate_webex_api.py`
- Inspect: `bin/output/tmp/cloud/webex/`

**Step 1: Read both generators end-to-end**

Focus areas (webex_ta):
- Splunk TA for Cisco Webex format (MM/DD/YYYY HH:MM:SS timestamps)
- Meeting usage history: duration, participants, client types
- OS/client profile distribution
- External domain participant handling

Focus areas (webex_api):
- Cisco Webex REST API JSON format
- Admin audit events: USERS, GROUPS, MEETINGS, COMPLIANCE, DEVICES
- Security audit: login events, token grants
- Meeting quality metrics

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=webex_ta,webex_api --days=3 --scenarios=all --test --quiet
```

**Step 3: Cross-reference with vendor format**

webex_ta: "Splunk TA for Cisco Webex Meetings field reference"
webex_api: "Cisco Webex Admin Audit Events API"

**Step 4: Fix all issues, re-run, verify**

**Step 5: Commit**

---

## Phase 4: Infrastructure Generators

### Task 13: Audit generate_linux.py (674 lines)

**Files:**
- Read: `bin/generators/generate_linux.py`
- Inspect: `bin/output/tmp/linux/`

**Step 1: Read generator code end-to-end**

Focus areas:
- Multiple output formats: auth.log (syslog), cpu (vmstat-style), memory, disk (df), iostat, network interfaces
- Server coverage: WEB-01, WEB-02 (DMZ Linux), SAP-PROD-01, SAP-DB-01, BASTION-BOS-01, MON-ATL-01
- Auth.log: SSH login/logout, sudo commands, PAM messages
- Memory leak scenario: gradual mem increase on WEB-01, OOM at Day 9 14:00
- Disk filling scenario: MON-ATL-01 disk 45%→98% over Days 1-5
- DDoS scenario: network traffic spike on WEB-01
- Metric intervals: every 5 minutes (288/day/host)

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=linux --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "Splunk TA for Unix and Linux sourcetypes"

Key sourcetypes:
- `linux:auth` — syslog format: `Mon DD HH:MM:SS hostname process[pid]: message`
- `vmstat` — `procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----`
- `df` — `Filesystem Size Used Avail Use% Mounted`
- `iostat` — device stats format
- `interfaces` — network interface stats

**Step 4: Correlation check**

- Verify server IPs match company.py (WEB-01=172.16.1.10, MON-ATL-01=10.20.20.30, etc.)
- Verify SSH auth events use correct employee usernames
- Verify memory_leak progression: 50% → 55% → 65% → 80% → 96% → OOM → 50%

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

### Task 14: Audit generate_mssql.py (704 lines)

**Files:**
- Read: `bin/generators/generate_mssql.py`
- Inspect: `bin/output/tmp/windows/mssql_errorlog.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- SQL Server ERRORLOG format: `YYYY-MM-DD HH:MM:SS.cc spidNN Message`
- Login events: service accounts (svc_ecommerce, svc_finance, svc_backup), DBA users
- Error events: severity levels, state codes
- Backup events: BACKUP DATABASE/LOG messages
- CPU runaway scenario: stuck backup, non-yielding scheduler, I/O timeouts (Days 11-12)
- Exfil scenario: xp_cmdshell execution by compromised user
- Connection source IPs: APP-BOS-01 (10.10.20.40) for e-commerce, employee IPs for DBA

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=mssql --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "SQL Server 2019 ERRORLOG format"

Key patterns:
- Timestamp format: `2026-01-01 10:30:45.12`
- Login: `Login succeeded for user 'xxx'. Connection made using 'TCP/IP'. [CLIENT: x.x.x.x]`
- Backup: `BACKUP DATABASE successfully processed XXX pages`
- Error: `Error: NNNNN, Severity: NN, State: N.`

**Step 4: Correlation check**

- Verify service account login source IPs match company.py servers
- Verify DBA login source IPs match company.py employee IPs
- Verify exfil xp_cmdshell events reference correct compromised user

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

### Task 15: Audit generate_perfmon.py (636 lines)

**Files:**
- Read: `bin/generators/generate_perfmon.py`
- Inspect: `bin/output/tmp/windows/perfmon.log`

**Step 1: Read generator code end-to-end**

Focus areas:
- Perfmon multiline key=value format
- Counter types: % Processor Time, Available MBytes, % Disk Time, Disk Queue Length, Bytes Total/sec
- Server-specific counters: SQL-PROD-01 gets SQL Server counters
- Client workstation metrics: configurable count (5-175), configurable interval
- CPU runaway scenario: SQL-PROD-01 CPU 100%, disk queue spike
- DDoS scenario: APP-BOS-01 CPU increase (downstream impact)
- Fixed 5-minute intervals (not affected by scale parameter)

**Step 2: Run test**

```bash
python3 bin/main_generate.py --sources=perfmon --days=3 --scenarios=all --test --quiet
```

**Step 3: Format verification**

Cross-reference with: "Splunk Perfmon input format key=value"

Verify:
- `collection="Performance Monitor"` header
- `object=Processor`, `counter="% Processor Time"`, `instance=_Total`, `Value=NN.NN`
- Realistic value ranges: CPU 0-100, Memory 0-MaxRAM, Disk 0-100

**Step 4: Correlation check**

- Verify server hostnames match company.py: `SQL-PROD-01`, `APP-BOS-01`, `DC-BOS-01`, etc.
- Verify CPU runaway CPU values hit 100% on SQL-PROD-01 Days 11-12
- Verify demo_host field matches hostname

**Step 5: Fix all issues, re-run, verify**

**Step 6: Commit**

---

## Phase 5: Cross-Generator Scenario Verification

After all individual generators are audited, run full integration tests.

### Task 16: Full 14-day generation run + scenario timeline verification

**Step 1: Generate all sources, all scenarios, 14 days**

```bash
python3 bin/main_generate.py --all --days=14 --scenarios=all --test --quiet
```

Capture event counts per source. Compare with previous known-good counts.

**Step 2: Verify exfil scenario timeline (14 days, 18 sources)**

Check that events appear on correct days in correct order across generators:
- Day 1-3: Recon (ASA port scans) — no other source should have exfil events yet
- Day 4: Initial access (Exchange phishing, Entra ID sign-in from Jessica Brown)
- Day 5-7: Lateral movement (ASA internal, WinEventLog 4625, Meraki, Catalyst, Sysmon)
- Day 8-10: Persistence (AWS IAM user creation, GCP storage, MSSQL xp_cmdshell)
- Day 11-14: Exfiltration (AWS S3, GCP storage, ASA outbound to threat IP)

For each phase, grep demo_id=exfil across ALL output files and verify day/hour ranges.

**Step 3: Verify ransomware scenario timeline (Days 8-9, 9 sources)**

All events should fall within Day 8 13:55 - Day 9 (cleanup):
- Exchange: phishing email (13:55)
- WinEventLog: process creation (14:02), dropper (14:03), service install (14:04)
- ASA: C2 callback (14:05), lateral denies (14:08-14:15)
- Meraki: IDS alert, client isolation (14:15)
- Sysmon: Day 9 cleanup events (08:00-09:00)

**Step 4: Verify ops scenarios**

- memory_leak: Linux memory metrics should show gradual increase Days 7-10 on WEB-01, OOM at Day 9 14:00
- cpu_runaway: Perfmon CPU should hit 100% on SQL-PROD-01 Days 11-12, fix at Day 12 10:30
- disk_filling: Linux disk metrics should show 45%→98% on MON-ATL-01 Days 1-5
- dead_letter_pricing: ServiceBus DLQ rate should spike Day 16, orders should have wrong prices

**Step 5: Verify network scenarios**

- ddos_attack: ASA deny events should ramp Days 18-19, access should show 503 errors
- firewall_misconfig: ASA deny events Day 6 10:15-12:05, access 100% errors same window
- certificate_expiry: ASA SSL failures Day 13 00:00-07:00, access 502 errors same window

**Step 6: Document all findings**

Create verification report with pass/fail per scenario per source.

**Step 7: Commit any fixes**

---

### Task 17: Cross-generator IP/user/hostname consistency check

**Step 1: Extract all IPs from generated data**

For each output file, extract source IPs and verify they exist in company.py:
- Employee IPs (10.10.30.x, 10.20.30.x, 10.30.30.x)
- Server IPs (10.10.20.x, 10.20.20.x, 172.16.1.x)
- VPN IPs (10.250.0.x)
- Customer IPs (various international ranges)
- Threat actor IP (185.220.101.42)

Flag any IP that doesn't belong to a known category.

**Step 2: Extract all usernames and verify**

Grep for usernames across all output files. Verify:
- Every username exists in company.py USERS
- Email format is consistent: `{username}@theTshirtCompany.com`
- Domain is consistent: `theTshirtCompany.com` (not `thefaketshirtcompany.com` or variants)

**Step 3: Extract all hostnames and verify**

Grep for hostnames. Verify:
- Server hostnames match company.py SERVERS exactly (case-sensitive)
- No old/removed server names appear (e.g., servers removed in infrastructure cleanup)

**Step 4: Document and fix any inconsistencies**

**Step 5: Commit**

---

### Task 18: Update CHANGEHISTORY.md and CLAUDE.md

**Step 1: Document all changes made across Tasks 1-17**

Add a comprehensive entry to `docs/CHANGEHISTORY.md` with:
- Date/time
- Summary of all generators audited
- Number of fixes per generator
- Verification results

**Step 2: Update Known Data Gaps in CLAUDE.md**

Remove any gaps that have been fixed. Add any new gaps discovered.

**Step 3: Commit**

---

## Execution Notes

- **Run commands from:** `TheFakeTshirtCompany/TA-FAKE-TSHRT/` directory
- **Test mode is default:** All `--test` runs write to `bin/output/tmp/`, safe to run repeatedly
- **Generator runtime:** Most generators complete in < 5 seconds for 3-day runs
- **Full 14-day run:** ~60-120 seconds with `--parallel=4`
- **Vendor format verification:** Use web search to find authoritative format documentation. If unsure, ask rather than guess.
- **Commit after each generator:** One commit per generator audit keeps changes traceable
- **CHANGEHISTORY entries:** One per generator (not one massive entry at the end)
