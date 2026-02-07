# Syntetisk Sikkerhetslogg-Validering — fake_tshrt

Komplett validering av syntetiske logger i Splunk-indeksen `fake_tshrt` på tvers av seks plattformer: AWS CloudTrail, Meraki IDS/IPS, Azure AD/Entra ID, GCP Audit Logs, Cisco Webex og Microsoft 365 Unified Audit Log.

---

## 1. AWS CloudTrail (`FAKE:aws:cloudtrail`)

**Antall hendelser:** 161  
**Event-typer:** S3 GetObject (61), Lambda Invoke (48), EC2 DescribeInstances (26), S3 PutObject (26)  
**Brukere:** admin-ops, data-pipeline, svc-backup, svc-deployment (alle IAMUser)

### Tier 1 — Kritisk (bryter realisme umiddelbart)

| # | Problem | Nåværende verdi | Korrekt verdi | Dokumentasjon |
|---|---------|----------------|---------------|---------------|
| 1 | **principalId endres per event** — Hver hendelse har unik principalId. I virkeligheten er dette en statisk identifikator per IAM-bruker. | `AIDA7CCDEAEB6BA6492A` (ny for hvert event) | `AIDACKCEVSQ6C2EXAMPLE` (fast per bruker, alfanumerisk, 21 tegn) | [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) |
| 2 | **principalId-format feil** — Bruker hex-tegn etter AIDA-prefiks. Ekte AWS bruker base-36 alfanumeriske tegn (A-Z, 0-9). | `AIDA7CCDEAEB6BA6492A` | `AIDAJQABLZS4A3QDU576Q` | [IAM Unique Identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids) |
| 3 | **Hver hendelse har unik kilde-IP** — admin-ops har 51 events fra 51 forskjellige IP-er. Ekte brukere har konsistente IP-er. | 51 unike IP-er for én bruker | 1–3 IP-er per bruker per økt | [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) |
| 4 | **Kun IAMUser-type** — Ingen AssumedRole (vanligste i produksjon), ingen AWSService, ingen Root. | 100% IAMUser | ~60% AssumedRole, ~30% IAMUser, ~10% AWSService/Root | [CloudTrail userIdentity types](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) |

### Tier 2 — Viktig (merkbart for analytikere)

| # | Problem | Detaljer |
|---|---------|---------|
| 5 | **userAgent identisk for ALLE events** | Alle 161 hendelser: `aws-cli/2.13.0 Python/3.11.4`. Ekte miljøer har variasjon: forskjellige SDK-versjoner, Terraform, boto3, konsoll (Mozilla/5.0), Lambda (aws-sdk-java), CloudFormation. |
| 6 | **Alle brukere gjør alle handlinger** | svc-backup gjør Lambda Invoke og S3 PutObject — urealistisk. Tjenestekontoer bør ha spesialiserte roller. |
| 7 | **Manglende nøkkelfelt** | `readOnly`, `managementEvent`, `eventCategory`, `accessKeyId`, `sessionContext`, `tlsDetails`, `resources` (for S3 events) — alle påkrevd i ekte CloudTrail. |
| 8 | **Ingen angrepstrafikk** | I motsetning til andre sourcetypes (Meraki, Azure, GCP) er det null angrepsscenario i AWS-dataene — ingen IAM-endringer, ingen sikkerhetshendelser. |

### Tier 3 — Polering

| # | Problem | Detaljer |
|---|---------|---------|
| 9 | **EC2 instance-ID for kort** | `i-0def789abc012` (13 hex-tegn). Ekte: `i-0a1b2c3d4e5f67890` (17 hex-tegn). |
| 10 | **Kun 4 API-handlinger** | Mangler sikkerhetskritiske hendelser: CreateAccessKey, PutBucketPolicy, AttachUserPolicy, ConsoleLogin, StopLogging, DeleteTrail. |
| 11 | **Placeholder account-ID** | `123456789012` — AWS sitt kjente eksempel-konto. Bør bruke tilfeldig 12-sifret tall. |

### AWS CloudTrail — Offisiell dokumentasjon

- [CloudTrail Record Contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) — Komplett feltdefinisjon for alle event-typer
- [CloudTrail userIdentity Element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) — Identitetstyper, principalId-format, sessionContext
- [CloudTrail Log File Examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html) — Ekte eksempler på management events, data events, Insights events
- [IAM CloudTrail Integration](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html) — Eksempler på IAMUser, AssumedRole, federated user events
- [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html) — Oversikt over management, data og network activity events

---

## 2. Meraki IDS/IPS (`FAKE:meraki:securityappliances`)

**Antall hendelser:** 63  
**Alle IDS-alerts fra:** 185.220.101.42 → 10.20.30.15

### Tier 1 — Kritisk

| # | Problem | Nåværende verdi | Korrekt verdi |
|---|---------|----------------|---------------|
| 1 | **Snort SID-er er sekvensielle runde tall** | 23456, 34567, 45678, 56789, 67890 | Ekte SID-er: 1:41768:5, 1:31408:6, 1:469:4, 1:45907:2 |
| 2 | **Kategori/beskrivelse mismatch** | Kategori "BROWSER-IE" med beskrivelse "Microsoft Edge" | Bruk konsistente Snort-regelkategorier |
| 3 | **demo_id-felt avslører syntetisk data** | `demo_id: "exfil"` | Fjern — finnes ikke i ekte Meraki-logger |
| 4 | **Urealistiske port-mappinger** | SQL injection mot port 445 (SMB) og 3389 (RDP) | SQL injection bør målrette port 80/443/3306/5432 |

### Tier 2 — Viktig

| # | Problem | Detaljer |
|---|---------|---------|
| 5 | **Alle events fra én kilde-IP til én destinasjon** | Null variasjon — ekte IDS viser mange kilder/destinasjoner |
| 6 | **Tilfeldige MAC-adresser med ugyldige OUI-prefikser** | Bruk kjente leverandør-prefikser: 00:18:0A (Meraki), 3C:22:FB (Apple), DC:A6:32 (Raspberry Pi) |
| 7 | **Mangler ts-felt** | Ekte Meraki security events har `ts` (epoch) i tillegg til `occurredAt` |

### Meraki — Offisiell dokumentasjon

- [Get Network Appliance Security Events](https://developer.cisco.com/meraki/api-v1/get-network-appliance-security-events/) — API-respons med ekte eksempler inkl. IDS Alert, File Scanned felter
- [Get Organization Appliance Security Events](https://developer.cisco.com/meraki/api-v1/get-organization-appliance-security-events/) — Org-nivå security events med felt-definisjoner
- [Get Network Events](https://developer.cisco.com/meraki/api-v1/get-network-events/) — Generelle nettverkshendelser (referanse for format)
- [Meraki Community: Log reference/schema for security events](https://community.meraki.com/t5/Security-SD-WAN/Log-reference-guide-schema-for-API-network-and-security-events/m-p/140810) — Felldiskusjon med ekte IDS Alert-eksempler (signatur, classification, priority)

---

## 3. Azure AD / Entra ID

**Sourcetypes:** FAKE:azure:aad:signin (10,614), FAKE:azure:aad:audit (1,566), FAKE:azure:aad:risk:detection (103)

### Tier 1 — Kritisk

| # | Problem | Nåværende verdi | Korrekt verdi |
|---|---------|----------------|---------------|
| 1 | **ID-format feil — alle ID-er er lesbare strenger** | userId: `user-carlos-martinez-id`, deviceId: `device-cmartinez-001`, appId: `app-hr-custom-001`, correlationId (audit): `audit-70842` | Alle ID-er i Entra ID er UUID-er: `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| 2 | **clientAppUsed mangler variasjon** | 100% "Browser" | ~60% Browser, ~25% "Mobile Apps and Desktop clients", ~10% "Exchange ActiveSync", ~5% andre |
| 3 | **MFA-terminologi feil** | `authMethod: "TOTP"` | Microsoft bruker: "Mobile app verification code" eller "Software OATH token" — TOTP vises aldri i ekte Entra ID-logger |

### Tier 2 — Viktig

| # | Problem | Detaljer |
|---|---------|---------|
| 4 | **appId/appDisplayName mismatch** | appId `00000003-0000-0000-c000-000000000000` brukt for både "Microsoft Graph" OG "Office 365" — tilhører eksklusivt Microsoft Graph |
| 5 | **Mangler userAgent-felt** | Nesten alltid til stede i ekte innloggingslogger |
| 6 | **Mangler authenticationRequirement** | singleFactorAuthentication / multiFactorAuthentication |
| 7 | **OS-inkonsistens** | Normal trafikk: "Windows 11", angrepstrafikk: "Android 13" (med versjonsnummer). Entra ID rapporterer Android uten versjon. |
| 8 | **Risikodeteksjon med ukjent lokasjon** | Alle risk detections har location: "Unknown". Impossible travel-deteksjoner krever geodata. |

### Tier 3 — Polering

| # | Problem | Detaljer |
|---|---------|---------|
| 9 | **Audit-logg ufullstendighet** | "Add member to group" mangler target group informasjon |
| 10 | **Mangler modifiedProperties** | Audit-logger mangler dette feltet for mange operasjoner |

### Azure AD / Entra ID — Offisiell dokumentasjon

- [Activity Log Schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas) — Overordnet schema-definisjon for sign-in, audit, og risk detection logger
- [Sign-in Logs Overview](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins) — Typer innloggingslogger, filteralternativer, datatilgang
- [Sign-in Log Activity Details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details) — Detaljerte feltbeskrivelser: clientAppUsed, authenticationRequirement, MFA-detaljer
- [Sign-in Log Schema in Azure Monitor](https://learn.microsoft.com/th-th/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema) — Komplett JSON-schema med alle felt og eksempeldata
- [SigninLogs Table Reference (Azure Monitor)](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) — Kolonnedefinisjoner for Log Analytics

---

## 4. GCP Audit Logs (`FAKE:google:gcp:pubsub:audit:admin_activity`)

**Antall hendelser:** 4,900+  
**Tjenester:** storage.googleapis.com (2,341), compute.googleapis.com (922), cloudfunctions.googleapis.com (726), bigquery.googleapis.com (692), iam.googleapis.com (6), cloudresourcemanager.googleapis.com (2)

### Tier 1 — Kritisk

| # | Problem | Nåværende verdi | Korrekt verdi |
|---|---------|----------------|---------------|
| 1 | **insertId er lesbar tekst i steden for tilfeldig hex** | Angrepshendelser: `attack-gcp-001`, `recon-gcp-295`, `discovery-gcp-400` | Alltid tilfeldig hex: `f96dbf2a6f03409e`, `53179D9A9B559.AD6ACC7.B40604EF` |
| 2 | **demo_id: "exfil" finnes ikke i ekte GCP** | Felt som ikke eksisterer i GCP audit log-schema | Fjern feltet helt |
| 3 | **Alle ressurser har zone: "us-central1-a"** | BigQuery, GCS og Cloud Functions har IKKE zone i resource.labels | GCS: `bucket_name`+`location`, BigQuery: `dataset_id`, Functions: `function_name`+`region` |

### Tier 2 — Viktig

| # | Problem | Detaljer |
|---|---------|---------|
| 4 | **callerSuppliedUserAgent identisk** | Alle 4,900+ events: `google-cloud-sdk/400.0.0`. Ekte: varierte SDK-versjoner, Terraform, konsoll, google-api-python-client |
| 5 | **resource.labels feil for BigQuery** | Bruker zone — ekte har project_id + dataset_id |
| 6 | **resource.labels feil for GCS** | Bruker zone — ekte har project_id + bucket_name + location |
| 7 | **resource.labels feil for Cloud Functions** | Bruker zone — ekte har function_name + project_id + region |
| 8 | **Mangler authorizationInfo** | Ekte logger inkluderer alltid permission-sjekkliste med granted/denied |

### Tier 3 — Polering

| # | Problem | Detaljer |
|---|---------|---------|
| 9 | **Mangler protoPayload.status** | Ekte: `{"code": 0, "message": "OK"}` (gRPC status) |
| 10 | **Mangler receiveTimestamp** | Alltid til stede i ekte GCP-logger |
| 11 | **Service account key ID er lesbar** | `malicious-key-001` → ekte: `a1b2c3d4e5f6g7h8i9j0` |
| 12 | **Timestamps for "runde"** | Angrepshendelser: 10:00:00, 10:05:00, 11:00:00 — ekte har alltid tilfeldige sekunder/millisekunder |

### GCP Audit Logs — Offisiell dokumentasjon

- [Cloud Audit Logs Overview](https://docs.cloud.google.com/logging/docs/audit) — LogEntry-typer, AuditLog-objekt, audit log names, identity/IP-håndtering
- [Understanding Audit Logs](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs) — Komplett eksempel med protoPayload, resource, insertId — den primære referansen for loggformat
- [AuditLog REST Reference](https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog) — Feltdefinisjoner for serviceName, authenticationInfo, authorizationInfo, requestMetadata, status
- [Cloud Audit Logs with Cloud Storage](https://docs.cloud.google.com/storage/docs/audit-logging) — GCS-spesifikke resource.labels og audit log-typer
- [Splunk Blog: Getting to Know GCP Audit Logs](https://www.splunk.com/en_us/blog/partners/getting-to-know-google-cloud-audit-logs.html) — Praktisk guide med ekte eksempler og Splunk-søk
- [Google SecOps: Collect Cloud Audit Logs](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/gcp-cloudaudit) — Ekte JSON-eksempel med komplett protoPayload inkl. authorizationInfo, requestMetadata med callerSuppliedUserAgent

---

## 5. Cisco Webex (`FAKE:cisco:webex:*`)

**8 sourcetypes, 3 007 hendelser totalt:**

| Sourcetype | Antall | Beskrivelse |
|------------|--------|-------------|
| `FAKE:cisco:webex:events` | 1 858 | Device health, meeting lifecycle, quality metrics, room analytics |
| `FAKE:cisco:webex:security:audit:events` | 471 | Bruker inn-/utlogging |
| `FAKE:cisco:webex:meeting:qualities` | 339 | Detaljert møtekvalitet per deltaker |
| `FAKE:cisco:webex:meetings:history:meetingattendeehistory` | 211 | Deltaker-historikk |
| `FAKE:cisco:webex:call:detailed_history` | 48 | Samtaledetaljer (CDR) |
| `FAKE:cisco:webex:meetings` | 42 | Møte-metadata |
| `FAKE:cisco:webex:meetings:history:meetingusagehistory` | 26 | Møtebruk-statistikk |
| `FAKE:cisco:webex:admin:audit:events` | 12 | Admin-handlinger i Control Hub |

### Tier 1 — Kritisk (bryter realisme umiddelbart)

| # | Problem | Nåværende verdi | Korrekt verdi | Dokumentasjon |
|---|---------|----------------|---------------|---------------|
| 1 | **actorId base64-enkoding er ødelagt** — Bruker `PEOPLE` som rå tekst inni base64-strengen i stedet for korrekt enkoding. Dekoding gir korrupt output (`ciscospark://us,ñ...` i stedet for `ciscospark://us/PEOPLE/<uuid>`). Påvirker alle 483 audit-events. | `Y2lzY29zcGFyazovL3VzLPEOPLE/73896daf-...` | `Y2lzY29zcGFyazovL3VzL1BFT1BMRS83Mzg5NmRh...` (korrekt base64 av `ciscospark://us/PEOPLE/<uuid>`) | [Webex People API](https://developer.webex.com/docs/api/v1/people) |
| 2 | **clientType/osType/hardwareType er fullstendig randomisert** — Alle kombinasjoner forekommer tilfeldig, inkludert umulige. ~70% av meeting quality-events (236 av 339) har ugyldige kombinasjoner. | `Webex Desktop` + `iOS` + `Dell Latitude`, `Webex Mobile (Android)` + `macOS` + `MacBook Pro`, `Webex Mobile (iOS)` + `Windows` + `Lenovo ThinkPad` | Webex Desktop → kun Windows/macOS/Linux. Webex Mobile (iOS) → kun iOS + iPhone/iPad. Webex Mobile (Android) → kun Android + Samsung/Pixel. MacBook Pro → kun macOS. | [Webex Meeting Qualities API](https://developer.webex.com/docs/api/v1/meeting-qualities) |
| 3 | **Samme clientType/clientOS-mismatch i deltaker-historikk** — 42 unike (av mulige 42) clientType/clientOS-kombianasjoner, de fleste umulige. | `Cisco Room Device` + `Windows 10`, `Phone (PSTN)` + `ChromeOS`, `Webex Mobile (Android)` + `macOS 14` | Cisco Room Device → RoomOS. Phone (PSTN) → null/ingen OS. Webex Desktop → Windows/macOS. | [Webex Meeting Participants API](https://developer.webex.com/docs/api/v1/meeting-participants) |
| 4 | **Device MAC-format feil i CDR** — Kolon-separert format med tilfeldige adresser. Ekte Webex CDR bruker sammenhengende 12-tegns hex uten separator. | `7A:B0:89:D3:3D:B4` | `6C710D8ABC10` | [Webex CDR-felt](https://developer.webex.com/blog/exploring-the-webex-calling-reports-and-analytics-apis) |

### Tier 2 — Viktig (merkbart for analytikere)

| # | Problem | Detaljer |
|---|---------|---------|
| 5 | **Call ID-format feil i CDR** | Bruker UUID: `388b5f0d-6cdb-451e-92c1-237619971dbc`. Ekte Webex CDR bruker SIP-format: `SSE1101163211405201218829100@10.177.4.29`. |
| 6 | **Department ID er lesbar tekst** | Nåværende: `Finance`, `Engineering`, `Legal`. Ekte Webex API: UUID som `4370c763-81ec-403b-aba3-626a7b1cf264`. |
| 7 | **Duration er string i stedet for integer** | CDR og attendee-historikk: `"545"` (string). Ekte API returnerer `545` (integer). Kan bryte SPL-beregninger som `| stats avg(Duration)`. |
| 8 | **Security audit har KUN login/logout** | 471 events: 230 login + 239 logout. Mangler: feilet innlogging, SSO-events, MFA-utfordringer, session timeout, policy-brudd. |
| 9 | **Grammatisk feil i eventDescription** | `"An user logged in"` → Korrekt: `"A user logged in"`. Samme for logged out. Webex sin offisielle API bruker "A user". |
| 10 | **Alle IP-er i security audit er interne** | Alle `actorIp` er `10.x.x.x`. Remote-ansatte ville generert offentlige IP-er (hjemmenett, VPN-exit, mobilt). |
| 11 | **Kun 4 userAgent-varianter i security audit** | Safari macOS, Chrome Windows, Firefox Windows, Safari iOS. Mangler: Webex-appen selv, Edge, Linux-varianter, Webex Teams-klient. |

### Tier 3 — Polering (kosmetisk)

| # | Problem | Detaljer |
|---|---------|---------|
| 12 | **actorOrgId har samme base64-feil** | `Y2lzY29zcGFyazovL3VzL09SR0FOSVpBVElPTi8af23e456-...` — dekoder til korrupt data. Skal være fullstendig base64-enkodet `ciscospark://us/ORGANIZATION/<uuid>`. |
| 13 | **Client version identisk for alle** | Alle meeting quality: `43.11.0.5678` eller `43.10.0.9012`. Ekte miljøer har bredere versjonsspredning. |
| 14 | **CDR mangler mange standard-felt** | Mangler bl.a.: `Final local SessionID`, `Final remote SessionID`, `Inbound trunk`, `Outbound trunk`, `International country`, `Release time`, `Releasing party`, `User UUID`, `Org UUID`, `Site main number`. |
| 15 | **Kun 2 admin-aktører i 12 events** | Mike Johnson og Jessica Brown. Ekte miljøer har flere admins med varierende roller (`Full_Admin`, `Read-Only_Admin`, `Device_Admin`). |

### Hva som fungerer bra ✓

- **Security audit event-struktur** — `id`, `actorId`, `actorOrgId`, `created`, `data`-objekt med nested felt følger ekte Webex API-respons godt.
- **Meeting-data er rik** — `meetingType`, `state`, `hostKey`, `siteUrl`, `webLink`, `sipAddress`, `joinBeforeHostMinutes` er alle realistiske felt.
- **Device health/room analytics** — CPU, minne, temperatur, periferi-status, ambient noise, people count gir gode telemetridata.
- **Quality metrics tidserier** — `packetLoss`, `latency`, `jitter`, `mediaBitRate` arrays med 42–47 samplingspunkter per sesjon er realistisk format.
- **Admin audit har god bredde** — 9 event-kategorier: USERS, MEETINGS, COMPLIANCE, DEVICES, GROUPS med varierte handlinger.
- **Meeting usage history** — Realistiske felt som `totalPeopleMinutes`, `totalVoipMinutes`, `totalTelephonyMinutes`, `peakAttendee`.

### Relevant dokumentasjon

- [Webex Security Audit Events API](https://developer.webex.com/docs/api/v1/security-audit-events) — Login/logout event-schema, feltnavn
- [Webex Admin Audit Events API](https://developer.webex.com/docs/api/v1/admin-audit-events) — Admin event-kategorier, actorId/targetId-format
- [Webex Meeting Qualities API](https://developer.webex.com/docs/api/v1/meeting-qualities) — Korrekt clientType, osType, hardwareType-felter
- [Webex Detailed Call History API](https://developer.webex.com/blog/exploring-the-webex-calling-reports-and-analytics-apis) — CDR feltformat inkl. Call ID (SIP), Device MAC (uten separator), Department ID (UUID)
- [Webex CDR Report Field Reference](https://help.webex.com/en-us/article/nmug598) — Komplett kolonnebeskrivelse for Calling Detailed Call History Report
- [Understand Detailed Call History Report](https://www.cisco.com/c/en/us/support/docs/unified-communications/webex-calling/220377-understand-detailed-call-history-report.html) — Cisco-guide med ekte CDR-eksempler og call-flow analyse

---

## 6. Microsoft 365 Unified Audit Log (`FAKE:o365:management:activity`)

**Antall hendelser:** 18 990 (14 dager, scale=1.0)
**Workloads:** SharePoint (RecordType 6, ~25%), OneDrive (RecordType 7, ~35%), MicrosoftTeams (RecordType 25, ~40%)
**Scenario-events:** exfil: 193, ransomware_attempt: 22

### Tier 1 — Kritisk (bryter realisme umiddelbart)

| # | Problem | Nåværende verdi | Korrekt verdi | Dokumentasjon |
|---|---------|----------------|---------------|---------------|
| 1 | **CommunicationType feil enum-verdier (Teams)** — Bruker `"Channel"` og `"OneOnOne"` som ikke finnes i ekte M365. | `"Channel"`, `"OneOnOne"` | `"TeamChat"`, `"PrivateChat"`, `"MeetingChat"` | [Office 365 Management API Schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema) |
| 2 | **Members.Role er integer, skal være string** — Bruker `"Role": 1` i stedet for strengverdier. | `"Role": 1` | `"Role": "Owner"` / `"Member"` / `"Guest"` | [MicrosoftTeamsMember Complex Type](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#microsoftteamsmember-complex-type) |
| 3 | **ChannelFileUploaded/ChannelFileAccessed er ikke ekte operasjoner** — Filer i Teams-kanaler logges som SharePoint-events (RecordType 6), IKKE som Teams-events (RecordType 25). ~35% av Teams-events bruker ugyldige operasjoner. | `"ChannelFileUploaded"`, `"ChannelFileAccessed"` | Bruk SharePoint RecordType 6 for kanal-filoperasjoner. Erstatt med ekte Teams-operasjoner som `"ChatCreated"`, `"MessageRead"`, `"TabAdded"` | [Audit log activities: Teams](https://learn.microsoft.com/en-us/purview/audit-log-activities#microsoft-teams-activities) |
| 4 | **Mangler TeamGuid-felt (Teams)** — Påkrevd identifikator for alle Teams-events, brukes i Splunk-korrelasjon og dashboards. | Mangler | `"TeamGuid": "19:0571b31b...@thread.skype"` | [Office 365 Management API Schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema) |
| 5 | **Mangler ChannelGuid-felt (Teams)** — Primær kanal-identifikator i API-et. | Mangler | `"ChannelGuid": "19:f2cb1f55...@thread.skype"` | [Office 365 Management API Schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema) |

### Tier 2 — Viktig (merkbart for analytikere)

| # | Problem | Detaljer |
|---|---------|---------|
| 6 | **UserKey-format feil for Teams-events** | SharePoint/OneDrive: UserKey er 16-tegns hex PUID (vår generering er nær riktig, men mangler `1003`-prefiks). Teams-events bruker Azure AD Object ID i GUID-format (`aff4cd58-1bb8-4899-94de-795f656b4a18`), ikke PUID. |
| 7 | **Mangler Version-felt** | Alle ekte events har `"Version": 1`. Mangler i all output. |
| 8 | **Mangler AADGroupId (Teams)** | Azure AD gruppe-GUID for teamet. Brukes i Sentinel og Splunk sikkerhet-workflows. |
| 9 | **ClientIP bruker alltid interne RFC1918-adresser** | Ekte M365 logger viser offentlige IP-er (NAT gateway). En bedrift med 175 ansatte ville typisk hatt 1-3 eksterne IP-er per kontor, ikke individuelle 10.x.x.x-adresser. |
| 10 | **ResultStatus alltid "Succeeded"** | 100% suksessrate. Ekte miljøer har ~2-5% `"Failed"` og `"PartiallySucceeded"` (tilgangsnektet, throttling). |
| 11 | **Mangler MessageId for MessageSent** | Ekte MessageSent-events inkluderer `"MessageId"` (numerisk streng som `"1661368101750"`). |
| 12 | **Members-objekt mangler felt** | Nåværende: bare `UPN` og `Role`. Ekte: også `DisplayName`, `Id` (Azure AD Object ID), `Email`. |

### Tier 3 — Polering

| # | Problem | Detaljer |
|---|---------|---------|
| 13 | **Mangler Site (Edm.Guid) felt** | SharePoint/OneDrive-events inkluderer ofte `Site` GUID i tillegg til `SiteUrl`. |
| 14 | **TeamCreated/TeamDeleted-frekvens for hyppig** | 3% + 2% = ~33 events/dag i en 175-person bedrift. Realistisk: 1-2 per uke. |
| 15 | **Mangler ChatThreadId for private chats** | Ekte private/gruppe-chat events inkluderer denne identifikatoren. |
| 16 | **Mangler Scope-felt** | Common Schema har `"Scope"` (0=online, 1=onprem), valgfritt men vanlig. |
| 17 | **UserKey PUID mangler standard-prefiks** | Ekte PUID starter med `1003` (MSA) eller `10032` (org). Vår hash gir tilfeldige prefikser. |

### Hva som fungerer bra ✓

- **Common schema-felt**: `Id` (UUID v4), `RecordType` (riktige heltall), `CreationTime` (ISO 8601 UTC), `Operation`, `OrganizationId`, `UserType`, `Workload`, `UserId` (UPN-format), `ClientIP` — alt korrekt typet og navngitt.
- **RecordType-verdier**: 6 (SharePointFileOperation), 7 (OneDrive), 25 (MicrosoftTeams) er alle korrekte.
- **SharePoint/OneDrive filoperasjoner**: `FileAccessed`, `FileModified`, `FileDownloaded`, `FileUploaded`, `FileCheckedOut/In`, `FileDeleted`, `SharingSet`, `FileSyncUploadedFull`, `FileRestored` — alle gyldige Microsoft-operasjoner.
- **SharePoint-feltstruktur**: `SiteUrl`, `SourceRelativeUrl`, `SourceFileName`, `SourceFileExtension`, `ObjectId`, `ItemType`, `EventSource`, `UserAgent` — alt riktig navngitt.
- **ObjectId URL-konstruksjon**: Korrekte maler for både SharePoint team-sites (`/sites/SiteName/Shared Documents/fil`) og OneDrive personal (`/personal/user_domain_com/Documents/fil`).
- **User agents**: Realistisk blanding av nettlesere, Office-apper, OneDrive sync-klient. Matcher ekte M365-miljøer.
- **Volumfordeling**: 25% SharePoint / 35% OneDrive / 40% Teams er en god tilnærming til ekte M365-aktivitet.
- **Scenario-integrasjon**: Exfil-scenariet bruker korrekt threat actor IP, målretter Finance-dokumenter, og inkluderer `SharingSet` til ekstern e-post. Ransomware-scenariet med rask filmodifisering og IT-admin gjenoppretting er godt modellert.
- **Deterministisk UserKey per bruker**: Konsistent per bruker via hash — korrekt oppførsel (PUID er statisk).
- **Timestamp-format**: ISO 8601 UTC med `Z`-suffiks matcher API-spesifikasjonen.

### Microsoft 365 Audit Log — Offisiell dokumentasjon

- [Office 365 Management Activity API Schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema) — Common schema, SharePoint Base schema, Teams schema med felt-definisjoner og komplekse typer
- [Audit Log Detailed Properties](https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties) — Alle felt per aktivitetstype
- [Audit Log Activities: Teams](https://learn.microsoft.com/en-us/purview/audit-log-activities#microsoft-teams-activities) — Komplett liste over Teams-operasjoner
- [Audit Log Activities: SharePoint](https://learn.microsoft.com/en-us/purview/audit-log-activities#sharepoint-file-activities) — SharePoint/OneDrive filoperasjoner
- [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) — Splunkbase app 4055, sourcetype `o365:management:activity`

---

## Oppsummering — Fellesproblemer på tvers av plattformer

| Problem | AWS | Meraki | Azure | GCP | Webex | M365 |
|---------|:---:|:------:|:-----:|:---:|:-----:|:----:|
| Lesbare ID-er / feil ID-format | ✗ | — | ✗ | ✗ | ✗ | ✓* |
| demo_id/syntetisk markør | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ |
| Ingen userAgent-variasjon | ✗ | — | ✗ | ✗ | ✗ | ✓ |
| Feil terminologi/felt-verdier | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Manglende standard-felt | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Angrepstrafikk inkludert | ✗ | ✓ | ✓ | ✓ | ✗ | ✓ |
| clientType/OS-mismatch | — | — | — | — | ✗ | — |

✓ = OK, ✗ = Problem funnet, — = Ikke relevant
\* M365 UserKey format er nær riktig for SP/OD men feil for Teams-events

### Topp 10 fikser med størst effekt (oppdatert med M365)

1. **Fiks clientType/osType/hardwareType-mapping i Webex** — 70% av meeting quality-data har umulige kombinasjoner. Opprett en mapping-tabell som sikrer logisk konsistens: Webex Desktop → Windows/macOS, Webex Mobile (iOS) → iOS + iPhone/iPad, etc. Påvirker 339 + 211 = 550 events.
2. **Fiks base64-enkoding av Webex actorId/actorOrgId** — Nåværende hybrid-format (delvis base64, delvis rå tekst) dekoder til korrupt data. Hele URI-en (`ciscospark://us/PEOPLE/<uuid>`) må base64-enkodes. Påvirker 483 audit-events.
3. **Erstatt alle lesbare ID-er med ekte formater** — UUID-er for Azure, alfanumeriske for AWS principalId, hex for GCP insertId, UUID for Webex Department ID. Viktigste enkeltfiks på tvers av alle plattformer.
4. **Fjern demo_id fra Meraki og GCP** — Avslører umiddelbart at data er syntetisk.
5. **Varier userAgent** — Samme verdi for tusenvis av events er et rødt flagg. Gjelder AWS, Azure, GCP og Webex security audit.
6. **Fiks CDR-feltformat i Webex** — Device MAC (fjern kolonner), Call ID (SIP-format), Department ID (UUID), Duration (integer).
7. **Fiks M365 Teams CommunicationType** — `"Channel"` → `"TeamChat"`, `"OneOnOne"` → `"PrivateChat"`. Legg til `"MeetingChat"`. Påvirker alle Teams-events (~40% av output).
8. **Fjern M365 ChannelFileUploaded/ChannelFileAccessed** — Ikke ekte operasjoner. Filer i Teams-kanaler logges som SharePoint RecordType 6. Erstatt med ekte Teams-operasjoner. Påvirker ~35% av Teams-events.
9. **Legg til TeamGuid/ChannelGuid i M365 Teams-events** — Påkrevde felt for korrelasjon i Splunk og Sentinel.
10. **Legg til angrepstrafikk i AWS CloudTrail og Webex** — De to plattformene uten angrepsscenario. For Webex: legg til feilede innlogginger, brute force, og admin policy-endringer fra ukjente IP-er.
