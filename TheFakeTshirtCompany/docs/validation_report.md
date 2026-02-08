# Syntetisk Sikkerhetslogg-Validering — fake_tshrt

Komplett validering av syntetiske logger i Splunk-indeksen `fake_tshrt` på tvers av fire plattformer: AWS CloudTrail, Meraki IDS/IPS, Azure AD/Entra ID, og GCP Audit Logs.

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

## Oppsummering — Fellesproblemer på tvers av plattformer

| Problem | AWS | Meraki | Azure | GCP |
|---------|:---:|:------:|:-----:|:---:|
| Lesbare ID-er i stedet for UUID/hex | ✗ | — | ✗ | ✗ |
| demo_id/syntetisk markør | ✓ | ✗ | ✓ | ✗ |
| Ingen userAgent-variasjon | ✗ | — | ✗ | ✗ |
| Feil terminologi/felt-verdier | ✗ | ✗ | ✗ | ✗ |
| Manglende standard-felt | ✗ | ✗ | ✗ | ✗ |
| Angrepstrafikk inkludert | ✗ | ✓ | ✓ | ✓ |

✓ = OK, ✗ = Problem funnet, — = Ikke relevant

### Topp 5 fikser med størst effekt

1. **Erstatt alle lesbare ID-er med ekte formater** — UUID-er for Azure, alfanumeriske for AWS principalId, hex for GCP insertId. Dette er den viktigste enkeltfiksken på tvers av alle plattformer.
2. **Fjern demo_id fra Meraki og GCP** — Avslører umiddelbart at data er syntetisk.
3. **Varier userAgent** — Samme verdi for tusenvis av events er et rødt flagg. Legg til realistisk distribusjon av klienter.
4. **Fiks resource.labels i GCP** — BigQuery og GCS har ikke zone. Feil schema gjør at Splunk-søk mot ekte og syntetisk data ikke kan sammenlignes.
5. **Legg til angrepstrafikk i AWS CloudTrail** — Eneste plattform uten angrepsscenario. Legg til IAM-endringer, credential harvesting, og CloudTrail manipulation fra ekstern IP.
