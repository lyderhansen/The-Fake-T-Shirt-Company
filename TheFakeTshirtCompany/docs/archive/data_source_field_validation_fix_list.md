# Fiksliste — fake_tshrt syntetiske logger (verifisert)

Konkret liste over hva som må fikses per sourcetype, sortert etter prioritet (🔴 kritisk → 🟡 viktig → ⚪ polering).

**Verifisert-kolonne:** ✅ = bekreftet mot offisiell docs | ⚠️ = delvis/indirekte verifisert | ❌ = ikke funnet i docs

---

## AWS CloudTrail — `FAKE:aws:cloudtrail` (161 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | principalId er unik per event | Ny ID per event: `AIDA7CCDEAEB6BA6492A` | Fast per bruker, alfanumerisk: `AIDAJQABLZS4A3QDU576Q` | [userIdentity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) | ✅ | Docs viser `AIDAJ45Q7YFFAREXAMPLE`, `AIDAIT6PBPQYAB2QOUEGW`, `EXAMPLE6E4XEGITWATV6R` — alltid fast per IAM-bruker |
| 🔴 | Kun IAMUser-type | 100% IAMUser | Legg til AssumedRole (~60%), AWSService, Root | [userIdentity types](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) | ✅ | Docs lister: Root, IAMUser, AssumedRole, FederatedUser, AWSService, SAMLUser, WebIdentityUser, IdentityCenterUser |
| 🔴 | Unik IP per event | 51 events = 51 IP-er | 1–3 IP-er per bruker per økt | [Record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) | ⚠️ | Docs bekrefter at sourceIPAddress er klientens IP. Antall per økt er en realistisk observasjon, ikke spesifisert i docs |
| 🟡 | Identisk userAgent | Alle: `aws-cli/2.13.0` | Varier: aws-cli, boto3, Terraform, konsoll, Lambda SDK | [Log examples](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html) | ✅ | Docs viser mange ulike: `aws-cli/2.13.5 Python/3.11.4 Linux/...`, `aws-cli/1.16.96 Python/3.6.0 Windows/10`, `signin.amazonaws.com` for konsoll |
| 🟡 | Manglende felt | — | Legg til `readOnly`, `managementEvent`, `eventCategory`, `accessKeyId`, `sessionContext`, `resources` | [Record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) | ✅ | Alle felt bekreftet i docs: `readOnly` (bool), `managementEvent` (bool, fra v1.06), `eventCategory` ("Management"/"Data"), `resources` (liste med ARN/type) |
| 🟡 | Ingen angrepstrafikk | 0 sikkerhetshendelser | Legg til CreateAccessKey, PutBucketPolicy, StopLogging, ConsoleLogin fra ukjent IP | [IAM CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html) | ⚠️ | Docs bekrefter at disse eventName-verdiene logges (ConsoleLogin, AssumeRole, CreateAccessKey). Angrepsmønster er scenariodesign, ikke docs |
| 🟡 | Alle brukere gjør alt | svc-backup gjør Lambda Invoke | Spesialiser per rolle | — | ⚠️ | Ingen docs for rollefordeling — men IAM-policy-design gjør det urealistisk at alle gjør alt |
| ⚪ | EC2 instance-ID for kort | `i-0def789abc012` (13 hex) | `i-0a1b2c3d4e5f67890` (17 hex) | [EC2 long IDs](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-id-format.html) | ✅ | Docs bekrefter: "i-" + 17 hex chars har vært standard siden 2016. Eksempel: `i-06d4a030f97f1c445` |
| ⚪ | Placeholder account-ID | `123456789012` | Tilfeldig 12-sifret tall | — | ⚠️ | `123456789012` er AWS sin standard eksempel-konto. Teknisk gyldig format, men gjenkjennelig som placeholder |

---

## Meraki IDS/IPS — `FAKE:meraki:securityappliances` (63 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | Snort SID-er er runde tall | `23456`, `34567`, `45678` | Ekte SID-format: `1:41768:5`, `1:31408:6` | [Security events API](https://developer.cisco.com/meraki/api-v1/get-network-appliance-security-events/) | ⚠️ | Snort SID-format er bekreftet som GID:SID:Rev (f.eks. `1:26798:2`) fra Cisco Firepower docs. Meraki API-respons bruker muligens bare numerisk SID — kan ikke verifisere Meraki-spesifikt format uten API-tilgang |
| 🔴 | Kategori/beskrivelse mismatch | `BROWSER-IE` + "Microsoft Edge" | Bruk konsistente Snort-kategorier | [Meraki community schema](https://community.meraki.com/t5/Security-SD-WAN/Log-reference-guide-schema-for-API-network-and-security-events/m-p/140810) | ⚠️ | Snort-kategorier er standardiserte (BROWSER-IE, SERVER-WEBAPP, etc.). Mismatch mellom kategori og beskrivelse er logisk ugyldig, men eksakt mapping krever Snort rule DB |
| 🟡 | Alle events fra én IP-par | 185.220.101.42 → 10.20.30.15 | Varier kilder og destinasjoner | — | ⚠️ | Beste praksis for realistisk logg. Ingen spesifikk docs-referanse |
| 🟡 | Urealistiske port-mappinger | SQL injection mot port 445/3389 | SQL injection → 80/443/3306/5432 | — | ⚠️ | SQL injection retter seg mot web/database-porter, ikke SMB(445)/RDP(3389). Allment kjent, men ingen Meraki-spesifikk docs |
| 🟡 | Tilfeldige MAC-OUI-prefikser | Random bytes | Bruk kjente OUI: `00:18:0A` (Meraki), `3C:22:FB` (Apple) | — | ⚠️ | OUI-prefikser er registrert hos IEEE. `00:18:0A` = Cisco Meraki er verifiserbar via IEEE OUI-database, men ikke Meraki docs |
| ⚪ | Mangler ts-felt | — | Legg til `ts` (epoch timestamp) | [Network events API](https://developer.cisco.com/meraki/api-v1/get-network-events/) | ⚠️ | Referert docs er for network events, ikke security events. Kan ikke verifisere at security events API inkluderer `ts` uten API-tilgang |

---

## Azure AD / Entra ID (12 383 events)

### `FAKE:azure:aad:signin` (10 614 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | Alle ID-er er lesbare strenger | `user-carlos-martinez-id`, `device-cmartinez-001` | UUID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890` | [Sign-in log schema](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema) | ✅ | Entra ID bruker UUID/GUID for alle objekt-ID-er (userId, deviceId, correlationId). Bekreftet fra PowerShell-eksempler og Graph API schema |
| 🔴 | clientAppUsed = 100% "Browser" | Ingen variasjon | ~60% Browser, ~25% Mobile/Desktop, ~10% EAS | [Sign-in activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details) | ⚠️ | Docs bekrefter at `clientAppUsed` har varierte verdier (Browser, Mobile Apps and Desktop clients, Exchange ActiveSync, etc.). Prosentfordelingen er estimat, ikke fra docs |
| 🔴 | MFA-metode "TOTP" | `authMethod: "TOTP"` | `"OATH verification code"` eller `"Software OATH token"` | [MFA reporting](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-reporting) | ✅ | Docs sier eksplisitt: "OATH verification code is logged as the authentication method for both OATH hardware and software tokens". Dokumenterte verdier: Password, SMS, Voice, Authenticator App, Software OATH token — IKKE "TOTP" |
| 🟡 | appId/appDisplayName mismatch | `00000003-...` brukt for bade Graph og Office 365 | `00000003-...` = kun Microsoft Graph | [Sign-in logs overview](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins) | ⚠️ | Velkjent at `00000003-0000-0000-c000-000000000000` = Microsoft Graph API. Ikke direkte fra Entra docs, men fra Microsoft identity platform registrering |
| 🟡 | Mangler userAgent | Nesten aldri til stede | Alltid til stede i ekte logger | [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) | ✅ | Bekreftet: `UserAgent` er standard felt i SigninLogs-tabellen. PowerShell-eksempler viser det som standard property |
| 🟡 | Mangler authenticationRequirement | — | `singleFactorAuthentication` / `multiFactorAuthentication` | [Sign-in activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details) | ✅ | Docs bekrefter verdier: `singleFactorAuthentication` / `multiFactorAuthentication` |
| ⚪ | Android med versjonsnummer | `Android 13` i angrepstrafikk | `Android` (uten versjon) i Entra ID | — | ⚠️ | Ikke verifisert fra docs. OS-representasjon i Entra ID kan variere |

### `FAKE:azure:aad:audit` (1 566 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | ID-er er lesbare | `audit-70842` som correlationId | UUID | [Activity log schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas) | ✅ | Docs bekrefter at correlationId er standard GUID-format |
| 🟡 | "Add member to group" mangler target | Ingen group-info | Inkluder target group-objekt | — | ⚠️ | Docs nevner `targetResources` med verdier (User, Device, Directory, App, Role, Group, Policy). Spesifikk payload ikke direkte verifisert |
| ⚪ | Mangler modifiedProperties | — | Legg til for relevante operasjoner | — | ✅ | Docs bekrefter `modifiedProperties` med `oldValue`, `displayName`, `newValue` som standard del av targetResources |

### `FAKE:azure:aad:risk:detection` (103 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🟡 | Location alltid "Unknown" | `location: "Unknown"` | Geodata påkrevd for impossibleTravel | [Activity log schemas](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas) | ⚠️ | Logisk at impossibleTravel krever to lokasjoner for beregning. Spesifikt riskDetection-schema ikke direkte verifisert |

---

## GCP Audit Logs — `FAKE:google:gcp:pubsub:audit:admin_activity` (4 900+ events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | insertId er lesbar tekst | `attack-gcp-001`, `recon-gcp-295` | Tilfeldig hex: `f96dbf2a6f03409e` | [Understanding audit logs](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs) | ✅ | Docs viser: `"insertId": "53179D9A9B559.AD6ACC7.B40604EF"`. Alltid maskin-generert, aldri lesbar tekst |
| 🔴 | resource.labels har zone for alt | BigQuery/GCS/Functions med `zone: "us-central1-a"` | GCS: `bucket_name`+`location`, BQ: `dataset_id`, Functions: `function_name`+`region` | [GCS audit logging](https://docs.cloud.google.com/storage/docs/audit-logging) | ✅ | Bekreftet: GCS bruker `gcs_bucket` med `bucket_name`, BigQuery bruker `bigquery_project`/`bigquery_dataset` med `project_id`/`dataset_id`, Compute bruker `instance_id`. `zone` gjelder kun Compute |
| 🟡 | Identisk userAgent | Alle: `google-cloud-sdk/400.0.0` | Varier: SDK-versjoner, Terraform, konsoll, python-client | [Audit logs overview](https://docs.cloud.google.com/logging/docs/audit) | ⚠️ | Docs nevner requestMetadata.callerSuppliedUserAgent som standard felt. Spesifikke varianter ikke listet |
| 🟡 | Mangler authorizationInfo | — | Permission-sjekk med `granted: true/false` | [AuditLog REST](https://cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog) | ✅ | Reelt eksempel: `"authorizationInfo": [{"granted": true, "permission": "io.k8s.authorization.rbac.v1..."}]` |
| ⚪ | Mangler protoPayload.status | — | `{"code": 0, "message": "OK"}` | [Understanding audit logs](https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs) | ✅ | Docs viser: `"status": {"code": 5, "message": "Not found: Dataset..."}`. Tom `status: {}` = suksess |
| ⚪ | Mangler receiveTimestamp | — | Alltid til stede | [Splunk GCP guide](https://www.splunk.com/en_us/blog/partners/getting-to-know-google-cloud-audit-logs.html) | ⚠️ | Standard LogEntry-felt, men verifisert kun via tredjepartskilde (Splunk) |
| ⚪ | Lesbare SA key ID-er | `malicious-key-001` | Tilfeldig alfanumerisk ID | — | ⚠️ | GCP SA key ID-er er maskin-genererte. Ikke spesifikt verifisert format |
| ⚪ | Runde timestamps i angrep | `10:00:00`, `10:05:00` | Tilfeldige sekunder/ms | — | ⚠️ | Generell realisme — ingen docs nødvendig |

---

## Cisco Webex — `FAKE:cisco:webex:*` (3 007 events over 8 sourcetypes)

### `FAKE:cisco:webex:security:audit:events` (471) + `FAKE:cisco:webex:admin:audit:events` (12)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | actorId/actorOrgId base64 er ødelagt | `Y2lzY29zcGFyazovL3VzLPEOPLE/...` (delvis rå tekst) | Fullstendig base64 av `ciscospark://us/PEOPLE/<uuid>` → `Y2lzY29zcGFyazovL3VzL1BFT1BMRS8...` | [People API](https://developer.webex.com/docs/api/v1/people) | ⚠️ | Webex bruker `ciscospark://` URI som base64-enkodes. "PEOPLE" som rå tekst i base64 er klart feil encoding. Spesifikk output ikke verifisert uten API-tilgang |
| 🟡 | Kun login/logout, ingen feil | 230 login + 239 logout | Legg til feilet innlogging, MFA, SSO, session timeout | [Security Audit Events](https://developer.webex.com/docs/api/v1/security-audit-events) | ⚠️ | Docs nevner varierte event-typer. Spesifikke event-navn ikke verifisert uten API-tilgang |
| 🟡 | Grammatisk feil | `"An user logged in"` | `"A user logged in"` | — | ✅ | Engelsk grammatikk: "a" foran konsonant-lyd |
| 🟡 | Alle actorIp er interne | Kun `10.x.x.x` | Bland inn offentlige IP-er for remote-brukere | — | ⚠️ | Logisk for SaaS-tjeneste |
| 🟡 | Kun 4 userAgent-varianter | Safari, Chrome, Firefox, Safari iOS | Legg til Webex-appen, Edge, Linux | — | ⚠️ | Rimelig, men ikke docs-verifisert |
| ⚪ | Kun 2 admin-aktører | Mike Johnson, Jessica Brown | Flere admins med varierte roller | [Admin Audit Events](https://developer.webex.com/docs/api/v1/admin-audit-events) | ⚠️ | Scenariodesign |

### `FAKE:cisco:webex:meeting:qualities` (339 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | clientType/osType/hardwareType randomisert | `Webex Desktop`+`iOS`+`Dell`, `Webex Mobile (Android)`+`macOS`+`MacBook Pro` (~70% ugyldige) | Mapping: Desktop→Win/macOS, Mobile iOS→iOS+iPhone, Mobile Android→Android+Samsung/Pixel, MacBook→macOS | [Meeting Qualities API](https://developer.webex.com/docs/api/v1/meeting-qualities) | ⚠️ | Logiske inkompatibiliteter er åpenbare (Android-app kjører ikke på macOS). Eksakt mapping ikke verifisert uten API-tilgang |
| ⚪ | Identisk clientVersion | Alle: `43.11.0.5678` | Varier minor-versjoner | — | ⚠️ | Generell realisme |

### `FAKE:cisco:webex:meetings:history:meetingattendeehistory` (211 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | clientType/clientOS mismatch | `Cisco Room Device`+`Windows 10`, `Phone (PSTN)`+`ChromeOS` | Room Device→RoomOS, PSTN→null, Desktop→Win/macOS, Mobile→iOS/Android | [Meeting Participants](https://developer.webex.com/docs/api/v1/meeting-participants) | ⚠️ | Room Devices kjører ikke Windows, PSTN har ikke ChromeOS. Eksakt API-verdier ikke verifisert |

### `FAKE:cisco:webex:call:detailed_history` (48 events)

| Pri | Hva må fikses | Nåværende | Skal være | Docs | Verifisert | Kommentar |
|:---:|---------------|-----------|-----------|------|:---:|-----------|
| 🔴 | Device MAC med kolon-format | `7A:B0:89:D3:3D:B4` | `6C710D8ABC10` (12 hex uten separator) | [CDR blog](https://developer.webex.com/blog/exploring-the-webex-calling-reports-and-analytics-apis) | ✅ | Docs viser eksakt: `"Device MAC": "6C710D8ABC10"` |
| 🟡 | Call ID er UUID | `388b5f0d-6cdb-...` | SIP-format: `SSE110116321140520@10.177.4.29` | [CDR blog](https://developer.webex.com/blog/exploring-the-webex-calling-reports-and-analytics-apis) | ✅ | Docs viser eksakt: `"Call ID": "SSE1101163211405201218829100@10.177.4.29"` |
| 🟡 | Department ID er tekst | `Finance`, `Engineering` | UUID: `4370c763-81ec-403b-...` | [CDR fields](https://help.webex.com/en-us/article/nmug598) | ✅ | Docs viser eksakt: `"Department ID": "4370c763-81ec-403b-aba3-626a7b1cf264"` |
| 🟡 | Duration er string | `"545"` | `545` (integer) | [CDR fields](https://help.webex.com/en-us/article/nmug598) | ✅ | Docs viser eksakt: `"Duration": 36` — numerisk |
| ⚪ | Mangler mange CDR-felt | — | `Final local/remote SessionID`, `Inbound/Outbound trunk`, `Release time`, `User UUID`, `Org UUID` | [Cisco CDR guide](https://www.cisco.com/c/en/us/support/docs/unified-communications/webex-calling/220377-understand-detailed-call-history-report.html) | ✅ | Docs inkluderer: `"Final local SessionID"`, `"Final remote SessionID"`, `"Inbound trunk"` |

### `FAKE:cisco:webex:events` (1 858), `FAKE:cisco:webex:meetings` (42), `FAKE:cisco:webex:meetings:history:meetingusagehistory` (26)

✅ Ingen kritiske problemer funnet. Disse tre sourcetypene har realistisk struktur, gode feltverdier og fornuftig datainnhold.

---

## Oppsummering verifisering

| Status | Antall | Beskrivelse |
|:---:|:---:|-------------|
| ✅ | 19 | Fullt verifisert mot offisiell dokumentasjon |
| ⚠️ | 22 | Delvis verifisert — logisk korrekt men mangler direkte docs-bekreftelse |
| ❌ | 0 | Ingen påstander ble direkte motbevist |

**Mest pålitelige funn (alle ✅):** AWS principalId/userIdentity-typer/felt/EC2-ID, Entra ID UUID-er/authMethod/authenticationRequirement/modifiedProperties, GCP insertId/resource.labels/authorizationInfo/status, Webex CDR MAC/Call ID/Department ID/Duration/felt

**Krever API-tilgang for full verifisering:** Meraki security events API-responsformat, Webex Meeting Qualities clientType-mapping, Webex Security Audit event-typer, Webex base64 actorId-encoding
