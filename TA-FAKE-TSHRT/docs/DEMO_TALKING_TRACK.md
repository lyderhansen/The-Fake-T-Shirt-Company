# Demo Talking Track - The FAKE T-Shirt Company

En dag-for-dag guide for å demonstrere sikkerhetshendelser og driftsproblemer i Splunk.

---

## Innhold

1. [Scenario-oversikt](#scenario-oversikt)
2. [Exfil - APT Data Exfiltration](#exfil---apt-data-exfiltration)
3. [Ransomware Attempt](#ransomware-attempt)
4. [Memory Leak](#memory-leak)
5. [CPU Runaway](#cpu-runaway)
6. [Disk Filling](#disk-filling)
7. [Firewall Misconfiguration](#firewall-misconfiguration)
8. [Certificate Expiry](#certificate-expiry)
9. [Splunk Queries](#splunk-queries)

---

## Scenario-oversikt

| Scenario | Kategori | Varighet | Kritisk tidspunkt | Viktigste logger |
|----------|----------|----------|-------------------|------------------|
| **Exfil** | Attack | 14 dager | Dag 11-13 nattestid | ASA, AWS, GCP, Exchange, WinEventLog |
| **Ransomware** | Attack | 1 dag | Dag 8, 14:00-14:15 | WinEventLog, Meraki, ASA, Exchange |
| **Memory Leak** | Ops | 10 dager | Dag 10, 14:00 (OOM) | Linux vmstat, ASA timeouts |
| **CPU Runaway** | Ops | 2 dager | Dag 12, 10:30 (fix) | Perfmon, WinEventLog |
| **Disk Filling** | Ops | 14 dager | Dag 13-14 (97%+) | Linux df |
| **Firewall Misconfig** | Network | 2 timer | Dag 7, 10:15-12:05 | ASA |
| **Certificate Expiry** | Network | 7 timer | Dag 12, 00:00-07:00 | ASA, Access logs |

### Scenario-filter i Splunk

Alle scenarioer er tagget med `demo_id` felt:

```spl
index=* demo_id=exfil | stats count by sourcetype
index=* demo_id=ransomware_attempt | stats count by sourcetype
index=* demo_id=memory_leak | stats count by sourcetype
```

---

# Exfil - APT Data Exfiltration

## Sammendrag

En 14-dagers APT-stil angrep hvor en trussel-aktør fra Tyskland:
1. Sender phishing til IT-admin i Atlanta
2. Beveger seg lateralt fra Atlanta → Boston
3. Stjeler credentials til finansanalytiker
4. Eksfiltrerer sensitiv data til sky-lagring

## Nøkkelpersoner

| Person | Rolle | Lokasjon | IP-adresse | Hostname |
|--------|-------|----------|------------|----------|
| **Jessica Brown** | IT Administrator | Atlanta | 10.20.30.15 | ATL-WS-JBROWN01 |
| **Alex Miller** | Sr. Financial Analyst | Boston | 10.10.30.55 | BOS-WS-AMILLER01 |
| **Threat Actor** | Angriper | Frankfurt, DE | 185.220.101.42 | - |

## Phishing-detaljer

- **Fake domene:** `rnicrosoft-security.com` (merk: "rn" ser ut som "m")
- **Avsender:** `security@rnicrosoft-security.com`
- **Emne:** "Action Required: Verify your account security"
- **Mottaker:** jessica.brown@theFakeTshirtCompany.com

---

## Dag-for-dag Timeline

### Dag 1-3: Rekognosering

**Hva skjer:**
- Trussel-aktør scanner nettverket fra ekstern IP
- Port scanning mot 22, 80, 443, 445, 1433, 3389
- Phishing-epost sendes til Jessica Brown (dag 1)

**Tid:** 20:00-23:00 (hovedsakelig kveldstid)

**Logger å se etter:**
| Logger | Event | Søk |
|--------|-------|-----|
| ASA | Port scans blokkert | `%ASA-4-106023 src=185.220.101.42` |
| ASA | Threat detection | `%ASA-4-733100` eller `%ASA-4-733101` |
| Exchange | Phishing sendt | `sender=*rnicrosoft-security.com` |

**Talking point:**
> "Her ser vi tidlige indikatorer på rekognosering. En ekstern IP (185.220.101.42) fra Tyskland scanner våre perimeter-porter. Samtidig ser vi en phishing-epost sendt til vår IT-admin Jessica Brown. Dette er klassisk APT-oppførsel - tålmodig forberedelse før selve angrepet."

---

### Dag 4: Initiell Kompromittering

**Hva skjer:**
- Jessica Brown klikker på phishing-lenken
- Credentials blir høstet
- Angriperen får tilgang til Jessica's e-post

**Tid:** 14:00-15:00 (midt på arbeidsdagen)

**Logger å se etter:**
| Logger | Event | Søk |
|--------|-------|-----|
| ASA | Inbound connection | `%ASA-6-302013 src=185.220.101.42` |
| Exchange | Safe Links klikk | `SafeLinksPolicy jessica.brown` |
| Entra ID | Mistenkelig pålogging | `user=jessica.brown location=Germany` |

**Talking point:**
> "Dag 4 er vendepunktet. Jessica klikker på lenken og credentials blir stjålet. Vi ser en inbound forbindelse fra threat actor IP, og mistenkelig pålogging fra Tyskland til hennes konto. Fra dette øyeblikket har angriperen fotfeste i nettverket."

---

### Dag 5-7: Lateral Bevegelse

**Hva skjer:**
- Angriper beveger seg fra Atlanta til Boston via SD-WAN
- SMB, RDP og SSH-forsøk mot servere
- Flere "access denied" events
- Forwarding-regel opprettes på Jessica's mailbox

**Tid:** 10:00-17:00 (arbeidstid)

**Hosts involvert:**
- Atlanta DC: 10.20.20.10
- Boston file server: 10.10.20.20
- Boston SQL: 10.10.20.30

**Logger å se etter:**
| Logger | Event | Søk |
|--------|-------|-----|
| ASA | Cross-site probing | `acl=cross_site_policy deny` |
| ASA | Internal ACL denies | `acl=server_segment_acl deny` |
| WinEventLog | Failed logon | `EventID=4625 src=10.20.30.15` |
| Exchange | Forwarding rule | `InboxRule jessica.brown forward` |

**Talking point:**
> "Nå ser vi lateral bevegelse. Angriperen bruker Jessica's credentials til å prøve tilgang på Boston-servere via vår SD-WAN tunnel. Vi ser multiple 'access denied' fra vår ACL. Samtidig opprettes en forwarding-regel som sender kopier av Jessica's e-post til en ekstern ProtonMail-konto."

---

### Dag 8-10: Privilege Escalation & Persistence

**Hva skjer:**
- Angriperen oppretter backdoor IAM-bruker i AWS
- GCP service account key genereres
- Alex Miller's credentials kompromitteres
- Data-staging på WEB-01

**Kritiske events:**
| Dag | Tid | Event |
|-----|-----|-------|
| 5 | 10:45 | AWS: CreateUser `svc-datasync` |
| 5 | 10:46 | AWS: AttachUserPolicy AdministratorAccess |
| 5 | 11:00 | GCP: CreateServiceAccountKey |

**Logger å se etter:**
| Logger | Event | Søk |
|--------|-------|-----|
| AWS CloudTrail | IAM user opprettet | `eventName=CreateUser userIdentity.userName=alex.miller` |
| AWS CloudTrail | Admin policy | `eventName=AttachUserPolicy` |
| GCP Audit | Service account | `methodName=CreateServiceAccountKey` |
| Linux vmstat | WEB-01 anomali | `host=WEB-01 cpu_pct>60` |

**Talking point:**
> "Dette er persistence-fasen. Angriperen oppretter en backdoor IAM-bruker 'svc-datasync' med full administrator-tilgang. Samtidig ser vi at Alex Miller's credentials nå brukes - han er vår senior finansanalytiker med tilgang til sensitiv data. WEB-01 viser uvanlig høy CPU-aktivitet som indikerer data-staging."

---

### Dag 11-13: Eksfiltrering

**Hva skjer:**
- Data eksfiltreres fra S3 og GCS buckets
- Store overføringer på natten for å unngå deteksjon
- 500MB-2.5GB per session

**Tid:** 01:00-05:00 (nattestid - lavt aktivitetsnivå)

**Sensitive filer som eksfiltreres:**
- `annual-financial-report.xlsx`
- `merger-plans-2025.docx`
- `employee-salaries.csv`
- `customer-database.csv`
- `q4-projections.xlsx`

**Logger å se etter:**
| Logger | Event | Søk |
|--------|-------|-----|
| AWS CloudTrail | S3 GetObject | `eventName=GetObject bucket=faketshirtco-financial-reports demo_id=exfil` |
| GCP Audit | Storage access | `methodName=storage.objects.get` |
| ASA | Store utgående overføringer | `bytes>500000000 demo_id=exfil` |
| Linux | Høy nettverkstrafikk | `host=WEB-01 network_bytes` |

**Talking point:**
> "Her skjer selve datatyveriet. Mellom 01:00 og 05:00 ser vi store data-overføringer. Angriperen har lært vårt trafikkmønster og vet at dette er lavaktivitetsperioden. Vi ser GetObject-kall mot vår finansielle S3-bucket med filer som 'merger-plans-2025.docx' og 'employee-salaries.csv'. Total eksfiltrert data: flere gigabyte over 3 netter."

---

## Exfil - Oppsummeringstabell

| Dag | Fase | Nøkkelevent | Viktigste logger |
|-----|------|-------------|------------------|
| 1-3 | Recon | Port scanning, phishing sendt | ASA deny, Exchange |
| 4 | Access | Jessica klikker lenke | ASA inbound, Entra ID |
| 5-7 | Lateral | ATL→BOS bevegelse | ASA ACL, WinEventLog 4625 |
| 8-10 | Persist | AWS/GCP backdoors | CloudTrail, GCP Audit |
| 11-13 | Exfil | Data theft 01:00-05:00 | S3/GCS access, ASA bytes |

---

# Ransomware Attempt

## Sammendrag

En ransomware-angrep som blir **oppdaget og stoppet**. Bruker Brooklyn White i Austin mottar phishing-epost med ondsinnet Word-makro. Meraki IDS oppdager lateral bevegelse og isolerer endepunktet automatisk.

**Utfall:** Angrepet feiler - EDR og IDS stopper det før kryptering.

## Nøkkelpersoner

| Person | Rolle | Lokasjon | IP-adresse | Hostname |
|--------|-------|----------|------------|----------|
| **Brooklyn White** | Sales Engineer | Austin | 10.30.30.20 | AUS-WS-BWHITE01 |
| **C2 Server** | Attacker infrastructure | Russia | 194.26.29.42 | - |

---

## Timeline - Dag 8

| Tid | Event | Beskrivelse |
|-----|-------|-------------|
| **13:55** | Email mottatt | "Outstanding Invoice - Immediate Action Required" med `Invoice_Q4_2026.docm` |
| **14:02** | Makro kjører | Brooklyn åpner vedlegget, Word-makro aktiveres |
| **14:03** | Dropper lansert | `svchost_update.exe` kjører fra Temp-mappe |
| **14:05** | C2 callback | HTTPS til 194.26.29.42:443 (Russland) |
| **14:08** | Lateral forsøk | SMB scanning av Austin subnet (10.30.30.21-40) |
| **14:12** | EDR deteksjon | Windows Defender oppdager `Trojan:Win32/Emotet.RPK!MTB` |
| **14:15** | Isolasjon | Meraki MX isolerer klient, AP disconnects |

---

## Logger å se etter

### Exchange - Phishing email
```spl
index=cloud sourcetype="ms:o365:*"
  sender="*invoices-delivery.com"
  recipient="brooklyn.white*"
  demo_id=ransomware_attempt
```

### Windows Event Log - Kill chain
```spl
index=windows sourcetype=XmlWinEventLog
  (EventID=4688 OR EventID=4697 OR EventID=1116)
  Computer="AUS-WS-BWHITE01"
  demo_id=ransomware_attempt
| sort _time
```

**Events i sekvens:**
- **4688** - WINWORD.EXE åpner Invoice_Q4_2026.docm
- **4688** - svchost_update.exe spawned fra WINWORD
- **4697** - Service "Windows Update Helper" installert
- **4625** - Flere failed logons til andre Austin-maskiner
- **1116** - Defender quarantine

### ASA - C2 kommunikasjon
```spl
index=network sourcetype=cisco:asa
  dest_ip=194.26.29.42
  demo_id=ransomware_attempt
```

### Meraki - IDS og isolasjon
```spl
index=network sourcetype=meraki:*
  (type=ids_alert OR type=client_isolated)
  demo_id=ransomware_attempt
```

---

## Talking Points

**Åpning:**
> "Dette scenarioet viser hvordan moderne forsvar kan stoppe et ransomware-angrep midt i angrepskjeden. Brooklyn White i Austin mottar en overbevisende faktura-epost."

**Deteksjon:**
> "Legg merke til timingen: bare 10 minutter fra makro-kjøring til full isolasjon. Windows Defender oppdager trojaneren, og samtidig ser Meraki IDS lateral SMB-scanning. Systemene korrelerer automatisk og isolerer endepunktet."

**Verdi:**
> "Uten denne integrasjonen ville angriperen hatt timer til å bevege seg lateralt og starte kryptering. I stedet har vi full forensics-data og en isolert maskin klar for reimaging."

---

# Memory Leak

## Sammendrag

En gradvis minnelekkasje på WEB-01 over 10 dager som kulminerer i OOM-krasj. Scenarioet viser hvordan operasjonelle problemer eskalerer og korrelerer på tvers av logger.

## Target

- **Server:** WEB-01
- **IP:** 172.16.1.10
- **Lokasjon:** Boston DMZ
- **RAM:** 64GB

---

## Progresjon

| Dager | Memory % | Swap | Symptomer |
|-------|----------|------|-----------|
| 1-3 | 50-60% | 0 | Normal drift |
| 4-5 | 60-75% | 0 | Ingen merkbar endring |
| 6-7 | 75-85% | 2-4 GB | Responstid øker |
| 8-9 | 85-95% | 8-16 GB | Tydelig tregt, swapping |
| **10 @14:00** | 98% → OOM | 25-30 GB | **KRASJ** → Restart |
| 11-14 | 50-60% | 0 | Normal etter restart |

---

## Kritisk tidspunkt: Dag 10, 14:00

**Hva skjer:**
1. Memory når 98%
2. Swap på 25-30 GB
3. OOM killer aktiveres
4. Server krasjer
5. Automatisk restart
6. Memory tilbake til ~50%

---

## Logger å se etter

### Linux vmstat - Memory trend
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| timechart avg(memory_pct) AS memory, avg(swap_used_kb) AS swap by host
```

### ASA - Connection timeouts
```spl
index=network sourcetype=cisco:asa
  dest_ip=172.16.1.10
  ("TCP FINs" OR "TCP Reset" OR "SYN Timeout")
  demo_id=memory_leak
| timechart count by reason
```

**Timeout-møster:**
- Dag 6-7: ~50 timeouts/dag
- Dag 8-9: ~150 timeouts/dag
- Dag 10: ~300 timeouts (peak før krasj)

---

## Talking Points

**Trend-analyse:**
> "Se på denne grafen. Memory øker gradvis over 10 dager - fra 55% til 98%. Dette er klassisk minnelekkasje. Swap-bruk begynner dag 6 og akselererer. Dag 10 klokken 14:00 krasjer serveren."

**Korrelasjon:**
> "Samtidig ser vi ASA-timeout events korrelert med memory-økningen. Kundene opplever treghet fordi serveren bruker mer tid på swapping enn på å håndtere requests."

**RCA:**
> "Root cause: minnelekkasje i web-applikasjonen. Etter restart er problemet midlertidig løst, men en permanent fix krever kode-endring."

---

# CPU Runaway

## Sammendrag

SQL backup-jobb på SQL-PROD-01 henger og forårsaker 100% CPU over 32 timer. DBA fikser problemet dag 12 klokken 10:30.

## Target

- **Server:** SQL-PROD-01
- **IP:** 10.10.20.30
- **Lokasjon:** Boston
- **Rolle:** Production SQL Database

---

## Timeline

### Dag 11 (Start)
| Tid | CPU % | Event |
|-----|-------|-------|
| 02:00 | 40% | Backup job starter |
| 08:00 | 65% | Brukere merker treghet |
| 14:00 | 78% | Applikasjon-timeouts starter |
| 20:00 | 88% | Disk queue bygger seg opp |

### Dag 12 (Kritisk + Fix)
| Tid | CPU % | Event |
|-----|-------|-------|
| 02:00 | 94% | Nesten full kapasitet |
| 08:00 | 100% | Full CPU-metning |
| **10:30** | **30%** | **DBA dreper job, restarter SQL** |
| 14:00 | 22% | Normalisering |
| 18:00 | 15% | Normal drift |

---

## Logger å se etter

### Perfmon - CPU trend
```spl
index=windows sourcetype=perfmon
  host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| timechart avg(Value) AS cpu
```

### Windows Event Log - SQL errors
```spl
index=windows sourcetype=XmlWinEventLog
  host=SQL-PROD-01
  (EventID=17883 OR EventID=833 OR EventID=19406)
  demo_id=cpu_runaway
```

**Events:**
- **17883** - "process appears to be non-yielding on CPU"
- **833** - "I/O requests taking longer than 15 seconds"
- **19406** - "backup job is not responding"

### Windows Event Log - Fix
```spl
index=windows sourcetype=XmlWinEventLog
  host=SQL-PROD-01
  (EventID=17148 OR EventID=17147)
  demo_id=cpu_runaway
```

**Events:**
- **17148** - "KILL command issued for SPID 67"
- **17147** - "SQL Server service restarted successfully"

---

## Talking Points

**Problemet:**
> "Se på denne CPU-grafen. Dag 11 klokken 02:00 starter backup-jobben. CPU klatrer jevnt fra 40% til 100% over 32 timer. Brukere begynner å klage rundt 65% - 'systemet er tregt'."

**Impact:**
> "Ved 100% CPU ser vi kaskadering: database connections timer ut, web-serveren returnerer 502-errors, og brukere kan ikke fullføre bestillinger."

**Løsningen:**
> "Dag 12 klokken 10:30 identifiserer DBA problemet. En KILL-kommando dreper den hengende prosessen, og SQL Server restartes. CPU dropper umiddelbart til 30% og normaliserer til 15% etter noen timer."

---

# Disk Filling

## Sammendrag

Monitoring-server i Atlanta fyller gradvis opp disken over 14 dager. Illustrerer "slow burn" operasjonelle problemer som ofte overses.

## Target

- **Server:** MON-ATL-01
- **IP:** 10.20.20.30
- **Lokasjon:** Atlanta
- **Disk:** 500 GB

---

## Progresjon

| Dag | Disk % | Status | GB ledig |
|-----|--------|--------|----------|
| 1 | 45-50% | Normal | 250-275 |
| 4 | 55-60% | Normal | 200-225 |
| 7 | 70-75% | Noticeable | 125-150 |
| 8 | 75-80% | **WARNING** | 100-125 |
| 10 | 82-88% | **HIGH** | 60-90 |
| 11 | 88-92% | **CRITICAL** | 40-60 |
| 13 | 95-97% | **EMERGENCY** | 15-25 |
| 14 | 97-98% | **EMERGENCY** | 10-15 |

---

## Logger å se etter

### Linux df - Disk trend
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| timechart avg(pct_used) AS disk_pct
```

### Linux - IO Wait correlation
```spl
index=linux sourcetype=vmstat host=MON-ATL-01 demo_id=disk_filling
| timechart avg(io_wait) AS io_wait, avg(disk_pct) AS disk
```

---

## Talking Points

**Trend:**
> "Dette viser en 14-dagers trend. Disk starter på 45% og klatrer jevnt til 98%. Dag 8 krysser vi 75% - warning threshold. Dag 11 er vi kritiske på 90%. Dag 13-14 er vi i emergency-sonen."

**Root cause:**
> "Årsaken er eksessiv logging fra monitoring-agenter uten log rotation policy. Et enkelt konfigurasjonsproblem som vokser til kritisk over tid."

**Korrelasjon:**
> "Legg merke til IO wait-økningen som korrelerer med disk-fyllingen. Når disken blir full, må systemet jobbe hardere for å finne ledig plass, noe som påvirker all I/O."

---

# Firewall Misconfiguration

## Sammendrag

Nettverksadmin prøver å blokkere threat-trafikk men gjør en ACL-feil og blokkerer all trafikk TIL webserveren i stedet for FRA threat actor.

**Varighet:** 1 time 45 minutter (10:15-12:05)

---

## Timeline - Dag 7

| Tid | Event | Beskrivelse |
|-----|-------|-------------|
| **10:15** | Admin login | SSH fra 10.10.10.50 |
| **10:16** | Configure mode | `configure terminal` |
| **10:18** | Feil ACL | `deny tcp any host 203.0.113.10 eq https` |
| **10:20** | Blokkering starter | Kundetrafikk blokkeres |
| **11:00** | Peak impact | ~60 deny events per time |
| **12:00** | Problem identifisert | NOC ser at web er nede |
| **12:03** | Rollback | ACL fjernet |
| **12:05** | Normal | Trafikk gjenopprettet |

---

## Logger å se etter

### ASA - Admin aktivitet
```spl
index=network sourcetype=cisco:asa
  (%ASA-5-111008 OR %ASA-5-111010 OR %ASA-6-605005)
  demo_id=firewall_misconfig
| sort _time
```

### ASA - Blokkert trafikk
```spl
index=network sourcetype=cisco:asa
  %ASA-4-106023
  dest_ip=203.0.113.10
  demo_id=firewall_misconfig
| timechart count
```

---

## Talking Points

**Hendelsen:**
> "Dag 7 klokken 10:18 gjør en admin en ACL-endring. Intensjonen var å blokkere trafikk fra threat actor, men syntaksen blokkerer trafikk TIL webserveren i stedet. Umiddelbart stopper all HTTPS-trafikk til vår nettbutikk."

**Deteksjon:**
> "Vi ser en massiv spike i deny-events mot 203.0.113.10 port 443. NOC oppdager problemet rundt 12:00 når alertene tikker inn og kunder klager."

**Læring:**
> "Rollback skjer 12:03. Total nedetid: 1 time 45 minutter. Dette understreker viktigheten av change management og pre-production testing av ACL-endringer."

---

# Certificate Expiry

## Sammendrag

Wildcard SSL-sertifikat utløper ved midnatt dag 12. Alle HTTPS-forbindelser feiler i 7 timer til NOC oppdager og fornyer sertifikatet.

**Varighet:** 7 timer (00:00-07:00)

## Sertifikat-detaljer

- **CN:** `*.theFakeTshirtCompany.com`
- **Issuer:** DigiCert SHA2 Extended Validation Server CA
- **Utløp:** Dag 12, 00:00 UTC

---

## Timeline - Dag 12

| Tid | Event | Beskrivelse |
|-----|-------|-------------|
| **00:00** | Cert expires | SSL handshakes feiler |
| **00:00-06:00** | Natttrafikk | 5-15 SSL-feil per time |
| **06:00-07:00** | Morgentrafikk | 20-40 SSL-feil per time |
| **06:15** | NOC alert | Monitoring oppdager problemet |
| **06:30** | RCA | Sertifikat-utløp identifisert |
| **06:45** | Fornying | Emergency cert renewal startet |
| **07:00** | Fix | Nytt sertifikat installert |

---

## Logger å se etter

### ASA - SSL failures
```spl
index=network sourcetype=cisco:asa
  (%ASA-6-725007 OR %ASA-4-725006)
  "certificate expired"
  demo_id=certificate_expiry
| timechart count
```

### Access log - HTTP errors
```spl
index=web sourcetype=access_combined
  (status=502 OR status=503)
  demo_id=certificate_expiry
| timechart count
```

---

## Talking Points

**Hendelsen:**
> "Midnatt dag 12 utløper vårt wildcard SSL-sertifikat. Fra dette øyeblikket feiler alle HTTPS-forbindelser. Kundene ser 'certificate expired' feil i nettleseren."

**Impact:**
> "Fordi det skjer på natten, er trafikkvolumet lavt og alertene drukner. Først når morgentrafikken øker rundt 06:00 eskalerer volumet nok til at NOC reagerer."

**Læring:**
> "Denne hendelsen understreker behovet for proaktiv sertifikat-monitoring med 30/14/7-dagers varsel før utløp."

---

# Splunk Queries

## Generelle scenario-queries

### Oversikt over alle scenarioer
```spl
index=* demo_id=*
| stats count by demo_id, sourcetype
| sort - count
```

### Timeline for ett scenario
```spl
index=* demo_id=exfil
| timechart count by sourcetype
```

### Finn nøkkelhendelser
```spl
index=* demo_id=exfil
  (src_ip=185.220.101.42 OR user=jessica.brown OR user=alex.miller)
| sort _time
| table _time, sourcetype, src_ip, dest_ip, user, action, message
```

---

## Exfil-spesifikke queries

### Threat actor aktivitet
```spl
index=network sourcetype=cisco:asa src=185.220.101.42 demo_id=exfil
| stats count by action, dest_port
```

### Cloud data access
```spl
index=cloud (sourcetype=aws:cloudtrail OR sourcetype=google:gcp:*)
  (eventName=GetObject OR methodName=*get*)
  demo_id=exfil
| stats count by eventName, bucketName
```

### Lateral movement
```spl
index=* demo_id=exfil
  (src_ip=10.20.30.15 OR src_ip=10.10.30.55)
  (dest_ip=10.10.20.* OR dest_ip=10.20.20.*)
| stats count by src_ip, dest_ip, dest_port
```

---

## Ops-scenario queries

### Memory leak progression
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| eval memory_gb = memory_used_kb / 1048576
| eval swap_gb = swap_used_kb / 1048576
| timechart span=1h avg(memory_gb) AS "Memory (GB)", avg(swap_gb) AS "Swap (GB)"
```

### CPU runaway
```spl
index=windows sourcetype=perfmon host=SQL-PROD-01
  counter="% Processor Time" demo_id=cpu_runaway
| timechart span=1h avg(Value) AS "CPU %"
```

### Disk filling
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| timechart span=1h avg(pct_used) AS "Disk %"
```

---

## Security dashboard query

### Attack timeline
```spl
index=* (demo_id=exfil OR demo_id=ransomware_attempt)
| eval severity=case(
    like(message, "%deny%") OR like(action, "%block%"), "blocked",
    like(message, "%built%") OR like(action, "%allow%"), "allowed",
    true(), "info"
)
| timechart count by severity
```

### Compromised users
```spl
index=* demo_id=exfil
  (user=jessica.brown OR user=alex.miller)
| stats count, earliest(_time) AS first_seen, latest(_time) AS last_seen by user, sourcetype
```

---

## Quick Reference

| Scenario | Primary Query |
|----------|--------------|
| Exfil | `demo_id=exfil src=185.220.101.42` |
| Ransomware | `demo_id=ransomware_attempt host=AUS-WS-BWHITE01` |
| Memory Leak | `demo_id=memory_leak host=WEB-01` |
| CPU Runaway | `demo_id=cpu_runaway host=SQL-PROD-01` |
| Disk Filling | `demo_id=disk_filling host=MON-ATL-01` |
| Firewall | `demo_id=firewall_misconfig dest_ip=203.0.113.10` |
| Certificate | `demo_id=certificate_expiry "certificate expired"` |

---

*Generert for The FAKE T-Shirt Company Splunk Demo Environment*
