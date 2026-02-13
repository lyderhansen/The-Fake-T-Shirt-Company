# Endringslogg - 3. februar 2026

## 1. Meraki MX Security Events

**Problem:** Meraki MX manglet flere sikkerhetshendelsestyper som `ids_alert`, `content_filtering`, `amp_malware_blocked`, og `client_isolation`.

**Løsning i `generators/generate_meraki.py`:**

- **Oppdatert IDS Alert-format** - Endret fra `eventType: "IDS Alert"` til Dashboard API-konsistent format:
  ```python
  "type": "security_event",
  "subtype": "ids_alert"
  ```

- **Nye security event-funksjoner:**
  - `mx_content_filtering_event()` - Web-innhold blokkert av kategorifiltre
  - `mx_amp_malware_event()` - AMP malware-deteksjon
  - `mx_client_isolation_event()` - Klient isolert pga. sikkerhetspolicy

- **Oppdatert baseline-generering** - `generate_mx_baseline_hour()` inkluderer nå security events (3% av trafikken):
  - 60% content_filtering
  - 25% amp_malware_blocked
  - 15% client_isolation

---

## 2. Meraki MR - Lagt til clientIp

**Problem:** MR (Access Point) hendelser manglet `clientIp` for korrelasjon.

**Løsning i `generators/generate_meraki.py`:**

Lagt til `client_ip` parameter til alle MR-funksjoner:
- `mr_association_event()`
- `mr_disassociation_event()`
- `mr_8021x_success_event()`
- `mr_8021x_failure_event()`
- `mr_wpa_auth_event()`

Oppdatert `generate_mr_baseline_hour()` til å generere og inkludere clientIp.

---

## 3. Weekend Volume for E-commerce

**Problem:** Access logs og ASA hadde for lavt volum på helger. En e-handelsside bør ha HØYERE trafikk på helger.

**Løsning i `shared/config.py`:**

**Nye weekend-faktorer:**
| Source | Før | Etter |
|--------|-----|-------|
| web | 70% | **110%** |
| firewall | 40% | **80%** |

**Nye aktivitetsmønstre:**

`HOUR_ACTIVITY_WEEKEND_ECOMMERCE` - Peak kl 16-18 (100%), ettermiddag høy (85-95%)

`HOUR_ACTIVITY_WEEKEND_FIREWALL` - Mix av e-commerce og enterprise trafikk

**Løsning i `shared/time_utils.py`:**

Oppdatert `get_hour_activity_level()` til å bruke source-spesifikke weekend-mønstre.

**Resultat:**
- Access logs: Helg har ~50% MER trafikk enn ukedager
- ASA: Helg har ~75-80% av ukedagstrafikk

---

## 4. --show-files Flag for Troubleshooting

**Problem:** Vanskelig å se hvilke filer som genereres under kjøring.

**Løsning:**

**`shared/config.py`:**
```python
GENERATOR_OUTPUT_FILES = {
    "asa": ["network/cisco_asa.log"],
    "meraki": ["network/meraki_mx_appliance.json", ...],
    # ... alle generatorer
}
```

**`main_generate.py`:**
- Lagt til `--show-files` CLI argument
- Oppdatert progress display for å vise filstier

**Output eksempel:**
```
# Standard:
[✓] gcp               2,869 events  (0.3s)

# Med --show-files:
[✓] output/cloud/gcp_audit.json                    2,869 events  (0.3s)
[✓] output/network/meraki_mx_appliance.json (+4)  315,895 events  (3.8s)
```

---

## 5. TUI Checkbox-forbedring

**Problem:** `Full Metrics` og `Show File Paths` brukte yes/no tekst i stedet for checkboxer.

**Løsning i `tui_generate.py`:**

- Endret fra `description="no"` til `selected=False` for checkbox-items
- Oppdatert rendering til å vise `[x]`/`[ ]` for disse feltene
- Oppdatert toggle-logikk til å bruke `selected` attributt

**TUI CONFIGURATION-seksjon nå:**
```
  Start Date: 2026-01-01
  Days: 14
  Scale: 1.0
  Perfmon Clients: 5
[ ] Full Metrics
[ ] Show File Paths
```

---

## 6. Synkronisering til TA-FAKE-TSHRT

**Alle endrede filer kopiert fra `python_generators/` til `TA-FAKE-TSHRT/bin/`:**

| Kategori | Filer |
|----------|-------|
| **Shared** | `config.py`, `time_utils.py` |
| **Main** | `main_generate.py`, `tui_generate.py` |
| **Generators** | `generate_meraki.py`, `generate_access.py`, `generate_linux.py`, `generate_aws.py`, `generate_entraid.py`, `generate_webex_ta.py` |
| **Scenarios** | `exfil.py`, `disk_filling.py`, `memory_leak.py`, `certificate_expiry.py` |

---

## Filer som ble endret

| Fil | Endringer |
|-----|-----------|
| `shared/config.py` | GENERATOR_OUTPUT_FILES, weekend faktorer, e-commerce/firewall aktivitetsmønstre |
| `shared/time_utils.py` | Source-spesifikke weekend-mønstre i `get_hour_activity_level()` |
| `generators/generate_meraki.py` | Security events (IDS, content filtering, AMP, client isolation), clientIp i MR |
| `main_generate.py` | `--show-files` flag, oppdatert progress display, eksempel i help |
| `tui_generate.py` | Checkbox for Full Metrics og Show File Paths |

---

## Viktig å huske

**Alle endringer må gjøres i BEGGE mapper:**
1. `python_generators/` - Utviklingsmappe
2. `TA-FAKE-TSHRT/bin/` - Splunk App-mappe
