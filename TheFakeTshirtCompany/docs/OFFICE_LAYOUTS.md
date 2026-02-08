# The FAKE T-Shirt Company - Office Layouts

Detaljerte plantegninger for alle kontorlokasjoner med plassering av:
- Nettverksutstyr (MX, MS, MR, MV, MT)
- Webex-enheter
- Møterom med kapasitet
- Nøkkelpersonell

---

## Lokasjonsoversikt

| Lokasjon | Kode | Adresse | Etasjer | Ansatte | Type |
|----------|------|---------|---------|---------|------|
| Boston, MA | BOS | 125 One Financial Center | 3 | ~93 | Hovedkontor |
| Atlanta, GA | ATL | 400 Peachtree Center | 2 | ~43 | IT/Regional Hub |
| Austin, TX | AUS | 200 Congress Ave | 1 | ~39 | Salg/Engineering |

---

## IP-adressering

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IP ADDRESSING SCHEME                               │
├──────────┬───────────┬───────────┬───────────┬───────────┬───────────┬──────┤
│ Location │ Management│  Servers  │   Users   │   WiFi    │ IoT/Sensor│Camera│
├──────────┼───────────┼───────────┼───────────┼───────────┼───────────┼──────┤
│ BOSTON   │ 10.10.10.x│ 10.10.20.x│ 10.10.30.x│ 10.10.40.x│ 10.10.60.x│.70.x │
│ ATLANTA  │ 10.20.10.x│ 10.20.20.x│ 10.20.30.x│ 10.20.40.x│ 10.20.60.x│.70.x │
│ AUSTIN   │ 10.30.10.x│     -     │ 10.30.30.x│ 10.30.40.x│ 10.30.60.x│.70.x │
└──────────┴───────────┴───────────┴───────────┴───────────┴───────────┴──────┘
```

---

## Nettverksarkitektur

```
                                    ☁️  INTERNET  ☁️
                                          │
                            ┌─────────────┴─────────────┐
                            │                           │
                            ▼                           │
                   ╔═══════════════════╗               │
                   ║   FW-EDGE-01      ║               │
                   ║   Cisco ASA       ║ ◄── Perimeter │
                   ║   5525-X          ║    ALL external
                   ╚═════════╤═════════╝    traffic    │
                             │                         │
                ┌────────────┼─────────────────────────┤
                │            │                         │
                ▼            ▼                         │
           ┌────────┐  ┌──────────┐                    │
           │  DMZ   │  │ Internal │                    │
           │172.16.1│  │          │                    │
           │WEB-01/02│ │          │                    │
           └────────┘  └────┬─────┘                    │
                            │                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
              ┌─────┴─────┐         ┌─────┴─────┐         ┌─────┴─────┐
              │  Comcast  │         │   AT&T    │         │  Verizon  │
              │   AT&T    │         │ Spectrum  │         │           │
              └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
                    │                     │                     │
          ┌─────────┴─────────┐   ┌───────┴───────┐   ┌─────────┴─────────┐
          │   BOSTON HQ       │   │  ATLANTA HUB  │   │   AUSTIN OFFICE   │
          │  ┌───────────┐    │   │ ┌───────────┐ │   │  ┌───────────┐    │
          │  │ MX-BOS-01 │────┼───┼─│ MX-ATL-01 │─┼───┼──│ MX-AUS-01 │    │
          │  │ MX-BOS-02 │    │   │ └───────────┘ │   │  └───────────┘    │
          │  │ (HA Pair) │    │   │    MX250      │   │      MX85         │
          │  │  SD-WAN   │    │   │    SD-WAN     │   │     SD-WAN        │
          │  └───────────┘    │   │               │   │                   │
          │     MX450         │   └───────────────┘   └───────────────────┘
          └───────────────────┘
                    │                     │                     │
                    └─────────────────────┼─────────────────────┘
                                          │
                              ╔═══════════════════════╗
                              ║   AutoVPN Full Mesh   ║
                              ║   Site-to-Site VPN    ║
                              ╚═══════════════════════╝
```

### Firewall-hierarki

| Lag | Enhet | Rolle |
|-----|-------|-------|
| **Perimeter** | FW-EDGE-01 (ASA 5525-X) | All ekstern trafikk, DMZ firewall, IDS/IPS |
| **SD-WAN Hub** | MX-BOS-01/02 (HA) | Boston intern, AutoVPN-konsentrator |
| **SD-WAN Spokes** | MX-ATL-01, MX-AUS-01 | Branch-kontorer, intern segmentering |

**Viktig:** ASA ser ALL ekstern trafikk (exfil, C2, angrep). Meraki MX håndterer intern/SD-WAN routing.

---

# 🏢 BOSTON HQ - 125 One Financial Center

## Utstyrsoversikt

| Type | Antall | Modell | Enhetsnavn |
|------|--------|--------|------------|
| MX Firewall | 2 | MX450 (HA) | MX-BOS-01, MX-BOS-02 |
| MS Core Switch | 2 | MS425-32 | MS-BOS-CORE-01, MS-BOS-CORE-02 |
| MS Access Switch | 3 | MS225-48 | MS-BOS-1F-IDF1, MS-BOS-2F-IDF1, MS-BOS-3F-IDF1 |
| MR Access Point | 16 | MR46 | AP-BOS-1F-01 → AP-BOS-3F-06 |
| MV Kamera | 10 | MV12, MV72 | CAM-BOS-* |
| MT Sensor | 6 | MT10, MT11, MT20 | MT-BOS-* |
| Webex | 10 | Diverse | WEBEX-BOS-* |

---

## 📍 Boston Etasje 1 - Lobby / Drift / Shipping

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                           BOSTON HQ - ETASJE 1                                         ║
║                       Lobby • Drift • Shipping • Besøksrom                             ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║   ┌──────────┐  ┌──────────┐  ┌──────────┐              ┌──────────┐  ┌──────────┐    ║
║   │   🛗     │  │   🛗     │  │   🛗     │              │   🚪     │  │   🚪     │    ║
║   │  HEIS 1  │  │  HEIS 2  │  │  HEIS 3  │              │ TRAPP A  │  │ TRAPP B  │    ║
║   └──────────┘  └──────────┘  └──────────┘              └──────────┘  └──────────┘    ║
║                                                                                        ║
║                              HEIS-LOBBY                                                ║
║                                                                                        ║
╠════════════════╦══════════════════════════════════════════════╦═══════════════════════╣
║                ║                                              ║                       ║
║   RESEPSJON    ║               HOVEDLOBBY                     ║    SIKKERHET          ║
║   ┌──────────┐ ║                                              ║    ┌─────────────┐    ║
║   │ 🖥️ Skjerm │ ║    ┌─────────────────────────────────┐      ║    │ 📹 KAMERA   │    ║
║   │ Velkommen │ ║    │                                 │      ║    │CAM-BOS-1F-01│    ║
║   │          │ ║    │     🪑    🪑    🪑    🪑        │      ║    ├─────────────┤    ║
║   │📶AP-BOS- │ ║    │    Sittegruppe / Venteområde    │      ║    │ 🪪 Badge    │    ║
║   │  1F-01   │ ║    │                                 │      ║    │   Reader    │    ║
║   └──────────┘ ║    │     🪑    🪑    🪑    🪑        │      ║    │             │    ║
║                ║    │                                 │      ║    │ Vaktrom     │    ║
║                ║    │        📶 AP-BOS-1F-02          │      ║    └─────────────┘    ║
║                ║    └─────────────────────────────────┘      ║                       ║
║                ║                                              ║                       ║
╠════════════════╬══════════════════════════════════════════════╬═══════════════════════╣
║                ║                                              ║                       ║
║  BESØKSROM     ║                                              ║     PAUSEROM          ║
║  "Harbor"      ║         DRIFTSSENTER                         ║                       ║
║  ┌──────────┐  ║  ┌────────────────────────────────────┐     ║  ┌─────────────────┐  ║
║  │ Kap: 6   │  ║  │                                    │     ║  │    ☕ KJØKKEN   │  ║
║  │          │  ║  │  🖥️  🖥️  🖥️  🖥️  🖥️   Dashboard   │     ║  │                 │  ║
║  │  🖥️      │  ║  │  Operatørplasser (5 ansatte)      │     ║  │  Kaffemaskin    │  ║
║  │ WEBEX-   │  ║  │                                    │     ║  │  Kjøleskap      │  ║
║  │ BOS-     │  ║  │       📶 AP-BOS-1F-03              │     ║  │  Mikrobølgeovn  │  ║
║  │ HARBOR   │  ║  │                                    │     ║  │                 │  ║
║  │ Desk Pro │  ║  │  Store skjermer med statusvisning  │     ║  │ 📶AP-BOS-1F-05 │  ║
║  └──────────┘  ║  └────────────────────────────────────┘     ║  │                 │  ║
║                ║                                              ║  └─────────────────┘  ║
╠════════════════╬══════════════════════════════════════════════╬═══════════════════════╣
║                ║                                              ║                       ║
║  BESØKSROM     ║       SHIPPING / MOTTAK                      ║   SERVERROM           ║
║  "Beacon"      ║                                              ║   [IDF-BOS-1F]        ║
║  ┌──────────┐  ║  ┌────────────────────────────────────┐     ║  ┌─────────────────┐  ║
║  │ Kap: 4   │  ║  │                                    │     ║  │                 │  ║
║  │          │  ║  │  📦 Pakkestasjon  📦 Pakkestasjon  │     ║  │ ┌─────────────┐ │  ║
║  │  🖥️      │  ║  │                                    │     ║  │ │ MS-BOS-1F-  │ │  ║
║  │ WEBEX-   │  ║  │  📦 Pakkebord    📦 Pakkebord     │     ║  │ │   IDF1      │ │  ║
║  │ BOS-     │  ║  │                                    │     ║  │ │ (48 porter) │ │  ║
║  │ BEACON   │  ║  │       📶 AP-BOS-1F-04              │     ║  │ └─────────────┘ │  ║
║  │ Room Kit │  ║  │                                    │     ║  │                 │  ║
║  │ Mini     │  ║  │  🗄️ Lagerhyller med inventar       │     ║  │ 📹CAM-BOS-1F-03│  ║
║  └──────────┘  ║  │                                    │     ║  │ 🌡️MT-BOS-1F-  │  ║
║                ║  └────────────────────────────────────┘     ║  │   TEMP-01      │  ║
║                ║                                              ║  │ 🚪MT-BOS-1F-  │  ║
║                ║                                              ║  │   DOOR-01      │  ║
║                ║                                              ║  └─────────────────┘  ║
╠════════════════╩══════════════════════════════════════════════╩═══════════════════════╣
║                                                                                        ║
║                           LASTERAMPE / PARKERING                                       ║
║                                                                                        ║
║             📹 CAM-BOS-EXT-01                    📹 CAM-BOS-EXT-02                     ║
║                  (Vest)                              (Øst)                             ║
║                                                                                        ║
╚════════════════════════════════════════════════════════════════════════════════════════╝

ETASJE 1 - UTSTYRSLISTE:
────────────────────────────────────────────────────────────────────────────────────────
 📶 Access Points │ AP-BOS-1F-01 (Resepsjon), AP-BOS-1F-02 (Lobby),
                  │ AP-BOS-1F-03 (Drift), AP-BOS-1F-04 (Shipping), AP-BOS-1F-05 (Pause)
────────────────────────────────────────────────────────────────────────────────────────
 📹 Kameraer      │ CAM-BOS-1F-01 (Sikkerhet), CAM-BOS-1F-03 (Serverrom),
                  │ CAM-BOS-EXT-01, CAM-BOS-EXT-02 (Parkering)
────────────────────────────────────────────────────────────────────────────────────────
 🌡️ Sensorer      │ MT-BOS-1F-TEMP-01, MT-BOS-1F-DOOR-01 (Serverrom)
────────────────────────────────────────────────────────────────────────────────────────
 🔌 Switcher      │ MS-BOS-1F-IDF1 (48 porter)
────────────────────────────────────────────────────────────────────────────────────────
 🖥️ Webex         │ WEBEX-BOS-HARBOR (Desk Pro), WEBEX-BOS-BEACON (Room Kit Mini)
────────────────────────────────────────────────────────────────────────────────────────
```

---

## 📍 Boston Etasje 2 - Finans / Marketing / HR

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                           BOSTON HQ - ETASJE 2                                         ║
║                         Finans • Marketing • HR                                        ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║   ┌──────────┐  ┌──────────┐  ┌──────────┐              ┌──────────┐  ┌──────────┐    ║
║   │   🛗     │  │   🛗     │  │   🛗     │              │   🚪     │  │   🚪     │    ║
║   │  HEIS 1  │  │  HEIS 2  │  │  HEIS 3  │              │ TRAPP A  │  │ TRAPP B  │    ║
║   └──────────┘  └──────────┘  └──────────┘              └──────────┘  └──────────┘    ║
║                                                                                        ║
║                              HEIS-LOBBY                                                ║
║                                                                                        ║
╠═══════════════════╦═══════════════════════════════════════════════╦════════════════════╣
║                   ║                                               ║                    ║
║  FINANSDIREKTØR   ║           ÅPENT KONTORLANDSKAP                ║    MØTEROM         ║
║  (Privat kontor)  ║              FINANS                           ║    "Faneuil"       ║
║  ┌─────────────┐  ║        (Finansteam - 20 ansatte)              ║    ┌────────────┐  ║
║  │             │  ║  ┌─────────────────────────────────────┐      ║    │ Kap: 12    │  ║
║  │ Robert      │  ║  │ 🖥️🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️🖥️ │      ║    │            │  ║
║  │ Wilson      │  ║  │                │                   │      ║    │  ┌──────┐  │  ║
║  │             │  ║  │ 🖥️🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️🖥️ │      ║    │  │Board │  │  ║
║  │  🪟 Vindu   │  ║  │                │                   │      ║    │  │  55  │  │  ║
║  │             │  ║  │   📶 AP-BOS-2F-01    📶 AP-BOS-2F-02│      ║    │  └──────┘  │  ║
║  └─────────────┘  ║  │                                     │      ║    │            │  ║
║                   ║  │ ╔═══════════════════════════════╗   │      ║    │ 🖥️ WEBEX-  │  ║
║                   ║  │ ║ ⭐ ALEX MILLER                ║   │      ║    │ BOS-FANEUIL│  ║
║                   ║  │ ║ Pult 2F-55                    ║   │      ║    │ Room Kit   │  ║
║                   ║  │ ║ IP: 10.10.30.55               ║   │      ║    │            │  ║
║                   ║  │ ║ 🎯 PRIMÆRT ANGREPSMÅL         ║   │      ║    └────────────┘  ║
║                   ║  │ ╚═══════════════════════════════╝   │      ║                    ║
║                   ║  └─────────────────────────────────────┘      ║                    ║
╠═══════════════════╬═══════════════════════════════════════════════╬════════════════════╣
║                   ║                                               ║                    ║
║    MØTEROM        ║           ÅPENT KONTORLANDSKAP                ║    HUDDLE          ║
║    "Quincy"       ║              MARKETING                        ║    "North End"     ║
║    ┌───────────┐  ║        (Marketingteam - 12 ansatte)           ║    ┌────────────┐  ║
║    │ Kap: 8    │  ║  ┌─────────────────────────────────────┐      ║    │ Kap: 4     │  ║
║    │           │  ║  │                                     │      ║    │            │  ║
║    │ 🖥️ WEBEX- │  ║  │  🖥️🖥️🖥️🖥️  Kreative stasjoner    │      ║    │ 🖥️ WEBEX-  │  ║
║    │ BOS-      │  ║  │                                     │      ║    │ BOS-       │  ║
║    │ QUINCY    │  ║  │  🖥️🖥️🖥️🖥️  Design-arbeidsplasser │      ║    │ NORTHEND   │  ║
║    │ Room Kit  │  ║  │                                     │      ║    │ Desk Pro   │  ║
║    │           │  ║  │       📶 AP-BOS-2F-03               │      ║    │            │  ║
║    └───────────┘  ║  │                                     │      ║    └────────────┘  ║
║                   ║  └─────────────────────────────────────┘      ║                    ║
╠═══════════════════╬═══════════════════════╦═══════════════════════╬════════════════════╣
║                   ║                       ║                       ║                    ║
║    HR-AVDELING    ║    VELVÆREROM         ║      PAUSEROM         ║   IDF-BOS-2F       ║
║  (HR-team - 6)    ║    (Stille sone)      ║      (Kantine)        ║                    ║
║  ┌─────────────┐  ║  ┌─────────────┐      ║  ┌─────────────────┐  ║  ┌──────────────┐  ║
║  │             │  ║  │             │      ║  │                 │  ║  │              │  ║
║  │ 🖥️🖥️🖥️     │  ║  │ 🧘 Meditasjon│      ║  │ ☕ Fullverdig   │  ║  │ MS-BOS-2F-   │  ║
║  │             │  ║  │             │      ║  │    kjøkken      │  ║  │   IDF1       │  ║
║  │ 📶AP-BOS-  │  ║  │ 🤱 Ammerom   │      ║  │                 │  ║  │ (48 porter)  │  ║
║  │   2F-04    │  ║  │             │      ║  │ 🪑🪑🪑 Spiseplass│  ║  │              │  ║
║  │             │  ║  │ Hvilerom    │      ║  │                 │  ║  │              │  ║
║  │ Private     │  ║  │             │      ║  │ 📶AP-BOS-2F-05 │  ║  │              │  ║
║  │ kontorer    │  ║  └─────────────┘      ║  └─────────────────┘  ║  └──────────────┘  ║
║  └─────────────┘  ║                       ║                       ║                    ║
╚═══════════════════╩═══════════════════════╩═══════════════════════╩════════════════════╝

ETASJE 2 - UTSTYRSLISTE:
────────────────────────────────────────────────────────────────────────────────────────
 📶 Access Points │ AP-BOS-2F-01, AP-BOS-2F-02 (Finans), AP-BOS-2F-03 (Marketing),
                  │ AP-BOS-2F-04 (HR), AP-BOS-2F-05 (Pauserom)
────────────────────────────────────────────────────────────────────────────────────────
 🔌 Switcher      │ MS-BOS-2F-IDF1 (48 porter)
────────────────────────────────────────────────────────────────────────────────────────
 🖥️ Webex         │ WEBEX-BOS-FANEUIL (Room Kit + Board 55)
                  │ WEBEX-BOS-QUINCY (Room Kit)
                  │ WEBEX-BOS-NORTHEND (Desk Pro)
────────────────────────────────────────────────────────────────────────────────────────

NØKKELPERSONELL - ETASJE 2:
────────────────────────────────────────────────────────────────────────────────────────
 ⭐ Alex Miller    │ Sr. Financial Analyst │ Pult 2F-55 │ IP: 10.10.30.55
                  │ 🎯 PRIMÆRT ANGREPSMÅL i exfil-scenario
────────────────────────────────────────────────────────────────────────────────────────
 👔 Robert Wilson │ Finansdirektør │ Privat kontor
────────────────────────────────────────────────────────────────────────────────────────
```

---

## 📍 Boston Etasje 3 - Ledelse / Engineering / Juridisk

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                           BOSTON HQ - ETASJE 3                                         ║
║                      Ledelse • Engineering • Juridisk                                  ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║   ┌──────────┐  ┌──────────┐  ┌──────────┐              ┌──────────┐  ┌──────────┐    ║
║   │   🛗     │  │   🛗     │  │   🛗     │              │   🚪     │  │   🚪     │    ║
║   │  HEIS 1  │  │  HEIS 2  │  │  HEIS 3  │              │ TRAPP A  │  │ TRAPP B  │    ║
║   └──────────┘  └──────────┘  └──────────┘              └──────────┘  └──────────┘    ║
║                                                                                        ║
║                         DIREKTØR-RESEPSJON                                             ║
║                          📶 AP-BOS-3F-01                                               ║
║                                                                                        ║
╠═══════════════════╦═══════════════════════════════════════════════╦════════════════════╣
║                   ║                                               ║                    ║
║  LEDERASSISTENT   ║            STYREROM "CAMBRIDGE"               ║   CEO KONTOR       ║
║     OMRÅDE        ║              Kapasitet: 20                    ║                    ║
║  ┌─────────────┐  ║  ┌─────────────────────────────────────┐      ║  ┌──────────────┐  ║
║  │             │  ║  │                                     │      ║  │              │  ║
║  │ 🖥️🖥️       │  ║  │    ┌───────────────────────────┐    │      ║  │  👔 John     │  ║
║  │ EA-pulter   │  ║  │    │                           │    │      ║  │    Smith     │  ║
║  │             │  ║  │    │  ┌─────────────────────┐  │    │      ║  │    CEO       │  ║
║  │             │  ║  │    │  │                     │  │    │      ║  │              │  ║
║  │             │  ║  │    │  │   🖥️ BOARD 85 PRO   │  │    │      ║  │  📶AP-BOS-  │  ║
║  └─────────────┘  ║  │    │  │                     │  │    │      ║  │    3F-02     │  ║
║                   ║  │    │  └─────────────────────┘  │    │      ║  │              │  ║
║                   ║  │    │                           │    │      ║  │  🪟 Hjørne-  │  ║
║                   ║  │    └───────────────────────────┘    │      ║  │    kontor    │  ║
║                   ║  │                                     │      ║  │              │  ║
║                   ║  │  🪑🪑🪑🪑🪑🪑🪑🪑🪑🪑  (20 stoler) │      ║  └──────────────┘  ║
║                   ║  │  🪑🪑🪑🪑🪑🪑🪑🪑🪑🪑              │      ║                    ║
║                   ║  │                                     │      ║                    ║
║                   ║  │  🖥️ WEBEX-BOS-CAMBRIDGE              │      ║                    ║
║                   ║  │  Room Kit Pro                       │      ║                    ║
║                   ║  │  📹 CAM-BOS-3F-01  📹 CAM-BOS-3F-02 │      ║                    ║
║                   ║  └─────────────────────────────────────┘      ║                    ║
╠═══════════════════╬═══════════════════════════════════════════════╬════════════════════╣
║  CFO KONTOR       ║                                               ║   CTO KONTOR       ║
║  ┌─────────────┐  ║        ÅPENT KONTORLANDSKAP                   ║  ┌──────────────┐  ║
║  │ 👔 Sarah    │  ║           ENGINEERING                         ║  │ 👔 Mike      │  ║
║  │   Wilson    │  ║      (Engineeringteam - 20 ansatte)           ║  │   Johnson    │  ║
║  │   CFO       │  ║  ┌─────────────────────────────────────┐      ║  │   CTO        │  ║
║  └─────────────┘  ║  │                                     │      ║  └──────────────┘  ║
║                   ║  │  🖥️🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️🖥️ │      ║                    ║
║  JURIDISK         ║  │  (Ståbord)      │  (Ståbord)       │      ║   SAMARBEIDSROM    ║
║  AVDELING         ║  │                 │                  │      ║   "Lab"            ║
║ (Juridisk - 6)    ║  │  🖥️🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️🖥️ │      ║   ┌──────────────┐  ║
║  ┌─────────────┐  ║  │  (Doble skjermer på alle plasser)  │      ║   │ Kap: 8       │  ║
║  │             │  ║  │                                     │      ║   │              │  ║
║  │ 📶AP-BOS-  │  ║  │   📶 AP-BOS-3F-03    📶 AP-BOS-3F-04│      ║   │ 🖥️ WEBEX-   │  ║
║  │   3F-05    │  ║  │                                     │      ║   │ BOS-LAB      │  ║
║  │             │  ║  │  🖼️ Whiteboard-vegger              │      ║   │ Board 55     │  ║
║  │ General    │  ║  └─────────────────────────────────────┘      ║   │              │  ║
║  │ Counsel    │  ║                                               ║   └──────────────┘  ║
║  └─────────────┘  ║                                               ║                    ║
╠═══════════════════╬═══════════════════════════════════════════════╬════════════════════╣
║   LITE MØTEROM    ║                                               ║                    ║
║   "Back Bay"      ║       PRIMÆR MDF / DATASENTER                 ║    PAUSEROM        ║
║   ┌───────────┐   ║       [MDF-BOS]                               ║                    ║
║   │ Kap: 6    │   ║  ╔═════════════════════════════════════╗      ║  ┌──────────────┐  ║
║   │           │   ║  ║                                     ║      ║  │              │  ║
║   │ 🖥️ WEBEX- │   ║  ║  🔥 MX-BOS-01      🔥 MX-BOS-02    ║      ║  │ 📶AP-BOS-   │  ║
║   │ BOS-      │   ║  ║     (HA-par MX450 Firewalls)       ║      ║  │   3F-06      │  ║
║   │ BACKBAY   │   ║  ║                                     ║      ║  │              │  ║
║   │ Room Kit  │   ║  ║  🔌 MS-BOS-CORE-01  🔌 MS-BOS-CORE-02║     ║  │ ☕ Kaffebar  │  ║
║   │ Mini      │   ║  ║     (Core switches MS425-32)       ║      ║  │              │  ║
║   └───────────┘   ║  ║                                     ║      ║  │ 🍪 Snacks   │  ║
║                   ║  ║  🔌 MS-BOS-3F-IDF1                  ║      ║  │              │  ║
║                   ║  ║     (Access switch MS225-48)       ║      ║  └──────────────┘  ║
║                   ║  ║                                     ║      ║                    ║
║                   ║  ║  📹 CAM-BOS-3F-03  📹 CAM-BOS-3F-04 ║      ║                    ║
║                   ║  ║  🌡️ MT-BOS-MDF-TEMP-01              ║      ║                    ║
║                   ║  ║  💧 MT-BOS-MDF-HUMID-01             ║      ║                    ║
║                   ║  ║  🚪 MT-BOS-MDF-DOOR-01              ║      ║                    ║
║                   ║  ╚═════════════════════════════════════╝      ║                    ║
╚═══════════════════╩═══════════════════════════════════════════════╩════════════════════╝

ETASJE 3 - UTSTYRSLISTE:
────────────────────────────────────────────────────────────────────────────────────────
 📶 Access Points │ AP-BOS-3F-01 (Direktør-resepsjon), AP-BOS-3F-02 (CEO),
                  │ AP-BOS-3F-03, AP-BOS-3F-04 (Engineering),
                  │ AP-BOS-3F-05 (Juridisk), AP-BOS-3F-06 (Pauserom)
────────────────────────────────────────────────────────────────────────────────────────
 📹 Kameraer      │ CAM-BOS-3F-01, CAM-BOS-3F-02 (Styrerom),
                  │ CAM-BOS-3F-03, CAM-BOS-3F-04 (MDF)
────────────────────────────────────────────────────────────────────────────────────────
 🌡️ Sensorer      │ MT-BOS-MDF-TEMP-01 (Temperatur)
                  │ MT-BOS-MDF-HUMID-01 (Fuktighet)
                  │ MT-BOS-MDF-DOOR-01 (Dør)
────────────────────────────────────────────────────────────────────────────────────────
 🔌 Core Switcher │ MS-BOS-CORE-01, MS-BOS-CORE-02 (MS425-32)
 🔌 Access Switch │ MS-BOS-3F-IDF1 (MS225-48)
────────────────────────────────────────────────────────────────────────────────────────
 🔥 Firewalls     │ MX-BOS-01, MX-BOS-02 (MX450 HA-par)
────────────────────────────────────────────────────────────────────────────────────────
 🖥️ Webex         │ WEBEX-BOS-CAMBRIDGE (Room Kit Pro + Board 85 Pro)
                  │ WEBEX-BOS-BACKBAY (Room Kit Mini)
                  │ WEBEX-BOS-LAB (Board 55)
────────────────────────────────────────────────────────────────────────────────────────

NØKKELPERSONELL - ETASJE 3:
────────────────────────────────────────────────────────────────────────────────────────
 👔 John Smith    │ CEO        │ Hjørnekontor
 👔 Sarah Wilson  │ CFO        │ Privat kontor
 👔 Mike Johnson  │ CTO        │ Privat kontor
 ⚖️ Juridisk      │ 6 ansatte  │ General Counsel + team
 💻 Engineering   │ 20 ansatte │ Åpent kontorlandskap
────────────────────────────────────────────────────────────────────────────────────────
```

---

# 🏢 ATLANTA HUB - 400 Peachtree Center

## Utstyrsoversikt

| Type | Antall | Modell | Enhetsnavn |
|------|--------|--------|------------|
| MX Firewall | 1 | MX250 | MX-ATL-01 |
| MS Core Switch | 2 | MS425-32 | MS-ATL-DC-01, MS-ATL-DC-02 |
| MS Access Switch | 2 | MS225-48 | MS-ATL-1F-IDF1, MS-ATL-2F-IDF1 |
| MR Access Point | 12 | MR46 | AP-ATL-1F-01 → AP-ATL-2F-06 |
| MV Kamera | 11 | MV12, MV32, MV72 | CAM-ATL-* |
| MT Sensor | 8 | MT10, MT11, MT20 | MT-ATL-* |
| Webex | 7 | Diverse | WEBEX-ATL-* |

---

## 📍 Atlanta Etasje 1 - IT Drift / Datasenter

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                           ATLANTA HUB - ETASJE 1                                       ║
║                        IT Drift • Datasenter • NOC                                     ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║   ┌──────────┐  ┌──────────┐                          ┌──────────┐  ┌──────────┐      ║
║   │   🛗     │  │   🛗     │                          │   🚪     │  │   🚪     │      ║
║   │  HEIS 1  │  │  HEIS 2  │                          │ TRAPP A  │  │ TRAPP B  │      ║
║   └──────────┘  └──────────┘                          └──────────┘  └──────────┘      ║
║                                                                                        ║
║                              HEIS-LOBBY                                                ║
║                                                                                        ║
╠═══════════════════╦═══════════════════════════════════════════════╦════════════════════╣
║                   ║                                               ║                    ║
║   RESEPSJON       ║         IT DRIFTSSENTER                       ║       NOC          ║
║   ┌─────────────┐ ║      (IT-team - 15 ansatte)                   ║   "Network Ops"    ║
║   │             │ ║  ┌─────────────────────────────────────┐      ║   ┌──────────────┐ ║
║   │ 📶AP-ATL-  │ ║  │                                     │      ║   │ Kap: 6       │ ║
║   │   1F-01    │ ║  │  🖥️🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️🖥️ │      ║   │              │ ║
║   │             │ ║  │                │                   │      ║   │ 📺📺📺📺     │ ║
║   │ 📹CAM-ATL- │ ║  │  📺📺📺📺📺📺📺📺📺📺📺📺📺📺📺📺│      ║   │ (4 store     │ ║
║   │   1F-01    │ ║  │  (16 Dashboard-skjermer)            │      ║   │  skjermer)   │ ║
║   │             │ ║  │                                     │      ║   │              │ ║
║   │ 🪪 Badge   │ ║  │  📶 AP-ATL-1F-02    📶 AP-ATL-1F-03 │      ║   │ 🖥️ WEBEX-   │ ║
║   │   Reader   │ ║  │                                     │      ║   │ ATL-NOC      │ ║
║   └─────────────┘ ║  │ ╔═══════════════════════════════╗   │      ║   │ Room Kit     │ ║
║                   ║  │ ║ ⭐ JESSICA BROWN              ║   │      ║   │              │ ║
║                   ║  │ ║ IT Administrator              ║   │      ║   │ [24/7 Drift] │ ║
║                   ║  │ ║ Pult 1F-15                    ║   │      ║   │              │ ║
║                   ║  │ ║ IP: 10.20.30.15               ║   │      ║   └──────────────┘ ║
║                   ║  │ ║ 🎯 INITIELL KOMPROMITTERING   ║   │      ║                    ║
║                   ║  │ ╚═══════════════════════════════╝   │      ║                    ║
║                   ║  └─────────────────────────────────────┘      ║                    ║
╠═══════════════════╬═══════════════════════════════════════════════╬════════════════════╣
║                   ║                                               ║                    ║
║   OPPLÆRINGSLAB   ║              DATASENTER                       ║   STAGING OMRÅDE   ║
║   "Peachtree"     ║              [DC-ATL]                         ║                    ║
║   ┌─────────────┐ ║  ╔═════════════════════════════════════╗      ║  ┌──────────────┐  ║
║   │ Kap: 16    │ ║  ║                                     ║      ║  │              │  ║
║   │             │ ║  ║  ┌─────────┐  ┌─────────┐          ║      ║  │ 📶AP-ATL-   │  ║
║   │ 🖥️🖥️🖥️🖥️   │ ║  ║  │ RACK A  │  │ RACK B  │          ║      ║  │   1F-05     │  ║
║   │ 🖥️🖥️🖥️🖥️   │ ║  ║  │ 🖥️      │  │ 🖥️      │          ║      ║  │              │  ║
║   │ 🖥️🖥️🖥️🖥️   │ ║  ║  │ 🖥️      │  │ 🖥️      │          ║      ║  │ IT-utstyr   │  ║
║   │ 🖥️🖥️🖥️🖥️   │ ║  ║  │ 🖥️      │  │ 🖥️      │          ║      ║  │ inventar    │  ║
║   │ (16 plasser)│ ║  ║  └─────────┘  └─────────┘          ║      ║  │              │  ║
║   │             │ ║  ║                                     ║      ║  │ 📦 Utpakking │  ║
║   │ 🖥️ WEBEX-  │ ║  ║  🔌 MS-ATL-DC-01   🔌 MS-ATL-DC-02  ║      ║  │ 🔧 Konfig-  │  ║
║   │ ATL-       │ ║  ║  🔥 MX-ATL-01                       ║      ║  │    benk      │  ║
║   │ PEACHTREE  │ ║  ║                                     ║      ║  │              │  ║
║   │ Room Kit   │ ║  ║  📹 CAM-ATL-DC-01  📹 CAM-ATL-DC-02 ║      ║  └──────────────┘  ║
║   │ Pro        │ ║  ║  📹 CAM-ATL-DC-03  📹 CAM-ATL-DC-04 ║      ║                    ║
║   │             │ ║  ║                                     ║      ║                    ║
║   │ 📶AP-ATL-  │ ║  ║  🌡️ MT-ATL-DC-TEMP-01..04           ║      ║                    ║
║   │   1F-04    │ ║  ║  💧 MT-ATL-DC-HUMID-01..02          ║      ║                    ║
║   └─────────────┘ ║  ║  🚪 MT-ATL-DC-DOOR-01               ║      ║                    ║
║                   ║  ╚═════════════════════════════════════╝      ║                    ║
╠═══════════════════╬═══════════════════╦═══════════════════════════╬════════════════════╣
║   LITE MØTEROM    ║                   ║                           ║   IDF-ATL-1F       ║
║   "Buckhead"      ║    PAUSEROM       ║       LAGER               ║                    ║
║   ┌───────────┐   ║  ┌─────────────┐  ║  ┌───────────────────┐    ║  ┌──────────────┐  ║
║   │ Kap: 4    │   ║  │             │  ║  │                   │    ║  │              │  ║
║   │           │   ║  │ 📶AP-ATL-  │  ║  │  📦 Reservedeler  │    ║  │ MS-ATL-1F-   │  ║
║   │ 🖥️ WEBEX- │   ║  │   1F-06    │  ║  │  🔌 Kabler        │    ║  │   IDF1       │  ║
║   │ ATL-      │   ║  │             │  ║  │  🔧 Verktøy       │    ║  │ (48 porter)  │  ║
║   │ BUCKHEAD  │   ║  │ ☕ Kjøkken  │  ║  │                   │    ║  │              │  ║
║   │ Desk Pro  │   ║  │ 🍕 Snacks   │  ║  │                   │    ║  │ 📹CAM-ATL-  │  ║
║   └───────────┘   ║  └─────────────┘  ║  └───────────────────┘    ║  │   1F-05     │  ║
║                   ║                   ║                           ║  └──────────────┘  ║
╚═══════════════════╩═══════════════════╩═══════════════════════════╩════════════════════╝

ETASJE 1 - UTSTYRSLISTE:
────────────────────────────────────────────────────────────────────────────────────────
 📶 Access Points │ AP-ATL-1F-01 (Resepsjon), AP-ATL-1F-02, AP-ATL-1F-03 (IT Drift),
                  │ AP-ATL-1F-04 (Opplæring), AP-ATL-1F-05 (Staging), AP-ATL-1F-06 (Pause)
────────────────────────────────────────────────────────────────────────────────────────
 📹 Kameraer      │ CAM-ATL-1F-01 (Lobby), CAM-ATL-DC-01..04 (Datasenter),
                  │ CAM-ATL-1F-05 (IDF)
────────────────────────────────────────────────────────────────────────────────────────
 🌡️ Sensorer      │ MT-ATL-DC-TEMP-01..04 (Temperatur)
                  │ MT-ATL-DC-HUMID-01..02 (Fuktighet)
                  │ MT-ATL-DC-DOOR-01 (Dør)
────────────────────────────────────────────────────────────────────────────────────────
 🔌 DC Switcher   │ MS-ATL-DC-01, MS-ATL-DC-02 (MS425-32)
 🔌 Access Switch │ MS-ATL-1F-IDF1 (MS225-48)
────────────────────────────────────────────────────────────────────────────────────────
 🔥 Firewall      │ MX-ATL-01 (MX250)
────────────────────────────────────────────────────────────────────────────────────────
 🖥️ Webex         │ WEBEX-ATL-NOC (Room Kit + 4 Skjermer)
                  │ WEBEX-ATL-PEACHTREE (Room Kit Pro)
                  │ WEBEX-ATL-BUCKHEAD (Desk Pro)
────────────────────────────────────────────────────────────────────────────────────────

NØKKELPERSONELL - ETASJE 1:
────────────────────────────────────────────────────────────────────────────────────────
 ⭐ Jessica Brown  │ IT Administrator │ Pult 1F-15 │ IP: 10.20.30.15
                  │ 🎯 INITIELL KOMPROMITTERING i exfil-scenario
────────────────────────────────────────────────────────────────────────────────────────
 👔 David Robinson│ IT Manager
 💻 Nicholas Kelly│ Sr. Systems Admin
 🔒 Samuel Wright │ IT Security Analyst
────────────────────────────────────────────────────────────────────────────────────────
```

---

## 📍 Atlanta Etasje 2 - Engineering / Salg / Marketing

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                           ATLANTA HUB - ETASJE 2                                       ║
║                      Engineering • Salg • Marketing                                    ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║   ┌──────────┐  ┌──────────┐                          ┌──────────┐  ┌──────────┐      ║
║   │   🛗     │  │   🛗     │                          │   🚪     │  │   🚪     │      ║
║   │  HEIS 1  │  │  HEIS 2  │                          │ TRAPP A  │  │ TRAPP B  │      ║
║   └──────────┘  └──────────┘                          └──────────┘  └──────────┘      ║
║                                                                                        ║
║                              HEIS-LOBBY                                                ║
║                                                                                        ║
╠═══════════════════╦═══════════════════════════════════════════════╦════════════════════╣
║                   ║                                               ║                    ║
║    MØTEROM        ║         ÅPENT KONTORLANDSKAP                  ║    LITE MØTEROM    ║
║    "Midtown"      ║            ENGINEERING                        ║    "Decatur"       ║
║    ┌───────────┐  ║       (Engineeringteam - 8 ansatte)           ║    ┌────────────┐  ║
║    │ Kap: 10   │  ║  ┌─────────────────────────────────────┐      ║    │ Kap: 4     │  ║
║    │           │  ║  │                                     │      ║    │            │  ║
║    │  ┌──────┐ │  ║  │  🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️        │      ║    │ 🖥️ WEBEX-  │  ║
║    │  │Board │ │  ║  │  (Utvikler-arbeidsplasser)         │      ║    │ ATL-       │  ║
║    │  │  55  │ │  ║  │                                     │      ║    │ DECATUR    │  ║
║    │  └──────┘ │  ║  │  📶 AP-ATL-2F-01    📶 AP-ATL-2F-02 │      ║    │ Desk Pro   │  ║
║    │           │  ║  │                                     │      ║    │            │  ║
║    │ 🖥️ WEBEX- │  ║  │  Ståpulter                          │      ║    └────────────┘  ║
║    │ ATL-      │  ║  └─────────────────────────────────────┘      ║                    ║
║    │ MIDTOWN   │  ║                                               ║                    ║
║    │ Room Kit  │  ║                                               ║                    ║
║    └───────────┘  ║                                               ║                    ║
╠═══════════════════╬═══════════════════════════════════════════════╬════════════════════╣
║                   ║                                               ║                    ║
║   HR / DRIFT      ║         ÅPENT KONTORLANDSKAP                  ║   TELEFONBOKSER    ║
║  (HR - 3)         ║         SALG / MARKETING                      ║   (4 bokser)       ║
║  (Drift - 3)      ║    (Salg - 5, Marketing - 5 ansatte)          ║   ┌────────────┐   ║
║  ┌─────────────┐  ║  ┌─────────────────────────────────────┐      ║   │ 📞 📞      │   ║
║  │             │  ║  │                                     │      ║   │ 📞 📞      │   ║
║  │ 🖥️🖥️🖥️     │  ║  │  🖥️🖥️🖥️🖥️🖥️  Salgspulter          │      ║   │            │   ║
║  │             │  ║  │                                     │      ║   │ 📶AP-ATL-  │   ║
║  │ 📶AP-ATL-  │  ║  │  🖥️🖥️🖥️🖥️🖥️  Marketing kreativ     │      ║   │   2F-05    │   ║
║  │   2F-03    │  ║  │                                     │      ║   │            │   ║
║  │             │  ║  │       📶 AP-ATL-2F-04               │      ║   │ Private    │   ║
║  │ Private     │  ║  └─────────────────────────────────────┘      ║   │ samtaler   │   ║
║  │ kontorbåser │  ║                                               ║   │ Videosamtaler│  ║
║  │ HR Manager  │  ║                                               ║   └────────────┘   ║
║  └─────────────┘  ║                                               ║                    ║
╠═══════════════════╬═══════════════════╦═══════════════════════════╬════════════════════╣
║   VELVÆREROM      ║                   ║    SAMARBEIDSROM          ║   IDF-ATL-2F       ║
║   (Stille sone)   ║    PAUSEROM       ║    "Innovation"           ║                    ║
║  ┌─────────────┐  ║    (Stort)        ║    ┌─────────────────┐    ║  ┌──────────────┐  ║
║  │             │  ║  ┌─────────────┐  ║    │ Kap: 8          │    ║  │              │  ║
║  │ 🧘 Meditasjon│  ║  │             │  ║    │                 │    ║  │ MS-ATL-2F-   │  ║
║  │             │  ║  │ 📶AP-ATL-  │  ║    │ 🖥️ WEBEX-       │    ║  │   IDF1       │  ║
║  │ 🤱 Ammerom  │  ║  │   2F-06    │  ║    │ ATL-INNOVATION  │    ║  │ (48 porter)  │  ║
║  │             │  ║  │             │  ║    │ Board 55        │    ║  │              │  ║
║  │             │  ║  │ ☕ Kjøkken  │  ║    │                 │    ║  │              │  ║
║  │             │  ║  │ 🪑 Spiseområde║    │ Idémyldring     │    ║  │              │  ║
║  └─────────────┘  ║  └─────────────┘  ║    └─────────────────┘    ║  └──────────────┘  ║
╚═══════════════════╩═══════════════════╩═══════════════════════════╩════════════════════╝

ETASJE 2 - UTSTYRSLISTE:
────────────────────────────────────────────────────────────────────────────────────────
 📶 Access Points │ AP-ATL-2F-01, AP-ATL-2F-02 (Engineering), AP-ATL-2F-03 (HR/Drift),
                  │ AP-ATL-2F-04 (Salg/Mktg), AP-ATL-2F-05 (Telefonbokser),
                  │ AP-ATL-2F-06 (Pauserom)
────────────────────────────────────────────────────────────────────────────────────────
 🔌 Switch        │ MS-ATL-2F-IDF1 (MS225-48)
────────────────────────────────────────────────────────────────────────────────────────
 🖥️ Webex         │ WEBEX-ATL-MIDTOWN (Room Kit + Board 55)
                  │ WEBEX-ATL-DECATUR (Desk Pro)
                  │ WEBEX-ATL-INNOVATION (Board 55)
────────────────────────────────────────────────────────────────────────────────────────

NØKKELPERSONELL - ETASJE 2:
────────────────────────────────────────────────────────────────────────────────────────
 💻 Engineering   │ 8 ansatte
 📈 Salg          │ 5 ansatte
 📢 Marketing     │ 5 ansatte
 👥 HR            │ 3 ansatte
 ⚙️ Drift         │ 3 ansatte
────────────────────────────────────────────────────────────────────────────────────────
```

---

# 🏢 AUSTIN KONTOR - 200 Congress Ave

## Utstyrsoversikt

| Type | Antall | Modell | Enhetsnavn |
|------|--------|--------|------------|
| MX Firewall | 1 | MX85 | MX-AUS-01 |
| MS Switch | 2 | MS250-48, MS225-24 | MS-AUS-01, MS-AUS-02 |
| MR Access Point | 8 | MR46 | AP-AUS-1F-01 → AP-AUS-1F-08 |
| MV Kamera | 4 | MV12, MV72 | CAM-AUS-* |
| MT Sensor | 2 | MT10, MT20 | MT-AUS-* |
| Webex | 4 | Diverse | WEBEX-AUS-* |

---

## 📍 Austin Etasje 1 - Salg / Engineering

```
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                          AUSTIN KONTOR - ETASJE 1                                      ║
║                          Salg • Engineering Hub                                        ║
╠═══════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                        ║
║                              HOVEDINNGANG                                              ║
║                          📹 CAM-AUS-1F-01                                              ║
║                                                                                        ║
╠═══════════════════╦═══════════════════════════════════════════════╦════════════════════╣
║                   ║                                               ║                    ║
║   RESEPSJON       ║         ÅPENT KONTORLANDSKAP                  ║    MØTEROM         ║
║   ┌─────────────┐ ║              SALG                             ║    "Congress"      ║
║   │             │ ║       (Salgsteam - 15 ansatte)                ║    ┌────────────┐  ║
║   │ 📶AP-AUS-  │ ║  ┌─────────────────────────────────────┐      ║    │ Kap: 12    │  ║
║   │   1F-01    │ ║  │                                     │      ║    │            │  ║
║   │             │ ║  │  🖥️🖥️🖥️🖥️🖥️  │  🖥️🖥️🖥️🖥️🖥️ │      ║    │  ┌──────┐  │  ║
║   │ 🖥️ Velkommen│ ║  │  🖥️🖥️🖥️🖥️🖥️  │                   │      ║    │  │Board │  │  ║
║   │   skjerm   │ ║  │                │                   │      ║    │  │  55  │  │  ║
║   │             │ ║  │  📶 AP-AUS-1F-02    📶 AP-AUS-1F-03 │      ║    │  └──────┘  │  ║
║   │             │ ║  │                                     │      ║    │            │  ║
║   └─────────────┘ ║  │  📺📺📺  Store dashboard-skjermer   │      ║    │ 🖥️ WEBEX-  │  ║
║                   ║  │  🖼️ Whiteboard-vegger               │      ║    │ AUS-       │  ║
║                   ║  └─────────────────────────────────────┘      ║    │ CONGRESS   │  ║
║                   ║                                               ║    │ Room Kit   │  ║
║                   ║                                               ║    └────────────┘  ║
╠═══════════════════╬═══════════════════════════════════════════════╬════════════════════╣
║                   ║                                               ║                    ║
║   LITE MØTEROM    ║         ÅPENT KONTORLANDSKAP                  ║    DEMO LAB        ║
║   "6th Street"    ║            ENGINEERING                        ║    "Live Oak"      ║
║   ┌───────────┐   ║       (Engineeringteam - 12 ansatte)          ║    ┌────────────┐  ║
║   │ Kap: 6    │   ║  ┌─────────────────────────────────────┐      ║    │ Kap: 8     │  ║
║   │           │   ║  │                                     │      ║    │            │  ║
║   │ 🖥️ WEBEX- │   ║  │  🖥️🖥️🖥️🖥️🖥️🖥️ (Utviklerpulter)     │      ║    │ 🖥️ WEBEX-  │  ║
║   │ AUS-      │   ║  │  🖥️🖥️🖥️🖥️🖥️🖥️ (Ståpulter)          │      ║    │ AUS-       │  ║
║   │ 6THSTREET │   ║  │                                     │      ║    │ LIVEOAK    │  ║
║   │ Room Kit  │   ║  │  📶 AP-AUS-1F-04    📶 AP-AUS-1F-05 │      ║    │ Room Kit   │  ║
║   │ Mini      │   ║  │                                     │      ║    │            │  ║
║   └───────────┘   ║  │  🖥️🖥️🖥️  Flere skjermer på hver plass│      ║    │ 🖥️ Demo-   │  ║
║                   ║  └─────────────────────────────────────┘      ║    │   utstyr   │  ║
║                   ║                                               ║    │ Kundedemonstrasj│
║                   ║                                               ║    └────────────┘  ║
╠═══════════════════╬═══════════════════╦═══════════════════════════╬════════════════════╣
║   TELEFONBOKSER   ║                   ║    SPILLROM               ║   SERVERROM        ║
║   (3 bokser)      ║    PAUSEROM       ║    "Recharge"             ║   [IDF-AUS]        ║
║   ┌───────────┐   ║  ┌─────────────┐  ║  ┌─────────────────┐      ║  ┌──────────────┐  ║
║   │ 📞        │   ║  │             │  ║  │                 │      ║  │              │  ║
║   │ 📞        │   ║  │ 📶AP-AUS-  │  ║  │  🎱 Biljard     │      ║  │ 🔥 MX-AUS-01│  ║
║   │ 📞        │   ║  │   1F-06    │  ║  │  ⚽ Bordfotball │      ║  │              │  ║
║   │           │   ║  │             │  ║  │  🎮 Gaming      │      ║  │ 🔌 MS-AUS-01│  ║
║   │ 📶AP-AUS- │   ║  │ ☕ Kjøkken  │  ║  │                 │      ║  │ 🔌 MS-AUS-02│  ║
║   │   1F-07   │   ║  │ ☕ Kaffebar │  ║  │ 📶AP-AUS-1F-08 │      ║  │              │  ║
║   │           │   ║  │ 🪑 Spiseplass║  ║  │                 │      ║  │ 📹CAM-AUS-  │  ║
║   │ Private   │   ║  │             │  ║  │                 │      ║  │   1F-02     │  ║
║   │ samtaler  │   ║  └─────────────┘  ║  └─────────────────┘      ║  │ 🌡️MT-AUS-  │  ║
║   │ Video     │   ║                   ║                           ║  │   TEMP-01   │  ║
║   └───────────┘   ║                   ║                           ║  │ 🚪MT-AUS-  │  ║
║                   ║                   ║                           ║  │   DOOR-01   │  ║
║                   ║                   ║                           ║  └──────────────┘  ║
╠═══════════════════╩═══════════════════╩═══════════════════════════╩════════════════════╣
║                                                                                        ║
║                              PARKERINGSPLASS                                           ║
║                                                                                        ║
║             📹 CAM-AUS-EXT-01                    📹 CAM-AUS-EXT-02                     ║
║                  (Vest)                              (Øst)                             ║
║                                                                                        ║
╚════════════════════════════════════════════════════════════════════════════════════════╝

ETASJE 1 - UTSTYRSLISTE:
────────────────────────────────────────────────────────────────────────────────────────
 📶 Access Points │ AP-AUS-1F-01 (Resepsjon), AP-AUS-1F-02, AP-AUS-1F-03 (Salg),
                  │ AP-AUS-1F-04, AP-AUS-1F-05 (Engineering), AP-AUS-1F-06 (Pause),
                  │ AP-AUS-1F-07 (Telefonbokser), AP-AUS-1F-08 (Spillrom)
────────────────────────────────────────────────────────────────────────────────────────
 📹 Kameraer      │ CAM-AUS-1F-01 (Inngang), CAM-AUS-1F-02 (Serverrom),
                  │ CAM-AUS-EXT-01, CAM-AUS-EXT-02 (Parkering)
────────────────────────────────────────────────────────────────────────────────────────
 🌡️ Sensorer      │ MT-AUS-TEMP-01, MT-AUS-DOOR-01 (Serverrom)
────────────────────────────────────────────────────────────────────────────────────────
 🔌 Switcher      │ MS-AUS-01 (MS250-48), MS-AUS-02 (MS225-24)
────────────────────────────────────────────────────────────────────────────────────────
 🔥 Firewall      │ MX-AUS-01 (MX85)
────────────────────────────────────────────────────────────────────────────────────────
 🖥️ Webex         │ WEBEX-AUS-CONGRESS (Room Kit + Board 55)
                  │ WEBEX-AUS-6THSTREET (Room Kit Mini)
                  │ WEBEX-AUS-LIVEOAK (Room Kit)
────────────────────────────────────────────────────────────────────────────────────────

NØKKELPERSONELL - AUSTIN:
────────────────────────────────────────────────────────────────────────────────────────
 📈 Zoey Collins      │ Sales Manager
 📈 Taylor Campbell   │ Regional Sales Director
 💻 Amelia Collins    │ Lead Engineer
────────────────────────────────────────────────────────────────────────────────────────
 📈 Salgsteam         │ 15 ansatte
 💻 Engineeringteam   │ 12 ansatte
 👥 HR/Marketing      │ 4 ansatte
────────────────────────────────────────────────────────────────────────────────────────
```

---

# 📋 MØTEROMOVERSIKT (Alle lokasjoner)

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              MØTEROM OVERSIKT                                           │
├──────────┬─────────────────┬───────┬─────────────────────────┬──────────────────────────┤
│ Lokasjon │ Romnavn         │ Kap   │ Webex-enhet             │ Funksjoner               │
├──────────┼─────────────────┼───────┼─────────────────────────┼──────────────────────────┤
│          │                 │       │                         │                          │
│ BOSTON   │ Cambridge       │  20   │ Room Kit Pro + Board 85 │ Styremøter, videokonf.   │
│          │ Faneuil         │  12   │ Room Kit + Board 55     │ Store møter              │
│          │ Quincy          │   8   │ Room Kit                │ Mellomstore møter        │
│          │ North End       │   4   │ Desk Pro                │ Huddle                   │
│          │ Back Bay        │   6   │ Room Kit Mini           │ Små møter                │
│          │ Lab             │   8   │ Board 55                │ Samarbeid/whiteboard     │
│          │ Harbor          │   6   │ Desk Pro                │ Besøksmøter              │
│          │ Beacon          │   4   │ Room Kit Mini           │ Besøksmøter              │
├──────────┼─────────────────┼───────┼─────────────────────────┼──────────────────────────┤
│          │                 │       │                         │                          │
│ ATLANTA  │ Peachtree       │  16   │ Room Kit Pro            │ Opplæring                │
│          │ Midtown         │  10   │ Room Kit + Board 55     │ Konferanser              │
│          │ NOC             │   6   │ Room Kit + 4 Displays   │ 24/7 Drift               │
│          │ Buckhead        │   4   │ Desk Pro                │ Huddle                   │
│          │ Decatur         │   4   │ Desk Pro                │ Huddle                   │
│          │ Innovation      │   8   │ Board 55                │ Idémyldring              │
├──────────┼─────────────────┼───────┼─────────────────────────┼──────────────────────────┤
│          │                 │       │                         │                          │
│ AUSTIN   │ Congress        │  12   │ Room Kit + Board 55     │ Hovedkonferanse          │
│          │ 6th Street      │   6   │ Room Kit Mini           │ Små møter                │
│          │ Live Oak        │   8   │ Room Kit                │ Kundedemoer              │
└──────────┴─────────────────┴───────┴─────────────────────────┴──────────────────────────┘
```

---

# 📡 TRÅDLØS SSID-KONFIGURASJON

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              SSID KONFIGURASJON                                         │
├──────────────────┬─────────────────────────┬──────┬───────────┬──────────────────────────┤
│ SSID             │ Autentisering           │ VLAN │ Lokasjoner│ Formål                   │
├──────────────────┼─────────────────────────┼──────┼───────────┼──────────────────────────┤
│ FakeTShirtCo-Corp    │ 802.1X (RADIUS)         │  40  │ Alle      │ Ansatte trådløst         │
│ FakeTShirtCo-Guest   │ WPA2-PSK + Captive Port │  80  │ Alle      │ Gjester                  │
│ FakeTShirtCo-IoT     │ WPA2-PSK                │  60  │ Alle      │ IoT-enheter, sensorer    │
│ FakeTShirtCo-Voice   │ 802.1X                  │  50  │ Alle      │ Webex-enheter, telefoner │
└──────────────────┴─────────────────────────┴──────┴───────────┴──────────────────────────┘
```

---

# 🖥️ SERVER-INFRASTRUKTUR

## Boston HQ (Primært datasenter)

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         BOSTON HQ - SERVERE                                             │
├─────────────────┬─────────────────┬──────────────────────────┬──────────────────────────┤
│ Hostname        │ IP              │ Rolle                    │ OS                       │
├─────────────────┼─────────────────┼──────────────────────────┼──────────────────────────┤
│ DC-BOS-01       │ 10.10.20.10     │ Domain Controller        │ Windows Server 2022      │
│ DC-BOS-02       │ 10.10.20.11     │ Domain Controller        │ Windows Server 2022      │
│ FILE-BOS-01     │ 10.10.20.20     │ Filserver                │ Windows Server 2022      │
│ SQL-PROD-01     │ 10.10.20.30     │ SQL Database             │ Windows Server 2022      │
│ APP-BOS-01      │ 10.10.20.40     │ Applikasjonsserver       │ Windows Server 2022      │
│ WEB-01          │ 172.16.1.10     │ Webserver (DMZ)          │ Ubuntu 22.04             │
│ WEB-02          │ 172.16.1.11     │ Webserver (DMZ)          │ Ubuntu 22.04             │
└─────────────────┴─────────────────┴──────────────────────────┴──────────────────────────┘
```

## Atlanta Hub (Sekundært datasenter)

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         ATLANTA HUB - SERVERE                                           │
├─────────────────┬─────────────────┬──────────────────────────┬──────────────────────────┤
│ Hostname        │ IP              │ Rolle                    │ OS                       │
├─────────────────┼─────────────────┼──────────────────────────┼──────────────────────────┤
│ DC-ATL-01       │ 10.20.20.10     │ Domain Controller (Rep)  │ Windows Server 2022      │
│ BACKUP-ATL-01   │ 10.20.20.20     │ Backup Server (Veeam)    │ Windows Server 2022      │
│ MON-ATL-01      │ 10.20.20.30     │ Monitoring (Splunk)      │ Ubuntu 22.04             │
│ DEV-ATL-01      │ 10.20.20.40     │ Dev/Test                 │ Ubuntu 22.04             │
│ DEV-ATL-02      │ 10.20.20.41     │ Dev/Test                 │ Ubuntu 22.04             │
└─────────────────┴─────────────────┴──────────────────────────┴──────────────────────────┘
```

## Austin kontor

- Ingen lokale servere (cloud-first tilnærming, bruker Atlanta/Boston)

---

# 🎯 ANGREPSSCENARIO-LOKASJONER

## Exfiltreringsscenario - Angrepssti

```
╔═════════════════════════════════════════════════════════════════════════════════════════╗
║                              EXFIL SCENARIO - TIDSLINJE                                 ║
╠═════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                         ║
║   DAG 1-3: REKOGNOSERING                                                               ║
║   ┌─────────────────────────────────────────────────────────────────────────────────┐   ║
║   │  🌐 EKSTERN ANGRIPER                                                             │   ║
║   │  IP: 185.220.101.42 (Frankfurt, Tyskland)                                       │   ║
║   │                                                                                  │   ║
║   │  → Portskanning mot alle lokasjoner                                             │   ║
║   │  → Phishing-e-poster sendt til IT-avdelingen                                    │   ║
║   └─────────────────────────────────────────────────────────────────────────────────┘   ║
║                                          │                                              ║
║                                          ▼                                              ║
║   DAG 4: INITIELL KOMPROMITTERING                                                      ║
║   ┌─────────────────────────────────────────────────────────────────────────────────┐   ║
║   │  📍 ATLANTA HUB - ETASJE 1                                                       │   ║
║   │  ┌─────────────────────────────────────────────────────────────────────────┐    │   ║
║   │  │  ⭐ JESSICA BROWN (IT Administrator)                                     │    │   ║
║   │  │  Arbeidsplass: Pult 1F-15                                               │    │   ║
║   │  │  IP: 10.20.30.15                                                        │    │   ║
║   │  │  Enhet: ATL-WS-JBROWN01                                                 │    │   ║
║   │  │                                                                          │    │   ║
║   │  │  🎣 Klikker på phishing-lenke                                           │    │   ║
║   │  │  💀 Credential harvesting utført                                        │    │   ║
║   │  └─────────────────────────────────────────────────────────────────────────┘    │   ║
║   └─────────────────────────────────────────────────────────────────────────────────┘   ║
║                                          │                                              ║
║                                          ▼                                              ║
║   DAG 5-7: LATERAL BEVEGELSE                                                           ║
║   ┌─────────────────────────────────────────────────────────────────────────────────┐   ║
║   │  🔗 ATLANTA → BOSTON (via SD-WAN VPN)                                            │   ║
║   │                                                                                  │   ║
║   │  Atlanta DC tilgang → AutoVPN → Boston fildeling                                │   ║
║   │  Krysssite-probing og privilegieeskalering                                      │   ║
║   └─────────────────────────────────────────────────────────────────────────────────┘   ║
║                                          │                                              ║
║                                          ▼                                              ║
║   DAG 8-10: PRIVILEGIEESKALERING                                                       ║
║   ┌─────────────────────────────────────────────────────────────────────────────────┐   ║
║   │  📍 BOSTON HQ - ETASJE 2                                                         │   ║
║   │  ┌─────────────────────────────────────────────────────────────────────────┐    │   ║
║   │  │  ⭐ ALEX MILLER (Sr. Financial Analyst)                                  │    │   ║
║   │  │  Arbeidsplass: Pult 2F-55                                               │    │   ║
║   │  │  IP: 10.10.30.55                                                        │    │   ║
║   │  │  Enhet: BOS-WS-AMILLER01                                                │    │   ║
║   │  │                                                                          │    │   ║
║   │  │  🔑 Credentials stjålet                                                 │    │   ║
║   │  │  📁 Tilgang til finansdata                                              │    │   ║
║   │  └─────────────────────────────────────────────────────────────────────────┘    │   ║
║   └─────────────────────────────────────────────────────────────────────────────────┘   ║
║                                          │                                              ║
║                                          ▼                                              ║
║   DAG 11-14: DATAEKSFILTRASJON                                                         ║
║   ┌─────────────────────────────────────────────────────────────────────────────────┐   ║
║   │  📤 EXFIL                                                                        │   ║
║   │                                                                                  │   ║
║   │  Kilde:      FILE-BOS-01 (Finance shares)                                       │   ║
║   │  Destinasjon: Ekstern skylagring                                                │   ║
║   │  Utgang:      MX-BOS-01/02 → Internett                                          │   ║
║   └─────────────────────────────────────────────────────────────────────────────────┘   ║
║                                                                                         ║
╚═════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## Kamera/Sensor Scenario-Triggere

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         SCENARIO-TRIGGERE                                               │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🚨 ETTER ARBEIDSTID BEVEGELSE                                                         │
│     Kamera: CAM-BOS-3F-03 (MDF)                                                        │
│     Trigger: Bevegelse utenfor 07:00-20:00                                             │
│                                                                                         │
│  🌡️ SERVERROM TEMPERATURØKNING                                                         │
│     Sensorer: MT-ATL-DC-TEMP-*                                                         │
│     Trigger: Temperatur overstiger 28°C                                                │
│                                                                                         │
│  🚪 UAUTORISERT DØRTILGANG                                                             │
│     Sensor: MT-BOS-MDF-DOOR-01                                                         │
│     Trigger: Dør åpnes uten badge-innslag                                              │
│                                                                                         │
│  📡 ROGUE AP DETEKSJON                                                                 │
│     Område: Nær CAM-ATL-DC-*                                                           │
│     Trigger: Under exfil-scenario                                                      │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Tegnforklaring

```
📶  Access Point (WiFi)        🔌  Switch               🔥  Firewall
📹  Kamera                     🌡️  Temperatursensor     💧  Fuktighetssensor
🚪  Dørsensor                  🖥️  Webex/Skjerm         ☕  Kjøkken/Kaffebar
🛗  Heis                       👔  Leder                ⭐  Nøkkelperson (angrep)
🎯  Angrepsmål                 📦  Lagring/Shipping     🧘  Velværerom
```
