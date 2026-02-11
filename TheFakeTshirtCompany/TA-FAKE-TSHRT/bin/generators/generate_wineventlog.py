#!/usr/bin/env python3
"""
Windows Event Log Generator.
Generates Security, System, and Application event logs with natural volume variation.

Includes:
- Security: Logon events (4624, 4625, 4672), Process creation (4688), User mgmt (4720-4728)
- System: Restart events (1074), Service events (7000-7045)
- Application: SQL Server events, IIS events, generic application events

Scenarios:
- ransomware_attempt: Security events (4688, 4697, 1116)
- exfil: Security events (4624, 4625, 4688, 4672, 4728)
- cpu_runaway: Application events (SQL Server 17883, 833, 19406)
"""

import argparse
import random
import sys
from pathlib import Path
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path, Config
from shared.time_utils import ts_winevent, date_add, calc_natural_events, TimeUtils
from shared.company import USERS, USER_KEYS, WINDOWS_SERVERS, get_random_user, get_internal_ip, Company
from scenarios.security import RansomwareAttemptScenario
from scenarios.security.phishing_test import PhishingTestScenario
from scenarios.registry import expand_scenarios

# =============================================================================
# WINDOWS EVENT TEMPLATES
# =============================================================================

RECORD_NUMBER = 0


def get_record_number() -> int:
    """Get next record number."""
    global RECORD_NUMBER
    RECORD_NUMBER += 1
    return RECORD_NUMBER


def _insert_demo_id(event: str, demo_id: str) -> str:
    """Insert demo_id field after the Type=<xyz> line in a WinEventLog event.

    Moves demo_id from the bottom of the event to just after the Type= line,
    making it easier to spot in Splunk and consistent with field ordering.

    Before: ...Type=Information\\nComputerName=...\\n...demo_id=exfil\\n
    After:  ...Type=Information\\ndemo_id=exfil\\nComputerName=...\\n...
    """
    if not demo_id:
        return event

    tag = f"demo_id={demo_id}\n"

    # Find "Type=" line and insert demo_id after it
    lines = event.split("\n")
    result = []
    inserted = False
    for line in lines:
        result.append(line)
        if not inserted and line.startswith("Type="):
            result.append(f"demo_id={demo_id}")
            inserted = True

    if not inserted:
        # Fallback: append at end if no Type= line found
        result.append(f"demo_id={demo_id}")

    return "\n".join(result)


def event_4624(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, logon_type: int, source_ip: str) -> str:
    """Generate successful logon event (4624)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    return f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4624
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Logon
RecordNumber={record}
Keywords=Audit Success
Message=An account was successfully logged on.

Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Logon Information:
\tLogon Type:\t\t{logon_type}
\tRestricted Admin Mode:\t-
\tVirtual Account:\t\tNo
\tElevated Token:\t\tYes

New Logon:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}
\tLogon GUID:\t\t{{{random.randint(10000000, 99999999):08x}-{random.randint(1000, 9999):04x}-{random.randint(1000, 9999):04x}-{random.randint(1000, 9999):04x}-{random.randint(100000000000, 999999999999):012x}}}

Network Information:
\tWorkstation Name:\t{user.split('.')[0].upper()}-PC
\tSource Network Address:\t{source_ip}
\tSource Port:\t\t{random.randint(49152, 65535)}
"""


def event_4625(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, source_ip: str, reason: str) -> str:
    """Generate failed logon event (4625)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    return f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4625
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Logon
RecordNumber={record}
Keywords=Audit Failure
Message=An account failed to log on.

Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Logon Type:\t\t3

Account For Which Logon Failed:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t{user}
\tAccount Domain:\t\tFAKETSHIRTCO

Failure Information:
\tFailure Reason:\t\t{reason}
\tStatus:\t\t\t0xC000006D
\tSub Status:\t\t0xC000006A

Network Information:
\tWorkstation Name:\t-
\tSource Network Address:\t{source_ip}
\tSource Port:\t\t{random.randint(49152, 65535)}
"""


def event_4672(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str) -> str:
    """Generate special privileges assigned event (4672)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    return f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4672
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Special Logon
RecordNumber={record}
Keywords=Audit Success
Message=Special privileges assigned to new logon.

Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-500
\tAccount Name:\t\t{user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Privileges:\t\tSeSecurityPrivilege
\t\t\tSeTakeOwnershipPrivilege
\t\t\tSeLoadDriverPrivilege
\t\t\tSeBackupPrivilege
\t\t\tSeRestorePrivilege
\t\t\tSeDebugPrivilege
\t\t\tSeSystemEnvironmentPrivilege
\t\t\tSeImpersonatePrivilege
"""


def event_1074(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, reason: str) -> str:
    """Generate system restart event (1074)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=User32
EventCode=1074
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The process C:\\Windows\\system32\\winlogon.exe (SYSTEM) has initiated the restart of computer {computer} on behalf of user NT AUTHORITY\\SYSTEM for the following reason: {reason}
\tReason Code: 0x80020003
\tShutdown Type: restart
"""


# =============================================================================
# SYSTEM EVENT TEMPLATES (New)
# =============================================================================

# Service configuration per server role
WINDOWS_SERVICES = {
    "DC-BOS-01": ["Active Directory Domain Services", "DNS Server", "DHCP Server", "Kerberos Key Distribution Center", "Windows Time", "Group Policy Client", "Netlogon"],
    "DC-BOS-02": ["Active Directory Domain Services", "DNS Server", "DHCP Server", "Kerberos Key Distribution Center", "Windows Time", "Group Policy Client", "Netlogon"],
    "BOS-FILE-01": ["File Server Resource Manager", "DFS Replication", "Volume Shadow Copy", "Windows Search", "Server", "LanmanServer"],
    "BOS-SQL-PROD-01": ["SQL Server (MSSQLSERVER)", "SQL Server Agent (MSSQLSERVER)", "SQL Server Browser", "SQL Server VSS Writer", "Volume Shadow Copy"],
    "APP-BOS-01": ["World Wide Web Publishing Service", "Windows Process Activation Service", ".NET Runtime Optimization Service", "ASP.NET State Service"],
    "DC-ATL-01": ["Active Directory Domain Services", "DNS Server", "Windows Time", "Group Policy Client", "Netlogon"],
    "ATL-FILE-01": ["File Server Resource Manager", "DFS Replication", "Volume Shadow Copy", "Windows Search"],
    "BACKUP-ATL-01": ["Veeam Backup Service", "Veeam Backup Catalog Service", "Volume Shadow Copy", "Windows Server Backup", "Microsoft Software Shadow Copy Provider"],
}

# Common services that run on all Windows servers
COMMON_SERVICES = [
    "Windows Event Log",
    "Windows Management Instrumentation",
    "Task Scheduler",
    "Windows Update",
    "Windows Firewall",
    "Remote Desktop Services",
    "Server",
    "Workstation",
]

# DCOM components that commonly generate errors
DCOM_COMPONENTS = [
    ("{C2F03A33-21F5-47FA-B4BB-156362A2F239}", "Background Intelligent Transfer Service"),
    ("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", "ShellServiceObjectDelayLoad"),
    ("{000C101C-0000-0000-C000-000000000046}", "Microsoft Office"),
    ("{D63B10C5-BB46-4990-A94F-E40B9D520160}", "RuntimeBroker"),
    ("{316CDED5-E4AE-4B15-9113-7055D84DCC97}", "AppXDeploymentClient"),
]


def event_7036_service_state(ts: str, computer: str, service: str, state: str) -> str:
    """Generate service state change event (7036) - most common System event."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=Service Control Manager
EventCode=7036
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The {service} service entered the {state} state.
"""


def event_6005_eventlog_started(ts: str, computer: str) -> str:
    """Generate Event Log service started event (6005) - indicates system boot."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=EventLog
EventCode=6005
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The Event log service was started.
"""


def event_6013_uptime(ts: str, computer: str, uptime_seconds: int) -> str:
    """Generate system uptime event (6013) - logged daily."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=EventLog
EventCode=6013
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The system uptime is {uptime_seconds} seconds.
"""


def event_37_time_sync(ts: str, computer: str, time_source: str) -> str:
    """Generate time synchronization success event (37) - W32Time."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=Microsoft-Windows-Time-Service
EventCode=37
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The time provider NtpClient is currently receiving valid time data from {time_source}.
"""


def event_10016_dcom(ts: str, computer: str, clsid: str, appname: str) -> str:
    """Generate DCOM permission error (10016) - common noise event."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=Microsoft-Windows-DistributedCOM
EventCode=10016
EventType=3
Type=Warning
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The application-specific permission settings do not grant Local Activation permission for the COM Server application with CLSID {clsid} and APPID {clsid} to the user NT AUTHORITY\\SYSTEM SID (S-1-5-18) from address LocalHost (Using LRPC) running in the application container Unavailable SID (Unavailable). This security permission can be modified using the Component Services administrative tool.
AppName={appname}
"""


def event_1014_dns_timeout(ts: str, computer: str, domain: str) -> str:
    """Generate DNS resolution timeout event (1014)."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=Microsoft-Windows-DNS-Client
EventCode=1014
EventType=2
Type=Warning
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=Name resolution for the name {domain} timed out after none of the configured DNS servers responded.
"""


def event_12_kernel_boot(ts: str, computer: str) -> str:
    """Generate kernel boot event (12) - system startup."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=Microsoft-Windows-Kernel-General
EventCode=12
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=The operating system started at system time {ts.split()[0]}.
"""


def event_6009_os_version(ts: str, computer: str) -> str:
    """Generate OS version event (6009) - logged at boot."""
    record = get_record_number()

    return f"""{ts}
LogName=System
SourceName=EventLog
EventCode=6009
EventType=4
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message=Microsoft (R) Windows (R) 10.0.17763 (Build 17763.5206).
"""


def event_4688(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, process_name: str, command_line: str,
               demo_id: str = None) -> str:
    """Generate process creation event (4688)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()
    process_id = random.randint(1000, 65535)
    parent_process_id = random.randint(500, 5000)

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4688
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Process Creation
RecordNumber={record}
Keywords=Audit Success
Message=A new process has been created.

Creator Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Target Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Process Information:
\tNew Process ID:\t\t0x{process_id:X}
\tNew Process Name:\t{process_name}
\tToken Elevation Type:\tTokenElevationTypeFull (2)
\tMandatory Label:\t\tMandatory Label\\High Mandatory Level
\tCreator Process ID:\t0x{parent_process_id:X}
\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe
\tProcess Command Line:\t{command_line}
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4728(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, admin_user: str, target_user: str, group_name: str,
               demo_id: str = None) -> str:
    """Generate member added to security-enabled global group event (4728)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4728
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Security Group Management
RecordNumber={record}
Keywords=Audit Success
Message=A member was added to a security-enabled global group.

Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-500
\tAccount Name:\t\t{admin_user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Member:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\tCN={target_user},CN=Users,DC=faketshirtco,DC=com

Group:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-512
\tGroup Name:\t\t{group_name}
\tGroup Domain:\t\tFAKETSHIRTCO
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4769(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, service_name: str, source_ip: str,
               demo_id: str = None) -> str:
    """Generate Kerberos service ticket requested event (4769)."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4769
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Kerberos Service Ticket Operations
RecordNumber={record}
Keywords=Audit Success
Message=A Kerberos service ticket was requested.

Account Information:
\tAccount Name:\t\t{user}@FAKETSHIRTCO.COM
\tAccount Domain:\t\tFAKETSHIRTCO.COM
\tLogon GUID:\t\t{{{random.randint(10000000, 99999999):08x}-{random.randint(1000, 9999):04x}-{random.randint(1000, 9999):04x}-{random.randint(1000, 9999):04x}-{random.randint(100000000000, 999999999999):012x}}}

Service Information:
\tService Name:\t\t{service_name}
\tService ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}

Network Information:
\tClient Address:\t\t::ffff:{source_ip}
\tClient Port:\t\t{random.randint(49152, 65535)}

Additional Information:
\tTicket Options:\t\t0x40810000
\tTicket Encryption Type:\t0x12
\tFailure Code:\t\t0x0
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4724(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, admin_user: str, target_user: str,
               demo_id: str = None) -> str:
    """Generate password reset attempt event (4724).

    An attempt was made to reset an account's password.
    Logged on domain controllers when an admin resets a user password.
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4724
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=User Account Management
RecordNumber={record}
Keywords=Audit Success
Message=An attempt was made to reset an account's password.

Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-500
\tAccount Name:\t\t{admin_user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Target Account:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{target_user}
\tAccount Domain:\t\tFAKETSHIRTCO
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4738(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, admin_user: str, target_user: str,
               changed_attributes: str = "PasswordLastSet",
               demo_id: str = None) -> str:
    """Generate user account changed event (4738).

    A user account was changed. Logged when account properties are modified,
    including password changes triggered by admin reset.
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4738
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=User Account Management
RecordNumber={record}
Keywords=Audit Success
Message=A user account was changed.

Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-500
\tAccount Name:\t\t{admin_user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Target Account:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{target_user}
\tAccount Domain:\t\tFAKETSHIRTCO

Changed Attributes:
\tSAM Account Name:\t-
\tDisplay Name:\t\t-
\tUser Principal Name:\t-
\tHome Directory:\t\t-
\tHome Drive:\t\t-
\tScript Path:\t\t-
\tProfile Path:\t\t-
\tUser Workstations:\t-
\tPassword Last Set:\t{ts}
\tAccount Expires:\t\t-
\tPrimary Group ID:\t-
\tAllowed To Delegate To:\t-
\tOld UAC Value:\t\t0x210
\tNew UAC Value:\t\t0x210
\tUser Account Control:\t-
\tUser Parameters:\t-
\tSID History:\t\t-
\tLogon Hours:\t\t-
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


# =============================================================================
# NEW SECURITY EVENT TEMPLATES (Phase 3)
# =============================================================================

# Scheduled task templates for EID 4698
SCHEDULED_TASK_TEMPLATES = [
    ("\\Microsoft\\Windows\\WindowsUpdate\\Automatic App Update", "C:\\Windows\\System32\\UsoClient.exe StartInteractiveScan"),
    ("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "C:\\Windows\\System32\\defrag.exe -c -h -k -g -$"),
    ("\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup", "C:\\Windows\\System32\\cleanmgr.exe /autoclean /d C:"),
    ("\\Microsoft\\Windows\\TaskScheduler\\Maintenance Configurator", "C:\\Windows\\System32\\taskhostw.exe"),
    ("\\Backup\\NightlyBackup", '"C:\\Program Files\\Windows Server Backup\\wbadmin.exe" start backup -quiet'),
    ("\\Monitoring\\HealthCheck", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -File C:\\Scripts\\HealthCheck.ps1"),
]


def event_4740(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, caller_computer: str,
               demo_id: str = None) -> str:
    """Generate account lockout event (4740).

    Key for: Password spray detection, brute force detection.
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4740
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=User Account Management
RecordNumber={record}
Keywords=Audit Success
Message=A user account was locked out.

Subject:
\tSecurity ID:\t\tS-1-5-18
\tAccount Name:\t\t{computer}$
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x3E7

Account That Was Locked Out:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{user}

Additional Information:
\tCaller Computer Name:\t{caller_computer}
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4768(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, source_ip: str,
               result_code: str = "0x0",
               demo_id: str = None) -> str:
    """Generate Kerberos TGT request event (4768).

    Key for: Kerberoasting baseline, AS-REP roasting detection.
    result_code: 0x0=success, 0x6=unknown principal, 0x12=disabled,
                 0x17=expired, 0x18=pre-auth failed.
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    keywords = "Audit Success" if result_code == "0x0" else "Audit Failure"
    ticket_options = random.choice(["0x40810010", "0x50800000", "0x40810000"])
    encryption = random.choice(["0x12", "0x17"])  # AES256, RC4

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4768
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Kerberos Authentication Service
RecordNumber={record}
Keywords={keywords}
Message=A Kerberos authentication ticket (TGT) was requested.

Account Information:
\tAccount Name:\t\t{user}
\tSupplied Realm Name:\tFAKETSHIRTCO.COM
\tUser ID:\t\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}

Service Information:
\tService Name:\t\tkrbtgt
\tService ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-502

Network Information:
\tClient Address:\t\t::ffff:{source_ip}
\tClient Port:\t\t{random.randint(49152, 65535)}

Additional Information:
\tTicket Options:\t\t{ticket_options}
\tResult Code:\t\t{result_code}
\tTicket Encryption Type:\t{encryption}
\tPre-Authentication Type:\t15
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4776(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, workstation: str,
               error_code: str = "0x0",
               demo_id: str = None) -> str:
    """Generate NTLM credential validation event (4776).

    Key for: NTLM relay detection, pass-the-hash detection.
    error_code: 0x0=success, 0xC000006A=bad password,
                0xC0000064=unknown user, 0xC0000234=locked out.
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    keywords = "Audit Success" if error_code == "0x0" else "Audit Failure"

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4776
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Credential Validation
RecordNumber={record}
Keywords={keywords}
Message=The computer attempted to validate the credentials for an account.

Authentication Package:\tMICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account:\t{user}
Source Workstation:\t{workstation}
Error Code:\t{error_code}
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_4698(base_date: str, day: int, hour: int, minute: int, second: int,
               computer: str, user: str, task_name: str, task_content: str,
               demo_id: str = None) -> str:
    """Generate scheduled task created event (4698).

    Key for: Persistence detection (attacker-created tasks).
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4698
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Other Object Access Events
RecordNumber={record}
Keywords=Audit Success
Message=A scheduled task was created.

Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Task Information:
\tTask Name:\t\t{task_name}
\tTask Content:\t\t{task_content}
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


# =============================================================================
# APPLICATION EVENT TEMPLATES
# =============================================================================

def event_application(base_date: str, day: int, hour: int, minute: int, second: int,
                      computer: str, source: str, event_id: int, level: str,
                      message: str, demo_id: str = None) -> str:
    """Generate generic Application log event."""
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    # Map level to EventType
    level_map = {
        "Information": ("0", "Information"),
        "Warning": ("2", "Warning"),
        "Error": ("1", "Error"),
        "Critical": ("1", "Error"),
    }
    event_type, type_str = level_map.get(level, ("0", "Information"))

    event = f"""{ts}
LogName=Application
SourceName={source}
EventCode={event_id}
EventType={event_type}
Type={type_str}
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message={message}
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def event_sql_server(base_date: str, day: int, hour: int, minute: int, second: int,
                     computer: str, event_id: int, level: str, message: str,
                     demo_id: str = None) -> str:
    """Generate SQL Server Application event."""
    return event_application(base_date, day, hour, minute, second,
                             computer, "MSSQLSERVER", event_id, level, message, demo_id)


def event_iis(base_date: str, day: int, hour: int, minute: int, second: int,
              computer: str, event_id: int, level: str, message: str,
              demo_id: str = None) -> str:
    """Generate IIS Application event."""
    return event_application(base_date, day, hour, minute, second,
                             computer, "W3SVC", event_id, level, message, demo_id)


# =============================================================================
# BASELINE GENERATORS
# =============================================================================

def generate_baseline_logons(base_date: str, day: int, hour: int, count: int) -> List[str]:
    """Generate baseline logon events."""
    events = []
    computers = WINDOWS_SERVERS
    logon_types = [2, 3, 10]

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        user = get_random_user()
        computer = random.choice(computers)
        logon_type = random.choice(logon_types)
        source_ip = user.get_ip()

        events.append(event_4624(base_date, day, hour, minute, second,
                                 computer, user.username, logon_type, source_ip))

    return events


def generate_baseline_special_logons(base_date: str, day: int, hour: int) -> List[str]:
    """Generate special privilege logon events."""
    events = []

    # Only during business hours, low frequency
    if hour < 8 or hour > 18:
        return events

    if random.random() > 0.125:  # 12.5% chance
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    admins = ["it.admin", "sec.admin"]
    admin = random.choice(admins)
    computer = random.choice(["DC-01", "DC-02"])

    events.append(event_4672(base_date, day, hour, minute, second, computer, admin))
    return events


def generate_baseline_failed_logons(base_date: str, day: int, hour: int) -> List[str]:
    """Generate occasional failed logon events."""
    events = []

    if random.random() > 0.05:  # 5% chance per hour
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    user = get_random_user()
    source_ip = get_internal_ip()

    events.append(event_4625(base_date, day, hour, minute, second,
                             "DC-01", user.username, source_ip,
                             "Unknown user name or bad password."))
    return events


def generate_baseline_system_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate system restart events (legacy - now minimal)."""
    events = []

    # Only at 3-4 AM on patch days
    if hour not in [3, 4]:
        return events

    # Patch days: day 7 and 14
    is_patch_day = day in [7, 14]

    if is_patch_day and random.random() < 0.8:
        minute = random.randint(5, 45)
        second = random.randint(0, 59)
        computer = random.choice(WINDOWS_SERVERS)
        events.append(event_1074(base_date, day, hour, minute, second,
                                 computer, "Operating System: Service pack (Planned)"))

    return events


def generate_baseline_system_hour(base_date: str, day: int, hour: int, event_count: int) -> List[str]:
    """Generate System channel events for one hour.

    Event distribution:
    - 50% Service state changes (7036)
    - 15% Time sync (37)
    - 15% DCOM errors (10016)
    - 10% DNS timeouts (1014)
    - 5% Uptime reports (6013)
    - 5% Restart events on patch days (1074)
    """
    events = []

    if event_count <= 0:
        return events

    # Get all servers that have services defined
    servers = list(WINDOWS_SERVICES.keys())

    for _ in range(event_count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = ts_winevent(base_date, day, hour, minute, second)
        computer = random.choice(servers)

        # Weighted event selection
        event_type = random.choices(
            ["service", "time_sync", "dcom", "dns", "uptime", "restart"],
            weights=[50, 15, 15, 10, 5, 5],
            k=1
        )[0]

        if event_type == "service":
            # Service state change (7036)
            server_services = WINDOWS_SERVICES.get(computer, COMMON_SERVICES)
            all_services = server_services + COMMON_SERVICES
            service = random.choice(all_services)
            state = random.choice(["running", "stopped", "running"])  # More starts than stops
            events.append(event_7036_service_state(ts, computer, service, state))

        elif event_type == "time_sync":
            # Time synchronization (37)
            # DCs sync from external, others from DC
            if "DC-" in computer:
                time_source = random.choice(["time.windows.com", "time.nist.gov", "pool.ntp.org"])
            else:
                time_source = random.choice(["DC-BOS-01.theFakeTshirtCompany.com", "DC-BOS-02.theFakeTshirtCompany.com"])
            events.append(event_37_time_sync(ts, computer, time_source))

        elif event_type == "dcom":
            # DCOM permission error (10016)
            clsid, appname = random.choice(DCOM_COMPONENTS)
            events.append(event_10016_dcom(ts, computer, clsid, appname))

        elif event_type == "dns":
            # DNS timeout (1014) - occasional
            domains = [
                "update.microsoft.com",
                "download.windowsupdate.com",
                "ctldl.windowsupdate.com",
                "ocsp.digicert.com",
                "crl.microsoft.com",
            ]
            domain = random.choice(domains)
            events.append(event_1014_dns_timeout(ts, computer, domain))

        elif event_type == "uptime":
            # System uptime (6013) - typically once per day per server
            # Calculate approximate uptime in seconds (since last boot or day 0)
            uptime_days = day + 1  # Days since "boot" on day 0
            uptime_seconds = uptime_days * 86400 + hour * 3600 + random.randint(0, 3600)
            events.append(event_6013_uptime(ts, computer, uptime_seconds))

        elif event_type == "restart":
            # Only on patch days (day 7, 14) during maintenance window
            is_patch_day = day in [7, 14]
            is_maintenance_hour = hour in [3, 4]
            if is_patch_day and is_maintenance_hour:
                events.append(event_1074(base_date, day, hour, minute, second,
                                         computer, "Operating System: Service pack (Planned)"))

    return events


def generate_day0_boot_events(base_date: str) -> List[str]:
    """Generate startup events for all servers on Day 0.

    Simulates system boot sequence:
    - Event 12: Kernel boot
    - Event 6009: OS version
    - Event 6005: Event Log started
    - Event 37: Time sync
    - Event 7036: Services starting
    """
    events = []

    # Boot sequence between 05:00 and 06:30
    for computer in WINDOWS_SERVICES.keys():
        boot_hour = 5
        boot_minute = random.randint(0, 30)
        boot_second = random.randint(0, 50)  # Max 50 to allow +5 seconds offset

        ts = ts_winevent(base_date, 0, boot_hour, boot_minute, boot_second)

        # Kernel boot (Event 12)
        events.append(event_12_kernel_boot(ts, computer))

        # OS version (Event 6009) - a few seconds later
        ts = ts_winevent(base_date, 0, boot_hour, boot_minute, boot_second + 2)
        events.append(event_6009_os_version(ts, computer))

        # Event Log started (Event 6005) - a few more seconds
        ts = ts_winevent(base_date, 0, boot_hour, boot_minute, boot_second + 5)
        events.append(event_6005_eventlog_started(ts, computer))

        # Time sync (Event 37) - after network is up
        ts = ts_winevent(base_date, 0, boot_hour, boot_minute + 1, random.randint(0, 30))
        if "DC-" in computer:
            time_source = random.choice(["time.windows.com", "time.nist.gov"])
        else:
            time_source = "DC-BOS-01.theFakeTshirtCompany.com"
        events.append(event_37_time_sync(ts, computer, time_source))

        # Services starting (Event 7036) - spread over a few minutes
        server_services = WINDOWS_SERVICES.get(computer, [])
        all_services = COMMON_SERVICES + server_services
        for i, service in enumerate(all_services):
            service_minute = boot_minute + 1 + (i // 5)  # Stagger services
            service_second = random.randint(0, 59)
            if service_minute >= 60:
                service_minute = 59
            ts = ts_winevent(base_date, 0, boot_hour, service_minute, service_second)
            events.append(event_7036_service_state(ts, computer, service, "running"))

    return events


# =============================================================================
# APPLICATION BASELINE GENERATORS
# =============================================================================

def generate_baseline_sql_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate baseline SQL Server events."""
    events = []
    computer = "BOS-SQL-PROD-01"

    # SQL Server service start on day 0, hour 6
    if day == 0 and hour == 6:
        events.append(event_sql_server(base_date, day, hour, 0, 0, computer,
                                       17162, "Information",
                                       "SQL Server is starting at normal priority base (=7). This is an informational message only. No user action is required."))
        events.append(event_sql_server(base_date, day, hour, 0, 5, computer,
                                       17126, "Information",
                                       "SQL Server is now ready for client connections. This is an informational message; no user action is required."))

    # Occasional backup completion (nightly at 2-3 AM)
    if hour == 2 and random.random() < 0.9:
        events.append(event_sql_server(base_date, day, hour, random.randint(30, 59), random.randint(0, 59), computer,
                                       18264, "Information",
                                       "Database backed up. Database: TShirtDB, creation date(time): 2025/01/01, pages dumped: 45280"))

    # Occasional deadlock detection (business hours, rare)
    if 9 <= hour <= 17 and random.random() < 0.02:
        events.append(event_sql_server(base_date, day, hour, random.randint(0, 59), random.randint(0, 59), computer,
                                       1205, "Warning",
                                       "Transaction (Process ID 58) was deadlocked on lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction."))

    return events


def generate_baseline_iis_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate baseline IIS events for web servers."""
    events = []
    web_servers = ["WEB-01", "WEB-02"]

    # IIS service start on day 0
    if day == 0 and hour == 6:
        for server in web_servers:
            events.append(event_iis(base_date, day, hour, 0, random.randint(10, 30), server,
                                    1073, "Information",
                                    "World Wide Web Publishing Service (W3SVC) successfully registered."))

    # Occasional worker process recycling (low frequency)
    if random.random() < 0.01:
        server = random.choice(web_servers)
        events.append(event_iis(base_date, day, hour, random.randint(0, 59), random.randint(0, 59), server,
                                5060, "Information",
                                "A worker process with process id of '4592' serving application pool 'DefaultAppPool' was shutdown due to worker process recycling."))

    return events


def generate_baseline_app_info_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate miscellaneous Application log events."""
    events = []

    # Windows Update events on patch days
    if day in [7, 14] and hour == 3:
        computer = random.choice(WINDOWS_SERVERS)
        events.append(event_application(base_date, day, hour, random.randint(0, 30), random.randint(0, 59), computer,
                                        "WindowsUpdateClient", 19, "Information",
                                        "Installation Successful: Windows successfully installed the following update: Security Update for Windows (KB5001234)"))

    # Occasional .NET runtime info
    if random.random() < 0.005:
        computer = random.choice(WINDOWS_SERVERS)
        events.append(event_application(base_date, day, hour, random.randint(0, 59), random.randint(0, 59), computer,
                                        ".NET Runtime", 1026, "Information",
                                        "Application: w3wp.exe CoreCLR Version: 6.0.1 .NET Version: 6.0.1"))

    return events


# =============================================================================
# NEW BASELINE GENERATORS (Phase 3: EID 4740, 4768, 4776, 4698)
# =============================================================================

def generate_baseline_kerberos_tgt(base_date: str, day: int, hour: int, count: int) -> List[str]:
    """Generate baseline Kerberos TGT request events (4768).

    Every user/service logon starts with a TGT request. Volume should be
    proportional to logon activity. ~2-3x logon count (machines + users).
    """
    events = []
    dc_computers = ["DC-BOS-01", "DC-BOS-02", "DC-ATL-01"]

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        user = get_random_user()
        computer = random.choice(dc_computers)
        source_ip = user.get_ip()

        # 98% success, 2% failure (mistyped password, expired)
        if random.random() < 0.02:
            result_code = random.choice(["0x18", "0x17", "0x6"])
        else:
            result_code = "0x0"

        events.append(event_4768(base_date, day, hour, minute, second,
                                 computer, user.username, source_ip,
                                 result_code))

    return events


def generate_baseline_ntlm_validation(base_date: str, day: int, hour: int, count: int) -> List[str]:
    """Generate baseline NTLM credential validation events (4776).

    NTLM is used for legacy auth, file shares, internal web apps.
    Lower volume than Kerberos in a modern AD environment.
    """
    events = []
    dc_computers = ["DC-BOS-01", "DC-BOS-02", "DC-ATL-01"]

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        user = get_random_user()
        computer = random.choice(dc_computers)
        ws_name = f"{user.username.split('.')[0].upper()}-PC"

        # 97% success, 3% failure (stale cached creds, typos)
        if random.random() < 0.03:
            error_code = random.choice(["0xC000006A", "0xC0000064"])
        else:
            error_code = "0x0"

        events.append(event_4776(base_date, day, hour, minute, second,
                                 computer, user.username, ws_name, error_code))

    return events


def generate_baseline_account_lockouts(base_date: str, day: int, hour: int) -> List[str]:
    """Generate baseline account lockout events (4740).

    Very low volume: ~1-3 per day during business hours.
    Users forget passwords after weekends, vacations, password resets.
    """
    events = []

    # Only during business hours, very low probability
    if hour < 7 or hour > 18:
        return events

    # ~8% chance per business hour = ~1 lockout/day average
    if random.random() > 0.08:
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    user = get_random_user()
    computer = random.choice(["DC-BOS-01", "DC-BOS-02", "DC-ATL-01"])
    caller = f"{user.username.split('.')[0].upper()}-PC"

    events.append(event_4740(base_date, day, hour, minute, second,
                             computer, user.username, caller))
    return events


def generate_baseline_scheduled_tasks(base_date: str, day: int, hour: int) -> List[str]:
    """Generate baseline scheduled task creation events (4698).

    Low volume: Windows creates/re-registers tasks during updates,
    admin scripts, maintenance. ~2-5/day spread across servers.
    """
    events = []

    # Scheduled tasks are mostly created during maintenance (early morning)
    # or business hours (admin activity)
    if hour in [3, 4]:
        prob = 0.15  # Higher during maintenance window
    elif 9 <= hour <= 16:
        prob = 0.03
    else:
        prob = 0.005

    if random.random() > prob:
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    computer = random.choice(WINDOWS_SERVERS)
    task_name, task_content = random.choice(SCHEDULED_TASK_TEMPLATES)

    # System account for automated tasks, admin for manual
    if hour in [3, 4]:
        user = f"{computer}$"
    else:
        user = random.choice(["it.admin", "sec.admin", "svc.backup"])

    events.append(event_4698(base_date, day, hour, minute, second,
                             computer, user, task_name, task_content))
    return events


# =============================================================================
# WINDOWS DEFENDER BASELINE EVENTS
# =============================================================================

def event_defender(base_date: str, day: int, hour: int, minute: int, second: int,
                   computer: str, event_id: int, event_type_str: str,
                   message: str, demo_id: str = None) -> str:
    """Generate a Windows Defender operational event.

    Uses LogName=Microsoft-Windows-Windows Defender/Operational to match
    real Windows Defender event log channel.
    """
    ts = ts_winevent(base_date, day, hour, minute, second)
    record = get_record_number()

    event = f"""{ts}
LogName=Microsoft-Windows-Windows Defender/Operational
SourceName=Microsoft-Windows-Windows Defender
EventCode={event_id}
EventType=0
Type={event_type_str}
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=None
RecordNumber={record}
Keywords=Classic
Message={message}
"""
    if demo_id:
        event = _insert_demo_id(event, demo_id)
    return event


def generate_baseline_defender_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate baseline Windows Defender operational events.

    Produces ambient Defender events that real Windows servers generate:
    - EventCode 1000: Scan started (nightly, 02:00-03:00 AM)
    - EventCode 1001: Scan completed (5-15 min after start)
    - EventCode 2000: Definition updates (2-3 per day, spread across hours)
    - EventCode 5007: Configuration changed (patch day only, day 7)

    Volume: ~40-50 events/day across all Windows servers = ~640 over 14 days.
    """
    events = []

    # Scheduled scan: 02:00-03:00 AM on every server
    if hour == 2:
        for computer in WINDOWS_SERVERS:
            # Stagger scan starts across the hour
            scan_minute = random.randint(0, 40)
            scan_second = random.randint(0, 59)

            # 1000: Scan started
            events.append(event_defender(
                base_date, day, hour, scan_minute, scan_second,
                computer, 1000, "Information",
                "Microsoft Defender Antivirus scan has started.\n"
                "\tScan Type: AntiSpyware\n"
                "\tScan Parameters: Quick Scan\n"
                f"\tUser: {computer}$\\SYSTEM"
            ))

            # 1001: Scan completed (5-15 min later)
            complete_minute = min(scan_minute + random.randint(5, 15), 59)
            duration_sec = (complete_minute - scan_minute) * 60 + random.randint(10, 50)
            items_scanned = random.randint(45000, 120000)

            events.append(event_defender(
                base_date, day, hour, complete_minute, random.randint(0, 59),
                computer, 1001, "Information",
                "Microsoft Defender Antivirus scan has finished.\n"
                "\tScan Type: AntiSpyware\n"
                "\tScan Parameters: Quick Scan\n"
                f"\tScan Duration: {duration_sec} seconds\n"
                f"\tItems Scanned: {items_scanned}\n"
                "\tThreats Detected: 0"
            ))

    # Definition updates: 2-3 times/day spread across hours 6, 12, 18
    if hour in [6, 12, 18]:
        for computer in WINDOWS_SERVERS:
            # ~80% chance each update window (so avg ~2.4/day/server)
            if random.random() > 0.80:
                continue

            minute = random.randint(0, 59)
            second = random.randint(0, 59)

            # Build version numbers based on day progression
            build_base = 600 + day * 2 + (hour // 6)
            prev_build = build_base - 1

            events.append(event_defender(
                base_date, day, hour, minute, second,
                computer, 2000, "Information",
                "Microsoft Defender Antivirus Security Intelligence Update.\n"
                f"\tCurrent Security Intelligence Version: 1.407.{build_base}.0\n"
                f"\tPrevious Security Intelligence Version: 1.407.{prev_build}.0\n"
                "\tUpdate Source: Microsoft Update Server\n"
                "\tUpdate Stage: Search"
            ))

    # Configuration change: patch day (day 7) during maintenance (03:00-04:00)
    if day == 7 and hour == 3:
        for computer in WINDOWS_SERVERS:
            if random.random() > 0.70:  # Not all servers at once
                continue

            minute = random.randint(10, 50)
            second = random.randint(0, 59)

            events.append(event_defender(
                base_date, day, hour, minute, second,
                computer, 5007, "Information",
                "Microsoft Windows Defender Antivirus Configuration has changed.\n"
                "\tFeature Name: Signature Update Interval\n"
                "\tOld Value: 24\n"
                "\tNew Value: 8"
            ))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_wineventlog(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_dir: str = None,
    quiet: bool = False,
) -> int:
    """Generate Windows Event Logs.

    Generates Security, System, and Application event logs.
    Integrates ransomware_attempt, exfil, and cpu_runaway scenarios.
    """

    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = get_output_path("windows", "").parent / "windows"

    out_dir.mkdir(parents=True, exist_ok=True)

    security_path = out_dir / "wineventlog_security.log"
    system_path = out_dir / "wineventlog_system.log"
    application_path = out_dir / "wineventlog_application.log"

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Initialize scenario support objects
    config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
    company = Company()
    time_utils = TimeUtils(start_date)

    # Initialize scenarios
    ransomware_scenario = None
    if "ransomware_attempt" in active_scenarios:
        ransomware_scenario = RansomwareAttemptScenario(demo_id_enabled=True)

    cpu_runaway_scenario = None
    if "cpu_runaway" in active_scenarios:
        try:
            from scenarios.ops.cpu_runaway import CpuRunawayScenario
            cpu_runaway_scenario = CpuRunawayScenario(demo_id_enabled=True)
        except ImportError:
            pass

    exfil_scenario = None
    if "exfil" in active_scenarios:
        try:
            from scenarios.security.exfil import ExfilScenario
            exfil_scenario = ExfilScenario(config, company, time_utils)
        except ImportError:
            pass

    phishing_test_scenario = None
    if "phishing_test" in active_scenarios:
        phishing_test_scenario = PhishingTestScenario(demo_id_enabled=True)

    base_logons_per_peak_hour = max(1, int(5 * scale))
    base_system_events_per_peak_hour = max(1, int(30 * scale))  # ~30 System events/peak hour
    base_kerberos_tgt_per_peak_hour = max(1, int(10 * scale))   # TGT requests (higher than logons)
    base_ntlm_per_peak_hour = max(1, int(3 * scale))           # NTLM validation (lower than Kerberos)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Windows Event Log Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {out_dir}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    security_events = []
    system_events = []
    application_events = []

    global RECORD_NUMBER
    RECORD_NUMBER = 0

    # Generate Day 0 boot events for all servers
    system_events.extend(generate_day0_boot_events(start_date))

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [WinEvent] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        for hour in range(24):
            # Calculate logon count using natural variation
            logon_count = calc_natural_events(base_logons_per_peak_hour, start_date, day, hour, "windows")

            # Calculate system event count using natural variation
            system_count = calc_natural_events(base_system_events_per_peak_hour, start_date, day, hour, "windows")

            # Calculate Kerberos/NTLM counts
            kerberos_count = calc_natural_events(base_kerberos_tgt_per_peak_hour, start_date, day, hour, "windows")
            ntlm_count = calc_natural_events(base_ntlm_per_peak_hour, start_date, day, hour, "windows")

            # Security events (baseline)
            security_events.extend(generate_baseline_logons(start_date, day, hour, logon_count))
            security_events.extend(generate_baseline_special_logons(start_date, day, hour))
            security_events.extend(generate_baseline_failed_logons(start_date, day, hour))
            security_events.extend(generate_baseline_kerberos_tgt(start_date, day, hour, kerberos_count))
            security_events.extend(generate_baseline_ntlm_validation(start_date, day, hour, ntlm_count))
            security_events.extend(generate_baseline_account_lockouts(start_date, day, hour))
            security_events.extend(generate_baseline_scheduled_tasks(start_date, day, hour))
            security_events.extend(generate_baseline_defender_events(start_date, day, hour))

            # System events (baseline) - NEW comprehensive generator
            system_events.extend(generate_baseline_system_hour(start_date, day, hour, system_count))

            # Application events (baseline)
            application_events.extend(generate_baseline_sql_events(start_date, day, hour))
            application_events.extend(generate_baseline_iis_events(start_date, day, hour))
            application_events.extend(generate_baseline_app_info_events(start_date, day, hour))

            # ===== SCENARIO EVENTS =====

            # Ransomware scenario (Security events)
            if ransomware_scenario:
                security_events.extend(ransomware_scenario.winevent_hour(day, hour, time_utils))

            # Phishing test scenario (4688 browser launch events)
            if phishing_test_scenario:
                security_events.extend(phishing_test_scenario.winevent_hour(day, hour, time_utils))

            # Exfil scenario (Security events)
            if exfil_scenario:
                exfil_events = exfil_scenario.winevent_hour(day, hour)
                for e in exfil_events:
                    if isinstance(e, str):
                        security_events.append(e)
                    else:
                        # Format dict to event string
                        security_events.append(format_scenario_event(
                            start_date, day, hour, e, time_utils
                        ))

            # CPU Runaway scenario (Application events - SQL Server)
            if cpu_runaway_scenario:
                cpu_events = cpu_runaway_scenario.winevent_get_events(day, hour)
                for e in cpu_events:
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    application_events.append(event_sql_server(
                        start_date, day, hour, minute, second,
                        "BOS-SQL-PROD-01",
                        e.get("event_id", 17883),
                        e.get("level", "Warning"),
                        e.get("message", "SQL Server event"),
                        demo_id="cpu_runaway"
                    ))

        if not quiet:
            print(f"  [WinEvent] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Write output
    with open(security_path, "w") as f:
        for event in security_events:
            f.write(event + "\n")

    with open(system_path, "w") as f:
        for event in system_events:
            f.write(event + "\n")

    with open(application_path, "w") as f:
        for event in application_events:
            f.write(event + "\n")

    total = len(security_events) + len(system_events) + len(application_events)

    if not quiet:
        # Count scenario events
        exfil_count = sum(1 for e in security_events if 'demo_id=exfil' in e)
        cpu_count = sum(1 for e in application_events if 'demo_id=cpu_runaway' in e)
        print(f"  [WinEvent] Complete! {total:,} events", file=sys.stderr)
        print(f"             Security: {len(security_events):,}, System: {len(system_events):,}, Application: {len(application_events):,}", file=sys.stderr)
        if exfil_count or cpu_count:
            print(f"             Scenario events: exfil={exfil_count}, cpu_runaway={cpu_count}", file=sys.stderr)

    return total


def format_scenario_event(base_date: str, day: int, hour: int, event_dict: dict,
                          time_utils: TimeUtils) -> str:
    """Format a scenario event dictionary to a log string."""
    minute = event_dict.get("minute", random.randint(0, 59))
    second = event_dict.get("second", random.randint(0, 59))
    computer = event_dict.get("computer", "BOS-DC-01")
    user = event_dict.get("user", "unknown")
    event_id = event_dict.get("event_id", 4624)
    demo_id = event_dict.get("demo_id")

    # Route to appropriate event generator
    if event_id == 4624:
        return event_4624(base_date, day, hour, minute, second, computer, user,
                          event_dict.get("logon_type", 3),
                          event_dict.get("source_ip", "10.10.30.50"))
    elif event_id == 4625:
        event = event_4625(base_date, day, hour, minute, second, computer, user,
                          event_dict.get("source_ip", "10.10.30.50"),
                          event_dict.get("reason", "Unknown user name or bad password."))
        if demo_id:
            event = _insert_demo_id(event, demo_id)
        return event
    elif event_id == 4672:
        event = event_4672(base_date, day, hour, minute, second, computer, user)
        if demo_id:
            event = _insert_demo_id(event, demo_id)
        return event
    elif event_id == 4688:
        return event_4688(base_date, day, hour, minute, second, computer, user,
                          event_dict.get("process_name", "cmd.exe"),
                          event_dict.get("command_line", "cmd.exe"),
                          demo_id)
    elif event_id == 4728:
        return event_4728(base_date, day, hour, minute, second, computer,
                          event_dict.get("admin_user", "it.admin"),
                          user, event_dict.get("group_name", "Domain Admins"),
                          demo_id)
    elif event_id == 4724:
        return event_4724(base_date, day, hour, minute, second, computer,
                          event_dict.get("admin_user", "it.admin"),
                          user, demo_id)
    elif event_id == 4738:
        return event_4738(base_date, day, hour, minute, second, computer,
                          event_dict.get("admin_user", "it.admin"),
                          user, event_dict.get("changed_attributes", "PasswordLastSet"),
                          demo_id)
    elif event_id == 4740:
        return event_4740(base_date, day, hour, minute, second, computer,
                          user, event_dict.get("caller_computer", "UNKNOWN-PC"),
                          demo_id)
    elif event_id == 4768:
        return event_4768(base_date, day, hour, minute, second, computer, user,
                          event_dict.get("source_ip", "10.10.30.50"),
                          event_dict.get("result_code", "0x0"),
                          demo_id)
    elif event_id == 4776:
        return event_4776(base_date, day, hour, minute, second, computer,
                          user, event_dict.get("workstation", "UNKNOWN-PC"),
                          event_dict.get("error_code", "0x0"),
                          demo_id)
    elif event_id == 4698:
        return event_4698(base_date, day, hour, minute, second, computer,
                          user, event_dict.get("task_name", "\\Unknown\\Task"),
                          event_dict.get("task_content", "unknown.exe"),
                          demo_id)
    elif event_id == 4769:
        return event_4769(base_date, day, hour, minute, second, computer, user,
                          event_dict.get("service_name", "cifs/FILE-01"),
                          event_dict.get("source_ip", "10.10.30.50"),
                          demo_id)
    else:
        # Generic security event
        ts = ts_winevent(base_date, day, hour, minute, second)
        record = get_record_number()
        event = f"""{ts}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode={event_id}
EventType=0
Type=Information
ComputerName={computer}.theFakeTshirtCompany.com
TaskCategory=Other
RecordNumber={record}
Keywords=Audit Success
Message={event_dict.get('message', 'Security event')}
"""
        if demo_id:
            event = _insert_demo_id(event, demo_id)
        return event


def main():
    parser = argparse.ArgumentParser(description="Generate Windows Event Logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output-dir")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_wineventlog(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_dir=args.output_dir, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
