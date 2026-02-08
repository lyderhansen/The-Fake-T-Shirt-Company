#!/usr/bin/env python3
"""
Microsoft SQL Server Error Log Generator.
Generates realistic ERRORLOG entries for SQL-PROD-01.

Baseline events:
- Startup/recovery messages (day 0)
- Nightly backup completions (02:00-03:00)
- Periodic checkpoints (FlushCache)
- User and service account logins
- Occasional deadlocks

Scenario events:
- cpu_runaway: Non-yielding scheduler, I/O timeouts, backup stuck, KILL + restart
- exfil: Failed login brute-force (lateral movement), xp_cmdshell (exfil)

Output format: Native SQL Server ERRORLOG
  YYYY-MM-DD HH:MM:SS.cc source      message
  (verified against real SQL Server 2019 ERRORLOG)

Splunk sourcetype: FAKE:mssql:errorlog
Compatible with: Splunk Add-on for Microsoft SQL Server (mssql:errorlog)
"""

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path, Config
from shared.time_utils import TimeUtils
from shared.company import Company
from scenarios.registry import expand_scenarios


# =============================================================================
# CONSTANTS
# =============================================================================

FILE_MSSQL_ERRORLOG = "mssql_errorlog.log"

# SQL-PROD-01 identity
SQL_HOST = "SQL-PROD-01"
SQL_IP = "10.10.20.30"
SQL_DOMAIN = "FAKETSHIRT"
SQL_PROCESS_ID = 1848

# Database names
DATABASES = ["master", "msdb", "model", "tempdb", "TShirtDB"]
PRIMARY_DB = "TShirtDB"

# Service accounts that connect to SQL
SERVICE_ACCOUNTS = [
    {"user": "svc_ecommerce", "client_ip": "172.16.1.10", "auth": "SQL Server authentication"},   # WEB-01
    {"user": "svc_ecommerce", "client_ip": "172.16.1.11", "auth": "SQL Server authentication"},   # WEB-02
    {"user": "svc_finance", "client_ip": "10.10.20.40", "auth": "SQL Server authentication"},     # APP-BOS-01
    {"user": "svc_backup", "client_ip": "10.20.20.50", "auth": "SQL Server authentication"},      # BACKUP-ATL-01
]

# Human users who connect (DBAs, IT staff)
DBA_USERS = [
    {"user": "steve.jackson", "client_ip": "10.20.30.20", "auth": "Windows authentication"},   # DBA Atlanta
    {"user": "jessica.brown", "client_ip": "10.20.30.15", "auth": "Windows authentication"},   # IT Admin Atlanta
    {"user": "mike.johnson", "client_ip": "10.10.30.11", "auth": "Windows authentication"},    # CTO Boston
]

# Backup configuration
BACKUP_SPID = 22
BACKUP_PATH = "G:\\Backup"
DATA_PATH = "G:\\Data"
BACKUP_PAGES = 45280
BACKUP_DURATION_SEC = 23.456


# =============================================================================
# OUTPUT FORMAT
# =============================================================================

def format_mssql_event(ts: datetime, source: str, error: int = 0,
                       severity: int = 0, state: int = 0,
                       message: str = "", demo_id: str = None) -> str:
    """Format a single MSSQL Error Log entry.

    Timestamp format: YYYY-MM-DD HH:MM:SS.cc (2-digit centiseconds)
    Source: Server (system-wide), spidNNs (system spid), spidNN (user), Logon
    Verified against real SQL Server 2019 ERRORLOG.
    """
    timestamp = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{ts.microsecond // 10000:02d}"

    if error > 0:
        # Error entries: header line with timestamp, message line indented (no timestamp)
        line = f"{timestamp} {source:<12}Error: {error}, Severity: {severity}, State: {state}.\n"
        line += f"{'':>22} {'':>12}{message}"
    else:
        line = f"{timestamp} {source:<12}{message}"

    if demo_id:
        line += f" demo_id={demo_id}"
    return line


# =============================================================================
# BASELINE: STARTUP EVENTS (Day 0 only)
# =============================================================================

def generate_startup_events(base_date: datetime) -> List[str]:
    """Generate SQL Server startup sequence events."""
    events = []
    ts = datetime(base_date.year, base_date.month, base_date.day, 6, 0, 0, 90000)

    messages = [
        (0,    "Server",  "Microsoft SQL Server 2022 (RTM-CU12) - 16.0.4120.1 (X64)"),
        (0,    "Server",  f"Server process ID is {SQL_PROCESS_ID}."),
        (0,    "Server",  "Authentication mode is MIXED."),
        (0,    "Server",  f"Logging SQL Server messages in file 'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\Log\\ERRORLOG'."),
        (0,    "Server",  "SQL Server detected 2 sockets with 8 cores per socket and 16 logical processors per socket, 16 total logical processors; using 16 logical processors based on SQL Server licensing. This is an informational message; no user action is required."),
        (0,    "Server",  "SQL Server is starting at normal priority base (=7). This is an informational message only. No user action is required."),
        (0,    "Server",  "Detected 65536 MB of RAM. This is an informational message; no user action is required."),
        (100,  "Server",  "Using conventional memory in the memory manager."),
        (200,  "Server",  "Default collation: SQL_Latin1_General_CP1_CI_AS (us_english 1033)"),
        (500,  "spid10s", "Starting up database 'master'."),
        (600,  "spid10s", "Starting up database 'msdb'."),
        (700,  "spid10s", "Starting up database 'model'."),
        (800,  "spid12s", f"Starting up database '{PRIMARY_DB}'."),
        (1200, "spid12s", f"Recovery of database '{PRIMARY_DB}' (5) is 100% complete (elapsed time: 2 seconds). This is an informational message only. No user action is required."),
        (1500, "Server",  "SQL Server is now ready for client connections. This is an informational message; no user action is required."),
    ]

    for offset_ms, source, message in messages:
        event_ts = ts + timedelta(milliseconds=offset_ms)
        events.append(format_mssql_event(event_ts, source, message=message))

    return events


# =============================================================================
# BASELINE: NIGHTLY BACKUP
# =============================================================================

def generate_backup_event(base_date: datetime, day: int,
                          cpu_runaway_active: bool = False) -> List[str]:
    """Generate nightly backup completion event.

    Backup runs at ~02:00-02:30. During cpu_runaway (day 10-11) the backup
    is stuck, so we skip the completion message.
    """
    events = []

    # Skip backup completion during cpu_runaway (it's stuck!)
    if cpu_runaway_active and day in (10, 11):
        return events

    # 90% chance of backup event (occasional skip for variety)
    if random.random() > 0.90:
        return events

    minute = random.randint(25, 55)
    second = random.randint(0, 59)
    cs = random.randint(0, 99)
    ts = datetime(base_date.year, base_date.month, base_date.day,
                  2, minute, second, cs * 10000) + timedelta(days=day)

    date_str = ts.strftime("%Y%m%d")
    duration = round(BACKUP_DURATION_SEC + random.uniform(-3, 5), 3)
    pages = BACKUP_PAGES + random.randint(-500, 500)
    mb_sec = round(pages * 8 / 1024 / duration, 3)

    events.append(format_mssql_event(
        ts, f"spid{BACKUP_SPID}",
        message=f"Backup database successfully processed {pages} pages in {duration} seconds ({mb_sec} MB/sec)."
    ))

    return events


# =============================================================================
# BASELINE: CHECKPOINTS
# =============================================================================

def generate_checkpoint_events(base_date: datetime, day: int, hour: int) -> List[str]:
    """Generate periodic FlushCache checkpoint events.

    Checkpoints happen roughly every 30 minutes during active hours.
    """
    events = []

    # Only during hours with activity
    if hour < 6 or hour > 22:
        return events

    # Two checkpoints per hour (roughly every 30 min)
    for offset_min in [random.randint(5, 25), random.randint(35, 55)]:
        # Skip occasionally for variety
        if random.random() < 0.15:
            continue

        second = random.randint(0, 59)
        cs = random.randint(0, 99)
        ts = datetime(base_date.year, base_date.month, base_date.day,
                      hour, offset_min, second, cs * 10000) + timedelta(days=day)

        dirty_pages = random.randint(50, 2000)
        events.append(format_mssql_event(
            ts, "Server",
            message=f"FlushCache: cleaned up {dirty_pages} dirty pages from buffer pool (database '{PRIMARY_DB}')."
        ))

    return events


# =============================================================================
# BASELINE: LOGIN EVENTS
# =============================================================================

def generate_login_events(base_date: datetime, day: int, hour: int,
                          scale: float = 1.0) -> List[str]:
    """Generate successful login events for service accounts and DBAs."""
    events = []

    # Service accounts: frequent during business hours, some at night
    if 6 <= hour <= 22:
        svc_count = max(1, int(random.randint(2, 5) * scale))
    elif hour in (0, 1, 2, 3):
        svc_count = random.randint(0, 1)  # Backup window
    else:
        svc_count = 0

    for _ in range(svc_count):
        svc = random.choice(SERVICE_ACCOUNTS)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        cs = random.randint(0, 99)
        ts = datetime(base_date.year, base_date.month, base_date.day,
                      hour, minute, second, cs * 10000) + timedelta(days=day)

        events.append(format_mssql_event(
            ts, "Logon",
            message=f"Login succeeded for user '{svc['user']}'. Connection made using {svc['auth']}. [CLIENT: {svc['client_ip']}]"
        ))

    # DBA logins: business hours only, 0-2 per hour
    if 8 <= hour <= 17:
        dba_count = random.randint(0, 1) if random.random() < 0.3 else 0
        for _ in range(dba_count):
            dba = random.choice(DBA_USERS)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            events.append(format_mssql_event(
                ts, "Logon",
                message=f"Login succeeded for user '{SQL_DOMAIN}\\{dba['user']}'. Connection made using {dba['auth']}. [CLIENT: {dba['client_ip']}]"
            ))

    return events


# =============================================================================
# BASELINE: DEADLOCKS
# =============================================================================

def generate_deadlock_events(base_date: datetime, day: int, hour: int) -> List[str]:
    """Generate occasional deadlock events (~2% chance per business hour)."""
    events = []

    if not (9 <= hour <= 17):
        return events

    if random.random() > 0.02:
        return events

    spid = random.randint(50, 120)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    cs = random.randint(0, 99)
    ts = datetime(base_date.year, base_date.month, base_date.day,
                  hour, minute, second, cs * 10000) + timedelta(days=day)

    events.append(format_mssql_event(
        ts, f"spid{spid}",
        error=1205, severity=13, state=45,
        message=f"Transaction (Process ID {spid}) was deadlocked on lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction."
    ))

    return events


# =============================================================================
# SCENARIO: cpu_runaway MSSQL EVENTS
# =============================================================================

def generate_cpu_runaway_events(base_date: datetime, day: int, hour: int,
                                cpu_runaway_scenario) -> List[str]:
    """Generate MSSQL Error Log events for cpu_runaway scenario.

    Uses the scenario's get_severity() for timeline alignment with
    Perfmon/WinEventLog/ASA events.

    Timeline:
        Day 10 02:00: Backup starts (gets stuck)
        Day 10 02:00-07:59: Warning errors (non-yielding, I/O)
        Day 10 08:00+: Critical errors (escalation)
        Day 11 00:00-10:29: Critical (backup unresponsive)
        Day 11 10:30: KILL issued by steve.jackson, service restart
        Day 11 10:30+: Recovery messages
    """
    events = []
    if not cpu_runaway_scenario:
        return events

    severity = cpu_runaway_scenario.get_severity(day, hour)
    if severity == 0:
        return events

    demo_id = "cpu_runaway"
    cfg = cpu_runaway_scenario.cfg

    # Day 10: Backup starts and gets stuck
    if day == cfg.start_day and hour == cfg.backup_hour:
        ts = datetime(base_date.year, base_date.month, base_date.day,
                      cfg.backup_hour, 0, 1, 230000) + timedelta(days=day)
        date_str = ts.strftime("%Y%m%d")
        events.append(format_mssql_event(
            ts, f"spid{BACKUP_SPID}",
            message=f"BACKUP DATABASE [{PRIMARY_DB}] TO DISK = N'{BACKUP_PATH}\\{PRIMARY_DB}_full_{date_str}.bak' WITH NOFORMAT, NOINIT, NAME = N'{PRIMARY_DB}-Full Backup', SKIP, NOREWIND, NOUNLOAD, STATS = 10",
            demo_id=demo_id
        ))

    # Warning phase (Day 10 after backup start, before hour 8)
    if severity == 1:
        # Non-yielding scheduler warning (30% chance/hour)
        if random.random() < 0.30:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            sched = random.randint(0, 3)
            worker = random.randint(0x100000000000, 0xFFFFFFFFFFFF)
            kernel_ms = random.randint(50000, 200000)
            user_ms = random.randint(100000, 500000)

            events.append(format_mssql_event(
                ts, "spid67",
                error=17883, severity=10, state=1,
                message=(
                    f"Process 0:0:0 (0x0043) Worker 0x{worker:016X} appears to be non-yielding on Scheduler {sched}. "
                    f"Thread creation time: {ts.strftime('%Y-%m-%dT%H:%M:%S')}. "
                    f"Approx Thread CPU Used: kernel {kernel_ms} ms, user {user_ms} ms."
                ),
                demo_id=demo_id
            ))

        # I/O delay warning (20% chance/hour)
        if random.random() < 0.20:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            date_str = (base_date + timedelta(days=day)).strftime("%Y%m%d")
            count = random.randint(3, 15)

            events.append(format_mssql_event(
                ts, "spid67",
                error=833, severity=10, state=2,
                message=f"SQL Server has encountered {count} occurrence(s) of I/O requests taking longer than 15 seconds to complete on file [{BACKUP_PATH}\\{PRIMARY_DB}_full_{date_str}.bak].",
                demo_id=demo_id
            ))

    # Critical phase (Day 10 hour 8+, Day 11 before fix)
    if severity == 2:
        # Non-yielding scheduler error (50-60% chance/hour)
        chance = 0.50 if day == cfg.start_day else 0.60
        if random.random() < chance:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            sched = random.randint(0, 3)
            worker = random.randint(0x100000000000, 0xFFFFFFFFFFFF)

            events.append(format_mssql_event(
                ts, "spid67",
                error=17883, severity=16, state=1,
                message=f"Process 0:0:0 (0x0043) Worker 0x{worker:016X} appears to be non-yielding on Scheduler {sched}.",
                demo_id=demo_id
            ))

        # Backup unresponsive (30-40% chance/hour)
        chance = 0.30 if day == cfg.start_day else 0.40
        if random.random() < chance:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            date_str = (base_date + timedelta(days=cfg.start_day)).strftime("%Y%m%d")
            events.append(format_mssql_event(
                ts, "spid67",
                error=19406, severity=16, state=1,
                message=f"The backup set in file '{BACKUP_PATH}\\{PRIMARY_DB}_full_{date_str}.bak' was created by BACKUP DATABASE and cannot be used for this restore operation.",
                demo_id=demo_id
            ))

        # I/O delay on data file (25-30% chance/hour)
        if random.random() < 0.28:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            count = random.randint(10, 50)
            events.append(format_mssql_event(
                ts, "spid67",
                error=833, severity=10, state=2,
                message=f"SQL Server has encountered {count} occurrence(s) of I/O requests taking longer than 15 seconds to complete on file [{DATA_PATH}\\{PRIMARY_DB}.mdf].",
                demo_id=demo_id
            ))

        # Memory pressure (15-20% chance/hour)
        if random.random() < 0.18:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            events.append(format_mssql_event(
                ts, "Server",
                error=701, severity=17, state=123,
                message="There is insufficient system memory in resource pool 'default' to run this query.",
                demo_id=demo_id
            ))

    # Fix time (Day 11 10:30)
    # Note: get_severity(day, hour) with minute=0 returns 2 (critical) for fix_hour,
    # because fix happens at minute 30. We check the fix condition directly.
    if day == cfg.end_day and hour == cfg.fix_hour:
        fix_ts = datetime(base_date.year, base_date.month, base_date.day,
                          cfg.fix_hour, cfg.fix_min, 0, 0) + timedelta(days=day)

        fix_messages = [
            (0,    "spid51",  None, f"KILL command issued for SPID 67 by login '{SQL_DOMAIN}\\steve.jackson' from host [10.20.30.20]."),
            (3,    "Server",  None, "Process 67 was killed by KILL command."),
            (5,    "Server",  None, "SQL Server shutdown was initiated."),
            (15,   "Server",  None, "SQL Server is terminating because of a system shutdown."),
            (30,   "Server",  None, f"Microsoft SQL Server 2022 (RTM-CU12) - 16.0.4120.1 (X64)"),
            (30,   "Server",  None, f"Server process ID is {SQL_PROCESS_ID}."),
            (31,   "Server",  None, "SQL Server is starting at normal priority base (=7). This is an informational message only. No user action is required."),
            (32,   "spid10s", None, "Starting up database 'master'."),
            (33,   "spid12s", None, f"Starting up database '{PRIMARY_DB}'."),
            (35,   "spid12s", None, f"Recovery of database '{PRIMARY_DB}' (5) is 100% complete (elapsed time: 3 seconds). This is an informational message only. No user action is required."),
            (38,   "Server",  None, "SQL Server is now ready for client connections. This is an informational message; no user action is required."),
        ]

        for offset_sec, source, error_info, message in fix_messages:
            event_ts = fix_ts + timedelta(seconds=offset_sec)
            events.append(format_mssql_event(event_ts, source, message=message, demo_id=demo_id))

    return events


# =============================================================================
# SCENARIO: exfil MSSQL EVENTS
# =============================================================================

def generate_exfil_events(base_date: datetime, day: int, hour: int,
                          exfil_scenario) -> List[str]:
    """Generate MSSQL Error Log events for exfil scenario.

    Lateral Movement (Day 5-7): Failed SQL login attempts from compromised host
    Persistence/Exfil (Day 11-13): xp_cmdshell, bulk export
    """
    events = []
    if not exfil_scenario:
        return events

    demo_id = "exfil"

    # Lateral movement: failed logins (Day 5-7, business hours)
    if 5 <= day <= 7 and 9 <= hour <= 17:
        # Jessica Brown's compromised workstation probing SQL
        attacker_ip = "10.20.30.15"  # jessica.brown ATL

        failed_users = [
            ("sa", "Password did not match that for the login provided."),
            ("admin", "Could not find a login matching the name provided."),
            (f"{SQL_DOMAIN}\\jessica.brown", "Token-based server access validation failed with an infrastructure error. Check for previous errors."),
            ("dbadmin", "Could not find a login matching the name provided."),
            ("sqluser", "Password did not match that for the login provided."),
        ]

        # 2-5 attempts per hour during active lateral phase
        attempts = random.randint(2, 5) if random.random() < 0.6 else 0
        for _ in range(attempts):
            user, reason = random.choice(failed_users)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            events.append(format_mssql_event(
                ts, "Logon",
                error=18456, severity=14, state=1,
                message=f"Login failed for user '{user}'. Reason: {reason} [CLIENT: {attacker_ip}]",
                demo_id=demo_id
            ))

    # Persistence/Exfil: suspicious activity (Day 11-13, business hours)
    if 11 <= day <= 13 and 10 <= hour <= 16:
        alex_ip = "10.10.30.55"  # alex.miller Boston

        # xp_cmdshell invocation (once per day during exfil window)
        if hour == 11 and random.random() < 0.7:
            minute = random.randint(10, 50)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            spid = random.randint(80, 120)
            events.append(format_mssql_event(
                ts, f"spid{spid}",
                message=f"xp_cmdshell was invoked by login '{SQL_DOMAIN}\\alex.miller' from host [{alex_ip}].",
                demo_id=demo_id
            ))

        # Staging table creation
        if hour == 12 and random.random() < 0.5:
            minute = random.randint(5, 30)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            spid = random.randint(80, 120)
            events.append(format_mssql_event(
                ts, f"spid{spid}",
                message="SELECT INTO created table 'tempdb..#export_staging'.",
                demo_id=demo_id
            ))

        # Bulk export
        if hour == 14 and random.random() < 0.5:
            minute = random.randint(10, 50)
            second = random.randint(0, 59)
            cs = random.randint(0, 99)
            ts = datetime(base_date.year, base_date.month, base_date.day,
                          hour, minute, second, cs * 10000) + timedelta(days=day)

            spid = random.randint(80, 120)
            rows = random.randint(15000, 85000)
            events.append(format_mssql_event(
                ts, f"spid{spid}",
                message=f"Bulk export to file 'C:\\Users\\Public\\staging\\finance_export_{day}.csv' completed. Rows exported: {rows}.",
                demo_id=demo_id
            ))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_mssql_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_dir: str = None,
    quiet: bool = False,
) -> int:
    """Generate Microsoft SQL Server Error Log.

    Produces a single output file: mssql_errorlog.log
    in the native SQL Server ERRORLOG format.
    """

    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = get_output_path("windows", "").parent / "windows"

    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = out_dir / FILE_MSSQL_ERRORLOG

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Initialize scenario objects
    config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
    company = Company()
    time_utils = TimeUtils(start_date)

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

    cpu_runaway_active = cpu_runaway_scenario is not None

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  MSSQL Error Log Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    base_date = datetime.strptime(start_date, "%Y-%m-%d")
    all_events = []

    # Day 0: Startup events
    all_events.extend(generate_startup_events(base_date))

    # Per-day generation
    for day in range(days):
        # Nightly backup
        all_events.extend(generate_backup_event(base_date, day, cpu_runaway_active))

        # Per-hour events
        for hour in range(24):
            # Baseline
            all_events.extend(generate_checkpoint_events(base_date, day, hour))
            all_events.extend(generate_login_events(base_date, day, hour, scale))
            all_events.extend(generate_deadlock_events(base_date, day, hour))

            # Scenarios
            if cpu_runaway_scenario:
                all_events.extend(generate_cpu_runaway_events(
                    base_date, day, hour, cpu_runaway_scenario))
            if exfil_scenario:
                all_events.extend(generate_exfil_events(
                    base_date, day, hour, exfil_scenario))

    # Sort events by timestamp (extract from first 22 chars)
    all_events.sort(key=lambda e: e[:22])

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(event + "\n")

    total_events = len(all_events)

    if not quiet:
        print(f"  Generated {total_events:,} MSSQL Error Log events", file=sys.stderr)

    return total_events


# =============================================================================
# STANDALONE EXECUTION
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate MSSQL Error Log")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--quiet", action="store_true")

    args = parser.parse_args()

    count = generate_mssql_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_dir=args.output_dir,
        quiet=args.quiet,
    )
    print(count)
