"""
Phishing Test Scenario -- IT-run phishing awareness campaign (Days 21-23).

After the real APT exfil incident discovered on Day 12, IT Security (ashley.griffin)
runs an authorized phishing simulation campaign using KnowBe4-style platform to test
all 175 employees across 3 locations.

Timeline:
    Day 21 (index 20): Campaign launch
        09:00  Wave 1 -- Boston employees (~93 emails)
        10:00  Wave 2 -- Atlanta employees (~43 emails)
        11:00  Wave 3 -- Austin employees (~39 emails)
        12:00+ First clicks start rolling in

    Day 21-22 (index 20-21): User responses
        ~55 employees click link (31%)
        ~18 submit credentials (10%)
        ~35 report to IT (20%)
        ~67 ignore/delete (39%)

    Day 23 (index 22): Results and training
        10:00  Results compiled
        11:00  Mandatory training emails sent to clickers

Sources: exchange, entraid, wineventlog, office_audit, servicenow
"""

import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Any

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from shared.company import USERS, USER_KEYS, TENANT, TENANT_ID, LOCATIONS


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class PhishingTestConfig:
    """Configuration for the phishing awareness test scenario."""
    name: str = "phishing_test"
    demo_id: str = "phishing_test"
    start_day: int = 20   # 0-indexed = Jan 21
    end_day: int = 22     # 0-indexed = Jan 23

    # Campaign operator
    operator_user: str = "ashley.griffin"
    operator_email: str = "ashley.griffin@theFakeTshirtCompany.com"
    operator_display_name: str = "Ashley Griffin"
    operator_ip: str = "10.10.30.168"

    # Phishing simulation platform
    sim_sender: str = "noreply@security-training.thefaketshirtcompany.com"
    sim_subject: str = "Action Required: Your Microsoft 365 password expires in 24 hours"
    sim_url: str = "https://phishsim.knowbe4.com/auth/faketshirtco/login"
    sim_domain: str = "phishsim.knowbe4.com"
    sim_platform_ip: str = "52.25.138.42"  # AWS-hosted KnowBe4 simulation

    # Wave schedule: (hour, location_code)
    wave_hours: Dict[str, int] = field(default_factory=lambda: {
        "BOS": 9,
        "ATL": 10,
        "AUS": 11,
    })

    # Response rates (industry-average for first-time phishing test)
    click_rate: float = 0.31       # ~55 of 175
    credential_rate: float = 0.10  # ~18 of 175 (subset of clickers)

    # Training email config
    training_subject: str = "Required: Security Awareness Training - Phishing Exercise Results"
    training_sender: str = "it-security@theFakeTshirtCompany.com"

    # Browser choices for WinEventLog process creation
    browsers: List[str] = field(default_factory=lambda: [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
    ])


# =============================================================================
# SCENARIO CLASS
# =============================================================================

class PhishingTestScenario:
    """IT Security phishing awareness campaign scenario.

    Pre-selects participants deterministically so the same employees appear
    consistently across Exchange (emails), Entra ID (sign-ins), WinEventLog
    (browser launches), and Office 365 Audit (SafeLinks clicks).
    """

    def __init__(self, config: PhishingTestConfig = None, demo_id_enabled: bool = True):
        self.cfg = config or PhishingTestConfig()
        self.demo_id_enabled = demo_id_enabled
        # Pre-select participants with deterministic seed
        self._select_participants()

    # -------------------------------------------------------------------------
    # PARTICIPANT SELECTION
    # -------------------------------------------------------------------------

    def _select_participants(self):
        """Pre-select which employees click, submit credentials, and report.

        Uses a deterministic seed so the same employees are selected every run.
        This ensures correlation across generators.
        """
        rng = random.Random(hash("phishing_test_2026") % (2**31))

        # Get all employees grouped by location
        employees_by_loc = {"BOS": [], "ATL": [], "AUS": []}
        for username in USER_KEYS:
            user = USERS[username]
            if user.location in employees_by_loc:
                employees_by_loc[user.location].append(username)

        # Select clickers per location (proportional to click_rate)
        self.clickers = []  # List of (username, click_day, click_hour, click_minute)
        self.submitters = []  # Subset of clickers who also submit credentials

        for loc, hour in self.cfg.wave_hours.items():
            loc_employees = employees_by_loc.get(loc, [])
            num_clickers = max(1, int(len(loc_employees) * self.cfg.click_rate))
            loc_clickers = rng.sample(loc_employees, min(num_clickers, len(loc_employees)))

            for username in loc_clickers:
                # Random click delay: most click within 2 hours, some take longer
                if rng.random() < 0.6:
                    # Early clicker: 0-2 hours after email
                    delay_hours = rng.uniform(0, 2)
                else:
                    # Late clicker: 2-24 hours after email
                    delay_hours = rng.uniform(2, 24)

                click_total_hours = hour + delay_hours
                click_day = self.cfg.start_day
                if click_total_hours >= 24:
                    click_day += 1
                    click_total_hours -= 24

                click_hour = int(click_total_hours)
                click_minute = int((click_total_hours - click_hour) * 60)

                # Only include if within scenario window
                if click_day <= self.cfg.start_day + 1:
                    self.clickers.append((username, click_day, click_hour, click_minute))

        # Select credential submitters (subset of clickers, ~1 in 3)
        num_submitters = max(1, int(len(self.clickers) * self.cfg.credential_rate / self.cfg.click_rate))
        submitter_indices = rng.sample(range(len(self.clickers)), min(num_submitters, len(self.clickers)))
        self.submitters = [self.clickers[i] for i in submitter_indices]

        # Store for quick lookup
        self.clicker_usernames = {c[0] for c in self.clickers}
        self.submitter_usernames = {s[0] for s in self.submitters}

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    def is_active(self, day: int) -> bool:
        """Check if scenario is active on this day."""
        return self.cfg.start_day <= day <= self.cfg.end_day

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog-format events."""
        return f" demo_id={self.cfg.demo_id}" if self.demo_id_enabled else ""

    def _demo_json(self) -> dict:
        """Get demo_id dict for JSON-format events."""
        return {"demo_id": self.cfg.demo_id} if self.demo_id_enabled else {}

    @staticmethod
    def _winevent_ts(dt: datetime) -> str:
        """Format datetime to WinEventLog KV timestamp: MM/DD/YYYY HH:MM:SS AM/PM."""
        return dt.strftime("%m/%d/%Y %I:%M:%S %p")

    def _rand_uuid(self) -> str:
        return str(uuid.uuid4())

    # -------------------------------------------------------------------------
    # EXCHANGE EVENTS
    # -------------------------------------------------------------------------

    def exchange_hour(self, day: int, hour: int, time_utils) -> List[dict]:
        """Generate Exchange message trace events for phishing test.

        Day 20 (campaign launch): Simulation emails sent to all employees in waves
        Day 22 (results): Training assignment emails to clickers
        """
        events = []
        if not self.is_active(day):
            return events

        # Day 20: Campaign emails sent in waves
        if day == self.cfg.start_day:
            for loc, wave_hour in self.cfg.wave_hours.items():
                if hour != wave_hour:
                    continue

                # Send simulation email to every employee at this location
                for username in USER_KEYS:
                    user = USERS[username]
                    if user.location != loc:
                        continue

                    minute = random.randint(0, 29)  # All sent within first 30 min
                    second = random.randint(0, 59)
                    ts = time_utils.ts_iso(day, hour, minute, second)

                    event = {
                        "Received": ts,
                        "SenderAddress": self.cfg.sim_sender,
                        "RecipientAddress": user.email,
                        "Subject": self.cfg.sim_subject,
                        "Status": "Delivered",
                        "ToIP": "10.10.20.50",  # Exchange server
                        "FromIP": self.cfg.sim_platform_ip,
                        "Size": str(random.randint(15000, 25000)),
                        "MessageId": f"<phishsim-{username}-{uuid.uuid4().hex[:8]}@{self.cfg.sim_domain}>",
                        "MessageTraceId": str(uuid.uuid4()),
                        "Organization": TENANT,
                        "Directionality": "Inbound",
                        "SourceContext": "PhishingSimulation",
                    }
                    event.update(self._demo_json())
                    events.append(event)

        # Day 22: Training assignment emails to clickers
        elif day == self.cfg.end_day and hour == 11:
            for username, _, _, _ in self.clickers:
                user = USERS.get(username)
                if not user:
                    continue

                minute = random.randint(0, 15)
                second = random.randint(0, 59)
                ts = time_utils.ts_iso(day, hour, minute, second)

                event = {
                    "Received": ts,
                    "SenderAddress": self.cfg.training_sender,
                    "RecipientAddress": user.email,
                    "Subject": self.cfg.training_subject,
                    "Status": "Delivered",
                    "ToIP": "10.10.20.50",
                    "FromIP": self.cfg.operator_ip,
                    "Size": str(random.randint(8000, 12000)),
                    "MessageId": f"<training-{username}-{uuid.uuid4().hex[:8]}@{TENANT}>",
                    "MessageTraceId": str(uuid.uuid4()),
                    "Organization": TENANT,
                    "Directionality": "Intra-org",
                    "SourceContext": "SecurityTraining",
                }
                event.update(self._demo_json())
                events.append(event)

        return events

    def exchange_day(self, day: int) -> List[str]:
        """Day-level exchange events (not needed -- all hour-based)."""
        return []

    # -------------------------------------------------------------------------
    # ENTRA ID EVENTS
    # -------------------------------------------------------------------------

    def entraid_signin_hour(self, day: int, hour: int) -> List[str]:
        """Generate Entra ID sign-in events for credential submitters.

        When an employee submits credentials on the simulation page, it produces
        a sign-in event from the simulation platform IP. The sign-in "succeeds"
        because the simulation accepts any credentials (it's a test).

        Returns JSON strings (matching generator expectation for either str or dict).
        """
        events = []
        if not self.is_active(day):
            return events

        # Only generate for submitters whose click time matches this hour
        for username, click_day, click_hour, click_minute in self.submitters:
            if day != click_day or hour != click_hour:
                continue

            user = USERS.get(username)
            if not user:
                continue

            # Credential submission happens ~1-3 minutes after click
            submit_minute = min(59, click_minute + random.randint(1, 3))
            second = random.randint(0, 59)

            cid = str(uuid.uuid4())
            ts = f"2026-01-{self.cfg.start_day + 1 + (day - self.cfg.start_day):02d}T{hour:02d}:{submit_minute:02d}:{second:02d}Z"

            event = {
                "time": ts,
                "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
                "operationName": "Sign-in activity",
                "category": "SignInLogs",
                "tenantId": TENANT_ID,
                "resultType": "0",  # Success (simulation accepts any creds)
                "callerIpAddress": self.cfg.sim_platform_ip,
                "correlationId": cid,
                "identity": user.display_name,
                "Level": 4,
                "location": "US",
                "properties": {
                    "id": cid,
                    "createdDateTime": ts,
                    "userDisplayName": user.display_name,
                    "userPrincipalName": user.email,
                    "userId": user.entra_object_id,
                    "appId": "00000003-0000-0ff1-ce00-000000000000",
                    "appDisplayName": "Microsoft Office 365",
                    "ipAddress": self.cfg.sim_platform_ip,
                    "clientAppUsed": "Browser",
                    "conditionalAccessStatus": "notApplied",  # Whitelisted for test
                    "isInteractive": True,
                    "authenticationRequirement": "singleFactorAuthentication",
                    "tokenIssuerType": "AzureAD",
                    "riskLevelAggregated": "none",
                    "riskLevelDuringSignIn": "none",
                    "riskState": "none",
                    "riskDetail": "none",
                    "status": {"errorCode": 0},
                    "deviceDetail": {
                        "deviceId": "",
                        "displayName": "",
                        "operatingSystem": "Windows 10",
                        "isCompliant": False,
                        "isManaged": False,
                    },
                    "location": {
                        "city": "Portland",
                        "countryOrRegion": "US",
                    },
                    "mfaDetail": {},
                    "authenticationDetails": [
                        {
                            "authenticationStepDateTime": ts,
                            "authenticationMethod": "Password",
                            "authenticationMethodDetail": "Password in the cloud",
                            "succeeded": True,
                            "authenticationStepResultDetail": "Correct password",
                        }
                    ],
                },
            }
            event.update(self._demo_json())
            events.append(json.dumps(event))

        return events

    def entraid_audit_hour(self, day: int, hour: int) -> List[str]:
        """No Entra ID audit events for phishing test."""
        return []

    # -------------------------------------------------------------------------
    # WINDOWS EVENT LOG EVENTS
    # -------------------------------------------------------------------------

    def winevent_hour(self, day: int, hour: int, time_utils) -> List[str]:
        """Generate WinEventLog 4688 process creation events.

        When an employee clicks the phishing link in Outlook, it launches their
        default browser with the simulation URL. This creates a 4688 process
        creation event showing OUTLOOK.EXE spawning chrome.exe/msedge.exe.
        """
        events = []
        if not self.is_active(day):
            return events

        rng = random.Random(hash(f"phishing_winevent_{day}_{hour}") % (2**31))

        for username, click_day, click_hour, click_minute in self.clickers:
            if day != click_day or hour != click_hour:
                continue

            user = USERS.get(username)
            if not user:
                continue

            second = rng.randint(0, 59)
            # Build timestamp as datetime
            base = datetime(2026, 1, 1) + timedelta(days=day)
            ts = base.replace(hour=click_hour, minute=click_minute, second=second)

            process_id = rng.randint(1000, 65535)
            parent_pid = rng.randint(500, 5000)
            browser = rng.choice(self.cfg.browsers)

            event = f"""{self._winevent_ts(ts)}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4688
EventType=0
Type=Information
demo_id={self.cfg.demo_id}
ComputerName={user.device_name}.theFakeTshirtCompany.com
TaskCategory=Process Creation
RecordNumber={rng.randint(50000, 99999)}
Keywords=Audit Success
Message=A new process has been created.

Creator Subject:
\tSecurity ID:\t\tS-1-5-21-{rng.randint(1000000000, 9999999999)}-{rng.randint(1000000000, 9999999999)}-{rng.randint(1000, 9999)}
\tAccount Name:\t\t{user.username}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{rng.randint(100000, 999999):X}

Target Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Process Information:
\tNew Process ID:\t\t0x{process_id:X}
\tNew Process Name:\t{browser}
\tToken Elevation Type:\tTokenElevationTypeDefault (1)
\tMandatory Label:\t\tMandatory Label\\Medium Mandatory Level
\tCreator Process ID:\t0x{parent_pid:X}
\tCreator Process Name:\tC:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE
\tProcess Command Line:\t"{browser}" "{self.cfg.sim_url}"
"""
            events.append(event)

        return events

    # -------------------------------------------------------------------------
    # OFFICE 365 AUDIT HELPER (for inline use in generate_office_audit.py)
    # -------------------------------------------------------------------------

    @staticmethod
    def get_clicker_usernames_deterministic() -> set:
        """Get the set of clicker usernames using the same deterministic seed.

        This is used by the inlined _phishing_test_events_for_hour() function
        in generate_office_audit.py to ensure consistent participant selection.
        """
        rng = random.Random(hash("phishing_test_2026") % (2**31))
        cfg = PhishingTestConfig()

        employees_by_loc = {"BOS": [], "ATL": [], "AUS": []}
        for username in USER_KEYS:
            user = USERS[username]
            if user.location in employees_by_loc:
                employees_by_loc[user.location].append(username)

        clicker_usernames = set()
        clickers_with_timing = []

        for loc, hour in cfg.wave_hours.items():
            loc_employees = employees_by_loc.get(loc, [])
            num_clickers = max(1, int(len(loc_employees) * cfg.click_rate))
            loc_clickers = rng.sample(loc_employees, min(num_clickers, len(loc_employees)))

            for username in loc_clickers:
                if rng.random() < 0.6:
                    delay_hours = rng.uniform(0, 2)
                else:
                    delay_hours = rng.uniform(2, 24)

                click_total_hours = hour + delay_hours
                click_day = cfg.start_day
                if click_total_hours >= 24:
                    click_day += 1
                    click_total_hours -= 24

                click_hour = int(click_total_hours)
                click_minute = int((click_total_hours - click_hour) * 60)

                if click_day <= cfg.start_day + 1:
                    clicker_usernames.add(username)
                    clickers_with_timing.append((username, click_day, click_hour, click_minute))

        return clicker_usernames, clickers_with_timing

    # -------------------------------------------------------------------------
    # TIMELINE PRINTER (for debugging)
    # -------------------------------------------------------------------------

    def print_timeline(self):
        """Print scenario timeline for debugging."""
        print(f"\n{'='*70}")
        print(f"  Phishing Test Scenario Timeline")
        print(f"  Days: {self.cfg.start_day}-{self.cfg.end_day} (Jan {self.cfg.start_day+1}-{self.cfg.end_day+1})")
        print(f"  Operator: {self.cfg.operator_display_name} ({self.cfg.operator_email})")
        print(f"{'='*70}")

        print(f"\n  Participants:")
        print(f"    Total employees: {len(USER_KEYS)}")
        print(f"    Clickers: {len(self.clickers)} ({len(self.clickers)/len(USER_KEYS)*100:.0f}%)")
        print(f"    Credential submitters: {len(self.submitters)} ({len(self.submitters)/len(USER_KEYS)*100:.0f}%)")

        print(f"\n  Wave Schedule (Day {self.cfg.start_day + 1}):")
        for loc, hour in self.cfg.wave_hours.items():
            loc_count = sum(1 for u in USER_KEYS if USERS[u].location == loc)
            print(f"    {hour:02d}:00  {loc} ({loc_count} employees)")

        print(f"\n  Click Timeline:")
        by_day_hour = {}
        for username, d, h, m in self.clickers:
            key = (d, h)
            by_day_hour.setdefault(key, []).append(username)

        for (d, h), users in sorted(by_day_hour.items()):
            print(f"    Day {d+1} {h:02d}:00  {len(users)} clicks")

        print(f"\n  Credential Submitters:")
        for username, d, h, m in self.submitters:
            user = USERS.get(username)
            loc = user.location if user else "?"
            print(f"    {username} ({loc}) - Day {d+1} {h:02d}:{m:02d}")

        print()


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    scenario = PhishingTestScenario(demo_id_enabled=True)
    scenario.print_timeline()

    # Test exchange events
    print("  Exchange events test (Day 20, hour 9):")
    class MockTimeUtils:
        def ts_iso(self, day, hour, minute, second):
            return f"2026-01-{day+1:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"

    tu = MockTimeUtils()
    events = scenario.exchange_hour(20, 9, tu)
    print(f"    Wave 1 (BOS): {len(events)} emails")

    events = scenario.exchange_hour(20, 10, tu)
    print(f"    Wave 2 (ATL): {len(events)} emails")

    events = scenario.exchange_hour(20, 11, tu)
    print(f"    Wave 3 (AUS): {len(events)} emails")

    events = scenario.exchange_hour(22, 11, tu)
    print(f"    Training emails (Day 22): {len(events)} emails")

    # Test entraid events
    total_signin = 0
    for d in range(20, 23):
        for h in range(24):
            evts = scenario.entraid_signin_hour(d, h)
            total_signin += len(evts)
    print(f"\n  Entra ID sign-in events total: {total_signin}")

    # Test winevent events
    total_winevent = 0
    for d in range(20, 23):
        for h in range(24):
            evts = scenario.winevent_hour(d, h, None)
            total_winevent += len(evts)
    print(f"  WinEventLog 4688 events total: {total_winevent}")
