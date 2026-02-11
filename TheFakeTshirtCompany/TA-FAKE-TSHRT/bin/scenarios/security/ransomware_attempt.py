#!/usr/bin/env python3
"""
Ransomware Attempt Scenario - Ransomware detected and stopped by EDR.

Timeline (Day 8-9):
    Day 8 13:55: Phishing email received with malicious .docm attachment
    Day 8 14:02: User opens attachment, macro executes
    Day 8 14:03: Dropper payload runs (svchost_update.exe)
    Day 8 14:05: C2 callback to Russian IP
    Day 8 14:08: Lateral movement attempts begin (SMB scanning)
    Day 8 14:12: EDR/AV detects suspicious activity
    Day 8 14:15: Meraki isolates endpoint
    Day 8 14:30: Security team notified, incident created
    Day 9: Cleanup and reimaging
"""

import random
from typing import List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class RansomwareAttemptConfig:
    """Configuration for ransomware attempt scenario."""
    name: str = "ransomware_attempt"
    demo_id: str = "ransomware_attempt"
    start_day: int = 7   # 0-indexed = Day 8 in calendar
    end_day: int = 8     # Day 9 = Cleanup day

    # Target user (Brooklyn White - Austin Sales)
    target_user: str = "brooklyn.white"
    target_email: str = "brooklyn.white@theFakeTshirtCompany.com"
    target_display_name: str = "Brooklyn White"
    target_location: str = "AUS"
    target_ip: str = "10.30.30.20"
    target_hostname: str = "AUS-WS-BWHITE01"

    # Threat actor C2
    c2_ip: str = "194.26.29.42"
    c2_port: int = 443
    c2_location: str = "Russia"
    c2_asn: str = "AS49505"

    # Timeline (hour, minute) on start_day
    email_received: Tuple[int, int] = (13, 55)
    macro_executed: Tuple[int, int] = (14, 2)
    c2_callback: Tuple[int, int] = (14, 5)
    lateral_start: Tuple[int, int] = (14, 8)
    edr_detection: Tuple[int, int] = (14, 12)
    isolation: Tuple[int, int] = (14, 15)

    # Lateral movement targets (Austin subnet)
    lateral_targets: List[str] = field(default_factory=lambda: [
        "10.30.30.21",  # dakota.harris (AUS-WS-DHARRIS01)
        "10.30.30.22",  # phoenix.martin (AUS-WS-PMARTIN01)
        "10.30.30.40",  # amelia.collins (AUS-WS-ACOLLINS01)
    ])

    # Malware indicators
    malware_name: str = "svchost_update.exe"
    malware_path: str = "C:\\Users\\bwhite\\AppData\\Local\\Temp\\svchost_update.exe"
    malware_hash: str = "a1b2c3d4e5f6789012345678901234567890abcd"
    phishing_attachment: str = "Invoice_Q4_2026.docm"
    phishing_sender: str = "accounting@invoices-delivery.com"
    phishing_subject: str = "Outstanding Invoice - Immediate Action Required"

    # Detection signatures
    av_signature: str = "Trojan:Win32/Emotet.RPK!MTB"
    ids_signature: str = "ET TROJAN Emotet CnC Beacon"


class RansomwareAttemptScenario:
    """
    Ransomware attempt scenario - attack is detected and stopped.

    Day 8: Attack and detection
    Day 9: Cleanup and recovery
    """

    def __init__(self, config: RansomwareAttemptConfig = None, demo_id_enabled: bool = True):
        self.cfg = config or RansomwareAttemptConfig()
        self.demo_id_enabled = demo_id_enabled
        # Resolve Brooklyn White's persistent MAC address
        from shared.company import USERS
        target_user = USERS.get(self.cfg.target_user)
        self.target_mac = target_user.mac_address if target_user else "AA:BB:CC:DD:EE:20"

    def is_active(self, day: int) -> bool:
        """Check if scenario is active on this day."""
        return self.cfg.start_day <= day <= self.cfg.end_day

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        return f" demo_id={self.cfg.demo_id}" if self.demo_id_enabled else ""

    def _demo_json(self) -> dict:
        """Get demo_id dict for JSON format."""
        return {"demo_id": self.cfg.demo_id} if self.demo_id_enabled else {}

    # =========================================================================
    # ASA EVENTS - C2 callback and lateral movement
    # =========================================================================

    def asa_hour(self, day: int, hour: int, time_utils) -> List[str]:
        """
        Generate ASA events for ransomware scenario.

        Events:
        - C2 callback (outbound HTTPS to Russian IP)
        - Lateral SMB attempts (internal, may be blocked by Meraki not ASA)
        """
        if not self.is_active(day):
            return []

        events = []

        # Only generate events on attack day during attack hour
        if day != self.cfg.start_day or hour != 14:
            return events

        # C2 Callback - Built connection (14:05)
        c2_minute = self.cfg.c2_callback[1]
        c2_second = random.randint(10, 30)
        c2_ts = time_utils.ts_syslog(day, hour, c2_minute, c2_second)
        conn_id = random.randint(100000, 999999)

        # Outbound C2 connection (inside → outside)
        src_port = random.randint(49152, 65535)
        events.append(
            f"{c2_ts} FW-EDGE-01 %ASA-6-302013: Built outbound TCP connection {conn_id} "
            f"for inside:{self.cfg.target_ip}/{src_port} (203.0.113.10/{src_port}) "
            f"to outside:{self.cfg.c2_ip}/{self.cfg.c2_port} ({self.cfg.c2_ip}/{self.cfg.c2_port})"
            f"{self._demo_suffix_syslog()}"
        )

        # Multiple C2 beacons over the next few minutes
        for i in range(3):
            beacon_minute = c2_minute + i + 1
            if beacon_minute < 60:
                beacon_ts = time_utils.ts_syslog(day, hour, beacon_minute, random.randint(0, 59))
                conn_id += 1
                beacon_src_port = random.randint(49152, 65535)
                events.append(
                    f"{beacon_ts} FW-EDGE-01 %ASA-6-302013: Built outbound TCP connection {conn_id} "
                    f"for inside:{self.cfg.target_ip}/{beacon_src_port} (203.0.113.10/{beacon_src_port}) "
                    f"to outside:{self.cfg.c2_ip}/{self.cfg.c2_port} ({self.cfg.c2_ip}/{self.cfg.c2_port})"
                    f"{self._demo_suffix_syslog()}"
                )

        return events

    # =========================================================================
    # EXCHANGE EVENTS - Phishing email
    # =========================================================================

    def exchange_hour(self, day: int, hour: int, time_utils) -> List[dict]:
        """
        Generate Exchange events for ransomware scenario.

        Events:
        - Phishing email with malicious attachment received
        """
        if day != self.cfg.start_day:
            return []

        email_hour = self.cfg.email_received[0]
        if hour != email_hour:
            return []

        events = []

        # Parse base_date string to datetime
        base_dt = datetime.strptime(time_utils.base_date, "%Y-%m-%d")

        # Phishing email received
        email_minute = self.cfg.email_received[1]
        email_ts = datetime(
            base_dt.year, base_dt.month, base_dt.day,
            email_hour, email_minute, random.randint(0, 59)
        ) + timedelta(days=day)

        event = {
            "Received": email_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "SenderAddress": self.cfg.phishing_sender,
            "RecipientAddress": self.cfg.target_email,
            "Subject": self.cfg.phishing_subject,
            "Status": "Delivered",
            "ToIP": "10.30.30.20",
            "FromIP": "185.234.72.15",
            "Size": str(random.randint(250000, 350000)),  # .docm file
            "MessageId": f"<{random.randint(100000, 999999)}.phishing@invoices-delivery.com>",
            "MessageTraceId": str(random.randint(10000000, 99999999)),
            "Organization": "theFakeTshirtCompany.com",
            "AttachmentNames": self.cfg.phishing_attachment,
        }
        event.update(self._demo_json())
        events.append(event)

        return events

    # =========================================================================
    # WINEVENTLOG EVENTS - Process execution, AV detection
    # =========================================================================

    def winevent_hour(self, day: int, hour: int, time_utils) -> List[str]:
        """
        Generate Windows Event Log events for ransomware scenario.

        Events:
        - 4688: Process creation (svchost_update.exe)
        - 4697: Service installed
        - 1116: Windows Defender detection
        - 4624/4625: Lateral movement attempts
        """
        if day != self.cfg.start_day or hour != 14:
            return []

        events = []

        # Parse base_date string to datetime
        base_dt = datetime.strptime(time_utils.base_date, "%Y-%m-%d")

        # Process creation - Macro drops payload (14:02)
        proc_minute = self.cfg.macro_executed[1]
        proc_ts = datetime(
            base_dt.year, base_dt.month, base_dt.day,
            14, proc_minute, random.randint(30, 59)
        ) + timedelta(days=day)

        # 4688 - Suspicious process created
        events.append(self._winevent_4688(proc_ts, self.cfg.target_hostname))

        # Dropper starts (14:03)
        dropper_ts = proc_ts + timedelta(seconds=random.randint(30, 60))
        events.append(self._winevent_4688_dropper(dropper_ts, self.cfg.target_hostname))

        # Service installed attempt (14:04)
        service_ts = dropper_ts + timedelta(seconds=random.randint(45, 90))
        events.append(self._winevent_4697(service_ts, self.cfg.target_hostname))

        # Lateral movement attempts (14:08-14:12)
        lateral_minute = self.cfg.lateral_start[1]
        for i, target_ip in enumerate(self.cfg.lateral_targets):
            lateral_ts = datetime(
                base_dt.year, base_dt.month, base_dt.day,
                14, lateral_minute + i, random.randint(0, 59)
            ) + timedelta(days=day)
            events.append(self._winevent_4625(lateral_ts, target_ip))

        # Windows Defender detection (14:12)
        detect_minute = self.cfg.edr_detection[1]
        detect_ts = datetime(
            base_dt.year, base_dt.month, base_dt.day,
            14, detect_minute, random.randint(0, 30)
        ) + timedelta(days=day)
        events.append(self._winevent_1116(detect_ts, self.cfg.target_hostname))

        return events

    @staticmethod
    def _winevent_ts(dt: datetime) -> str:
        """Format datetime to WinEventLog KV timestamp: MM/DD/YYYY HH:MM:SS AM/PM."""
        return dt.strftime("%m/%d/%Y %I:%M:%S %p")

    def _winevent_4688(self, ts: datetime, hostname: str) -> str:
        """Process creation event - Word launching macro (KV format)."""
        ts_str = self._winevent_ts(ts)
        process_id = random.randint(1000, 65535)
        parent_process_id = random.randint(500, 5000)

        return f"""{ts_str}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4688
EventType=0
Type=Information
demo_id={self.cfg.demo_id}
ComputerName={hostname}.theFakeTshirtCompany.com
TaskCategory=Process Creation
RecordNumber={random.randint(50000, 99999)}
Keywords=Audit Success
Message=A new process has been created.

Creator Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{self.cfg.target_user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Target Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Process Information:
\tNew Process ID:\t\t0x{process_id:X}
\tNew Process Name:\tC:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
\tToken Elevation Type:\tTokenElevationTypeFull (2)
\tMandatory Label:\t\tMandatory Label\\High Mandatory Level
\tCreator Process ID:\t0x{parent_process_id:X}
\tCreator Process Name:\tC:\\Windows\\explorer.exe
\tProcess Command Line:\t"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "{self.cfg.phishing_attachment}"
"""

    def _winevent_4688_dropper(self, ts: datetime, hostname: str) -> str:
        """Process creation event - Dropper execution (KV format)."""
        ts_str = self._winevent_ts(ts)
        process_id = random.randint(1000, 65535)
        parent_process_id = random.randint(500, 5000)

        return f"""{ts_str}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4688
EventType=0
Type=Information
demo_id={self.cfg.demo_id}
ComputerName={hostname}.theFakeTshirtCompany.com
TaskCategory=Process Creation
RecordNumber={random.randint(50000, 99999)}
Keywords=Audit Success
Message=A new process has been created.

Creator Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{self.cfg.target_user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Target Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Process Information:
\tNew Process ID:\t\t0x{process_id:X}
\tNew Process Name:\t{self.cfg.malware_path}
\tToken Elevation Type:\tTokenElevationTypeFull (2)
\tMandatory Label:\t\tMandatory Label\\High Mandatory Level
\tCreator Process ID:\t0x{parent_process_id:X}
\tCreator Process Name:\tC:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
\tProcess Command Line:\t"{self.cfg.malware_path}" -silent -connect
"""

    def _winevent_4697(self, ts: datetime, hostname: str) -> str:
        """Service installed event (KV format)."""
        ts_str = self._winevent_ts(ts)

        return f"""{ts_str}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4697
EventType=0
Type=Information
demo_id={self.cfg.demo_id}
ComputerName={hostname}.theFakeTshirtCompany.com
TaskCategory=Security System Extension
RecordNumber={random.randint(50000, 99999)}
Keywords=Audit Success
Message=A service was installed in the system.

Subject:
\tSecurity ID:\t\tS-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}
\tAccount Name:\t\t{self.cfg.target_user}
\tAccount Domain:\t\tFAKETSHIRTCO
\tLogon ID:\t\t0x{random.randint(100000, 999999):X}

Service Information:
\tService Name:\t\tWindows Update Helper
\tService File Name:\t{self.cfg.malware_path}
\tService Type:\t\t0x10
\tService Start Type:\t2
\tService Account:\t\tLocalSystem
"""

    def _winevent_4625(self, ts: datetime, target_ip: str) -> str:
        """Failed logon - lateral movement attempt (KV format)."""
        ts_str = self._winevent_ts(ts)

        return f"""{ts_str}
LogName=Security
SourceName=Microsoft-Windows-Security-Auditing
EventCode=4625
EventType=0
Type=Information
demo_id={self.cfg.demo_id}
ComputerName={self.cfg.target_hostname}.theFakeTshirtCompany.com
TaskCategory=Logon
RecordNumber={random.randint(50000, 99999)}
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
\tAccount Name:\t\tAdministrator
\tAccount Domain:\t\tFAKETSHIRTCO

Failure Information:
\tFailure Reason:\t\tUnknown user name or bad password.
\tStatus:\t\t\t0xC000006D
\tSub Status:\t\t0xC000006A

Network Information:
\tWorkstation Name:\t{self.cfg.target_hostname}
\tSource Network Address:\t{self.cfg.target_ip}
\tSource Port:\t\t{random.randint(49152, 65535)}
"""

    def _winevent_1116(self, ts: datetime, hostname: str) -> str:
        """Windows Defender malware detection (KV format)."""
        ts_str = self._winevent_ts(ts)

        return f"""{ts_str}
LogName=Microsoft-Windows-Windows Defender/Operational
SourceName=Microsoft-Windows-Windows Defender
EventCode=1116
EventType=0
Type=Warning
demo_id={self.cfg.demo_id}
ComputerName={hostname}.theFakeTshirtCompany.com
TaskCategory=Malware Detection
RecordNumber={random.randint(50000, 99999)}
Keywords=Audit Success
Message=Microsoft Defender Antivirus has detected malware or other potentially unwanted software.

\tName:\t\t\t{self.cfg.av_signature}
\tID:\t\t\t2147816890
\tSeverity:\t\tSevere
\tCategory:\t\tTrojan
\tPath:\t\t\t{self.cfg.malware_path}
\tDetection Origin:\tInternet
\tExecution Status:\tSuspended
\tProcess Name:\t\t{self.cfg.malware_path}
\tAction:\t\t\tQuarantine
\tAction Status:\t\tSuccess
\tAdditional Actions Required:\tNo additional actions required
\tUser:\t\t\tFAKETSHIRTCO\\{self.cfg.target_user}
"""

    # =========================================================================
    # MERAKI EVENTS - IDS alert and client isolation (Dashboard API JSON)
    # =========================================================================

    def meraki_hour(self, day: int, hour: int, time_utils) -> dict:
        """
        Generate Meraki events for ransomware scenario (Dashboard API JSON format).

        Returns:
            dict with 'mx' and 'mr' keys containing event lists:
            - mx: MX security appliance events (IDS alerts, client isolation)
            - mr: MR access point events (disassociation)
        """
        if day != self.cfg.start_day or hour != 14:
            return {"mx": [], "mr": []}

        mx_events = []
        mr_events = []

        # Parse base_date string to datetime
        base_dt = datetime.strptime(time_utils.base_date, "%Y-%m-%d")

        # IDS alert - SMB scanning (14:12)
        ids_minute = self.cfg.edr_detection[1]
        ids_ts = datetime(
            base_dt.year, base_dt.month, base_dt.day,
            14, ids_minute, random.randint(0, 30)
        ) + timedelta(days=day)
        ids_iso = ids_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # IDS Alert (getNetworkApplianceSecurityEvents format)
        mx_events.append({
            "ts": ids_iso,
            "eventType": "IDS Alert",
            "deviceMac": "00:18:0A:C0:01:01",  # MX-AUS-01 MAC
            "deviceName": "MX-AUS-01",
            "deviceSerial": "MX-AUS-01",
            "clientMac": self.target_mac,
            "srcIp": f"{self.cfg.target_ip}:49152",
            "destIp": f"{self.cfg.lateral_targets[0]}:445",
            "protocol": "tcp/ip",
            "priority": "1",
            "classification": "2",
            "blocked": True,
            "message": self.cfg.ids_signature,
            "signature": "1:2001569:15",
            "ruleId": "meraki:intrusion/snort/GID/1/SID/2001569",
            "demo_id": self.cfg.demo_id
        })

        # More IDS alerts for lateral attempts
        for i, target in enumerate(self.cfg.lateral_targets[1:], 1):
            alert_ts = ids_ts + timedelta(seconds=random.randint(30, 120) * i)
            alert_iso = alert_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            mx_events.append({
                "ts": alert_iso,
                "eventType": "IDS Alert",
                "deviceMac": "00:18:0A:C0:01:01",
                "deviceName": "MX-AUS-01",
                "deviceSerial": "MX-AUS-01",
                "clientMac": self.target_mac,
                "srcIp": f"{self.cfg.target_ip}:{49152 + i}",
                "destIp": f"{target}:445",
                "protocol": "tcp/ip",
                "priority": "2",
                "classification": "3",
                "blocked": True,
                "message": "SMB Brute Force Attempt",
                "signature": "1:2001570:8",
                "ruleId": "meraki:intrusion/snort/GID/1/SID/2001570",
                "demo_id": self.cfg.demo_id
            })

        # Client isolation (14:15) - Dashboard API format
        iso_minute = self.cfg.isolation[1]
        iso_ts = datetime(
            base_dt.year, base_dt.month, base_dt.day,
            14, iso_minute, random.randint(0, 30)
        ) + timedelta(days=day)
        iso_iso = iso_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Use Brooklyn White's persistent MAC address
        target_mac = self.target_mac

        mx_events.append({
            "occurredAt": iso_iso,
            "networkId": "N_FakeTShirtCo_AUS",
            "type": "client_isolated",
            "description": "Client isolated due to security threat",
            "category": "appliance",
            "deviceSerial": "MX-AUS-01",
            "deviceName": "MX-AUS-01",
            "clientMac": target_mac,
            "eventData": {
                "client_ip": self.cfg.target_ip,
                "reason": "Security threat detected - IDS alert triggered",
                "isolated_by": "Automatic security policy"
            },
            "demo_id": self.cfg.demo_id
        })

        # AP disconnect (MR event) - Dashboard API format
        disassoc_ts = iso_ts + timedelta(seconds=2)
        disassoc_iso = disassoc_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        mr_events.append({
            "occurredAt": disassoc_iso,
            "networkId": "N_FakeTShirtCo_AUS",
            "type": "disassociation",
            "description": "802.11 disassociation - security isolation",
            "category": "wireless",
            "clientMac": target_mac,
            "deviceSerial": "AP-AUS-1F-01",
            "deviceName": "AP-AUS-1F-01",
            "eventData": {
                "radio": "1",
                "vap": "0",
                "reason": "Forced disconnect - security isolation"
            },
            "demo_id": self.cfg.demo_id
        })

        return {"mx": mx_events, "mr": mr_events}

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def has_scenario_events(self, day: int, hour: int) -> bool:
        """Check if this day/hour has scenario events."""
        if not self.is_active(day):
            return False
        if day == self.cfg.start_day and hour == 14:
            return True
        return False

    def get_phase(self, day: int) -> str:
        """Get the attack phase for display purposes."""
        if day < self.cfg.start_day:
            return "pre_attack"
        elif day == self.cfg.start_day:
            return "attack_and_detection"
        elif day == self.cfg.end_day:
            return "cleanup"
        else:
            return "post_incident"
