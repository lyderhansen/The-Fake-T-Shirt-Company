#!/usr/bin/env python3
"""
ServiceNow ITSM Generator

Generates realistic ServiceNow data in key-value format:
- Incidents: IT support tickets with lifecycle (New → Closed)
- CMDB: Configuration Items (servers, network, apps, workstations, relationships)
- Change Requests: Standard/normal/emergency changes with lifecycle

Correlates with existing scenarios (cpu_runaway, memory_leak, firewall_misconfig, etc.).

Output format: Key-value pairs (one event per line)
Splunk sourcetypes: servicenow:incident, servicenow:cmdb, servicenow:change
"""

import argparse
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add
from shared.company import (
    USERS, SERVERS, LOCATIONS, USER_KEYS, TENANT,
    ASA_PERIMETER, MERAKI_FIREWALLS, ALL_SERVERS,
)

# =============================================================================
# CONSTANTS
# =============================================================================

FILE_SERVICENOW = "servicenow_incidents.log"
FILE_SERVICENOW_CMDB = "servicenow_cmdb.log"
FILE_SERVICENOW_CHANGE = "servicenow_change.log"

# Incident volume
BASE_INCIDENTS_PER_DAY = 20  # ~175 employees
MONDAY_MULTIPLIER = 1.3
WEEKEND_INCIDENTS = 5

# Incident states
STATES = ["New", "In Progress", "On Hold", "Resolved", "Closed"]

# Priorities (1 = Critical, 5 = Planning)
PRIORITIES = {
    1: {"name": "Critical", "resolve_hours": (1, 4), "weight": 5},
    2: {"name": "High", "resolve_hours": (2, 8), "weight": 15},
    3: {"name": "Moderate", "resolve_hours": (4, 24), "weight": 40},
    4: {"name": "Low", "resolve_hours": (8, 48), "weight": 30},
    5: {"name": "Planning", "resolve_hours": (24, 168), "weight": 10},
}

# =============================================================================
# ASSIGNMENT GROUPS
# =============================================================================

ASSIGNMENT_GROUPS = {
    "Service Desk": {
        "members": ["helpdesk.agent1", "helpdesk.agent2", "helpdesk.agent3"],
        "display": ["HD Agent 1", "HD Agent 2", "HD Agent 3"],
    },
    "Desktop Support": {
        "members": ["desktop.tech1", "desktop.tech2"],
        "display": ["Desktop Tech 1", "Desktop Tech 2"],
    },
    "Network Operations": {
        "members": ["network.admin", "network.eng1"],
        "display": ["Network Admin", "Network Engineer"],
    },
    "Database Admins": {
        "members": ["dba.admin1", "dba.admin2"],
        "display": ["DBA Admin 1", "DBA Admin 2"],
    },
    "Application Support": {
        "members": ["app.support1", "app.support2"],
        "display": ["App Support 1", "App Support 2"],
    },
    "Security Operations": {
        "members": ["sec.analyst1", "sec.analyst2"],
        "display": ["Security Analyst 1", "Security Analyst 2"],
    },
    "Linux Admins": {
        "members": ["linux.admin1", "linux.admin2"],
        "display": ["Linux Admin 1", "Linux Admin 2"],
    },
}

# =============================================================================
# INCIDENT TEMPLATES
# =============================================================================

INCIDENT_TEMPLATES = {
    "hardware": {
        "weight": 25,
        "assignment_group": "Desktop Support",
        "incidents": [
            {"short": "Laptop not powering on", "subcategory": "Laptop", "priority": 3},
            {"short": "Docking station not detecting monitors", "subcategory": "Docking Station", "priority": 4},
            {"short": "Keyboard not responding", "subcategory": "Peripheral", "priority": 4},
            {"short": "Mouse double-clicking issue", "subcategory": "Peripheral", "priority": 5},
            {"short": "Laptop battery not charging", "subcategory": "Laptop", "priority": 3},
            {"short": "Laptop screen flickering", "subcategory": "Laptop", "priority": 3},
            {"short": "Headset microphone not working", "subcategory": "Peripheral", "priority": 4},
            {"short": "Printer not printing", "subcategory": "Printer", "priority": 4},
            {"short": "Webcam not detected", "subcategory": "Peripheral", "priority": 4},
            {"short": "External monitor no signal", "subcategory": "Monitor", "priority": 3},
        ],
    },
    "software": {
        "weight": 30,
        "assignment_group": "Application Support",
        "incidents": [
            {"short": "Microsoft Teams crashing on startup", "subcategory": "Collaboration", "priority": 2},
            {"short": "Outlook not syncing emails", "subcategory": "Email", "priority": 2},
            {"short": "Excel macro not running", "subcategory": "Office", "priority": 4},
            {"short": "Adobe Acrobat license expired", "subcategory": "License", "priority": 3},
            {"short": "VPN client disconnecting frequently", "subcategory": "VPN", "priority": 2},
            {"short": "Zoom meeting crashes when sharing screen", "subcategory": "Collaboration", "priority": 3},
            {"short": "OneDrive sync stuck", "subcategory": "Cloud Storage", "priority": 3},
            {"short": "Software installation request", "subcategory": "Installation", "priority": 5},
            {"short": "Application running slow", "subcategory": "Performance", "priority": 3},
            {"short": "Browser extensions causing issues", "subcategory": "Browser", "priority": 4},
        ],
    },
    "network": {
        "weight": 15,
        "assignment_group": "Network Operations",
        "incidents": [
            {"short": "Cannot connect to VPN", "subcategory": "VPN", "priority": 2},
            {"short": "Slow internet connection", "subcategory": "Connectivity", "priority": 3},
            {"short": "Wi-Fi keeps dropping", "subcategory": "Wireless", "priority": 3},
            {"short": "Cannot access shared network drive", "subcategory": "File Share", "priority": 2},
            {"short": "Network printer offline", "subcategory": "Printer", "priority": 4},
            {"short": "Website not loading", "subcategory": "Connectivity", "priority": 3},
            {"short": "VPN connection slow", "subcategory": "VPN", "priority": 3},
        ],
    },
    "account": {
        "weight": 20,
        "assignment_group": "Service Desk",
        "incidents": [
            {"short": "Password reset request", "subcategory": "Password", "priority": 4},
            {"short": "Account locked out", "subcategory": "Account", "priority": 2},
            {"short": "Cannot access shared drive - permissions", "subcategory": "Permissions", "priority": 3},
            {"short": "MFA not working", "subcategory": "Authentication", "priority": 2},
            {"short": "New employee account setup", "subcategory": "Onboarding", "priority": 3},
            {"short": "Request for elevated permissions", "subcategory": "Permissions", "priority": 4},
            {"short": "SSO login failing", "subcategory": "Authentication", "priority": 2},
            {"short": "Email distribution list access request", "subcategory": "Email", "priority": 5},
        ],
    },
    "infrastructure": {
        "weight": 10,
        "assignment_group": "Database Admins",
        "incidents": [
            {"short": "Server not responding to ping", "subcategory": "Server", "priority": 1},
            {"short": "Database connection timeout", "subcategory": "Database", "priority": 2},
            {"short": "Application service down", "subcategory": "Application", "priority": 1},
            {"short": "Disk space warning on server", "subcategory": "Storage", "priority": 3},
            {"short": "Scheduled job failed", "subcategory": "Automation", "priority": 3},
            {"short": "SSL certificate expiring soon", "subcategory": "Security", "priority": 3},
        ],
    },
}

# =============================================================================
# SCENARIO-SPECIFIC INCIDENTS
# =============================================================================

SCENARIO_INCIDENTS = {
    "cpu_runaway": {
        "days": [10, 11],  # Day 11-12 (0-indexed)
        "incidents": [
            {
                "short": "SQL Server performance degradation on SQL-PROD-01",
                "category": "Infrastructure",
                "subcategory": "Database",
                "priority": 1,
                "cmdb_ci": "SQL-PROD-01",
                "assignment_group": "Database Admins",
                "description": "Users reporting extremely slow database queries. Multiple applications affected.",
                "close_notes": "Killed stuck backup job SPID 67, restarted SQL Server service. Root cause: backup job entered infinite loop.",
            },
            {
                "short": "Application timeout errors - database queries failing",
                "category": "Software",
                "subcategory": "Application",
                "priority": 2,
                "assignment_group": "Application Support",
                "description": "Multiple users reporting timeout errors when accessing business applications.",
                "close_notes": "Related to SQL-PROD-01 performance issue. Resolved when database was fixed.",
            },
            {
                "short": "Business application unresponsive",
                "category": "Software",
                "subcategory": "Application",
                "priority": 2,
                "assignment_group": "Application Support",
                "description": "ERP system extremely slow, users cannot complete daily tasks.",
                "close_notes": "Cascading effect from SQL server issue. Resolved after DB restart.",
            },
        ],
    },
    "memory_leak": {
        "days": [6, 7, 8, 8, 9],  # Days 7-10 (0-indexed), escalating -- scenario ends at day 9 (OOM+restart)
        "incidents": [
            {
                "short": "Website slow to load",
                "category": "Infrastructure",
                "subcategory": "Web Server",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Customer-facing website experiencing slow response times.",
                "close_notes": "Memory leak in web application. Server restarted, dev team notified for fix.",
            },
            {
                "short": "Customer complaints - checkout page unresponsive",
                "category": "Infrastructure",
                "subcategory": "Web Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Multiple customer complaints about checkout failures. Revenue impact.",
                "close_notes": "Related to memory leak on WEB-01. Emergency restart resolved immediate issue.",
            },
            {
                "short": "Web server high memory usage alert",
                "category": "Infrastructure",
                "subcategory": "Server",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Monitoring alert: WEB-01 memory usage above 90%.",
                "close_notes": "Memory leak confirmed. Scheduled restart resolved. Patch being developed.",
            },
            {
                "short": "Web server swap usage critical",
                "category": "Infrastructure",
                "subcategory": "Server",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "WEB-01 swap usage at 8GB and climbing. System becoming unresponsive.",
                "close_notes": "Memory leak causing excessive swapping. Restart scheduled.",
            },
            {
                "short": "Application timeouts on WEB-01",
                "category": "Infrastructure",
                "subcategory": "Application",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Multiple application timeout errors. Users reporting 504 Gateway Timeout.",
                "close_notes": "Related to memory exhaustion. System restart restored service.",
            },
            {
                "short": "CRITICAL: WEB-01 memory at 98% - OOM imminent",
                "category": "Infrastructure",
                "subcategory": "Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "URGENT: WEB-01 memory usage at 98%, swap at 25GB. OOM killer activation expected. Immediate action required.",
                "close_notes": "OOM killer activated at 14:00. Server crashed and was restarted. Root cause: memory leak in web application. Permanent fix deployed.",
            },
        ],
    },
    "firewall_misconfig": {
        "days": [5],  # Day 6 (0-indexed)
        "hours": [10, 11, 12],  # 10:00-12:59 — outage 10:20-12:05, resolution at 12:03
        "incidents": [
            {
                "short": "External users cannot access company website",
                "category": "Network",
                "subcategory": "Firewall",
                "priority": 1,
                "assignment_group": "Network Operations",
                "description": "All external traffic to company website being blocked. Customer impact confirmed.",
                "close_notes": "Firewall rule misconfiguration. ACL blocking inbound traffic to web server IP. Rolled back change.",
            },
            {
                "short": "Customer reports - 403 Forbidden errors on website",
                "category": "Network",
                "subcategory": "Firewall",
                "priority": 1,
                "assignment_group": "Network Operations",
                "description": "Sales team receiving customer calls about website access denied errors.",
                "close_notes": "Related to firewall misconfiguration. Fixed by reverting ACL change.",
            },
        ],
    },
    "ransomware_attempt": {
        "days": [7],  # Day 8 (0-indexed) - attack day
        "hours": [14, 15],  # 14:00-15:00 when incident created
        "incidents": [
            {
                "short": "CRITICAL: Malware detected on AUS-WS-BWHITE01",
                "category": "Security",
                "subcategory": "Malware",
                "priority": 1,
                "cmdb_ci": "AUS-WS-BWHITE01",
                "assignment_group": "Security Operations",
                "description": "Windows Defender detected malware 'Trojan:Win32/Emotet.RPK!MTB' on workstation. User reported suspicious email attachment.",
                "close_notes": "Ransomware dropper detected and blocked by EDR. Endpoint isolated, reimaged. User education scheduled.",
            },
            {
                "short": "Endpoint AUS-WS-BWHITE01 isolated - security incident",
                "category": "Security",
                "subcategory": "Incident Response",
                "priority": 1,
                "cmdb_ci": "AUS-WS-BWHITE01",
                "assignment_group": "Security Operations",
                "description": "Meraki network isolation triggered for compromised endpoint. Lateral movement attempts detected to 10.30.30.21, 10.30.30.22, 10.30.30.40.",
                "close_notes": "Forensic analysis complete. No data exfiltration confirmed. Endpoint reimaged. User Brooklyn White received security awareness training.",
            },
            {
                "short": "User workstation reimaging request - post security incident",
                "category": "Hardware",
                "subcategory": "Laptop",
                "priority": 2,
                "cmdb_ci": "AUS-WS-BWHITE01",
                "assignment_group": "Desktop Support",
                "description": "Workstation AUS-WS-BWHITE01 needs reimaging following security incident INC-SEC-2026-001.",
                "close_notes": "Fresh Windows image applied. User profile restored from backup. Endpoint verified clean.",
            },
        ],
    },
    "exfil": {
        "days": [11],  # Day 12 (0-indexed) - incident response begins
        "hours": [15, 16],  # 15:00-16:00 after initial detection at 14:30
        "incidents": [
            {
                "short": "Suspicious outbound data transfer detected from BOS-WS-AMILLER01",
                "category": "Security",
                "subcategory": "Data Loss",
                "priority": 1,
                "cmdb_ci": "BOS-WS-AMILLER01",
                "assignment_group": "Security Operations",
                "description": "Threat detection alert: Sustained high-volume outbound traffic from 10.10.30.55 to external IP 185.220.101.42 (Frankfurt, Germany). Burst rate exceeded configured threshold. Multiple TCP sessions transferring 500MB-2.5GB each during off-hours (01:00-05:00).",
                "close_notes": "Confirmed APT-style data exfiltration. Compromised accounts: jessica.brown (initial access), alex.miller (primary target). Malicious IAM user svc-datasync and GCP SA svc-gcs-sync removed. Forwarding rule deleted. All sessions revoked. Full IR report filed.",
            },
            {
                "short": "Compromised account investigation - alex.miller",
                "category": "Security",
                "subcategory": "Account Breach",
                "priority": 2,
                "cmdb_ci": "BOS-WS-AMILLER01",
                "assignment_group": "Security Operations",
                "description": "Account alex.miller added to Domain Admins group by jessica.brown. Unauthorized AWS IAM user and GCP service account created. Entra ID application 'DataSync Service' registered with admin consent.",
                "close_notes": "Password reset, MFA re-enrolled. Domain Admin membership revoked. Cloud credentials rotated. Endpoint reimaged.",
            },
            {
                "short": "Email forwarding rule - jessica.brown mailbox",
                "category": "Security",
                "subcategory": "Email Compromise",
                "priority": 2,
                "cmdb_ci": "exchange",
                "assignment_group": "Security Operations",
                "description": "Auto-forwarding rule discovered in jessica.brown's mailbox. All incoming email forwarded to external address backup-jessica.brown@protonmail.com since Day 4.",
                "close_notes": "Forwarding rule removed. Mailbox audit enabled. Password reset and MFA re-enrolled. Security awareness training scheduled.",
            },
        ],
    },
    "certificate_expiry": {
        "days": [12],  # Day 13 (0-indexed) - certificate expires at midnight
        "hours": [6, 7],  # 06:00-07:00 when NOC notices and incident created
        "incidents": [
            {
                "short": "CRITICAL: SSL certificate expired - website down",
                "category": "Infrastructure",
                "subcategory": "Certificate",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Network Operations",
                "description": "Wildcard SSL certificate for *.theFakeTshirtCompany.com expired at midnight. Customers unable to access website. All HTTPS connections failing with certificate errors.",
                "close_notes": "Emergency certificate renewal completed. New wildcard certificate installed on WEB-01 and WEB-02. Services restored at 07:00. Root cause: certificate renewal reminder was missed. Implemented automated monitoring.",
            },
            {
                "short": "Customer complaints - cannot access website",
                "category": "Infrastructure",
                "subcategory": "Web Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Service Desk",
                "description": "Multiple customer calls reporting 'Your connection is not private' error when accessing theFakeTshirtCompany.com. Started around midnight.",
                "close_notes": "Related to SSL certificate expiry (parent incident). Certificate renewed, website accessible.",
            },
            {
                "short": "Implement SSL certificate expiry monitoring",
                "category": "Infrastructure",
                "subcategory": "Certificate",
                "priority": 3,
                "assignment_group": "Network Operations",
                "description": "Post-incident task: Set up automated SSL certificate expiry monitoring with 30/14/7 day alerts to prevent future outages.",
                "close_notes": "Implemented certificate monitoring using Nagios/PRTG. Alerts configured for 30, 14, 7, and 1 day before expiry. Added to runbook.",
            },
        ],
    },
    "dead_letter_pricing": {
        "days": [15, 15, 15],  # Day 16 (0-indexed): 3 incidents/updates throughout the day
        "hours": [9, 11, 13],  # 09:00 auto-alert, 11:30 escalation, 13:30 post-incident
        "incidents": [
            {
                "short": "ServiceBus dead-letter queue threshold exceeded",
                "category": "Infrastructure",
                "subcategory": "Middleware",
                "priority": 3,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Application Support",
                "description": "Automated alert: ServiceBus dead-letter queue 'prices-queue' exceeded 500 messages. Consumer service 'servicebus-price-consumer' is not running. Price update messages are accumulating.",
                "close_notes": "Consumer crashed due to OutOfMemoryException at 08:00. Systemd auto-restart failed (start-limit-hit). Manually restarted at 12:00. DLQ drained by 12:30.",
            },
            {
                "short": "Customer complaints - incorrect product pricing on web store",
                "category": "Business",
                "subcategory": "E-Commerce",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Application Support",
                "description": "Multiple customer reports of pricing discrepancies on theFakeTshirtCompany.com. Some products showing lower prices than expected, others showing higher. Checkout errors increasing. Revenue impact confirmed.",
                "close_notes": "Root cause: ServiceBus price update consumer crash caused web store to serve stale cached prices. 42 products affected. Revenue impact estimated at $500-800. Consumer restarted, prices corrected.",
            },
            {
                "short": "Post-incident: ServiceBus consumer crash root cause analysis",
                "category": "Infrastructure",
                "subcategory": "Middleware",
                "priority": 3,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Application Support",
                "description": "Post-incident review for DLQ pricing incident. Need to identify root cause of consumer crash and implement preventive measures.",
                "close_notes": "Root cause: memory leak in PriceUpdateConsumer.ProcessMessageAsync when processing bulk price updates. Fix: added message batching (max 50/batch), circuit breaker pattern, and DLQ count alerting at 100 messages. Deployed hotfix v2.4.1.",
            },
        ],
    },
    "ddos_attack": {
        "days": [17, 17, 18],  # Day 18 (P1 DDoS alert at 09:00, P1 customer complaints at 11:00), Day 19 (P3 review)
        "hours": [9, 11, 10],  # Hour hints for each incident
        "incidents": [
            {
                "short": "CRITICAL: DDoS attack detected - website under volumetric HTTP flood",
                "category": "Network",
                "subcategory": "Security",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Network Operations",
                "description": "NOC alert: Volumetric HTTP flood targeting WEB-01/WEB-02 (172.16.1.10/11). Inbound traffic from 10+ source IPs exceeding 5Gbps. ASA rate limiting engaged. Website response times 10x normal.",
                "close_notes": "Emergency ACL applied at 10:00 blocking wave 1 botnet IPs. Attacker adapted with new IPs at 12:00 (wave 2). ISP-level DDoS filtering activated at 14:00. Attack fully subsided by 18:00. Post-incident review scheduled.",
            },
            {
                "short": "Customer complaints - website extremely slow and returning 503 errors",
                "category": "Network",
                "subcategory": "Web Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Service Desk",
                "description": "Multiple customer reports of website being unreachable or extremely slow. 60% of requests returning HTTP 503. Revenue impact confirmed - orders dropping significantly.",
                "close_notes": "Related to DDoS attack on web servers. Emergency mitigation restored partial service. Full recovery after ISP filtering activated. Estimated revenue loss during attack window.",
            },
            {
                "short": "Post-incident review: DDoS attack mitigation and permanent defenses",
                "category": "Network",
                "subcategory": "Security",
                "priority": 3,
                "assignment_group": "Network Operations",
                "description": "Post-incident review for DDoS attack on Jan 18. Need to evaluate response effectiveness and implement permanent DDoS mitigation.",
                "close_notes": "Review completed. Recommendations: 1) Implement always-on CDN/DDoS protection (Cloudflare/AWS Shield), 2) Pre-configure emergency ACL templates, 3) Establish ISP DDoS scrubbing SLA, 4) Add rate-limiting at application layer. Change request submitted.",
            },
        ],
    },
    "phishing_test": {
        "days": [20, 22],  # Day 21 (campaign deployed), Day 23 (results summary)
        "hours": [9, 10],  # 09:00 campaign deployment, 10:00 results
        "incidents": [
            {
                "short": "Phishing awareness campaign deployed - KnowBe4 simulation",
                "category": "Security",
                "subcategory": "Security Awareness",
                "priority": 4,
                "assignment_group": "Security Operations",
                "description": "IT Security phishing awareness campaign launched. Simulated phishing emails sent to all 175 employees across BOS/ATL/AUS. Using KnowBe4 platform with Microsoft 365 password expiry lure. Campaign operator: Ashley Griffin.",
                "close_notes": "Campaign deployed successfully. Wave 1 (BOS) at 09:00, Wave 2 (ATL) at 10:00, Wave 3 (AUS) at 11:00. All 175 emails delivered. Monitoring link clicks and credential submissions.",
            },
            {
                "short": "Phishing test results: 31% click rate, 10% credential submission",
                "category": "Security",
                "subcategory": "Security Awareness",
                "priority": 3,
                "assignment_group": "Security Operations",
                "description": "Phishing simulation results compiled. 55 of 175 employees (31%) clicked the link. 18 employees (10%) submitted credentials on the fake login page. 35 employees reported the email to IT (20%). Mandatory security awareness training assigned to all clickers.",
                "close_notes": "Results shared with management. Training emails sent to 55 employees who clicked. Recommended quarterly phishing simulations and enhanced email security training for new hires.",
            },
        ],
    },
    "disk_filling": {
        "days": [2, 3, 4],  # Day 3 (warning @ 75%), Day 4 (critical @ 88%), Day 5 (emergency @ 96%)
        "incidents": [
            {
                "short": "Disk space warning on MON-ATL-01",
                "category": "Infrastructure",
                "subcategory": "Storage",
                "priority": 3,
                "cmdb_ci": "MON-ATL-01",
                "assignment_group": "Linux Admins",
                "description": "Monitoring alert: MON-ATL-01 disk usage above 75%. Server hosts critical monitoring services.",
                "close_notes": "Identified excessive logging from monitoring agents. Implemented log rotation policy.",
            },
            {
                "short": "CRITICAL: Disk space critical on MON-ATL-01",
                "category": "Infrastructure",
                "subcategory": "Storage",
                "priority": 2,
                "cmdb_ci": "MON-ATL-01",
                "assignment_group": "Linux Admins",
                "description": "MON-ATL-01 disk usage at 88%. Monitoring services may fail if not addressed.",
                "close_notes": "Emergency cleanup performed. Archived old logs to backup storage.",
            },
            {
                "short": "EMERGENCY: Server MON-ATL-01 disk nearly full",
                "category": "Infrastructure",
                "subcategory": "Storage",
                "priority": 1,
                "cmdb_ci": "MON-ATL-01",
                "assignment_group": "Linux Admins",
                "description": "CRITICAL: MON-ATL-01 at 96% disk capacity. Monitoring services impacted. Alerting may be degraded.",
                "close_notes": "Expanded disk volume, migrated historical logs to new storage array. RCA scheduled for next week.",
            },
        ],
    },
}

# =============================================================================
# CMDB CONFIGURATION
# =============================================================================

# Server role → assignment group mapping
SERVER_ASSIGNMENT_GROUPS = {
    "Domain Controller": "Desktop Support",
    "File Server": "Desktop Support",
    "Database Server": "Database Admins",
    "Application Server": "Application Support",
    "Web Server": "Linux Admins",
    "Backup Server": "Linux Admins",
    "Monitoring Server": "Linux Admins",
    "Dev/Test Server": "Linux Admins",
}

# Server role → hardware specs
SERVER_SPECS = {
    "Domain Controller": {"manufacturer": "Dell", "model": "PowerEdge R650", "cpu": 8, "ram": 32, "disk": 500},
    "File Server": {"manufacturer": "Dell", "model": "PowerEdge R750", "cpu": 16, "ram": 64, "disk": 4000},
    "Database Server": {"manufacturer": "Dell", "model": "PowerEdge R750", "cpu": 16, "ram": 64, "disk": 2000},
    "Application Server": {"manufacturer": "Dell", "model": "PowerEdge R650", "cpu": 8, "ram": 32, "disk": 500},
    "Web Server": {"manufacturer": "Dell", "model": "PowerEdge R650", "cpu": 8, "ram": 16, "disk": 250},
    "Backup Server": {"manufacturer": "Dell", "model": "PowerEdge R750", "cpu": 8, "ram": 32, "disk": 8000},
    "Monitoring Server": {"manufacturer": "Dell", "model": "PowerEdge R650", "cpu": 8, "ram": 32, "disk": 1000},
    "Dev/Test Server": {"manufacturer": "Dell", "model": "PowerEdge R650", "cpu": 4, "ram": 16, "disk": 250},
}

# Network device specs
NETWORK_SPECS = {
    "ASA 5525-X": {"manufacturer": "Cisco", "category": "Network", "subcategory": "Firewall"},
    "MX450": {"manufacturer": "Cisco Meraki", "category": "Network", "subcategory": "SD-WAN Gateway"},
    "MX250": {"manufacturer": "Cisco Meraki", "category": "Network", "subcategory": "SD-WAN Gateway"},
    "MX85": {"manufacturer": "Cisco Meraki", "category": "Network", "subcategory": "SD-WAN Gateway"},
}

# Business applications
BUSINESS_APPS = [
    {"name": "E-Commerce Platform", "assignment_group": "Application Support",
     "depends_on": ["WEB-01", "WEB-02", "SQL-PROD-01"]},
    {"name": "Active Directory", "assignment_group": "Desktop Support",
     "depends_on": ["DC-BOS-01", "DC-BOS-02", "DC-ATL-01"]},
    {"name": "Corporate Email (O365)", "assignment_group": "Application Support",
     "depends_on": []},
    {"name": "Monitoring System", "assignment_group": "Linux Admins",
     "depends_on": ["MON-ATL-01"]},
    {"name": "Finance Application", "assignment_group": "Application Support",
     "depends_on": ["APP-BOS-01", "SQL-PROD-01"]},
    {"name": "Backup System", "assignment_group": "Linux Admins",
     "depends_on": ["BACKUP-ATL-01"]},
]

# Scenario workstations (Lenovo ThinkPad T14s Gen 5)
SCENARIO_WORKSTATIONS = [
    {"name": "BOS-WS-AMILLER01", "ip": "10.10.30.55", "location": "BOS",
     "user": "alex.miller", "os": "Windows 11 Enterprise"},
    {"name": "AUS-WS-BWHITE01", "ip": "10.30.30.20", "location": "AUS",
     "user": "brooklyn.white", "os": "Windows 11 Enterprise"},
    {"name": "ATL-WS-JBROWN01", "ip": "10.20.30.15", "location": "ATL",
     "user": "jessica.brown", "os": "Windows 11 Enterprise"},
]


# =============================================================================
# CHANGE REQUEST CONFIGURATION
# =============================================================================

# Change volume
BASE_CHANGES_PER_DAY = 3   # Weekday
WEEKEND_CHANGES = 1

# Baseline change templates
CHANGE_TEMPLATES = [
    {"short": "Scheduled Windows security patches - {server}",
     "category": "Software", "type": "standard", "risk": "Low",
     "assignment_group": "Desktop Support", "duration_hours": 2},
    {"short": "Deploy application update to {server}",
     "category": "Application", "type": "normal", "risk": "Moderate",
     "assignment_group": "Application Support", "duration_hours": 3},
    {"short": "Network switch firmware upgrade - {location}",
     "category": "Network", "type": "normal", "risk": "Moderate",
     "assignment_group": "Network Operations", "duration_hours": 4},
    {"short": "Database maintenance window - {server}",
     "category": "Database", "type": "standard", "risk": "Low",
     "assignment_group": "Database Admins", "duration_hours": 2},
    {"short": "Backup schedule adjustment for {server}",
     "category": "Infrastructure", "type": "standard", "risk": "Low",
     "assignment_group": "Linux Admins", "duration_hours": 1},
    {"short": "Add new VLAN for IoT devices at {location}",
     "category": "Network", "type": "normal", "risk": "Moderate",
     "assignment_group": "Network Operations", "duration_hours": 3},
    {"short": "Increase disk allocation on {server}",
     "category": "Infrastructure", "type": "standard", "risk": "Low",
     "assignment_group": "Linux Admins", "duration_hours": 1},
    {"short": "Update monitoring thresholds for {server}",
     "category": "Infrastructure", "type": "standard", "risk": "Low",
     "assignment_group": "Application Support", "duration_hours": 1},
]

# Scenario-linked changes
SCENARIO_CHANGES = {
    "firewall_misconfig": {
        "day": 5,  # Day 6 (0-indexed) — BEFORE the outage on Day 7
        "changes": [{
            "short": "Update ACL rules on FW-EDGE-01 - permit new vendor subnet",
            "type": "normal", "category": "Network", "risk": "Moderate", "impact": 2,
            "cmdb_ci": "FW-EDGE-01", "assignment_group": "Network Operations",
            "description": (
                "Add permit rules for new vendor subnet 198.51.100.0/24 to FW-EDGE-01 "
                "inbound ACL. Required for new B2B integration with shipping provider."
            ),
            "planned_start": {"day": 6, "hour": 10, "minute": 0},
            "planned_end": {"day": 6, "hour": 11, "minute": 0},
            "close_code": "Successful with issues",
            "close_notes": (
                "ACL change applied but introduced blocking rule for 0.0.0.0/0 inbound on "
                "interface outside. Root cause: copy-paste error in ACL entry. Rollback "
                "performed at 12:05. Post-change review identified gap in peer review process."
            ),
        }],
    },
    "cpu_runaway": {
        "day": 11,  # Day 12 (0-indexed) — matches actual fix at 10:30
        "changes": [{
            "short": "Emergency: Kill stuck backup job on SQL-PROD-01",
            "type": "emergency", "category": "Database", "risk": "High", "impact": 1,
            "cmdb_ci": "SQL-PROD-01", "assignment_group": "Database Admins",
            "description": (
                "Emergency change to terminate stuck backup SPID 67 on SQL-PROD-01. "
                "Backup job has been running for 20+ hours causing 100% CPU and cascading "
                "application failures."
            ),
            "close_notes": (
                "Killed stuck backup process SPID 67. SQL Server service restarted. "
                "CPU dropped from 100% to 25% within 5 minutes. All dependent applications "
                "restored. RCA: backup job deadlock with maintenance task."
            ),
        }],
    },
    "certificate_expiry": {
        "day": 11,
        "changes": [{
            "short": "Emergency: Renew expired SSL certificate for *.theFakeTshirtCompany.com",
            "type": "emergency", "category": "Security", "risk": "High", "impact": 1,
            "cmdb_ci": "WEB-01", "assignment_group": "Network Operations",
            "description": (
                "Wildcard SSL certificate for *.theFakeTshirtCompany.com expired at "
                "midnight 2026-01-12. All HTTPS traffic failing. E-commerce revenue impact."
            ),
            "close_notes": (
                "New wildcard certificate purchased from DigiCert. Installed on WEB-01 "
                "and WEB-02. Services restored at 07:00. Implemented automated certificate "
                "monitoring with 30/14/7-day alerts."
            ),
        }],
    },
    "memory_leak": {
        "day": 8,  # Day 9 (0-indexed) — OOM crash day
        "changes": [{
            "short": "Emergency: Restart WEB-01 application services after OOM",
            "type": "emergency", "category": "Application", "risk": "High", "impact": 1,
            "cmdb_ci": "WEB-01", "assignment_group": "Linux Admins",
            "description": (
                "WEB-01 experienced OOM kill at 14:00. Linux kernel killed Apache "
                "processes. Website down. Emergency restart required."
            ),
            "close_notes": (
                "Server restarted. Application services restored at 14:15. Memory leak "
                "in PHP session handler identified. Temporary fix: increased swap and "
                "added cron job to restart Apache nightly. Permanent fix in dev sprint."
            ),
        }],
    },
    "exfil": {
        "day": 11,  # Day 12 — IR response
        "changes": [{
            "short": "Emergency: Isolate compromised endpoints - Security Incident",
            "type": "emergency", "category": "Security", "risk": "High", "impact": 1,
            "cmdb_ci": "BOS-WS-AMILLER01", "assignment_group": "Security Operations",
            "description": (
                "Isolate endpoints involved in confirmed data exfiltration. "
                "BOS-WS-AMILLER01 and ATL-WS-JBROWN01 identified as compromised. "
                "Revoke all cloud credentials. Remove malicious forwarding rules."
            ),
            "close_notes": (
                "Endpoints isolated via Meraki network policy. All credentials rotated "
                "for alex.miller and jessica.brown. AWS IAM user svc-datasync deleted. "
                "GCP SA svc-gcs-sync removed. Exchange forwarding rule deleted."
            ),
        }],
    },
    "ransomware_attempt": {
        "day": 7,  # Day 8
        "changes": [{
            "short": "Emergency: Network isolation for AUS-WS-BWHITE01 - Malware detected",
            "type": "emergency", "category": "Security", "risk": "High", "impact": 2,
            "cmdb_ci": "AUS-WS-BWHITE01", "assignment_group": "Security Operations",
            "description": (
                "Ransomware dropper detected on AUS-WS-BWHITE01. Meraki network "
                "isolation applied. Endpoint quarantined pending forensic analysis."
            ),
            "close_notes": (
                "Endpoint isolated and reimaged. No lateral spread confirmed. "
                "Malware variant: Trojan:Win32/Emotet.RPK!MTB. Entry vector: "
                "phishing email with malicious Excel attachment."
            ),
        }],
    },
    "ddos_attack": {
        "day": 18,  # Day 19 -- post-incident permanent mitigation
        "changes": [{
            "short": "Emergency: Deploy DDoS mitigation - ACL + ISP filtering for web servers",
            "type": "emergency", "category": "Network", "risk": "High", "impact": 1,
            "cmdb_ci": "WEB-01", "assignment_group": "Network Operations",
            "description": (
                "Emergency change in response to volumetric DDoS attack on Jan 18. "
                "Actions: 1) Apply permanent rate-limiting ACLs on FW-EDGE-01, "
                "2) Enable ISP DDoS scrubbing service, 3) Configure CDN-based "
                "DDoS protection for public web endpoints 203.0.113.10."
            ),
            "close_notes": (
                "Permanent DDoS mitigation deployed: Rate-limiting ACLs on FW-EDGE-01 "
                "(max 1000 conn/sec per source IP). ISP DDoS scrubbing SLA activated "
                "(auto-trigger at 2Gbps). Cloudflare CDN configured for web servers. "
                "Emergency ACL templates documented in runbook. Recovery confirmed."
            ),
        }],
    },
    "phishing_test": {
        "day": 19,  # Day 20 (0-indexed) -- pre-campaign approval
        "changes": [{
            "short": "Standard: Deploy phishing awareness simulation campaign",
            "type": "standard", "category": "Security", "risk": "Low", "impact": 3,
            "assignment_group": "Security Operations",
            "description": (
                "Deploy IT Security phishing awareness campaign using KnowBe4 platform. "
                "Simulated Microsoft 365 password expiry emails to all 175 employees. "
                "Scheduled for Jan 21 in 3 waves: BOS 09:00, ATL 10:00, AUS 11:00. "
                "Approved by CISO following real phishing incident on Day 12."
            ),
            "planned_start": {"day": 20, "hour": 9, "minute": 0},
            "planned_end": {"day": 22, "hour": 17, "minute": 0},
            "close_code": "Successful",
            "close_notes": (
                "Campaign completed successfully. 175 emails sent, all delivered. "
                "Results: 55 clicked (31%), 18 submitted credentials (10%), "
                "35 reported to IT (20%), 67 ignored (39%). Mandatory training "
                "assigned to 55 clickers. Quarterly campaign cadence recommended."
            ),
        }],
    },
    "disk_filling": {
        "day": 3,  # Day 4 -- proactive change
        "changes": [{
            "short": "Increase disk allocation on MON-ATL-01",
            "type": "standard", "category": "Infrastructure", "risk": "Low", "impact": 3,
            "cmdb_ci": "MON-ATL-01", "assignment_group": "Linux Admins",
            "description": (
                "Proactive disk expansion for MON-ATL-01. Current usage trending "
                "upward. Extend /var partition by 100GB from SAN."
            ),
            "close_notes": (
                "Disk expansion completed. /var extended from 200GB to 300GB. "
                "Note: Usage continued to climb -- separate investigation needed."
            ),
        }],
    },
    "dead_letter_pricing": {
        "day": 15,  # Day 16 -- consumer restart
        "changes": [{
            "short": "Emergency: Restart ServiceBus price update consumer on WEB-01",
            "type": "emergency", "category": "Application", "risk": "Moderate", "impact": 2,
            "cmdb_ci": "WEB-01", "assignment_group": "Application Support",
            "description": (
                "ServiceBus price update consumer crashed at 08:00 due to "
                "OutOfMemoryException. Systemd auto-restart failed. Dead-letter "
                "queue at 620 messages. Manual restart and DLQ replay required."
            ),
            "close_notes": (
                "Consumer manually restarted at 12:00. DLQ replay completed by "
                "12:30 (620 messages processed, 0 errors). All product prices "
                "verified against catalog. 43 prices corrected. Hotfix v2.4.1 "
                "deployed with message batching and circuit breaker."
            ),
        }],
    },
}

# =============================================================================
# CLOSE CODES AND NOTES
# =============================================================================

CLOSE_CODES = ["Solved", "Workaround", "Not Reproducible", "Duplicate", "No Action Required"]

GENERIC_CLOSE_NOTES = {
    "hardware": [
        "Replaced defective hardware component",
        "Reseated connections, issue resolved",
        "Updated drivers, hardware functioning normally",
        "Device replaced under warranty",
        "Cleaned hardware, issue resolved",
    ],
    "software": [
        "Reinstalled application, issue resolved",
        "Updated to latest version",
        "Cleared cache and temporary files",
        "Reset user profile settings",
        "Applied vendor patch",
    ],
    "network": [
        "Reset network configuration",
        "VPN profile recreated",
        "Network cable replaced",
        "DHCP lease renewed",
        "DNS cache flushed",
    ],
    "account": [
        "Password reset completed",
        "Account unlocked",
        "Permissions granted as requested",
        "MFA reset and reconfigured",
        "Group membership updated",
    ],
    "infrastructure": [
        "Service restarted successfully",
        "Disk space cleared",
        "Scheduled task reconfigured",
        "Certificate renewed",
        "Server rebooted to apply updates",
    ],
}

WORK_NOTES = [
    "Investigating reported issue",
    "Contacted user for more details",
    "Reproduced the issue in test environment",
    "Escalating to next level support",
    "Awaiting vendor response",
    "Applied temporary workaround",
    "Testing fix in progress",
    "User confirmed issue resolved",
    "Monitoring for recurrence",
    "Scheduled follow-up with user",
]

# =============================================================================
# INCIDENT TRACKING
# =============================================================================

_incident_counter = 0


def get_next_incident_number() -> str:
    """Generate next incident number."""
    global _incident_counter
    _incident_counter += 1
    return f"INC{_incident_counter:07d}"


def reset_incident_counter():
    """Reset incident counter (for testing)."""
    global _incident_counter
    _incident_counter = 0


# =============================================================================
# HELPERS
# =============================================================================

def format_kv_line(fields: Dict) -> str:
    """Format a dictionary as a key-value line."""
    parts = []
    for key, value in fields.items():
        if value is not None:
            # demo_id is always unquoted (consistent with all other generators)
            if key == "demo_id":
                parts.append(f'{key}={value}')
            elif isinstance(value, str):
                value = value.replace('"', '\\"')
                parts.append(f'{key}="{value}"')
            else:
                parts.append(f'{key}={value}')
    return " ".join(parts)


def get_random_user() -> Tuple[str, str]:
    """Get random user (username, display_name)."""
    username = random.choice(USER_KEYS)
    user = USERS[username]
    email = f"{username}@{TENANT}"
    return email, user.display_name


def get_random_location() -> str:
    """Get random location name."""
    loc_code = random.choice(list(LOCATIONS.keys()))
    return LOCATIONS[loc_code]["name"]


def get_priority() -> int:
    """Get weighted random priority."""
    weights = [PRIORITIES[p]["weight"] for p in range(1, 6)]
    return random.choices(range(1, 6), weights=weights)[0]


def get_category() -> Tuple[str, Dict]:
    """Get weighted random category and its config."""
    categories = list(INCIDENT_TEMPLATES.keys())
    weights = [INCIDENT_TEMPLATES[c]["weight"] for c in categories]
    category = random.choices(categories, weights=weights)[0]
    return category.title(), INCIDENT_TEMPLATES[category]


def get_assignment_member(group_name: str) -> Tuple[str, str]:
    """Get random member from assignment group (email, display_name)."""
    group = ASSIGNMENT_GROUPS.get(group_name, ASSIGNMENT_GROUPS["Service Desk"])
    idx = random.randint(0, len(group["members"]) - 1)
    member = group["members"][idx]
    display = group["display"][idx]
    return f"{member}@{TENANT}", display


# =============================================================================
# INCIDENT LIFECYCLE GENERATOR
# =============================================================================

@dataclass
class Incident:
    """Represents a ServiceNow incident."""
    number: str
    short_description: str
    description: str
    category: str
    subcategory: str
    priority: int
    urgency: int
    impact: int
    caller_id: str
    caller_name: str
    assignment_group: str
    assigned_to: Optional[str]
    assigned_to_name: Optional[str]
    cmdb_ci: Optional[str]
    location: str
    opened_at: datetime
    demo_id: Optional[str] = None
    close_notes: Optional[str] = None


def generate_incident_lifecycle(incident: Incident, base_date: datetime) -> List[str]:
    """
    Generate all events for an incident lifecycle.
    Returns list of key-value formatted lines.
    """
    events = []

    # Calculate resolution time based on priority
    resolve_min, resolve_max = PRIORITIES[incident.priority]["resolve_hours"]
    resolve_hours = random.uniform(resolve_min, resolve_max)

    # Event 1: New (incident created)
    fields = {
        "sys_updated_on": incident.opened_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "New",
        "short_description": incident.short_description,
        "description": incident.description,
        "category": incident.category,
        "subcategory": incident.subcategory,
        "priority": incident.priority,
        "urgency": incident.urgency,
        "impact": incident.impact,
        "caller_id": incident.caller_id,
        "caller_name": incident.caller_name,
        "assignment_group": incident.assignment_group,
        "location": incident.location,
    }
    if incident.cmdb_ci:
        fields["cmdb_ci"] = incident.cmdb_ci
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Event 2: Assigned (5-30 min later)
    assign_delay = random.randint(5, 30)
    assign_time = incident.opened_at + timedelta(minutes=assign_delay)
    assigned_to, assigned_name = get_assignment_member(incident.assignment_group)

    fields = {
        "sys_updated_on": assign_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "In Progress",
        "assigned_to": assigned_to,
        "assigned_to_name": assigned_name,
        "work_notes": random.choice(WORK_NOTES[:5]),  # Investigation notes
    }
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Event 3: Work notes update (30-60 min later, optional for longer incidents)
    if resolve_hours > 2:
        update_delay = random.randint(30, 90)
        update_time = assign_time + timedelta(minutes=update_delay)

        fields = {
            "sys_updated_on": update_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number": incident.number,
            "state": "In Progress",
            "work_notes": random.choice(WORK_NOTES[3:]),  # Progress notes
        }
        if incident.demo_id:
            fields["demo_id"] = incident.demo_id
        events.append(format_kv_line(fields))

    # Event 4: Resolved
    resolved_time = incident.opened_at + timedelta(hours=resolve_hours)

    # Get close notes
    if incident.close_notes:
        close_notes = incident.close_notes
    else:
        category_lower = incident.category.lower()
        if category_lower in GENERIC_CLOSE_NOTES:
            close_notes = random.choice(GENERIC_CLOSE_NOTES[category_lower])
        else:
            close_notes = random.choice(GENERIC_CLOSE_NOTES["software"])

    # Check SLA breach: if resolve_hours exceeds SLA target for this priority
    sla_target_hours = PRIORITIES[incident.priority]["resolve_hours"][1]  # max target
    sla_breached = resolve_hours > sla_target_hours

    fields = {
        "sys_updated_on": resolved_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "Resolved",
        "resolved_by": assigned_to,
        "resolved_by_name": assigned_name,
        "close_code": random.choice(CLOSE_CODES[:2]),  # Mostly Solved/Workaround
        "close_notes": close_notes,
    }
    if sla_breached:
        fields["sla_breached"] = "true"
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Priority escalation: ~10% chance for P3+ incidents, mid-lifecycle
    escalated = False
    if incident.priority >= 3 and random.random() < 0.10:
        escalated = True
        escalation_time = incident.opened_at + timedelta(hours=resolve_hours * 0.4)
        new_priority = max(1, incident.priority - 1)
        esc_fields = {
            "sys_updated_on": escalation_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number": incident.number,
            "state": "In Progress",
            "priority": new_priority,
            "urgency": new_priority,
            "work_notes": f"Priority escalated from {incident.priority} to {new_priority} - customer impact increasing",
        }
        if sla_breached:
            esc_fields["sla_breached"] = "true"
        if incident.demo_id:
            esc_fields["demo_id"] = incident.demo_id
        events.append(format_kv_line(esc_fields))

    # Event 5: Closed (1-24 hours after resolved)
    close_delay = random.randint(1, 24)
    closed_time = resolved_time + timedelta(hours=close_delay)

    fields = {
        "sys_updated_on": closed_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "Closed",
    }
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Incident reopening: ~8% of resolved incidents get reopened
    if random.random() < 0.08:
        reopen_delay = random.randint(2, 48)  # 2-48 hours after close
        reopen_time = closed_time + timedelta(hours=reopen_delay)

        # Reopen event
        reopen_fields = {
            "sys_updated_on": reopen_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number": incident.number,
            "state": "In Progress",
            "reopen_count": 1,
            "work_notes": random.choice([
                "Issue recurred after initial fix",
                "User reports problem not fully resolved",
                "Related symptoms returned after restart",
                "Workaround no longer effective",
            ]),
        }
        if incident.demo_id:
            reopen_fields["demo_id"] = incident.demo_id
        events.append(format_kv_line(reopen_fields))

        # Re-resolve (1-8 hours after reopen)
        reresolve_delay = random.uniform(1, 8)
        reresolve_time = reopen_time + timedelta(hours=reresolve_delay)

        reresolve_fields = {
            "sys_updated_on": reresolve_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number": incident.number,
            "state": "Resolved",
            "resolved_by": assigned_to,
            "close_code": "Solved",
            "close_notes": random.choice([
                "Root cause identified and permanent fix applied",
                "Applied vendor hotfix, monitoring for recurrence",
                "Replaced component, issue confirmed resolved",
                "Configuration corrected, verified with user",
            ]),
        }
        if incident.demo_id:
            reresolve_fields["demo_id"] = incident.demo_id
        events.append(format_kv_line(reresolve_fields))

        # Re-close
        reclose_time = reresolve_time + timedelta(hours=random.randint(1, 12))
        reclose_fields = {
            "sys_updated_on": reclose_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number": incident.number,
            "state": "Closed",
            "reopen_count": 1,
        }
        if incident.demo_id:
            reclose_fields["demo_id"] = incident.demo_id
        events.append(format_kv_line(reclose_fields))

    return events


# =============================================================================
# CMDB GENERATOR
# =============================================================================

def _cmdb_sys_id(name: str) -> str:
    """Generate deterministic sys_id from CI name."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}.theFakeTshirtCompany.com"))


def generate_cmdb_records(start_date: str) -> List[str]:
    """Generate static CMDB CI records and relationships as KV lines.

    Sources: SERVERS, ASA_PERIMETER, MERAKI_FIREWALLS, BUSINESS_APPS,
    SCENARIO_WORKSTATIONS, and dependency relationships.
    """
    # sys_updated_on = day before start_date
    base_date = datetime.strptime(start_date, "%Y-%m-%d")
    cmdb_ts = (base_date - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")

    records = []
    asset_counter = 0

    # Location code → full name
    loc_names = {code: loc["full_name"] for code, loc in LOCATIONS.items()}

    # --- Servers (12) ---
    for hostname, server in SERVERS.items():
        asset_counter += 1
        specs = SERVER_SPECS.get(server.role, SERVER_SPECS["Dev/Test Server"])
        os_name = "Windows Server 2022" if server.os == "windows" else "Ubuntu 22.04 LTS"
        os_version = "21H2" if server.os == "windows" else "22.04"
        ci_class = "cmdb_ci_win_server" if server.os == "windows" else "cmdb_ci_linux_server"

        # Map role to category/subcategory
        role_map = {
            "Domain Controller": ("Server", "Active Directory"),
            "File Server": ("Server", "File Storage"),
            "Database Server": ("Server", "Database"),
            "Application Server": ("Server", "Application"),
            "Web Server": ("Server", "Web"),
            "Backup Server": ("Server", "Backup"),
            "Monitoring Server": ("Server", "Monitoring"),
            "Dev/Test Server": ("Server", "Development"),
        }
        cat, subcat = role_map.get(server.role, ("Server", "General"))

        fields = {
            "sys_updated_on": cmdb_ts,
            "sys_id": _cmdb_sys_id(hostname),
            "sys_class_name": ci_class,
            "name": hostname,
            "ip_address": server.ip,
            "os": os_name,
            "os_version": os_version,
            "location": loc_names.get(server.location, "Boston HQ"),
            "operational_status": "1",
            "assignment_group": SERVER_ASSIGNMENT_GROUPS.get(server.role, "Service Desk"),
            "asset_tag": f"ASSET-{server.location}-SRV-{asset_counter:03d}",
            "serial_number": f"SN-{hostname}-2024",
            "manufacturer": specs["manufacturer"],
            "model_id": specs["model"],
            "cpu_count": specs["cpu"],
            "ram": specs["ram"],
            "disk_space": specs["disk"],
            "dns_domain": "theFakeTshirtCompany.com",
            "fqdn": f"{hostname}.theFakeTshirtCompany.com",
            "category": cat,
            "subcategory": subcat,
            "record_type": "ci",
        }
        records.append(format_kv_line(fields))

    # --- Network devices (5) ---
    # ASA perimeter
    asa = ASA_PERIMETER
    fields = {
        "sys_updated_on": cmdb_ts,
        "sys_id": _cmdb_sys_id(asa["hostname"]),
        "sys_class_name": "cmdb_ci_net_gear",
        "name": asa["hostname"],
        "ip_address": "10.10.0.1",
        "location": loc_names.get(asa["location"], "Boston HQ"),
        "operational_status": "1",
        "assignment_group": "Network Operations",
        "serial_number": f"SN-{asa['hostname']}-2024",
        "manufacturer": "Cisco",
        "model_id": asa["model"],
        "category": "Network",
        "subcategory": "Firewall",
        "record_type": "ci",
    }
    records.append(format_kv_line(fields))

    # Meraki MX firewalls
    for loc_code, mx_config in MERAKI_FIREWALLS.items():
        specs = NETWORK_SPECS.get(mx_config["model"], {})
        for device_name in mx_config["devices"]:
            fields = {
                "sys_updated_on": cmdb_ts,
                "sys_id": _cmdb_sys_id(device_name),
                "sys_class_name": "cmdb_ci_net_gear",
                "name": device_name,
                "location": loc_names.get(loc_code, "Boston HQ"),
                "operational_status": "1",
                "assignment_group": "Network Operations",
                "serial_number": f"SN-{device_name}-2024",
                "manufacturer": specs.get("manufacturer", "Cisco Meraki"),
                "model_id": mx_config["model"],
                "category": specs.get("category", "Network"),
                "subcategory": specs.get("subcategory", "SD-WAN Gateway"),
                "record_type": "ci",
            }
            records.append(format_kv_line(fields))

    # --- Business applications (6) ---
    for app in BUSINESS_APPS:
        fields = {
            "sys_updated_on": cmdb_ts,
            "sys_id": _cmdb_sys_id(app["name"]),
            "sys_class_name": "cmdb_ci_app_server",
            "name": app["name"],
            "location": "Boston HQ",
            "operational_status": "1",
            "assignment_group": app["assignment_group"],
            "category": "Application",
            "subcategory": "Business Service",
            "record_type": "ci",
        }
        records.append(format_kv_line(fields))

    # --- Scenario workstations (3, Lenovo ThinkPad) ---
    for ws in SCENARIO_WORKSTATIONS:
        fields = {
            "sys_updated_on": cmdb_ts,
            "sys_id": _cmdb_sys_id(ws["name"]),
            "sys_class_name": "cmdb_ci_computer",
            "name": ws["name"],
            "ip_address": ws["ip"],
            "os": ws["os"],
            "os_version": "23H2",
            "location": loc_names.get(ws["location"], "Boston HQ"),
            "operational_status": "1",
            "assignment_group": "Desktop Support",
            "serial_number": f"SN-{ws['name']}-2025",
            "manufacturer": "Lenovo",
            "model_id": "ThinkPad T14s Gen 5",
            "cpu_count": 8,
            "ram": 16,
            "disk_space": 512,
            "assigned_to": f"{ws['user']}@{TENANT}",
            "category": "Workstation",
            "subcategory": "Laptop",
            "record_type": "ci",
        }
        records.append(format_kv_line(fields))

    # --- Relationships (app → infrastructure) ---
    for app in BUSINESS_APPS:
        parent_id = _cmdb_sys_id(app["name"])
        for dep_name in app["depends_on"]:
            child_id = _cmdb_sys_id(dep_name)
            fields = {
                "sys_updated_on": cmdb_ts,
                "sys_id": _cmdb_sys_id(f"{app['name']}::{dep_name}"),
                "sys_class_name": "cmdb_rel_ci",
                "parent_sys_id": parent_id,
                "parent_name": app["name"],
                "child_sys_id": child_id,
                "child_name": dep_name,
                "type": "Depends on::Used by",
                "record_type": "relationship",
            }
            records.append(format_kv_line(fields))

    return records


# =============================================================================
# CHANGE REQUEST GENERATOR
# =============================================================================

_change_counter = 0


def get_next_change_number() -> str:
    """Generate next change request number."""
    global _change_counter
    _change_counter += 1
    return f"CHG{_change_counter:07d}"


def reset_change_counter():
    """Reset change counter (for testing)."""
    global _change_counter
    _change_counter = 0


def generate_change_lifecycle(change_num: str, change_data: dict,
                              change_time: datetime, demo_id: str = None,
                              base_date: datetime = None) -> List[str]:
    """Generate all state transitions for a change request.

    Change lifecycle:
        New → Assess → Authorize → Scheduled → Implement → Review → Closed
    Emergency changes collapse Assess+Authorize into minutes.

    Args:
        base_date: The generation start date (day 0). Used to resolve
                   absolute day references in planned_start/planned_end.
    """
    events = []
    is_emergency = change_data.get("type") == "emergency"

    requester_email, requester_name = get_assignment_member(
        change_data.get("assignment_group", "Service Desk"))

    # Shared fields for demo_id
    def _add_demo_id(fields):
        if demo_id:
            fields["demo_id"] = demo_id

    # State 1: New
    fields = {
        "sys_updated_on": change_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "type": change_data.get("type", "standard"),
        "state": "New",
        "short_description": change_data["short"],
        "description": change_data.get("description", change_data["short"]),
        "category": change_data.get("category", "Infrastructure"),
        "priority": change_data.get("priority", 3),
        "risk": change_data.get("risk", "Low"),
        "impact": change_data.get("impact", 3),
        "assignment_group": change_data.get("assignment_group", "Service Desk"),
        "requested_by": requester_email,
    }
    if change_data.get("cmdb_ci"):
        fields["cmdb_ci"] = change_data["cmdb_ci"]
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    # State 2: Assess
    if is_emergency:
        assess_delay = random.randint(5, 15)  # minutes
    else:
        assess_delay = random.randint(60, 240)  # 1-4 hours
    assess_time = change_time + timedelta(minutes=assess_delay)

    fields = {
        "sys_updated_on": assess_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "state": "Assess",
        "work_notes": "Risk assessment completed" if not is_emergency else "Emergency - expedited assessment",
    }
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    # State 3: Authorize
    if is_emergency:
        auth_delay = random.randint(5, 20)
    else:
        auth_delay = random.randint(120, 480)  # 2-8 hours
    auth_time = assess_time + timedelta(minutes=auth_delay)

    assigned_to, assigned_name = get_assignment_member(
        change_data.get("assignment_group", "Service Desk"))
    fields = {
        "sys_updated_on": auth_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "state": "Authorize",
        "assigned_to": assigned_to,
        "assigned_to_name": assigned_name,
        "work_notes": "Change approved" if not is_emergency else "Emergency change approved by CAB chair",
    }
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    # State 4: Scheduled
    duration_hours = change_data.get("duration_hours", 2)
    if "planned_start" in change_data and base_date is not None:
        # Absolute day reference from generation start_date
        ps = change_data["planned_start"]
        planned_start = datetime(
            base_date.year, base_date.month, base_date.day,
            ps["hour"], ps["minute"]
        ) + timedelta(days=ps["day"])
    elif is_emergency:
        planned_start = auth_time + timedelta(minutes=random.randint(10, 30))
    else:
        # Schedule for next day during maintenance window (22:00-06:00)
        planned_start = auth_time + timedelta(hours=random.randint(4, 24))

    if "planned_end" in change_data and base_date is not None:
        pe = change_data["planned_end"]
        planned_end = datetime(
            base_date.year, base_date.month, base_date.day,
            pe["hour"], pe["minute"]
        ) + timedelta(days=pe["day"])
    else:
        planned_end = planned_start + timedelta(hours=duration_hours)

    sched_time = auth_time + timedelta(minutes=random.randint(5, 30))
    fields = {
        "sys_updated_on": sched_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "state": "Scheduled",
        "planned_start_date": planned_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "planned_end_date": planned_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    # State 5: Implement
    fields = {
        "sys_updated_on": planned_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "state": "Implement",
        "actual_start_date": planned_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "work_notes": "Implementation started",
    }
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    # State 6: Review
    actual_end = planned_end + timedelta(minutes=random.randint(-15, 30))
    fields = {
        "sys_updated_on": actual_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "state": "Review",
        "actual_end_date": actual_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "work_notes": "Implementation complete, in review",
    }
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    # State 7: Closed
    close_delay = random.randint(1, 24)
    closed_time = actual_end + timedelta(hours=close_delay)

    close_code = change_data.get("close_code", "Successful")
    close_notes = change_data.get("close_notes", "Change completed successfully. No issues reported.")

    fields = {
        "sys_updated_on": closed_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": change_num,
        "state": "Closed",
        "close_code": close_code,
        "close_notes": close_notes,
    }
    _add_demo_id(fields)
    events.append(format_kv_line(fields))

    return events


def generate_baseline_changes(base_date: datetime, day: int, count: int) -> List[str]:
    """Generate normal day-to-day change requests."""
    events = []

    for _ in range(count):
        # Business hours for change creation
        hour = random.randint(8, 16)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        change_time = datetime(
            base_date.year, base_date.month, base_date.day,
            hour, minute, second,
        ) + timedelta(days=day)

        template = random.choice(CHANGE_TEMPLATES)

        # Replace placeholders
        server = random.choice(ALL_SERVERS)
        location = random.choice(list(LOCATIONS.values()))["full_name"]
        short = template["short"].format(
            server=server, location=location, device=server)

        change_data = {
            "short": short,
            "category": template["category"],
            "type": template["type"],
            "risk": template["risk"],
            "assignment_group": template["assignment_group"],
            "duration_hours": template["duration_hours"],
            "impact": 3,
            "priority": 3 if template["type"] == "standard" else 2,
        }

        change_num = get_next_change_number()
        events.extend(generate_change_lifecycle(change_num, change_data, change_time))

    return events


def generate_scenario_changes(base_date: datetime, day: int, scenarios: str) -> List[str]:
    """Generate scenario-linked change requests for a day.

    Uses same scenario filtering as generate_scenario_incidents().
    """
    events = []
    if scenarios == "none":
        return events

    scenario_set = set(s.strip() for s in scenarios.split(",")) if "," in scenarios else {scenarios}

    for scenario_name, config in SCENARIO_CHANGES.items():
        # Same filtering logic as generate_scenario_incidents
        if scenario_name in scenario_set:
            pass
        elif "all" in scenario_set:
            pass
        elif "attack" in scenario_set and scenario_name in ["exfil", "ransomware_attempt", "phishing_test"]:
            pass
        elif "ops" in scenario_set and scenario_name in ["cpu_runaway", "memory_leak", "disk_filling", "dead_letter_pricing"]:
            pass
        elif "network" in scenario_set and scenario_name in ["firewall_misconfig", "certificate_expiry", "ddos_attack"]:
            pass
        else:
            continue

        if day != config["day"]:
            continue

        for change_data in config["changes"]:
            is_emergency = change_data.get("type") == "emergency"
            if is_emergency:
                hour = random.randint(8, 16)
            else:
                hour = random.randint(9, 14)

            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            change_time = datetime(
                base_date.year, base_date.month, base_date.day,
                hour, minute, second,
            ) + timedelta(days=day)

            change_num = get_next_change_number()
            events.extend(generate_change_lifecycle(
                change_num, change_data, change_time, demo_id=scenario_name,
                base_date=base_date))

    return events


# =============================================================================
# INCIDENT GENERATORS
# =============================================================================

def generate_normal_incidents(base_date: datetime, day: int, count: int) -> List[str]:
    """Generate normal (non-scenario) incidents for a day."""
    events = []

    for _ in range(count):
        # Random time during business hours (7am - 6pm) with some after-hours
        if random.random() < 0.85:
            hour = random.randint(7, 17)
        else:
            hour = random.choice([6, 18, 19, 20])
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        incident_time = datetime(
            base_date.year, base_date.month, base_date.day,
            hour, minute, second
        ) + timedelta(days=day)

        # Get category and template
        category, config = get_category()
        template = random.choice(config["incidents"])

        # Get caller
        caller_email, caller_name = get_random_user()

        # Create incident
        incident = Incident(
            number=get_next_incident_number(),
            short_description=template["short"],
            description=f"User reported: {template['short']}",
            category=category,
            subcategory=template.get("subcategory", "General"),
            priority=template.get("priority", get_priority()),
            urgency=template.get("priority", get_priority()),
            impact=random.randint(2, 4),
            caller_id=caller_email,
            caller_name=caller_name,
            assignment_group=config["assignment_group"],
            assigned_to=None,
            assigned_to_name=None,
            cmdb_ci=None,
            location=get_random_location(),
            opened_at=incident_time,
            demo_id=None,
        )

        events.extend(generate_incident_lifecycle(incident, base_date))

    return events


def generate_scenario_incidents(base_date: datetime, day: int, scenarios: str) -> List[str]:
    """Generate scenario-related incidents for a day."""
    events = []

    if scenarios == "none":
        return events

    # Check each scenario
    # Parse comma-separated scenarios into a set
    scenario_set = set(s.strip() for s in scenarios.split(",")) if "," in scenarios else {scenarios}

    for scenario_name, config in SCENARIO_INCIDENTS.items():
        # Skip if scenario not enabled
        # Allow individual scenario names or category names
        if scenario_name in scenario_set:
            pass  # Exact match - proceed
        elif "all" in scenario_set:
            pass  # All scenarios enabled
        elif "attack" in scenario_set and scenario_name in ["exfil", "ransomware_attempt", "phishing_test"]:
            pass  # Attack category
        elif "ops" in scenario_set and scenario_name in ["cpu_runaway", "memory_leak", "disk_filling", "dead_letter_pricing"]:
            pass  # Ops category
        elif "network" in scenario_set and scenario_name in ["firewall_misconfig", "certificate_expiry", "ddos_attack"]:
            pass  # Network category
        else:
            continue  # Skip this scenario

        # Check if this day is active for the scenario
        if day not in config["days"]:
            continue

        # Check hour restrictions if any
        if "hours" in config:
            # Only generate during specific hours
            hour = random.choice(config["hours"])
        else:
            # Business hours
            hour = random.randint(8, 16)

        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        incident_time = datetime(
            base_date.year, base_date.month, base_date.day,
            hour, minute, second
        ) + timedelta(days=day)

        # Generate 1-2 incidents from this scenario
        num_incidents = random.randint(1, min(2, len(config["incidents"])))
        selected = random.sample(config["incidents"], num_incidents)

        for template in selected:
            caller_email, caller_name = get_random_user()

            incident = Incident(
                number=get_next_incident_number(),
                short_description=template["short"],
                description=template.get("description", f"User reported: {template['short']}"),
                category=template.get("category", "Infrastructure"),
                subcategory=template.get("subcategory", "General"),
                priority=template.get("priority", 1),
                urgency=template.get("priority", 1),
                impact=1 if template.get("priority", 2) <= 2 else 2,
                caller_id=caller_email,
                caller_name=caller_name,
                assignment_group=template.get("assignment_group", "Service Desk"),
                assigned_to=None,
                assigned_to_name=None,
                cmdb_ci=template.get("cmdb_ci"),
                location="Boston HQ",  # Most infrastructure is in Boston
                opened_at=incident_time,
                demo_id=scenario_name,
                close_notes=template.get("close_notes"),
            )

            events.extend(generate_incident_lifecycle(incident, base_date))

    return events


def _get_timestamp(event: str) -> str:
    """Extract sys_updated_on from key-value line for sorting."""
    if 'sys_updated_on="' in event:
        start = event.find('sys_updated_on="') + 16
        end = event.find('"', start)
        return event[start:end]
    return ""


def generate_servicenow_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """
    Generate ServiceNow ITSM logs: incidents, CMDB, and change requests.

    Args:
        start_date: Start date in YYYY-MM-DD format
        days: Number of days to generate
        scale: Volume scale factor
        scenarios: Scenario filter (none, exfil, all, attack, ops, network)
        output_file: Output file path for incidents (default: output/itsm/servicenow_incidents.log)
        quiet: Suppress progress output

    Returns:
        Total number of events generated across all three output files
    """
    # Reset counters for fresh run
    reset_incident_counter()
    reset_change_counter()

    # Parse start date
    base_date = datetime.strptime(start_date, "%Y-%m-%d")

    # Output paths
    if output_file is None:
        incident_path = get_output_path("itsm", FILE_SERVICENOW)
    else:
        incident_path = output_file
    cmdb_path = get_output_path("itsm", FILE_SERVICENOW_CMDB)
    change_path = get_output_path("itsm", FILE_SERVICENOW_CHANGE)

    Path(incident_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cmdb_path).parent.mkdir(parents=True, exist_ok=True)
    Path(change_path).parent.mkdir(parents=True, exist_ok=True)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  ServiceNow ITSM Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {scenarios}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # -------------------------------------------------------------------------
    # 1. CMDB (static, one-time)
    # -------------------------------------------------------------------------
    cmdb_records = generate_cmdb_records(start_date)

    with open(cmdb_path, 'w') as f:
        for record in cmdb_records:
            f.write(record + "\n")

    if not quiet:
        print(f"  [CMDB] {len(cmdb_records)} records written to {cmdb_path}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 2. Incidents (existing logic)
    # -------------------------------------------------------------------------
    all_incidents = []

    for day in range(days):
        current_date = base_date + timedelta(days=day)
        weekday = current_date.weekday()

        # Calculate incident count for this day
        if weekday >= 5:  # Weekend
            day_count = WEEKEND_INCIDENTS
        elif weekday == 0:  # Monday
            day_count = int(BASE_INCIDENTS_PER_DAY * MONDAY_MULTIPLIER)
        else:
            day_count = BASE_INCIDENTS_PER_DAY

        day_count = int(day_count * scale)
        day_count = max(1, day_count + random.randint(-3, 3))

        events = generate_normal_incidents(base_date, day, day_count)
        all_incidents.extend(events)

        scenario_events = generate_scenario_incidents(base_date, day, scenarios)
        all_incidents.extend(scenario_events)

    all_incidents.sort(key=_get_timestamp)

    with open(incident_path, 'w') as f:
        for event in all_incidents:
            f.write(event + "\n")

    if not quiet:
        print(f"  [Incidents] {len(all_incidents)} events written to {incident_path}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # 3. Change Requests (new)
    # -------------------------------------------------------------------------
    all_changes = []

    for day in range(days):
        current_date = base_date + timedelta(days=day)
        weekday = current_date.weekday()

        # Baseline changes
        if weekday >= 5:
            change_count = WEEKEND_CHANGES
        else:
            change_count = BASE_CHANGES_PER_DAY

        change_count = max(0, int(change_count * scale) + random.randint(-1, 1))

        baseline = generate_baseline_changes(base_date, day, change_count)
        all_changes.extend(baseline)

        # Scenario changes
        scenario_chg = generate_scenario_changes(base_date, day, scenarios)
        all_changes.extend(scenario_chg)

    all_changes.sort(key=_get_timestamp)

    with open(change_path, 'w') as f:
        for event in all_changes:
            f.write(event + "\n")

    if not quiet:
        print(f"  [Changes] {len(all_changes)} events written to {change_path}", file=sys.stderr)

    total = len(cmdb_records) + len(all_incidents) + len(all_changes)

    if not quiet:
        print(f"  Total: {total:,} events ({len(cmdb_records)} CMDB, "
              f"{len(all_incidents)} incidents, {len(all_changes)} changes)", file=sys.stderr)

    return total


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="ServiceNow Incident Generator")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Number of days")
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE, help="Volume scale factor")
    parser.add_argument("--scenarios", default="all", help="Scenarios: none, all, attack, ops, network")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")

    args = parser.parse_args()

    if not args.quiet:
        print(f"Generating ServiceNow incidents...")
        print(f"  Start date: {args.start_date}")
        print(f"  Days: {args.days}")
        print(f"  Scale: {args.scale}")
        print(f"  Scenarios: {args.scenarios}")

    count = generate_servicenow_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )

    if not args.quiet:
        print(f"Done! Generated {count} events.")


if __name__ == "__main__":
    main()
