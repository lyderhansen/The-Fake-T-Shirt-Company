TA-FAKE-TSHRT - The Fake T-Shirt Company Demo Log Generator
============================================================

Version: 1.0.0
Author: Splunk Demo

> **AI Disclaimer:** This project was primarily developed with AI assistance (Claude).
> While care has been taken to ensure accuracy, there may be inconsistencies or errors
> in the generated logs that have not yet been discovered. Please report any issues.

DESCRIPTION
-----------
This Technical Add-on generates realistic synthetic log data for Splunk demos
and training. The logs simulate a fictional e-commerce company "The FAKE T-Shirt
Company" with approximately 175 employees across 3 US locations (Boston HQ,
Atlanta Hub, Austin Office) and 13 servers.

The generator includes:
- 26 data source generators producing 60+ Splunk sourcetypes
- 10 coordinated scenarios (APT exfiltration, ransomware, DDoS, phishing, etc.)
- Realistic business data (72 IT-themed products, customer orders)
- Multi-site network architecture with proper IP addressing
- CIM-compliant field extractions, lookups, and event types

DATA SOURCES
------------
Network:
- Cisco ASA Firewall (FAKE:cisco:asa)
- Cisco Meraki MX/MR/MS/MV/MT (FAKE:meraki:*)
- Cisco Catalyst Switches (FAKE:cisco:ios)
- Cisco ACI Fabric (FAKE:cisco:aci:fault/event/audit)

Cloud & Identity:
- AWS CloudTrail (FAKE:aws:cloudtrail)
- AWS GuardDuty (FAKE:aws:cloudwatch:guardduty)
- AWS Billing CUR (FAKE:aws:billing:cur)
- Microsoft Entra ID Sign-in/Audit (FAKE:azure:aad:*)
- GCP Audit Logs (FAKE:google:gcp:pubsub:*)
- Cisco Secure Access DNS/Proxy/Firewall/Audit (FAKE:cisco:umbrella:*)
- Cisco Catalyst Center (FAKE:cisco:catalyst:*)

Collaboration:
- Microsoft Exchange Message Trace (FAKE:o365:reporting:messagetrace)
- Microsoft 365 Audit (FAKE:o365:management:activity)
- Cisco Webex Devices, Meetings, API (FAKE:cisco:webex:*)

Endpoints:
- Windows Event Logs (FAKE:WinEventLog)
- Windows Sysmon (FAKE:WinEventLog:Sysmon)
- Windows Performance Monitor (FAKE:Perfmon:*)
- Microsoft SQL Server Error Log (FAKE:mssql:errorlog)
- Linux System Metrics (FAKE:cpu, FAKE:vmstat, FAKE:df, FAKE:iostat, FAKE:interfaces)
- Linux Authentication (FAKE:linux:auth)

Business / Applications:
- Apache Access Logs (FAKE:access_combined)
- Retail Orders (FAKE:online:order)
- Azure ServiceBus (FAKE:azure:servicebus)
- SAP S/4HANA Audit Log (FAKE:sap:auditlog)
- ServiceNow Incidents/CMDB/Change (FAKE:servicenow:*)

SCENARIOS
---------
Attack:
- exfil: 14-day APT data exfiltration campaign
- ransomware_attempt: Ransomware detected and blocked by EDR
- phishing_test: IT-run phishing awareness campaign (post-exfil)

Operations:
- memory_leak: Application memory leak causing OOM crash
- cpu_runaway: SQL backup job causing 100% CPU
- disk_filling: Gradual disk space exhaustion
- dead_letter_pricing: ServiceBus dead-letter queue causes wrong prices

Network:
- firewall_misconfig: Accidental firewall rule blocking traffic
- certificate_expiry: SSL certificate expiration causing outage
- ddos_attack: Volumetric HTTP flood from botnet

All scenarios are tagged with demo_id field for easy filtering:
  index=fake_tshrt demo_id=exfil | stats count by sourcetype

INSTALLATION
------------
1. Copy TA-FAKE-TSHRT folder to $SPLUNK_HOME/etc/apps/
2. Create index: fake_tshrt
3. Restart Splunk

USAGE
-----
Generate logs:
  cd $SPLUNK_HOME/etc/apps/TA-FAKE-TSHRT/bin
  python3 main_generate.py --all --days=14 --scenarios=all --no-test

Or use interactive TUI:
  python3 tui_generate.py

Command line options:
  --all                    Generate all log sources
  --sources=X,Y            Comma-separated sources or groups
  --days=N                 Number of days (default: 14)
  --scenarios=X            Scenarios: none, exfil, all, attack, ops, network
  --start-date=YYYY-MM-DD  Start date (default: 2026-01-01)
  --scale=N.N              Volume scale factor (default: 1.0)
  --parallel=N             Parallel workers (default: 4)
  --test                   Write to output/tmp/ (DEFAULT - safe for testing)
  --no-test                Write to output/ (production - for Splunk ingestion)

VERIFICATION
------------
After generating logs and restarting Splunk:

  index=fake_tshrt | stats count by sourcetype

Filter by scenario:
  index=fake_tshrt demo_id=exfil | stats count by sourcetype

DOCUMENTATION
-------------
See the docs/ folder for:
- Scenario guides with timelines (docs/scenarios/)
- Data source documentation (docs/datasource_docs/)
- Sample SPL queries (docs/reference/)
- Demo talking track (docs/guides/)

REQUIREMENTS
------------
- Python 3.8+ (stdlib only - no external dependencies)
- Splunk Enterprise 8.0+

OPTIONAL DEPENDENCIES
---------------------
For enhanced field extraction and CIM compliance, install these TAs:
- Splunk Add-on for Cisco ASA
- Splunk Add-on for AWS
- Splunk Add-on for Microsoft Cloud Services
- Splunk Add-on for Google Cloud Platform
- Cisco Meraki Add-on for Splunk
- Splunk Add-on for ServiceNow
- Splunk Add-on for Unix and Linux

SUPPORT
-------
This is demo/training software. Use at your own risk.
Not for production use.
