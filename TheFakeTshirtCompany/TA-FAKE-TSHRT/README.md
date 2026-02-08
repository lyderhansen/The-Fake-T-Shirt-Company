TA-FAKE-TSHRT - T-Shirt Company Demo Log Generator
==================================================

Version: 1.0.0
Author: Splunk Demo

DESCRIPTION
-----------
This Technical Add-on generates realistic synthetic log data for Splunk demos
and training. The logs simulate a fictional e-commerce company "The T-Shirt
Company" with approximately 175 employees across 3 US locations (Boston,
Atlanta, Austin).

The generator includes:
- 17 different data sources (AWS, Azure, GCP, Cisco ASA, Meraki, Webex, etc.)
- 7 coordinated scenarios (APT exfiltration, memory leak, CPU runaway, etc.)
- Realistic business data (72 IT-themed products, customer orders)
- Multi-site network architecture with proper IP addressing

DATA SOURCES
------------
Network Security:
- Cisco ASA Firewall (cisco:asa:demo)
- Cisco Meraki MX/MR/MS/MV/MT (meraki:*:demo)

Cloud Security:
- AWS CloudTrail (aws:cloudtrail:demo)
- Azure Entra ID Sign-in/Audit (azure:aad:*:demo)
- GCP Audit Logs (google:gcp:*:demo)

Collaboration:
- Microsoft Exchange (o365:reporting:messagetrace:demo)
- Cisco Webex (cisco:webex:*:demo)

Endpoints:
- Windows Event Logs (WinEventLog:demo)
- Windows Performance Monitor (Perfmon:*:demo)
- Linux System Metrics (cpu, vmstat, df, iostat, interfaces)

Business:
- Apache Access Logs (access_combined:demo)
- Retail Orders (online:order:demo)
- Azure ServiceBus (azure:servicebus:demo)
- ServiceNow Incidents (servicenow:incident:demo)

SCENARIOS
---------
Attack:
- exfil: 14-day APT data exfiltration campaign

Operations:
- memory_leak: Application memory leak causing OOM crash
- cpu_runaway: SQL backup job causing 100% CPU
- disk_filling: Gradual disk space exhaustion
- certificate_expiry: SSL certificate expiration

Network:
- firewall_misconfig: Accidental firewall rule blocking traffic

INSTALLATION
------------
1. Copy TA-FAKE-TSHRT folder to $SPLUNK_HOME/etc/apps/
2. Create index: splunk_demo
3. Restart Splunk

USAGE
-----
Generate logs:
  cd $SPLUNK_HOME/etc/apps/TA-FAKE-TSHRT/bin
  python3 main_generate.py --all --days=14 --scenarios=exfil

Or use interactive TUI:
  python3 tui_generate.py

Command line options:
  --all                    Generate all log sources
  --sources=X,Y            Comma-separated sources
  --days=N                 Number of days (default: 14)
  --scenarios=X            Scenarios: none, exfil, all, attack, ops
  --start-date=YYYY-MM-DD  Start date (default: 2026-01-01)

VERIFICATION
------------
After generating logs and restarting Splunk:

  index=splunk_demo | stats count by sourcetype

Filter by scenario:
  index=splunk_demo demo_id=exfil | stats count by sourcetype

DOCUMENTATION
-------------
See the docs/ folder for:
- Scenario guides with timelines
- Data source documentation
- Sample SPL queries

REQUIREMENTS
------------
- Python 3.8+
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

SUPPORT
-------
This is demo/training software. Use at your own risk.
Not for production use.

