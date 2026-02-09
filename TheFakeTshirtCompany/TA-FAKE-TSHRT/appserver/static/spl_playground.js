/**
 * SPL Playground - Interactive query explorer for TA-FAKE-TSHRT
 *
 * Provides a library of ~60 pre-built SPL queries organized by category,
 * a code editor textarea, programmatic search execution via SearchManager,
 * and visualization toggling between table/chart modes.
 *
 * Must be loaded via dashboard script attribute: script="spl_playground.js"
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';

    console.log('[SPL Playground] spl_playground.js loaded');

    var defaultTokens = mvc.Components.get("default");
    var submittedTokens = mvc.Components.get("submitted");

    // ========================================================================
    // Query Library (~60 queries across 10 categories)
    // ========================================================================

    var QUERY_LIBRARY = [

        // ---- Getting Started ----
        {
            category: "Getting Started",
            name: "Count events by sourcetype",
            description: "The most fundamental SPL query. Uses tstats for fast indexed-field counting, then sorts descending. Great first query to see what data exists.",
            query: '| tstats count where index=fake_tshrt by sourcetype\n| sort - count',
            viz: "bar"
        },
        {
            category: "Getting Started",
            name: "Event volume over time",
            description: "Timechart shows event counts bucketed by hour across all sourcetypes. Look for the daily activity curve -- peaks during business hours, dips at night.",
            query: '| tstats count where index=fake_tshrt by _time span=1h\n| timechart span=1h sum(count) AS events',
            viz: "timechart"
        },
        {
            category: "Getting Started",
            name: "List all hosts",
            description: "Shows every unique host reporting to this index. Hosts include servers, firewalls, APs, switches, cameras, and sensors across 3 locations.",
            query: '| tstats count where index=fake_tshrt by host\n| sort - count',
            viz: "table"
        },
        {
            category: "Getting Started",
            name: "Find all scenario events",
            description: "The demo_id field tags events belonging to scenarios (exfil, ransomware, memory_leak, etc.). This shows which scenarios have data and how many events each produced.",
            query: 'index=fake_tshrt demo_id=*\n| stats count by demo_id\n| sort - count',
            viz: "pie"
        },
        {
            category: "Getting Started",
            name: "Sample raw events (first 20)",
            description: "Use 'head' to grab a small sample of raw events. Good for understanding event structure and available fields before writing complex queries.",
            query: 'index=fake_tshrt\n| head 20\n| table _time sourcetype host _raw',
            viz: "table"
        },
        {
            category: "Getting Started",
            name: "Count unique values",
            description: "The dc() (distinct count) function counts unique values. This shows how many unique users, source IPs, and hosts exist across the entire dataset.",
            query: 'index=fake_tshrt\n| stats dc(user) AS unique_users dc(src) AS unique_sources dc(host) AS unique_hosts dc(sourcetype) AS sourcetypes',
            viz: "single"
        },
        {
            category: "Getting Started",
            name: "Events by sourcetype over time",
            description: "A stacked timechart showing how each sourcetype contributes to overall volume. Network sources (ASA, Meraki) typically dominate.",
            query: '| tstats count where index=fake_tshrt by _time, sourcetype span=1d\n| timechart span=1d sum(count) by sourcetype',
            viz: "timechart"
        },
        {
            category: "Getting Started",
            name: "Event categories breakdown",
            description: "Uses eval/case to group sourcetypes into logical categories (Network, Cloud, Endpoints, etc.) for a high-level view of data distribution.",
            query: 'index=fake_tshrt\n| eval category=case(\n    match(sourcetype,"cisco:asa|meraki"),"Network",\n    match(sourcetype,"aws|azure|google|gcp"),"Cloud",\n    match(sourcetype,"WinEvent|Perfmon"),"Endpoints",\n    match(sourcetype,"webex|o365|reporting"),"Collaboration",\n    match(sourcetype,"access|order|servicebus"),"Applications",\n    match(sourcetype,"linux|vmstat|iostat|df|cpu"),"Linux",\n    match(sourcetype,"servicenow"),"ITSM",\n    1=1,"Other")\n| stats count by category\n| sort - count',
            viz: "pie"
        },

        // ---- Security Investigation ----
        {
            category: "Security Investigation",
            name: "Threat actor IP activity",
            description: "Search for the known threat actor IP (185.220.101.42) across all sources. This IP appears in ASA firewall logs, Meraki, and potentially cloud logs during the exfil scenario.",
            query: 'index=fake_tshrt (src="185.220.101.42" OR dest="185.220.101.42" OR src_ip="185.220.101.42")\n| stats count earliest(_time) AS first_seen latest(_time) AS last_seen by sourcetype\n| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M") last_seen=strftime(last_seen,"%Y-%m-%d %H:%M")\n| sort - count',
            viz: "table"
        },
        {
            category: "Security Investigation",
            name: "Failed login analysis",
            description: "Entra ID sign-in failures grouped by user and error code. Look for brute force patterns (many failures for one user) or credential stuffing (failures across many users).",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin" status=Failure\n| stats count by user errorCode\n| sort - count\n| head 20',
            viz: "bar"
        },
        {
            category: "Security Investigation",
            name: "Port scan detection",
            description: "Finds sources hitting many different destination ports -- a classic indicator of port scanning. The threshold of 20+ unique ports per source filters out normal traffic.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" action=denied\n| stats dc(dest_port) AS unique_ports count by src\n| where unique_ports > 20\n| sort - unique_ports',
            viz: "table"
        },
        {
            category: "Security Investigation",
            name: "Large data transfers (potential exfil)",
            description: "Identifies unusually large outbound data transfers from the ASA firewall. During the exfil scenario, look for alex.miller's workstation (10.10.30.55) sending large volumes.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" bytes_out>0\n| stats sum(bytes_out) AS total_bytes by src dest\n| eval total_MB=round(total_bytes/1024/1024,2)\n| where total_MB > 10\n| sort - total_MB\n| table src dest total_MB',
            viz: "table"
        },
        {
            category: "Security Investigation",
            name: "Privilege escalation events",
            description: "Windows Event ID 4672 indicates special privileges assigned to a new logon. Frequent or unexpected privilege assignments can indicate lateral movement.",
            query: 'index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4672\n| stats count by user dest\n| sort - count',
            viz: "table"
        },
        {
            category: "Security Investigation",
            name: "Exfil scenario full timeline",
            description: "Shows the complete exfiltration attack timeline across all sourcetypes, day by day. The attack progresses from recon (days 1-3) through compromise (day 4) to exfiltration (days 11-14).",
            query: 'index=fake_tshrt demo_id=exfil\n| timechart span=1d count by sourcetype',
            viz: "column"
        },
        {
            category: "Security Investigation",
            name: "Ransomware attempt timeline",
            description: "The ransomware scenario targets Brooklyn White in Austin on days 8-9. This shows the detection and response across network, email, and endpoint sources.",
            query: 'index=fake_tshrt demo_id=ransomware_attempt\n| timechart span=1h count by sourcetype',
            viz: "timechart"
        },
        {
            category: "Security Investigation",
            name: "Compromised user cross-source activity",
            description: "Correlates alex.miller (the exfil target) across every data source. Look for anomalous activity patterns -- after-hours access, unusual cloud API calls, large downloads.",
            query: 'index=fake_tshrt (user="alex.miller" OR userName="alex.miller" OR userPrincipalName="alex.miller@theTshirtCompany.com" OR src="10.10.30.55")\n| stats count earliest(_time) AS first latest(_time) AS last by sourcetype\n| eval first=strftime(first,"%m/%d %H:%M") last=strftime(last,"%m/%d %H:%M")\n| sort - count',
            viz: "table"
        },
        {
            category: "Security Investigation",
            name: "After-hours authentication",
            description: "Finds logins occurring outside business hours (before 7 AM or after 7 PM). Legitimate overtime happens on days 3 and 7, but the exfil scenario also has suspicious after-hours activity.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin" status=Success\n| eval hour=strftime(_time,"%H")\n| where hour<7 OR hour>19\n| stats count by user hour\n| sort - count',
            viz: "table"
        },

        // ---- Cloud Security ----
        {
            category: "Cloud Security",
            name: "AWS API activity overview",
            description: "Shows the most common AWS CloudTrail API calls. Normal activity includes S3 reads, EC2 describes, and IAM lookups. Suspicious calls include CreateUser, CreateAccessKey.",
            query: 'index=fake_tshrt sourcetype="FAKE:aws:cloudtrail"\n| stats count by eventName\n| sort - count\n| head 20',
            viz: "bar"
        },
        {
            category: "Cloud Security",
            name: "AWS suspicious API calls",
            description: "Filters for high-risk AWS API actions that create persistence (new users, access keys, policies). These appear during the exfil scenario when the attacker establishes cloud backdoors.",
            query: 'index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" (eventName=CreateUser OR eventName=CreateAccessKey OR eventName=PutUserPolicy OR eventName=AttachUserPolicy)\n| table _time eventName userIdentity.userName sourceIPAddress requestParameters.*',
            viz: "table"
        },
        {
            category: "Cloud Security",
            name: "GCP audit activity summary",
            description: "Google Cloud Platform audit logs showing API method calls. Look for admin activity like IAM changes, compute instance creation, or storage access.",
            query: 'index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:audit"\n| stats count by methodName\n| sort - count\n| head 20',
            viz: "bar"
        },
        {
            category: "Cloud Security",
            name: "Entra ID sign-in summary",
            description: "Azure AD authentication overview showing success vs failure rates per user. High failure rates for a single user may indicate brute force; failures across many users suggest password spraying.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin"\n| stats count(eval(status="Success")) AS successes count(eval(status="Failure")) AS failures by user\n| eval failure_rate=round(failures/(successes+failures)*100,1)\n| sort - failures\n| head 20',
            viz: "table"
        },
        {
            category: "Cloud Security",
            name: "Entra ID audit changes",
            description: "Azure AD audit logs capture directory changes -- password resets, group modifications, app registrations. Look for unauthorized changes during the exfil timeline.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:audit"\n| stats count by operationName\n| sort - count',
            viz: "bar"
        },
        {
            category: "Cloud Security",
            name: "Cloud activity by user",
            description: "Combines AWS, GCP, and Entra ID to show which users are most active across cloud platforms. Useful for identifying shadow IT or compromised accounts.",
            query: 'index=fake_tshrt (sourcetype="FAKE:aws:cloudtrail" OR sourcetype="FAKE:google:gcp:pubsub:audit" OR sourcetype="FAKE:azure:aad:signin")\n| eval cloud_user=coalesce(user,userName,"userIdentity.userName")\n| stats count by cloud_user sourcetype\n| sort - count',
            viz: "table"
        },

        // ---- Network Analysis ----
        {
            category: "Network Analysis",
            name: "ASA traffic by action",
            description: "Cisco ASA firewall actions: Built (allowed new connection), Teardown (connection closed), Denied (blocked). A healthy network has mostly Built/Teardown with few Denies.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa"\n| stats count by action\n| sort - count',
            viz: "pie"
        },
        {
            category: "Network Analysis",
            name: "Top destination ports",
            description: "Shows which destination ports see the most traffic through the ASA. Common ports: 443 (HTTPS), 80 (HTTP), 53 (DNS), 25 (SMTP). Unusual high-traffic ports may indicate tunneling.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" dest_port=*\n| stats count by dest_port\n| sort - count\n| head 20',
            viz: "bar"
        },
        {
            category: "Network Analysis",
            name: "Denied connections by source",
            description: "Groups firewall denials by source IP. External IPs with many denies may be scanning. Internal IPs with denies may indicate misconfiguration or lateral movement attempts.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" action=denied\n| stats count by src\n| sort - count\n| head 20',
            viz: "bar"
        },
        {
            category: "Network Analysis",
            name: "Meraki IDS/IPS alerts",
            description: "Meraki MX security appliance intrusion detection events. These fire when suspicious traffic patterns match known attack signatures.",
            query: 'index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" type=security_event\n| stats count by signature src dest\n| sort - count',
            viz: "table"
        },
        {
            category: "Network Analysis",
            name: "SD-WAN VPN tunnel status",
            description: "Meraki AutoVPN events showing tunnel establishment and teardown between sites (Boston, Atlanta, Austin). Look for tunnel flaps that indicate WAN instability.",
            query: 'index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" (type=vpn OR type=sd_wan*)\n| stats count by type host\n| sort - count',
            viz: "table"
        },
        {
            category: "Network Analysis",
            name: "Wireless client associations",
            description: "Meraki MR access point events showing client connections, disconnections, and roaming. High disassociation rates may indicate RF issues.",
            query: 'index=fake_tshrt sourcetype="FAKE:meraki:accesspoints" (type=association OR type=disassociation)\n| stats count by type host ssid\n| sort - count',
            viz: "table"
        },
        {
            category: "Network Analysis",
            name: "Firewall misconfig scenario",
            description: "Day 7 firewall misconfiguration -- an ACL error causes a 2-hour outage (10:15-12:05). Look for the spike in denied connections and the ServiceNow incident.",
            query: 'index=fake_tshrt demo_id=firewall_misconfig\n| timechart span=15m count by sourcetype',
            viz: "timechart"
        },

        // ---- Authentication ----
        {
            category: "Authentication",
            name: "Auth success vs failure over time",
            description: "Timechart of authentication outcomes. Spikes in failures during business hours may indicate password resets; failures at odd hours may indicate attacks.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin"\n| timechart span=1h count by status',
            viz: "timechart"
        },
        {
            category: "Authentication",
            name: "Top failed login users",
            description: "Users with the most failed authentication attempts. Jessica Brown and Alex Miller will show elevated failures during the exfil scenario.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin" status=Failure\n| stats count by user\n| sort - count\n| head 15',
            viz: "bar"
        },
        {
            category: "Authentication",
            name: "Login locations (city/country)",
            description: "Maps authentication events to geographic locations from Entra ID. Look for logins from unexpected locations -- the threat actor operates from Frankfurt, Germany.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin"\n| stats count by city country\n| sort - count',
            viz: "table"
        },
        {
            category: "Authentication",
            name: "Windows logon events (4624/4625)",
            description: "Windows Security log events for successful (4624) and failed (4625) logons. Multiple 4625 events for a single account may indicate brute force.",
            query: 'index=fake_tshrt sourcetype="FAKE:WinEventLog" (EventCode=4624 OR EventCode=4625)\n| eval result=if(EventCode=4624,"Success","Failure")\n| stats count by user dest result\n| sort - count',
            viz: "table"
        },
        {
            category: "Authentication",
            name: "Multi-factor auth analysis",
            description: "Examines Entra ID sign-in events for MFA status. Successful logins without MFA from unusual locations are high-risk indicators.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin" status=Success\n| stats count by user mfaRequired city\n| sort - count',
            viz: "table"
        },

        // ---- IT Operations ----
        {
            category: "IT Operations",
            name: "CPU usage by server over time",
            description: "Perfmon Processor metrics for all servers. Look for SQL-PROD-01 spiking to 100% during the cpu_runaway scenario (days 11-12).",
            query: 'index=fake_tshrt sourcetype="FAKE:Perfmon" counter="% Processor Time" instance="_Total"\n| timechart span=1h avg(Value) by demo_host',
            viz: "timechart"
        },
        {
            category: "IT Operations",
            name: "Memory utilization trend",
            description: "Perfmon Memory metrics tracking available megabytes. WEB-01 shows a gradual decline during the memory_leak scenario (days 6-9) before OOM crash on day 9.",
            query: 'index=fake_tshrt sourcetype="FAKE:Perfmon" counter="Available MBytes"\n| timechart span=1h avg(Value) by demo_host',
            viz: "timechart"
        },
        {
            category: "IT Operations",
            name: "Disk space monitoring (Linux)",
            description: "Linux df command output showing disk usage. MON-ATL-01 fills from 45% to 98% during the disk_filling scenario (days 1-5).",
            query: 'index=fake_tshrt sourcetype="FAKE:df"\n| timechart span=4h avg(UsePct) by host',
            viz: "timechart"
        },
        {
            category: "IT Operations",
            name: "CPU runaway scenario deep dive",
            description: "Focused view of SQL-PROD-01 during the cpu_runaway scenario. CPU hits 100% from a stuck backup job, causing DB connection failures and web errors.",
            query: 'index=fake_tshrt demo_id=cpu_runaway demo_host="SQL-PROD-01"\n| timechart span=30m avg(Value) by counter',
            viz: "timechart"
        },
        {
            category: "IT Operations",
            name: "Memory leak scenario deep dive",
            description: "WEB-01 memory leak progression: gradual consumption over days 6-9, OOM crash at day 9 14:00, manual restart. Watch Available MBytes decline to near-zero.",
            query: 'index=fake_tshrt demo_id=memory_leak\n| timechart span=1h avg(Value) by counter',
            viz: "timechart"
        },
        {
            category: "IT Operations",
            name: "Windows critical events",
            description: "Windows Event Log errors and warnings across all servers. Correlate spikes with the cpu_runaway and ransomware scenarios.",
            query: 'index=fake_tshrt sourcetype="FAKE:WinEventLog" (Type=Error OR Type=Warning)\n| stats count by Type EventCode dest\n| sort - count\n| head 20',
            viz: "table"
        },
        {
            category: "IT Operations",
            name: "ServiceNow incidents by priority",
            description: "IT service management incidents created during scenarios. Priority 1/2 incidents correlate with the firewall_misconfig, certificate_expiry, and cpu_runaway scenarios.",
            query: 'index=fake_tshrt sourcetype="FAKE:servicenow:incident"\n| stats count by priority state\n| sort priority',
            viz: "bar"
        },
        {
            category: "IT Operations",
            name: "Certificate expiry scenario",
            description: "Day 12 SSL certificate expiration causes a 7-hour outage (00:00-07:00). Shows the cascade: cert expires, HTTPS fails, users get errors, ServiceNow ticket created.",
            query: 'index=fake_tshrt demo_id=certificate_expiry\n| timechart span=30m count by sourcetype',
            viz: "timechart"
        },

        // ---- Retail/Business ----
        {
            category: "Retail/Business",
            name: "Order volume over time",
            description: "E-commerce order events by day. Orders follow business patterns -- higher on weekdays, lower on weekends. Each order generates 5 status events (created, processing, payment, fulfilled, delivered).",
            query: 'index=fake_tshrt sourcetype="FAKE:online:order" status=created\n| timechart span=1d count AS orders',
            viz: "column"
        },
        {
            category: "Retail/Business",
            name: "Revenue by day",
            description: "Daily revenue from completed orders. Multiply order count by average order value (~$50-80). Look for Monday boost (115% volume) and weekend dips.",
            query: 'index=fake_tshrt sourcetype="FAKE:online:order" status=created\n| timechart span=1d sum(total) AS daily_revenue',
            viz: "timechart"
        },
        {
            category: "Retail/Business",
            name: "Top products by quantity",
            description: "Most popular products in The Fake T-Shirt Company catalog. 72 IT-themed products across T-shirts, hoodies, joggers, and accessories.",
            query: 'index=fake_tshrt sourcetype="FAKE:online:order" status=created\n| stats count by product_name\n| sort - count\n| head 15',
            viz: "bar"
        },
        {
            category: "Retail/Business",
            name: "Order status distribution",
            description: "Each order passes through 5 statuses: created > processing > payment_confirmed > fulfilled > delivered. This shows the distribution -- should be roughly equal counts.",
            query: 'index=fake_tshrt sourcetype="FAKE:online:order"\n| stats count by status\n| sort count',
            viz: "pie"
        },
        {
            category: "Retail/Business",
            name: "Web traffic patterns",
            description: "Apache access log showing HTTP methods and response codes over time. Normal: mostly 200 OK. During scenarios: 500 errors spike when backend services fail.",
            query: 'index=fake_tshrt sourcetype="FAKE:access_combined"\n| timechart span=1h count by status',
            viz: "timechart"
        },
        {
            category: "Retail/Business",
            name: "Service Bus message flow",
            description: "Azure Service Bus handles async messaging between the web tier and order processing. Messages correlate with order events -- look for queue depth increases during outages.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:servicebus"\n| stats count by operationName\n| sort - count',
            viz: "bar"
        },

        // ---- Collaboration ----
        {
            category: "Collaboration",
            name: "Webex meeting volume by day",
            description: "Cisco Webex meeting events over time. Peak on weekdays during business hours. Meeting rooms span 17 conference rooms across Boston, Atlanta, and Austin.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:webex:events"\n| timechart span=1d count by type',
            viz: "column"
        },
        {
            category: "Collaboration",
            name: "Email traffic overview",
            description: "Exchange/O365 message trace showing email flow. Look for phishing emails during the exfil scenario (day 4) and suspicious attachments.",
            query: 'index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace"\n| stats count by SenderAddress\n| sort - count\n| head 15',
            viz: "bar"
        },
        {
            category: "Collaboration",
            name: "M365 audit operations",
            description: "Office 365 management activity audit log showing user and admin operations. FileAccessed, FileModified, and MailItemsAccessed are normal; look for unusual admin operations.",
            query: 'index=fake_tshrt sourcetype="FAKE:o365:management:activity"\n| stats count by Operation\n| sort - count\n| head 20',
            viz: "bar"
        },
        {
            category: "Collaboration",
            name: "Top email recipients",
            description: "Who receives the most email? Heavy email to specific users during the exfil scenario may indicate social engineering or data staging via email.",
            query: 'index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace"\n| stats count by RecipientAddress\n| sort - count\n| head 15',
            viz: "bar"
        },
        {
            category: "Collaboration",
            name: "Meeting room utilization",
            description: "Webex room device analytics showing which conference rooms are most active. Problem rooms (North End, Peachtree) show consistent quality issues.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:webex:events" type=device_health\n| stats count by roomName\n| sort - count',
            viz: "bar"
        },

        // ---- Cross-Source Correlation ----
        {
            category: "Cross-Source Correlation",
            name: "All scenarios timeline",
            description: "Overlay all 7 scenarios on a single timeline. Shows how security (exfil days 1-14), ops (memory_leak 6-9, cpu_runaway 11-12), and network (misconfig day 7) scenarios overlap.",
            query: 'index=fake_tshrt demo_id=*\n| timechart span=1d count by demo_id',
            viz: "timechart"
        },
        {
            category: "Cross-Source Correlation",
            name: "User activity across all sources",
            description: "Pick a user and see their footprint across every data source. Great for incident investigation -- start with a suspicious user and fan out to all their activity.",
            query: 'index=fake_tshrt (user="alex.miller" OR userName="alex.miller" OR src="10.10.30.55")\n| stats count by sourcetype\n| sort - count',
            viz: "bar"
        },
        {
            category: "Cross-Source Correlation",
            name: "Network deny + auth failure correlation",
            description: "Finds IPs that are both denied at the firewall AND failing authentication. This intersection is a strong indicator of an active attack -- legitimate users rarely trigger both.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" action=denied\n| stats dc(dest_port) AS ports count AS fw_denies by src\n| where fw_denies > 5\n| rename src AS attacker_ip\n| join type=inner attacker_ip [search index=fake_tshrt sourcetype="FAKE:azure:aad:signin" status=Failure | stats count AS auth_fails by src_ip | rename src_ip AS attacker_ip]\n| table attacker_ip fw_denies ports auth_fails',
            viz: "table"
        },
        {
            category: "Cross-Source Correlation",
            name: "CPU spike + web error correlation",
            description: "When SQL-PROD-01 CPU hits 100% (cpu_runaway), the web tier starts returning 500 errors. This query overlays both metrics to show the cascading failure.",
            query: 'index=fake_tshrt ((sourcetype="FAKE:Perfmon" counter="% Processor Time" demo_host="SQL-PROD-01") OR (sourcetype="FAKE:access_combined" status>=500))\n| eval metric=if(sourcetype="FAKE:Perfmon","CPU %","HTTP 500s")\n| timechart span=1h avg(Value) AS cpu_pct count(eval(metric="HTTP 500s")) AS web_errors',
            viz: "timechart"
        },
        {
            category: "Cross-Source Correlation",
            name: "Attack kill chain reconstruction",
            description: "Reconstructs the exfiltration attack step by step across all sources, sorted chronologically. Each phase (recon, access, lateral movement, exfil) uses different sourcetypes.",
            query: 'index=fake_tshrt demo_id=exfil\n| eval day=strftime(_time,"%m/%d")\n| stats count earliest(_time) AS first latest(_time) AS last values(sourcetype) AS sources by day\n| eval first=strftime(first,"%H:%M") last=strftime(last,"%H:%M")\n| sort _time\n| table day first last count sources',
            viz: "table"
        },

        // ---- Advanced Techniques ----
        {
            category: "Advanced Techniques",
            name: "Transaction: order lifecycle",
            description: "The 'transaction' command groups related events. Each order has 5 events (created > processing > payment > fulfilled > delivered). Transaction shows the full lifecycle as one unit.",
            query: 'index=fake_tshrt sourcetype="FAKE:online:order"\n| transaction orderId maxspan=7d\n| stats avg(duration) AS avg_seconds count AS orders\n| eval avg_hours=round(avg_seconds/3600,1)',
            viz: "single"
        },
        {
            category: "Advanced Techniques",
            name: "Subsearch: from firewall deny to auth",
            description: "Subsearch finds IPs denied at the firewall, then uses those IPs to search authentication logs. This two-stage approach narrows a large dataset efficiently.",
            query: 'index=fake_tshrt sourcetype="FAKE:azure:aad:signin"\n    [search index=fake_tshrt sourcetype="FAKE:cisco:asa" action=denied | stats count by src | where count>10 | fields src | rename src AS src_ip]\n| stats count by user src_ip status\n| sort - count',
            viz: "table"
        },
        {
            category: "Advanced Techniques",
            name: "Timechart with overlay",
            description: "Uses 'appendcols' to overlay two independent time series on one chart. Shows ASA denies alongside Entra ID failures to visualize correlated attack activity.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" action=denied\n| timechart span=1h count AS firewall_denies\n| appendcols [search index=fake_tshrt sourcetype="FAKE:azure:aad:signin" status=Failure | timechart span=1h count AS auth_failures]',
            viz: "timechart"
        },
        {
            category: "Advanced Techniques",
            name: "Eval and field creation",
            description: "Demonstrates eval for creating calculated fields: categorizing severity, computing rates, and formatting output. Essential for building custom dashboards.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa"\n| stats count AS total count(eval(action="denied")) AS denied count(eval(action="built")) AS built by src\n| eval deny_rate=round(denied/total*100,1)\n| eval risk=case(deny_rate>50,"Critical",deny_rate>20,"High",deny_rate>5,"Medium",1=1,"Low")\n| sort - deny_rate\n| head 15\n| table src total built denied deny_rate risk',
            viz: "table"
        },
        {
            category: "Advanced Techniques",
            name: "Stats vs tstats comparison",
            description: "Shows the speed difference between stats (raw events) and tstats (indexed metadata). For simple counts, tstats is dramatically faster on large datasets.",
            query: '| tstats count where index=fake_tshrt by sourcetype\n| sort - count\n| head 10\n| eval note="tstats uses indexed fields = fast. Use stats when you need raw field values."',
            viz: "table"
        },
        {
            category: "Advanced Techniques",
            name: "Where + eval filtering",
            description: "Demonstrates advanced filtering: combining where clauses with eval expressions for complex conditions. Finds servers with CPU > 80% and rising.",
            query: 'index=fake_tshrt sourcetype="FAKE:Perfmon" counter="% Processor Time" instance="_Total"\n| bin _time span=1h\n| stats avg(Value) AS avg_cpu by _time demo_host\n| streamstats current=f window=2 avg(avg_cpu) AS prev_cpu by demo_host\n| where avg_cpu > 80 AND avg_cpu > prev_cpu\n| eval trend="RISING"\n| table _time demo_host avg_cpu prev_cpu trend',
            viz: "table"
        },
        {
            category: "Advanced Techniques",
            name: "Lookup enrichment with eval",
            description: "Uses eval/case to enrich events with network zone information based on IP ranges. In production, you'd use a lookup table, but eval works for quick analysis.",
            query: 'index=fake_tshrt sourcetype="FAKE:cisco:asa" src=10.*\n| eval network_zone=case(\n    cidrmatch("10.10.0.0/16",src),"Boston",\n    cidrmatch("10.20.0.0/16",src),"Atlanta",\n    cidrmatch("10.30.0.0/16",src),"Austin",\n    cidrmatch("172.16.0.0/16",src),"DMZ",\n    1=1,"Unknown")\n| stats count by network_zone action\n| sort network_zone',
            viz: "table"
        }
    ];

    // ========================================================================
    // Populate Query Picker
    // ========================================================================

    function populateQueryPicker(category) {
        var picker = $('#query-picker');
        picker.empty();

        var filtered = QUERY_LIBRARY;
        if (category && category !== 'All Categories') {
            filtered = QUERY_LIBRARY.filter(function(q) {
                return q.category === category;
            });
        }

        filtered.forEach(function(q, i) {
            var opt = $('<option></option>')
                .text(q.name)
                .attr('data-index', QUERY_LIBRARY.indexOf(q))
                .attr('title', q.description);
            picker.append(opt);
        });

        if (filtered.length === 0) {
            picker.append('<option disabled>No queries in this category</option>');
        }
    }

    // ========================================================================
    // Token helper: set on both default and submitted models
    // ========================================================================

    var currentViz = 'table';

    function setToken(name, value) {
        // Use the form. prefix - this triggers SimpleXML's built-in auto-sync
        // from default model (form.token) to submitted model (token)
        // because the <input> elements are in the <fieldset> with submitButton="false"
        defaultTokens.set('form.' + name, value);
        console.log('[SPL Playground] setToken: form.' + name + ' = ' + String(value).substring(0, 60));
    }

    // ========================================================================
    // Run Search
    // ========================================================================

    function runSearch(spl) {
        if (!spl || !spl.trim()) {
            setStatus('Enter a query to run', 'ready');
            return;
        }

        console.log('[SPL Playground] Running search:', spl.substring(0, 120));
        setStatus('Searching...', 'progress');

        // Set the spl_query token via the hidden fieldset input's form. prefix
        // SimpleXML auto-syncs form.spl_query -> spl_query on submitted model
        setToken('spl_query', spl);

        // Listen for the search to complete via the named search component
        var searchComponent = mvc.Components.get('playground_search');
        if (searchComponent) {
            searchComponent.on('search:done', function handler(properties) {
                var count = (properties.content && properties.content.resultCount) || 0;
                setStatus('Completed - ' + count.toLocaleString() + ' results', 'success');
                searchComponent.off('search:done', handler);
            });
            searchComponent.on('search:error', function handler() {
                setStatus('Error - check your SPL syntax', 'error');
                searchComponent.off('search:error', handler);
            });
        }
    }

    // ========================================================================
    // Status Helper
    // ========================================================================

    function setStatus(message, type) {
        var el = $('#search-status');
        el.text(message);
        el.removeClass('status-ready status-progress status-success status-error');
        el.addClass('status-' + type);
    }

    // ========================================================================
    // Visualization Toggle
    // ========================================================================

    function setActiveViz(vizType) {
        currentViz = vizType;
        $('.viz-btn').removeClass('viz-active');
        $('.viz-btn[data-viz="' + vizType + '"]').addClass('viz-active');

        if (vizType === 'table' || vizType === 'single') {
            $('#table_row').show();
            $('#chart_row').hide();
        } else {
            $('#table_row').hide();
            $('#chart_row').show();

            // Map viz type to Splunk chart type
            var chartType = vizType;
            if (vizType === 'timechart') chartType = 'area';

            setToken('chart_type', chartType);
        }
    }

    // ========================================================================
    // Event Handlers
    // ========================================================================

    // Category dropdown change
    defaultTokens.on("change:query_category", function(model, value) {
        populateQueryPicker(value);
    });

    // Query picker - single click to load
    $(document).on('change', '#query-picker', function() {
        var selected = $(this).find(':selected');
        var idx = parseInt(selected.attr('data-index'), 10);
        if (isNaN(idx)) return;

        var q = QUERY_LIBRARY[idx];
        $('#spl-editor').val(q.query);
        $('#query-description').html(
            '<strong>' + q.category + ':</strong> ' + q.description
        );
        setActiveViz(q.viz);
    });

    // Query picker - double click to load AND run
    $(document).on('dblclick', '#query-picker option', function() {
        var idx = parseInt($(this).attr('data-index'), 10);
        if (isNaN(idx)) return;

        var q = QUERY_LIBRARY[idx];
        $('#spl-editor').val(q.query);
        $('#query-description').html(
            '<strong>' + q.category + ':</strong> ' + q.description
        );
        setActiveViz(q.viz);
        runSearch(q.query);
    });

    // Run button
    $(document).on('click', '#run-btn', function() {
        var spl = $('#spl-editor').val();
        runSearch(spl);
    });

    // Clear button
    $(document).on('click', '#clear-btn', function() {
        $('#spl-editor').val('');
        $('#query-description').html('Select a query from the library or type your own SPL.');
        setStatus('Ready', 'ready');
    });

    // Ctrl+Enter / Cmd+Enter to run
    $(document).on('keydown', '#spl-editor', function(e) {
        if ((e.ctrlKey || e.metaKey) && e.keyCode === 13) {
            e.preventDefault();
            var spl = $('#spl-editor').val();
            runSearch(spl);
        }
    });

    // Viz toggle buttons
    $(document).on('click', '.viz-btn', function() {
        var vizType = $(this).data('viz');
        setActiveViz(vizType);
    });

    // Sourcetype reference click to insert
    $(document).on('click', '.st-ref', function() {
        var st = $(this).text();
        var editor = $('#spl-editor');
        var current = editor.val();
        if (!current.trim()) {
            editor.val('index=fake_tshrt sourcetype="' + st + '"\n| stats count by host\n| sort - count');
        } else {
            // Append sourcetype filter
            editor.val(current);
        }
        $(this).addClass('st-clicked');
        var el = $(this);
        setTimeout(function() { el.removeClass('st-clicked'); }, 300);
    });

    // ========================================================================
    // Initialize
    // ========================================================================

    // chart_type default is set in the XML <input> element

    // Hide chart row initially (table is default viz)
    $('#chart_row').hide();

    populateQueryPicker('All Categories');
    setStatus('Ready - select a query or type your own SPL', 'ready');

    console.log('[SPL Playground] Initialized with ' + QUERY_LIBRARY.length + ' queries');
});
