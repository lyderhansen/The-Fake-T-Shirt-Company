#!/usr/bin/env python3
"""
Cisco Secure Access (Umbrella/SSE) log generator.

Generates 4 CSV output files matching verified Cisco Umbrella S3 export formats:
  - DNS logs (v10, 16 columns): ~100K-120K/day at scale=1.0
  - Proxy/SWG logs (v5, 26 columns): ~25K-40K/day
  - Cloud Firewall logs (14 columns): ~8K/day
  - Audit logs (9 columns): ~15/day

Architecture story: All 175 employees route DNS through Umbrella.
VPN-enabled users (~100) connect via RAVPN. SWG proxies web traffic.

All CSV formats verified against:
  - Cisco Umbrella Log Management docs (S3 export)
  - Splunk TA for Cisco Umbrella (Splunkbase #3847)
"""

import argparse
import hashlib
import random
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import (
    calc_natural_events,
    date_add,
    parse_date,
    is_weekend,
)
from shared.company import (
    USERS,
    USER_KEYS,
    VPN_USERS,
    SERVERS,
    TENANT,
    ORG_NAME,
    THREAT_IP,
    THREAT_COUNTRY,
    COMP_USER,
    COMP_WS_IP,
    COMP_LOCATION,
    LATERAL_USER,
    JESSICA_WS_IP,
    JESSICA_LOCATION,
    PHISHING_DOMAIN,
    EXT_SERVICE_IPS,
    get_internal_ip,
    get_external_ip,
    get_random_user,
    get_us_ip,
)
from scenarios.registry import expand_scenarios, is_scenario_active_day

# =============================================================================
# SECURE ACCESS CONFIGURATION
# =============================================================================

# Organization
ORG_ID = "7654321"
ORG_LABEL = "FakeTShirtCo"

# Tunnel device identifiers (per site, Umbrella CDFW tunnel)
TUNNEL_DEVICES = {
    "BOS": {"id": "tunnel-bos-001", "label": "BOS-HQ", "wan_ip": "203.0.113.10"},
    "ATL": {"id": "tunnel-atl-001", "label": "ATL-HUB", "wan_ip": "203.0.113.20"},
    "AUS": {"id": "tunnel-aus-001", "label": "AUS-OFF", "wan_ip": "203.0.113.30"},
}

# DNS policy IDs
DNS_POLICY_DEFAULT = "100001"
DNS_POLICY_STRICT = "100002"

# Web (proxy) policy IDs
WEB_POLICY_DEFAULT = "200001"
WEB_POLICY_STRICT = "200002"

# Firewall rule IDs
FW_RULE_ALLOW_WEB = "300001"
FW_RULE_ALLOW_DNS = "300002"
FW_RULE_DENY_ALL = "300099"

# Umbrella data centers
UMBRELLA_DCS = ["iad1.edc", "ord1.edc", "dfw1.edc", "sjc1.edc", "atl1.edc"]

# =============================================================================
# DNS DOMAIN POOLS
# =============================================================================

# Commonly queried domains (weighted by frequency)
COMMON_DOMAINS = [
    # Microsoft 365 (heaviest — all employees use it)
    ("outlook.office365.com", "Business Services,Cloud Services", 20),
    ("login.microsoftonline.com", "Business Services,Cloud Services", 12),
    ("graph.microsoft.com", "Business Services,Cloud Services", 8),
    ("teams.microsoft.com", "Business Services,Cloud Services", 10),
    ("sharepoint.com", "Business Services,Cloud Services", 6),
    ("onedrive.live.com", "Business Services,Cloud Services", 5),
    ("office.com", "Business Services,Cloud Services", 4),
    # Google (search, ads, analytics on web properties)
    ("www.google.com", "Search Engines", 8),
    ("accounts.google.com", "Search Engines,Cloud Services", 3),
    ("googleapis.com", "Cloud Services", 4),
    ("google-analytics.com", "Web Analytics", 5),
    # AWS (e-commerce backend)
    ("s3.amazonaws.com", "Cloud Services", 5),
    ("ec2.amazonaws.com", "Cloud Services", 3),
    ("console.aws.amazon.com", "Cloud Services", 2),
    # Cisco (Webex, Meraki, Secure Access itself)
    ("webex.com", "Business Services", 6),
    ("wbx2.com", "Business Services", 4),
    ("ciscospark.com", "Business Services", 3),
    ("meraki.com", "Business Services", 2),
    ("dashboard.meraki.com", "Business Services", 2),
    # GitHub (engineering)
    ("github.com", "Software/Technology", 5),
    ("api.github.com", "Software/Technology", 3),
    ("raw.githubusercontent.com", "Software/Technology", 2),
    # CDN / Infrastructure
    ("cdn.jsdelivr.net", "Infrastructure", 4),
    ("cdnjs.cloudflare.com", "Infrastructure", 3),
    ("ajax.googleapis.com", "Infrastructure", 3),
    ("fonts.googleapis.com", "Infrastructure", 3),
    # Social (marketing team)
    ("www.linkedin.com", "Social Networking", 3),
    ("twitter.com", "Social Networking", 2),
    ("www.facebook.com", "Social Networking", 2),
    # SaaS tools
    ("app.hubspot.com", "Business Services", 3),
    ("slack.com", "Business Services", 2),
    ("zoom.us", "Business Services", 2),
    ("servicenow.com", "Business Services", 2),
    ("salesforce.com", "Business Services", 3),
    # General browsing
    ("www.amazon.com", "Shopping", 3),
    ("www.reddit.com", "Forums/Message boards", 2),
    ("stackoverflow.com", "Software/Technology", 3),
    ("en.wikipedia.org", "Reference", 2),
    ("www.nytimes.com", "News/Media", 2),
    ("www.bbc.com", "News/Media", 1),
    ("weather.com", "Weather", 2),
    # E-commerce (own site)
    ("thefaketshirtcompany.com", "Business Services", 3),
    ("api.thefaketshirtcompany.com", "Business Services", 2),
]

# Blocked category domains (will get "Blocked" action)
BLOCKED_DOMAINS = [
    ("malware-test-domain.example.com", "Malware", "Malware"),
    ("phishing-test.example.net", "Phishing", "Phishing"),
    ("crypto-mining-pool.example.org", "Cryptomining", "Cryptomining"),
    ("adult-content.example.com", "Adult Themes", "Adult Themes"),
    ("gambling-site.example.net", "Gambling", "Gambling"),
    ("proxy-anonymizer.example.org", "Proxy/Anonymizer", "Proxy/Anonymizer"),
]

# Infrastructure/automated DNS (servers, not users)
INFRA_DOMAINS = [
    ("time.windows.com", "Infrastructure", 5),
    ("time.google.com", "Infrastructure", 3),
    ("ocsp.digicert.com", "Infrastructure", 4),
    ("crl.microsoft.com", "Infrastructure", 3),
    ("ctldl.windowsupdate.com", "Software/Technology", 3),
    ("settings-win.data.microsoft.com", "Software/Technology", 2),
    ("wpad.thefaketshirtcompany.com", "Infrastructure", 2),
    ("isatap.thefaketshirtcompany.com", "Infrastructure", 1),
]

# DNS query types (weighted)
DNS_QUERY_TYPES = [
    ("1 (A)", 60),
    ("28 (AAAA)", 15),
    ("5 (CNAME)", 8),
    ("15 (MX)", 3),
    ("16 (TXT)", 4),
    ("2 (NS)", 2),
    ("33 (SRV)", 3),
    ("65 (HTTPS)", 5),
]

# DNS response codes (weighted)
DNS_RESPONSE_CODES = [
    ("NOERROR", 92),
    ("NXDOMAIN", 5),
    ("SERVFAIL", 2),
    ("REFUSED", 1),
]

# Destination countries for DNS
DNS_DEST_COUNTRIES = [
    ("US", 70), ("IE", 8), ("NL", 5), ("DE", 4), ("GB", 3),
    ("SG", 2), ("JP", 2), ("CA", 2), ("AU", 2), ("FR", 2),
]

# =============================================================================
# PROXY / SWG CONFIGURATION
# =============================================================================

# Common web URLs (weighted)
PROXY_URLS = [
    ("https://outlook.office365.com/owa/", "text/html", "Business Services", 15),
    ("https://teams.microsoft.com/", "text/html", "Business Services", 10),
    ("https://login.microsoftonline.com/common/oauth2/authorize", "text/html", "Business Services", 8),
    ("https://graph.microsoft.com/v1.0/me/messages", "application/json", "Business Services", 6),
    ("https://sharepoint.com/sites/TShirtCo/", "text/html", "Business Services", 5),
    ("https://github.com/faketshirtco/", "text/html", "Software/Technology", 5),
    ("https://console.aws.amazon.com/s3/", "text/html", "Cloud Services", 4),
    ("https://app.hubspot.com/contacts/", "text/html", "Business Services", 3),
    ("https://www.google.com/search?q=", "text/html", "Search Engines", 8),
    ("https://stackoverflow.com/questions/", "text/html", "Software/Technology", 4),
    ("https://www.linkedin.com/feed/", "text/html", "Social Networking", 3),
    ("https://www.amazon.com/", "text/html", "Shopping", 3),
    ("https://cdn.jsdelivr.net/npm/", "application/javascript", "Infrastructure", 5),
    ("https://fonts.googleapis.com/css2", "text/css", "Infrastructure", 4),
    ("https://api.thefaketshirtcompany.com/v1/products", "application/json", "Business Services", 3),
    ("https://salesforce.com/lightning/page/home", "text/html", "Business Services", 3),
    ("https://servicenow.com/nav_to.do", "text/html", "Business Services", 2),
    ("https://www.nytimes.com/", "text/html", "News/Media", 2),
    ("https://www.reddit.com/r/sysadmin/", "text/html", "Forums/Message boards", 2),
    ("https://weather.com/weather/today/", "text/html", "Weather", 2),
]

# HTTP status codes (weighted)
HTTP_STATUS_CODES = [
    ("200", 70), ("301", 5), ("302", 8), ("304", 5),
    ("403", 3), ("404", 4), ("500", 2), ("502", 1), ("503", 2),
]

# HTTP methods (weighted)
HTTP_METHODS = [
    ("GET", 65), ("POST", 20), ("PUT", 5), ("DELETE", 2),
    ("OPTIONS", 3), ("HEAD", 3), ("PATCH", 2),
]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

# AMP dispositions (weighted)
AMP_DISPOSITIONS = [
    ("Clean", 95), ("Unknown", 3), ("Malicious", 1), ("Low Risk", 1),
]

# Proxy actions (weighted)
PROXY_ACTIONS = [
    ("ALLOWED", 94), ("BLOCKED", 4), ("WARNED", 2),
]

# =============================================================================
# CLOUD FIREWALL CONFIGURATION
# =============================================================================

# Common destination ports (weighted)
FW_DEST_PORTS = [
    ("443", 55), ("80", 15), ("53", 8), ("8443", 5),
    ("993", 3), ("587", 3), ("25", 2), ("22", 2),
    ("3389", 1), ("5060", 1), ("8080", 3), ("9443", 2),
]

# IP protocols (weighted)
FW_IP_PROTOCOLS = [
    ("6", 75),    # TCP
    ("17", 20),   # UDP
    ("1", 3),     # ICMP
    ("47", 2),    # GRE
]

# Firewall verdicts (weighted)
FW_VERDICTS = [
    ("ALLOW", 90), ("BLOCK", 8), ("DROP", 2),
]

# =============================================================================
# AUDIT CONFIGURATION
# =============================================================================

AUDIT_ACTION_TYPES = [
    ("dnspolicies", "update", 20),
    ("dnspolicies", "create", 5),
    ("dnspolicies", "delete", 2),
    ("webpolicies", "update", 15),
    ("webpolicies", "create", 3),
    ("fwpolicies", "update", 10),
    ("fwpolicies", "create", 2),
    ("tunnels", "update", 5),
    ("networks", "update", 8),
    ("networks", "create", 3),
    ("identities", "update", 5),
    ("identities", "create", 3),
    ("roaming_computers", "update", 4),
    ("roaming_computers", "create", 2),
    ("admin_users", "update", 3),
    ("admin_users", "create", 1),
    ("reports", "create", 5),
    ("integrations", "update", 2),
    ("destinations", "update", 5),
    ("destinations", "create", 3),
]

# Admins who manage Umbrella
UMBRELLA_ADMINS = [
    "david.robinson",   # IT Director
    "jessica.brown",    # IT Administrator (ATL)
    "patrick.gonzalez", # Systems Administrator
    "stephanie.barnes", # Network Administrator
    "ashley.griffin",   # Security Engineer
    "nicole.simmons",   # Security Analyst
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _weighted_choice(items: list) -> Any:
    """Pick from a weighted list of (value, weight) tuples."""
    values = [i[0] for i in items]
    weights = [i[1] for i in items]
    return random.choices(values, weights=weights, k=1)[0]


def _weighted_choice_full(items: list) -> tuple:
    """Pick full tuple from a weighted list where last element is weight."""
    weights = [i[-1] for i in items]
    return random.choices(items, weights=weights, k=1)[0]


def _csv_quote(value: str) -> str:
    """Quote a CSV field value (Umbrella style -- all fields double-quoted)."""
    # Escape internal double quotes
    escaped = str(value).replace('"', '""')
    return f'"{escaped}"'


def _format_timestamp(start_date: str, day: int, hour: int,
                      minute: int = None, second: int = None) -> str:
    """Generate Umbrella timestamp: 'YYYY-MM-DD HH:MM:SS'."""
    if minute is None:
        minute = random.randint(0, 59)
    if second is None:
        second = random.randint(0, 59)
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _get_user_identity(user) -> Tuple[str, str, str]:
    """Get Umbrella identity fields for a user.

    Returns:
        (most_granular_identity, identities, identity_type)
    """
    username = user.username
    email = user.email
    location = user.location
    tunnel_label = TUNNEL_DEVICES[location]["label"]

    most_granular = f"{username} ({email})"
    identities = f"{username},{tunnel_label},{ORG_LABEL}-Corp"
    identity_type = "AD Users"

    return most_granular, identities, identity_type


def _get_dest_ip_for_domain(domain: str) -> str:
    """Generate a plausible destination IP for a domain."""
    # Use hash for deterministic mapping
    h = hashlib.md5(domain.encode()).digest()
    # Microsoft
    if any(ms in domain for ms in ["microsoft", "office", "sharepoint", "onedrive", "live.com"]):
        return f"52.{96 + h[0] % 10}.{h[1] % 256}.{h[2] % 256}"
    # Google
    if any(g in domain for g in ["google", "googleapis", "gstatic"]):
        return f"142.{250 + h[0] % 6}.{h[1] % 256}.{h[2] % 256}"
    # AWS
    if "amazonaws" in domain or "aws" in domain:
        return f"54.{230 + h[0] % 10}.{h[1] % 256}.{h[2] % 256}"
    # GitHub
    if "github" in domain:
        return f"140.82.{121 + h[0] % 5}.{h[1] % 256}"
    # Cisco
    if any(c in domain for c in ["webex", "cisco", "meraki", "wbx2", "ciscospark"]):
        return f"173.{36 + h[0] % 10}.{h[1] % 256}.{h[2] % 256}"
    # CDN
    if any(c in domain for c in ["cdn", "cloudflare", "jsdelivr"]):
        return f"104.{16 + h[0] % 10}.{h[1] % 256}.{h[2] % 256}"
    # Default: semi-random based on domain hash
    return f"{h[0] % 128 + 64}.{h[1] % 256}.{h[2] % 256}.{h[3] % 256}"


def _get_sha256_for_content(url: str) -> str:
    """Generate a deterministic SHA256 for proxy content (empty for most)."""
    # Only generate SHA for file downloads
    if any(ext in url for ext in [".exe", ".msi", ".zip", ".dll", ".js"]):
        return hashlib.sha256(url.encode()).hexdigest()
    return ""


# =============================================================================
# DNS LOG GENERATOR
# =============================================================================

def _generate_dns_event(start_date: str, day: int, hour: int,
                        user=None, domain_override: str = None,
                        action_override: str = None,
                        categories_override: str = None,
                        blocked_categories: str = "",
                        demo_id: str = "") -> str:
    """Generate a single DNS CSV line (v10 format, 16 columns).

    Columns:
        Timestamp, Most Granular Identity, Identities, InternalIp, ExternalIp,
        Action, QueryType, ResponseCode, Domain, Categories,
        Most Granular Identity Type, Identity Types, Blocked Categories,
        Rule ID, Destination Countries, Organization ID
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    timestamp = _format_timestamp(start_date, day, hour, minute, second)

    # Pick user
    if user is None:
        user = USERS[random.choice(USER_KEYS)]

    # Identity
    most_granular, identities, id_type = _get_user_identity(user)
    tunnel = TUNNEL_DEVICES[user.location]
    external_ip = tunnel["wan_ip"]

    # 15% of VPN-enabled users show VPN pool IP (remote workers)
    if user.vpn_enabled and random.random() < 0.15:
        internal_ip = user.vpn_ip
    else:
        internal_ip = user.ip_address

    # Domain selection
    if domain_override:
        domain = domain_override
        categories = categories_override or "Uncategorized"
        action = action_override or "Allowed"
    else:
        # 98% common domains, 1% infra, 1% blocked
        roll = random.random()
        if roll < 0.01:
            # Blocked domain
            blocked = random.choice(BLOCKED_DOMAINS)
            domain = blocked[0]
            categories = blocked[1]
            action = "Blocked"
            blocked_categories = blocked[2]
        elif roll < 0.02:
            # Infrastructure
            infra = _weighted_choice_full(INFRA_DOMAINS)
            domain = infra[0]
            categories = infra[1]
            action = "Allowed"
        else:
            # Common domain
            entry = _weighted_choice_full(COMMON_DOMAINS)
            domain = entry[0]
            categories = entry[1]
            action = "Allowed"

    if action_override:
        action = action_override

    # Query type and response
    query_type = _weighted_choice(DNS_QUERY_TYPES)
    response_code = "NOERROR" if action == "Allowed" else _weighted_choice(DNS_RESPONSE_CODES)

    # Destination country
    dest_country = _weighted_choice(DNS_DEST_COUNTRIES)

    # Rule ID (empty for allowed, policy ID for blocked)
    rule_id = DNS_POLICY_STRICT if action == "Blocked" else DNS_POLICY_DEFAULT

    # Identity types
    identity_types = "AD Users,Internal Networks"

    # Build CSV line (all fields quoted)
    fields = [
        _csv_quote(timestamp),
        _csv_quote(most_granular),
        _csv_quote(identities),
        _csv_quote(internal_ip),
        _csv_quote(external_ip),
        _csv_quote(action),
        _csv_quote(query_type),
        _csv_quote(response_code),
        _csv_quote(domain),
        _csv_quote(categories),
        _csv_quote(id_type),
        _csv_quote(identity_types),
        _csv_quote(blocked_categories),
        _csv_quote(rule_id),
        _csv_quote(dest_country),
        _csv_quote(ORG_ID),
    ]

    line = ",".join(fields)

    # Append demo_id if present (outside CSV for Splunk extraction)
    if demo_id:
        line += f" demo_id={demo_id}"

    return f"{timestamp}\t{line}"  # Prepend sortable timestamp (stripped before write)


# =============================================================================
# PROXY / SWG LOG GENERATOR
# =============================================================================

def _generate_proxy_event(start_date: str, day: int, hour: int,
                          user=None, url_override: str = None,
                          action_override: str = None,
                          categories_override: str = None,
                          status_override: str = None,
                          demo_id: str = "") -> str:
    """Generate a single Proxy CSV line (v5 format, 26 columns).

    Columns:
        Timestamp, Policy Identity Label, Internal Client IP, External Client IP,
        Destination IP, Content Type, Action, URL, Referer, User Agent,
        Status Code, Request Size, Response Size, Response Body Size, SHA256,
        Categories, AV Detections, PUAs, AMP Disposition, AMP Malware Name,
        AMP Score, Policy Identity Type, Blocked Categories, Identities,
        Identity Types, Request Method
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    timestamp = _format_timestamp(start_date, day, hour, minute, second)

    # Pick user
    if user is None:
        user = USERS[random.choice(USER_KEYS)]

    tunnel = TUNNEL_DEVICES[user.location]
    external_ip = tunnel["wan_ip"]
    tunnel_label = tunnel["label"]

    # 15% of VPN-enabled users show VPN pool IP (remote workers)
    if user.vpn_enabled and random.random() < 0.15:
        internal_ip = user.vpn_ip
    else:
        internal_ip = user.ip_address

    # URL selection
    if url_override:
        url = url_override
        content_type = "text/html"
        categories = categories_override or "Uncategorized"
        action = action_override or "ALLOWED"
    else:
        entry = _weighted_choice_full(PROXY_URLS)
        url = entry[0]
        content_type = entry[1]
        categories = entry[2]
        action = _weighted_choice(PROXY_ACTIONS)

    if action_override:
        action = action_override
    if status_override:
        status_code = status_override
    else:
        status_code = _weighted_choice(HTTP_STATUS_CODES)

    # Destination IP from domain in URL
    try:
        domain = url.split("//")[1].split("/")[0]
    except (IndexError, AttributeError):
        domain = "unknown.com"
    dest_ip = _get_dest_ip_for_domain(domain)

    # Request details
    request_method = _weighted_choice(HTTP_METHODS)
    user_agent = random.choice(USER_AGENTS)
    request_size = str(random.randint(200, 5000))
    response_size = str(random.randint(1000, 200000))
    response_body_size = str(int(int(response_size) * 0.95))
    sha256 = _get_sha256_for_content(url)

    # AMP
    amp_disp = _weighted_choice(AMP_DISPOSITIONS)
    amp_malware = "" if amp_disp in ("Clean", "Unknown") else "Win.Trojan.Generic"
    amp_score = "" if amp_disp in ("Clean", "Unknown") else str(random.randint(50, 100))

    # AV / PUA
    av_detections = ""
    puas = ""

    # Blocked categories
    blocked_cats = categories if action == "BLOCKED" else ""

    # Identity fields
    policy_identity = user.username
    policy_identity_type = "AD Users"
    identities_str = f"{user.username},{tunnel_label}"
    identity_types = "AD Users,Internal Networks"

    # Referer (empty most of the time)
    referer = ""

    # Build CSV line (all fields quoted)
    fields = [
        _csv_quote(timestamp),
        _csv_quote(policy_identity),
        _csv_quote(internal_ip),
        _csv_quote(external_ip),
        _csv_quote(dest_ip),
        _csv_quote(content_type),
        _csv_quote(action),
        _csv_quote(url),
        _csv_quote(referer),
        _csv_quote(user_agent),
        _csv_quote(status_code),
        _csv_quote(request_size),
        _csv_quote(response_size),
        _csv_quote(response_body_size),
        _csv_quote(sha256),
        _csv_quote(categories),
        _csv_quote(av_detections),
        _csv_quote(puas),
        _csv_quote(amp_disp),
        _csv_quote(amp_malware),
        _csv_quote(amp_score),
        _csv_quote(policy_identity_type),
        _csv_quote(blocked_cats),
        _csv_quote(identities_str),
        _csv_quote(identity_types),
        _csv_quote(request_method),
    ]

    line = ",".join(fields)

    if demo_id:
        line += f" demo_id={demo_id}"

    return f"{timestamp}\t{line}"


# =============================================================================
# CLOUD FIREWALL LOG GENERATOR
# =============================================================================

def _generate_firewall_event(start_date: str, day: int, hour: int,
                             user=None, src_ip_override: str = None,
                             dst_ip_override: str = None,
                             dst_port_override: str = None,
                             verdict_override: str = None,
                             demo_id: str = "") -> str:
    """Generate a single Cloud Firewall CSV line (14 columns).

    Columns:
        Timestamp, Origin ID, Identity, Identity Type, Direction,
        IP Protocol, Packet Size, Source IP, Source Port,
        Destination IP, Destination Port, Data Center, Rule ID, Verdict
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    timestamp = _format_timestamp(start_date, day, hour, minute, second)

    # Pick user or use override
    if user is None:
        user = USERS[random.choice(USER_KEYS)]

    tunnel = TUNNEL_DEVICES[user.location]
    origin_id = f"[org-{ORG_LABEL.lower()}-001]"
    identity = tunnel["label"]
    identity_type = "CDFW Tunnel Device"

    direction = "OUTBOUND"
    ip_protocol = _weighted_choice(FW_IP_PROTOCOLS)
    packet_size = str(random.randint(64, 1500))

    src_ip = src_ip_override or user.ip_address
    src_port = str(random.randint(1024, 65535))
    dst_ip = dst_ip_override or get_external_ip()
    dst_port = dst_port_override or _weighted_choice(FW_DEST_PORTS)

    dc = random.choice(UMBRELLA_DCS)
    verdict = verdict_override or _weighted_choice(FW_VERDICTS)

    rule_id = FW_RULE_DENY_ALL if verdict in ("BLOCK", "DROP") else FW_RULE_ALLOW_WEB

    fields = [
        _csv_quote(timestamp),
        _csv_quote(origin_id),
        _csv_quote(identity),
        _csv_quote(identity_type),
        _csv_quote(direction),
        _csv_quote(ip_protocol),
        _csv_quote(packet_size),
        _csv_quote(src_ip),
        _csv_quote(src_port),
        _csv_quote(dst_ip),
        _csv_quote(dst_port),
        _csv_quote(dc),
        _csv_quote(rule_id),
        _csv_quote(verdict),
    ]

    line = ",".join(fields)

    if demo_id:
        line += f" demo_id={demo_id}"

    return f"{timestamp}\t{line}"


# =============================================================================
# AUDIT LOG GENERATOR
# =============================================================================

def _generate_audit_event(start_date: str, day: int, hour: int,
                          admin_user: str = None,
                          action_type: str = None,
                          action_name: str = None,
                          before_val: str = "",
                          after_val: str = "",
                          demo_id: str = "") -> str:
    """Generate a single Audit CSV line (9 columns).

    Columns:
        ID, Time, Email, User, Type, Action, Logged in from, Before, After
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    timestamp = _format_timestamp(start_date, day, hour, minute, second)

    if admin_user is None:
        admin_username = random.choice(UMBRELLA_ADMINS)
    else:
        admin_username = admin_user

    admin = USERS.get(admin_username)
    admin_email = admin.email if admin else f"{admin_username}@{TENANT}"
    admin_ip = admin.ip_address if admin else "10.10.30.180"

    if action_type is None or action_name is None:
        entry = _weighted_choice_full(AUDIT_ACTION_TYPES)
        action_type = entry[0]
        action_name = entry[1]

    # Generate before/after values based on action type
    if not before_val and not after_val:
        if action_name == "update":
            if "policies" in action_type:
                after_val = random.choice([
                    "enabled: true", "enabled: false",
                    "blockPage: custom", "logging: full",
                    "safeSearch: enabled", "categories: updated",
                ])
            elif action_type == "networks":
                after_val = random.choice([
                    "name: BOS-HQ", "subnet: 10.10.0.0/16",
                    "tunnelEnabled: true",
                ])
            else:
                after_val = f"modified: {action_type}"
        elif action_name == "create":
            after_val = f"created: {action_type}"
        elif action_name == "delete":
            before_val = f"removed: {action_type}"

    # Audit ID (empty in real Umbrella exports)
    audit_id = ""

    fields = [
        _csv_quote(audit_id),
        _csv_quote(timestamp),
        _csv_quote(admin_email),
        _csv_quote(""),  # User field (empty in Umbrella audit)
        _csv_quote(action_type),
        _csv_quote(action_name),
        _csv_quote(admin_ip),
        _csv_quote(before_val),
        _csv_quote(after_val),
    ]

    line = ",".join(fields)

    if demo_id:
        line += f" demo_id={demo_id}"

    return f"{timestamp}\t{line}"


# =============================================================================
# SCENARIO INTEGRATION
# =============================================================================

def _generate_exfil_dns_events(start_date: str, day: int, hour: int) -> List[str]:
    """Generate DNS events for exfil scenario.

    Timeline:
      Days 0-3 (Recon): Threat actor scans; minimal DNS impact
      Day 4 (Initial Access): Jessica clicks phishing link -> DNS for phishing domain
      Days 5-7 (Lateral): Internal probing; DNS for staging/C2 domains
      Days 8-10 (Persistence): C2 beacon DNS callbacks every few hours
      Days 11-13 (Exfil): DNS tunneling indicators, cloud storage domains
    """
    events = []
    comp_user = USERS[COMP_USER]
    lateral_user = USERS[LATERAL_USER]

    # C2 domains (DNS beaconing)
    c2_domains = [
        "update-service.example.com",
        "cdn-sync.example.net",
        "api-analytics.example.org",
    ]

    # Cloud storage for exfiltration
    exfil_storage = [
        "transfer.sh",
        "mega.nz",
        "file.io",
    ]

    if day == 4 and hour == 10:
        # Jessica resolves phishing domain
        events.append(_generate_dns_event(
            start_date, day, hour, user=lateral_user,
            domain_override=PHISHING_DOMAIN,
            categories_override="Newly Seen Domains",
            action_override="Allowed",
            demo_id="exfil"
        ))

    elif 5 <= day <= 7:
        # Lateral movement: occasional C2 DNS lookups from Jessica
        if hour in (9, 14, 20) and random.random() < 0.7:
            c2 = random.choice(c2_domains)
            events.append(_generate_dns_event(
                start_date, day, hour, user=lateral_user,
                domain_override=c2,
                categories_override="Uncategorized",
                action_override="Allowed",
                demo_id="exfil"
            ))

    elif 8 <= day <= 10:
        # Persistence: C2 beaconing from compromised user (Alex)
        if hour % 3 == 0:  # Every 3 hours
            c2 = random.choice(c2_domains)
            events.append(_generate_dns_event(
                start_date, day, hour, user=comp_user,
                domain_override=c2,
                categories_override="Uncategorized",
                action_override="Allowed",
                demo_id="exfil"
            ))

    elif 11 <= day <= 13:
        # Exfiltration: DNS tunneling + cloud storage lookups
        if hour % 2 == 0:
            # C2 beacon continues
            c2 = random.choice(c2_domains)
            events.append(_generate_dns_event(
                start_date, day, hour, user=comp_user,
                domain_override=c2,
                categories_override="Uncategorized",
                action_override="Allowed",
                demo_id="exfil"
            ))
        if 9 <= hour <= 17 and random.random() < 0.5:
            # Cloud storage lookups during business hours
            storage = random.choice(exfil_storage)
            events.append(_generate_dns_event(
                start_date, day, hour, user=comp_user,
                domain_override=storage,
                categories_override="Cloud Storage",
                action_override="Allowed",
                demo_id="exfil"
            ))

    return events


def _generate_exfil_proxy_events(start_date: str, day: int, hour: int) -> List[str]:
    """Generate Proxy events for exfil scenario.

    Days 11-13: Data uploads to cloud storage via SWG.
    """
    events = []
    comp_user = USERS[COMP_USER]

    if 11 <= day <= 13 and 10 <= hour <= 16:
        if random.random() < 0.4:
            # Upload to cloud storage
            storage_urls = [
                "https://transfer.sh/upload",
                "https://mega.nz/upload",
                "https://file.io/",
            ]
            url = random.choice(storage_urls)
            events.append(_generate_proxy_event(
                start_date, day, hour, user=comp_user,
                url_override=url,
                categories_override="Cloud Storage",
                action_override="ALLOWED",
                status_override="200",
                demo_id="exfil"
            ))

    return events


def _generate_exfil_fw_events(start_date: str, day: int, hour: int) -> List[str]:
    """Generate Firewall events for exfil scenario.

    Days 8-13: Unusual outbound connections from compromised hosts.
    """
    events = []
    comp_user = USERS[COMP_USER]

    if 8 <= day <= 13 and hour % 4 == 0:
        if random.random() < 0.6:
            # Outbound connection to C2 IP
            events.append(_generate_firewall_event(
                start_date, day, hour, user=comp_user,
                dst_ip_override=THREAT_IP,
                dst_port_override="443",
                verdict_override="ALLOW",
                demo_id="exfil"
            ))

    return events


def _generate_ransomware_dns_events(start_date: str, day: int, hour: int) -> List[str]:
    """Generate DNS events for ransomware_attempt scenario.

    Day 7: Brooklyn White resolves phishing domain
    Day 8: Attempted malware download domain (blocked)
    """
    events = []

    brooklyn = USERS.get("brooklyn.white")
    if brooklyn is None:
        return events

    if day == 7 and hour == 11:
        # Brooklyn resolves phishing domain
        events.append(_generate_dns_event(
            start_date, day, hour, user=brooklyn,
            domain_override="secure-docshare.example.com",
            categories_override="Newly Seen Domains",
            action_override="Allowed",
            demo_id="ransomware_attempt"
        ))

    elif day == 8 and hour == 9:
        # Malware download domain blocked
        events.append(_generate_dns_event(
            start_date, day, hour, user=brooklyn,
            domain_override="dl-update-service.example.net",
            categories_override="Malware",
            action_override="Blocked",
            blocked_categories="Malware",
            demo_id="ransomware_attempt"
        ))

    return events


def _generate_ransomware_proxy_events(start_date: str, day: int, hour: int) -> List[str]:
    """Generate Proxy events for ransomware_attempt scenario.

    Day 8: Proxy blocks malware download.
    """
    events = []

    brooklyn = USERS.get("brooklyn.white")
    if brooklyn is None:
        return events

    if day == 8 and hour == 9:
        events.append(_generate_proxy_event(
            start_date, day, hour, user=brooklyn,
            url_override="https://dl-update-service.example.net/update.exe",
            categories_override="Malware",
            action_override="BLOCKED",
            status_override="403",
            demo_id="ransomware_attempt"
        ))

    return events


def _generate_phishing_test_dns_events(start_date: str, day: int, hour: int) -> List[str]:
    """Generate DNS events for phishing_test scenario.

    Days 20-22: IT runs phishing simulation; employees resolve test domain.
    """
    events = []

    phishing_sim_domain = "phishing-sim.thefaketshirtcompany.com"

    if 20 <= day <= 22 and 9 <= hour <= 17:
        # Random employees resolve the phishing sim domain
        # ~5-10 per hour during business hours over 3 days
        num_lookups = random.randint(3, 8)
        for _ in range(num_lookups):
            user = USERS[random.choice(USER_KEYS)]
            events.append(_generate_dns_event(
                start_date, day, hour, user=user,
                domain_override=phishing_sim_domain,
                categories_override="Business Services",
                action_override="Allowed",
                demo_id="phishing_test"
            ))

    return events


# =============================================================================
# MAIN GENERATOR FUNCTION
# =============================================================================

def generate_secure_access_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Cisco Secure Access (Umbrella) logs.

    Produces 4 CSV output files:
        - DNS logs (~100K-120K/day)
        - Proxy/SWG logs (~25K-40K/day)
        - Cloud Firewall logs (~8K/day)
        - Audit logs (~15/day)

    Args:
        start_date: Start date in YYYY-MM-DD format
        days: Number of days to generate
        scale: Volume multiplier (1.0 = normal)
        scenarios: Comma-separated scenario names or "none"/"all"
        output_file: Override output path (base name, ignored for multi-file)
        quiet: Suppress progress output

    Returns:
        int: Total number of events generated across all files
    """
    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Output paths (4 files)
    dns_path = get_output_path("cloud", "cisco_secure_access/cisco_secure_access_dns.csv")
    proxy_path = get_output_path("cloud", "cisco_secure_access/cisco_secure_access_proxy.csv")
    fw_path = get_output_path("cloud", "cisco_secure_access/cisco_secure_access_firewall.csv")
    audit_path = get_output_path("cloud", "cisco_secure_access/cisco_secure_access_audit.csv")

    # Progress header
    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco Secure Access Generator (DNS + Proxy + Firewall + Audit)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {dns_path.parent}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Collect events per file (with sort key prefix)
    dns_events: List[str] = []
    proxy_events: List[str] = []
    fw_events: List[str] = []
    audit_events: List[str] = []

    # Volume settings (events per peak hour at scale=1.0)
    # DNS: 175 users * ~25 queries/hr peak = ~4375/hr -> ~105K/day
    # Proxy: 175 users * ~8 requests/hr peak = ~1400/hr -> ~33K/day
    # Firewall: ~350/hr -> ~8K/day
    # Audit: ~0.6/hr (15/day, clustered in business hours)
    dns_base = int(4375 * scale)
    proxy_base = int(1400 * scale)
    fw_base = int(350 * scale)

    demo_id_counts = {"dns": 0, "proxy": 0, "fw": 0, "audit": 0}

    # Main generation loop
    for day in range(days):
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [SecureAccess] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        for hour in range(24):
            # --- DNS ---
            dns_count = calc_natural_events(dns_base, start_date, day, hour, "cloud")
            for _ in range(dns_count):
                dns_events.append(_generate_dns_event(start_date, day, hour))

            # --- Proxy ---
            proxy_count = calc_natural_events(proxy_base, start_date, day, hour, "cloud")
            for _ in range(proxy_count):
                proxy_events.append(_generate_proxy_event(start_date, day, hour))

            # --- Firewall ---
            fw_count = calc_natural_events(fw_base, start_date, day, hour, "firewall")
            for _ in range(fw_count):
                fw_events.append(_generate_firewall_event(start_date, day, hour))

            # --- Audit (business hours only, ~15/day) ---
            if 8 <= hour <= 17 and not is_weekend(day_date):
                # ~1.5 events per business hour
                if random.random() < 0.15 * scale:
                    audit_events.append(_generate_audit_event(start_date, day, hour))

            # --- Scenario events ---
            if "exfil" in active_scenarios and is_scenario_active_day("exfil", day):
                exfil_dns = _generate_exfil_dns_events(start_date, day, hour)
                dns_events.extend(exfil_dns)
                demo_id_counts["dns"] += len(exfil_dns)

                exfil_proxy = _generate_exfil_proxy_events(start_date, day, hour)
                proxy_events.extend(exfil_proxy)
                demo_id_counts["proxy"] += len(exfil_proxy)

                exfil_fw = _generate_exfil_fw_events(start_date, day, hour)
                fw_events.extend(exfil_fw)
                demo_id_counts["fw"] += len(exfil_fw)

            if "ransomware_attempt" in active_scenarios and is_scenario_active_day("ransomware_attempt", day):
                ransom_dns = _generate_ransomware_dns_events(start_date, day, hour)
                dns_events.extend(ransom_dns)
                demo_id_counts["dns"] += len(ransom_dns)

                ransom_proxy = _generate_ransomware_proxy_events(start_date, day, hour)
                proxy_events.extend(ransom_proxy)
                demo_id_counts["proxy"] += len(ransom_proxy)

            if "phishing_test" in active_scenarios and is_scenario_active_day("phishing_test", day):
                phish_dns = _generate_phishing_test_dns_events(start_date, day, hour)
                dns_events.extend(phish_dns)
                demo_id_counts["dns"] += len(phish_dns)

    # Sort all events by timestamp (tab-separated prefix)
    dns_events.sort()
    proxy_events.sort()
    fw_events.sort()
    audit_events.sort()

    # Write files (strip sort prefix)
    def _write_csv(path: Path, events: List[str]):
        with open(path, "w") as f:
            for ev in events:
                # Strip the "timestamp\t" sort prefix
                idx = ev.index("\t")
                f.write(ev[idx + 1:] + "\n")

    _write_csv(dns_path, dns_events)
    _write_csv(proxy_path, proxy_events)
    _write_csv(fw_path, fw_events)
    _write_csv(audit_path, audit_events)

    total = len(dns_events) + len(proxy_events) + len(fw_events) + len(audit_events)
    total_demo = sum(demo_id_counts.values())

    if not quiet:
        print(f"  [SecureAccess] Complete! {total:,} total events written", file=sys.stderr)
        print(f"          DNS:      {len(dns_events):,} events -> {dns_path.name}", file=sys.stderr)
        print(f"          Proxy:    {len(proxy_events):,} events -> {proxy_path.name}", file=sys.stderr)
        print(f"          Firewall: {len(fw_events):,} events -> {fw_path.name}", file=sys.stderr)
        print(f"          Audit:    {len(audit_events):,} events -> {audit_path.name}", file=sys.stderr)
        if total_demo:
            print(f"          demo_id events: {total_demo:,} "
                  f"(dns={demo_id_counts['dns']}, proxy={demo_id_counts['proxy']}, "
                  f"fw={demo_id_counts['fw']}, audit={demo_id_counts['audit']})",
                  file=sys.stderr)

    return total


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate Cisco Secure Access (Umbrella) logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --days=7                    Generate 7 days of logs
  %(prog)s --days=14 --scenarios=exfil Generate with exfil scenario
  %(prog)s --scale=0.5                 Half the event volume
  %(prog)s --quiet                     Suppress progress output
        """
    )
    parser.add_argument(
        "--start-date", default=DEFAULT_START_DATE,
        help=f"Start date YYYY-MM-DD (default: {DEFAULT_START_DATE})"
    )
    parser.add_argument(
        "--days", type=int, default=DEFAULT_DAYS,
        help=f"Number of days (default: {DEFAULT_DAYS})"
    )
    parser.add_argument(
        "--scale", type=float, default=DEFAULT_SCALE,
        help=f"Volume scale factor (default: {DEFAULT_SCALE})"
    )
    parser.add_argument(
        "--scenarios", default="none",
        help="Scenarios: none, exfil, ransomware_attempt, phishing_test, all"
    )
    parser.add_argument(
        "--output", help="Output directory override (ignored for multi-file)"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output"
    )

    args = parser.parse_args()

    count = generate_secure_access_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )

    print(count)


if __name__ == "__main__":
    main()
