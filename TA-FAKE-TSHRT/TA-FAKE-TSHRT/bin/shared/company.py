#!/usr/bin/env python3
"""
Company configuration - The FAKE T-Shirt Company.
All organization-specific data: users, servers, network ranges, cloud config,
locations, infrastructure, and threat actor information for attack scenarios.

Multi-site architecture:
  - Boston HQ (BOS): Headquarters, 3 floors, ~93 employees
  - Atlanta Hub (ATL): IT/Regional Hub, 2 floors, ~43 employees
  - Austin Office (AUS): Sales/Engineering, 1 floor, ~39 employees
"""

import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# =============================================================================
# ORGANIZATION IDENTITY
# =============================================================================

ORG_NAME = "The FAKE T-Shirt Company"
TENANT = "theFakeTshirtCompany.com"
TENANT_ID = "af23e456-7890-1234-5678-abcdef012345"
ORG_NAME_LOWER = "faketshirtcompany"

# =============================================================================
# LOCATION CONFIGURATION
# =============================================================================

LOCATIONS = {
    "BOS": {
        "name": "Boston",
        "full_name": "Boston HQ",
        "state": "MA",
        "type": "Headquarters",
        "address": "125 One Financial Center",
        "floors": 3,
        "timezone": "America/New_York",
        "employee_count": 93,
    },
    "ATL": {
        "name": "Atlanta",
        "full_name": "Atlanta Hub",
        "state": "GA",
        "type": "IT/Regional Hub",
        "address": "400 Peachtree Center",
        "floors": 2,
        "timezone": "America/New_York",
        "employee_count": 43,
    },
    "AUS": {
        "name": "Austin",
        "full_name": "Austin Office",
        "state": "TX",
        "type": "Sales/Engineering Office",
        "address": "200 Congress Ave",
        "floors": 1,
        "timezone": "America/Chicago",
        "employee_count": 39,
    },
}

# =============================================================================
# NETWORK CONFIGURATION - PER LOCATION
# =============================================================================

# IP addressing scheme per location
NETWORK_CONFIG = {
    "BOS": {
        "prefix": "10.10",
        "management": "10.10.10.0/24",
        "servers": "10.10.20.0/24",
        "users_wired": "10.10.30.0/23",
        "users_wifi": "10.10.40.0/23",
        "voice": "10.10.50.0/24",
        "iot": "10.10.60.0/24",
        "cameras": "10.10.70.0/24",
        "guest": "10.10.80.0/24",
    },
    "ATL": {
        "prefix": "10.20",
        "management": "10.20.10.0/24",
        "servers": "10.20.20.0/24",
        "users_wired": "10.20.30.0/24",
        "users_wifi": "10.20.40.0/24",
        "voice": "10.20.50.0/24",
        "iot": "10.20.60.0/24",
        "cameras": "10.20.70.0/24",
        "guest": "10.20.80.0/24",
    },
    "AUS": {
        "prefix": "10.30",
        "management": "10.30.10.0/24",
        "servers": None,  # No local servers
        "users_wired": "10.30.30.0/24",
        "users_wifi": "10.30.40.0/24",
        "voice": "10.30.50.0/24",
        "iot": "10.30.60.0/24",
        "cameras": "10.30.70.0/24",
        "guest": "10.30.80.0/24",
    },
}

# Meraki Dashboard API Network IDs (per location)
NETWORK_IDS = {
    "BOS": "N_FakeTShirtCo_BOS",
    "ATL": "N_FakeTShirtCo_ATL",
    "AUS": "N_FakeTShirtCo_AUS",
}

# Legacy internal prefixes (for backward compatibility)
INT_PFX = ["10.10.30", "10.10.31", "10.20.30", "10.30.30"]

# DMZ network (Boston only)
DMZ_PFX = "172.16.1"

# Public IPs for web servers (NAT from DMZ)
WEB01_PUBLIC_IP = "203.0.113.10"
WEB02_PUBLIC_IP = "203.0.113.11"

# DNS servers
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]

# US-based residential IP prefixes (for remote workers)
US_IP_PFX = ["73.158.42", "107.77.195", "108.28.163", "174.63.88", "68.105.12", "71.222.45"]

# External service IPs
EXT_SERVICE_IPS = [
    "13.107.42.14",      # Microsoft 365
    "52.169.118.173",    # Azure
    "52.239.228.100",    # Azure Storage
    "140.82.121.4",      # GitHub
    "172.217.14.78",     # Google
    "54.239.28.85",      # AWS
    "35.186.224.25",     # GCP
]

# World IP pools for scan noise
WORLD_IP_PREFIXES = ["45.155", "37.19", "102.67", "103.21", "186.90", "91.231", "5.44"]

# =============================================================================
# CLOUD CONFIGURATION
# =============================================================================

# AWS
AWS_ACCOUNT_ID = "123456789012"
AWS_REGION = "us-east-1"
AWS_SECONDARY_REGION = "us-west-2"
AWS_BUCKET_SENSITIVE = "faketshirtcompany-finance-data"
AWS_BUCKET_BACKUP = "faketshirtcompany-backups-prod"

# GCP
GCP_PROJECT = "faketshirtcompany-prod-01"
GCP_REGION = "us-central1"
GCP_ZONE = "us-central1-a"
GCP_BUCKET_SENSITIVE = "faketshirtcompany-confidential-docs"

# =============================================================================
# THREAT ACTOR CONFIGURATION
# =============================================================================

THREAT_IP = "185.220.101.42"
THREAT_COUNTRY = "DE"
THREAT_COUNTRY_NAME = "Germany"
THREAT_CITY = "Frankfurt"
THREAT_ASN = "AS205100"
THREAT_ASN_NAME = "F3 Netze e.V."

# =============================================================================
# COMPROMISED USER (Primary Target) - Boston HQ, Floor 2
# =============================================================================

COMP_USER = "alex.miller"
COMP_USER_ID = "user-alex-miller-id"
COMP_DISPLAY = "Alex Miller"
COMP_EMAIL = f"{COMP_USER}@{TENANT}"
COMP_DEPARTMENT = "Finance"
COMP_TITLE = "Senior Financial Analyst"
COMP_WS_IP = "10.10.30.55"  # Boston, Floor 2
COMP_WS_HOSTNAME = "BOS-WS-AMILLER01"
COMP_WS_CITY = "Boston"
COMP_LOCATION = "BOS"
COMP_FLOOR = 2

# =============================================================================
# SECONDARY USER (Initial Compromise - IT Admin) - Atlanta Hub, Floor 1
# =============================================================================

LATERAL_USER = "jessica.brown"
LATERAL_USER_ID = "user-jessica-brown-id"
LATERAL_DISPLAY = "Jessica Brown"
LATERAL_EMAIL = f"{LATERAL_USER}@{TENANT}"
LATERAL_DEPARTMENT = "IT"
LATERAL_TITLE = "IT Administrator"
JESSICA_WS_IP = "10.20.30.15"  # Atlanta, Floor 1
JESSICA_WS_HOSTNAME = "ATL-WS-JBROWN01"
JESSICA_WS_CITY = "Atlanta"
JESSICA_LOCATION = "ATL"
JESSICA_FLOOR = 1
JESSICA_HOME_IP = "107.77.195.42"
JESSICA_DEVICE_ID = "device-jessica-001"

# =============================================================================
# PHISHING CONFIGURATION
# =============================================================================

PHISHING_DOMAIN = "rnicrosoft-security.com"
PHISHING_URL = f"https://{PHISHING_DOMAIN}/auth/login"
PHISHING_SENDER = f"security-alert@{PHISHING_DOMAIN}"
PHISHING_SUBJECT = "[Action Required] Verify your Microsoft 365 account"
PHISHING_MAIL_ID = "phish-msg-001"
MALICIOUS_APP_NAME = "Microsoft Security Verification"
MALICIOUS_APP_ID = "app-mal-12345678-abcd-1234-abcd-123456789abc"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class User:
    """Employee user record with location and device information."""
    username: str
    user_id: str
    display_name: str
    location: str           # BOS, ATL, AUS
    floor: int
    department: str
    title: str
    manager: str            # Manager's username
    vip: bool
    vpn_enabled: bool
    device_name: str        # e.g., BOS-WS-AMILLER01
    ip_address: str         # Static internal IP
    device_id: str
    home_ip_prefix: str     # For remote work

    @property
    def email(self) -> str:
        return f"{self.username}@{TENANT}"

    @property
    def city(self) -> str:
        return LOCATIONS[self.location]["name"]

    @property
    def country(self) -> str:
        return "US"

    def get_home_ip(self) -> str:
        """Get a random home IP for this user."""
        return f"{self.home_ip_prefix}.{random.randint(1, 254)}"

    def get_ip(self) -> str:
        """Get the user's office IP address."""
        return self.ip_address


@dataclass
class Server:
    """Server record with location and baseline metrics."""
    hostname: str
    location: str           # BOS, ATL
    os: str
    role: str
    ip: str
    cpu_baseline_min: int
    cpu_baseline_max: int
    ram_baseline_min: int
    ram_baseline_max: int


# =============================================================================
# USER DATABASE - 175 EMPLOYEES
# =============================================================================

# Format: username -> (user_id, display_name, location, floor, department, title, manager, vip, vpn, device_name, ip_address, device_id, home_ip_prefix)

_USER_DATA = {
    # ==========================================================================
    # BOSTON HQ - FLOOR 3: EXECUTIVE (6)
    # ==========================================================================
    "john.smith": ("user-john-smith-id", "John Smith", "BOS", 3, "Executive", "CEO", None, True, True, "BOS-WS-JSMITH01", "10.10.30.10", "device-jsmith-001", "73.158.42"),
    "sarah.wilson": ("user-sarah-wilson-id", "Sarah Wilson", "BOS", 3, "Executive", "CFO", "john.smith", True, True, "BOS-WS-SWILSON01", "10.10.30.11", "device-swilson-001", "108.28.163"),
    "mike.johnson": ("user-mike-johnson-id", "Mike Johnson", "BOS", 3, "Executive", "CTO", "john.smith", True, True, "BOS-WS-MJOHNSON01", "10.10.30.12", "device-mjohnson-001", "174.63.88"),
    "jennifer.davis": ("user-jennifer-davis-id", "Jennifer Davis", "BOS", 3, "Executive", "COO", "john.smith", True, True, "BOS-WS-JDAVIS01", "10.10.30.13", "device-jdavis-001", "68.105.12"),
    "richard.chen": ("user-richard-chen-id", "Richard Chen", "BOS", 3, "Executive", "VP Engineering", "mike.johnson", True, True, "BOS-WS-RCHEN01", "10.10.30.14", "device-rchen-001", "71.222.45"),
    "margaret.taylor": ("user-margaret-taylor-id", "Margaret Taylor", "BOS", 3, "Executive", "VP Sales", "john.smith", True, True, "BOS-WS-MTAYLOR01", "10.10.30.15", "device-mtaylor-001", "107.77.195"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 2: FINANCE (22)
    # ==========================================================================
    "robert.wilson": ("user-robert-wilson-id", "Robert Wilson", "BOS", 2, "Finance", "Finance Director", "sarah.wilson", True, True, "BOS-WS-RWILSON01", "10.10.30.50", "device-rwilson-001", "73.158.42"),
    "alex.miller": ("user-alex-miller-id", "Alex Miller", "BOS", 2, "Finance", "Senior Financial Analyst", "robert.wilson", False, True, "BOS-WS-AMILLER01", "10.10.30.55", "device-alex-001", "108.28.163"),
    "michael.lewis": ("user-michael-lewis-id", "Michael Lewis", "BOS", 2, "Finance", "Financial Analyst", "robert.wilson", False, True, "BOS-WS-MLEWIS01", "10.10.30.56", "device-michael-001", "174.63.88"),
    "lucy.rogers": ("user-lucy-rogers-id", "Lucy Rogers", "BOS", 2, "Finance", "Financial Analyst", "robert.wilson", False, True, "BOS-WS-LROGERS01", "10.10.30.57", "device-lucy-001", "108.28.163"),
    "ella.white": ("user-ella-white-id", "Ella White", "BOS", 2, "Finance", "Senior Accountant", "robert.wilson", False, True, "BOS-WS-EWHITE01", "10.10.30.58", "device-ella-001", "174.63.88"),
    "zoey.edwards": ("user-zoey-edwards-id", "Zoey Edwards", "BOS", 2, "Finance", "Accountant", "robert.wilson", False, False, "BOS-WS-ZEDWARDS01", "10.10.30.59", "device-zoey-e-001", "68.105.12"),
    "zara.brooks": ("user-zara-brooks-id", "Zara Brooks", "BOS", 2, "Finance", "Accountant", "robert.wilson", False, False, "BOS-WS-ZBROOKS01", "10.10.30.60", "device-zara-001", "68.105.12"),
    "daniel.garcia": ("user-daniel-garcia-id", "Daniel Garcia", "BOS", 2, "Finance", "Financial Analyst", "robert.wilson", False, True, "BOS-WS-DGARCIA01", "10.10.30.61", "device-dgarcia-001", "71.222.45"),
    "emma.martinez": ("user-emma-martinez-id", "Emma Martinez", "BOS", 2, "Finance", "AP Specialist", "robert.wilson", False, False, "BOS-WS-EMARTINEZ01", "10.10.30.62", "device-emartinez-001", "73.158.42"),
    "james.anderson": ("user-james-anderson-id", "James Anderson", "BOS", 2, "Finance", "AR Specialist", "robert.wilson", False, False, "BOS-WS-JANDERSON01", "10.10.30.63", "device-janderson-001", "107.77.195"),
    "olivia.thomas": ("user-olivia-thomas-id", "Olivia Thomas", "BOS", 2, "Finance", "Tax Analyst", "robert.wilson", False, True, "BOS-WS-OTHOMAS01", "10.10.30.64", "device-othomas-001", "108.28.163"),
    "william.jackson": ("user-william-jackson-id", "William Jackson", "BOS", 2, "Finance", "Budget Analyst", "robert.wilson", False, False, "BOS-WS-WJACKSON01", "10.10.30.65", "device-wjackson-001", "174.63.88"),
    "sophia.harris": ("user-sophia-harris-id", "Sophia Harris", "BOS", 2, "Finance", "Payroll Specialist", "robert.wilson", False, False, "BOS-WS-SHARRIS01", "10.10.30.66", "device-sharris-001", "68.105.12"),
    "benjamin.clark": ("user-benjamin-clark-id", "Benjamin Clark", "BOS", 2, "Finance", "Financial Analyst", "robert.wilson", False, True, "BOS-WS-BCLARK01", "10.10.30.67", "device-bclark-001", "71.222.45"),
    "isabella.rodriguez": ("user-isabella-rodriguez-id", "Isabella Rodriguez", "BOS", 2, "Finance", "Accountant", "robert.wilson", False, False, "BOS-WS-IRODRIGUEZ01", "10.10.30.68", "device-irodriguez-001", "73.158.42"),
    "mason.lee": ("user-mason-lee-id", "Mason Lee", "BOS", 2, "Finance", "Financial Analyst", "robert.wilson", False, True, "BOS-WS-MLEE01", "10.10.30.69", "device-mlee-001", "107.77.195"),
    "mia.walker": ("user-mia-walker-id", "Mia Walker", "BOS", 2, "Finance", "Treasury Analyst", "robert.wilson", False, True, "BOS-WS-MWALKER01", "10.10.30.70", "device-mwalker-001", "108.28.163"),
    "ethan.hall": ("user-ethan-hall-id", "Ethan Hall", "BOS", 2, "Finance", "FP&A Analyst", "robert.wilson", False, False, "BOS-WS-EHALL01", "10.10.30.71", "device-ehall-001", "174.63.88"),
    "charlotte.young": ("user-charlotte-young-id", "Charlotte Young", "BOS", 2, "Finance", "Accountant", "robert.wilson", False, False, "BOS-WS-CYOUNG01", "10.10.30.72", "device-cyoung-001", "68.105.12"),
    "alexander.king": ("user-alexander-king-id", "Alexander King", "BOS", 2, "Finance", "Senior Accountant", "robert.wilson", False, True, "BOS-WS-AKING01", "10.10.30.73", "device-aking-001", "71.222.45"),
    "amelia.wright": ("user-amelia-wright-id", "Amelia Wright", "BOS", 2, "Finance", "Billing Specialist", "robert.wilson", False, False, "BOS-WS-AWRIGHT01", "10.10.30.74", "device-awright-001", "73.158.42"),
    "henry.scott": ("user-henry-scott-id", "Henry Scott", "BOS", 2, "Finance", "Financial Analyst", "robert.wilson", False, True, "BOS-WS-HSCOTT01", "10.10.30.75", "device-hscott-001", "107.77.195"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 2: MARKETING (12)
    # ==========================================================================
    "olivia.moore": ("user-olivia-moore-id", "Olivia Moore", "BOS", 2, "Marketing", "Marketing Director", "jennifer.davis", True, True, "BOS-WS-OMOORE01", "10.10.30.100", "device-olivia-001", "68.105.12"),
    "skylar.johnson": ("user-skylar-johnson-id", "Skylar Johnson", "BOS", 2, "Marketing", "Brand Manager", "olivia.moore", False, True, "BOS-WS-SJOHNSON01", "10.10.30.101", "device-skylar-001", "108.28.163"),
    "scarlett.nelson": ("user-scarlett-nelson-id", "Scarlett Nelson", "BOS", 2, "Marketing", "Content Manager", "olivia.moore", False, True, "BOS-WS-SNELSON01", "10.10.30.102", "device-scarlett-001", "174.63.88"),
    "hazel.brown": ("user-hazel-brown-id", "Hazel Brown", "BOS", 2, "Marketing", "Social Media Manager", "olivia.moore", False, False, "BOS-WS-HBROWN01", "10.10.30.103", "device-hazel-001", "108.28.163"),
    "laura.bell": ("user-laura-bell-id", "Laura Bell", "BOS", 2, "Marketing", "Marketing Coordinator", "olivia.moore", False, False, "BOS-WS-LBELL01", "10.10.30.104", "device-laura-001", "71.222.45"),
    "victoria.adams": ("user-victoria-adams-id", "Victoria Adams", "BOS", 2, "Marketing", "Digital Marketing Specialist", "olivia.moore", False, True, "BOS-WS-VADAMS01", "10.10.30.105", "device-vadams-001", "73.158.42"),
    "nathan.baker": ("user-nathan-baker-id", "Nathan Baker", "BOS", 2, "Marketing", "Graphic Designer", "olivia.moore", False, False, "BOS-WS-NBAKER01", "10.10.30.106", "device-nbaker-001", "107.77.195"),
    "grace.carter": ("user-grace-carter-id", "Grace Carter", "BOS", 2, "Marketing", "SEO Specialist", "olivia.moore", False, True, "BOS-WS-GCARTER01", "10.10.30.107", "device-gcarter-001", "108.28.163"),
    "dylan.evans": ("user-dylan-evans-id", "Dylan Evans", "BOS", 2, "Marketing", "Email Marketing Specialist", "olivia.moore", False, False, "BOS-WS-DEVANS01", "10.10.30.108", "device-devans-001", "174.63.88"),
    "lily.foster": ("user-lily-foster-id", "Lily Foster", "BOS", 2, "Marketing", "Marketing Analyst", "olivia.moore", False, True, "BOS-WS-LFOSTER01", "10.10.30.109", "device-lfoster-001", "68.105.12"),
    "ryan.green": ("user-ryan-green-id", "Ryan Green", "BOS", 2, "Marketing", "Product Marketing Manager", "olivia.moore", False, True, "BOS-WS-RGREEN01", "10.10.30.110", "device-rgreen-001", "71.222.45"),
    "chloe.hill": ("user-chloe-hill-id", "Chloe Hill", "BOS", 2, "Marketing", "Creative Designer", "olivia.moore", False, False, "BOS-WS-CHILL01", "10.10.30.111", "device-chill-001", "73.158.42"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 2: HR (6)
    # ==========================================================================
    "aria.ramirez": ("user-aria-ramirez-id", "Aria Ramirez", "BOS", 2, "HR", "HR Director", "jennifer.davis", True, True, "BOS-WS-ARAMIREZ01", "10.10.31.10", "device-aria-001", "108.28.163"),
    "zoe.reed": ("user-zoe-reed-id", "Zoe Reed", "BOS", 2, "HR", "HR Manager", "aria.ramirez", False, True, "BOS-WS-ZREED01", "10.10.31.11", "device-zoe-001", "108.28.163"),
    "claire.torres": ("user-claire-torres-id", "Claire Torres", "BOS", 2, "HR", "Recruiter", "aria.ramirez", False, False, "BOS-WS-CTORRES01", "10.10.31.12", "device-claire-t-001", "68.105.12"),
    "sarah.morris": ("user-sarah-morris-id", "Sarah Morris", "BOS", 2, "HR", "Benefits Coordinator", "aria.ramirez", False, False, "BOS-WS-SMORRIS01", "10.10.31.13", "device-sarah-001", "71.222.45"),
    "logan.price": ("user-logan-price-id", "Logan Price", "BOS", 2, "HR", "HR Specialist", "aria.ramirez", False, True, "BOS-WS-LPRICE01", "10.10.31.14", "device-lprice-001", "73.158.42"),
    "madison.quinn": ("user-madison-quinn-id", "Madison Quinn", "BOS", 2, "HR", "Recruiter", "aria.ramirez", False, False, "BOS-WS-MQUINN01", "10.10.31.15", "device-mquinn-001", "107.77.195"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 3: ENGINEERING (20)
    # ==========================================================================
    "nicholas.lewis": ("user-nicholas-lewis-id", "Nicholas Lewis", "BOS", 3, "Engineering", "Engineering Manager", "richard.chen", False, True, "BOS-WS-NLEWIS01", "10.10.30.150", "device-nicholas-001", "107.77.195"),
    "amelia.phillips": ("user-amelia-phillips-id", "Amelia Phillips", "BOS", 3, "Engineering", "Senior Software Engineer", "nicholas.lewis", False, True, "BOS-WS-APHILLIPS01", "10.10.30.151", "device-amelia-001", "174.63.88"),
    "nathan.hall": ("user-nathan-hall-id", "Nathan Hall", "BOS", 3, "Engineering", "Senior Software Engineer", "nicholas.lewis", False, True, "BOS-WS-NHALL01", "10.10.30.152", "device-nathan-001", "107.77.195"),
    "charles.nguyen": ("user-charles-nguyen-id", "Charles Nguyen", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-CNGUYEN01", "10.10.30.153", "device-charles-001", "108.28.163"),
    "justin.howard": ("user-justin-howard-id", "Justin Howard", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-JHOWARD01", "10.10.30.154", "device-justin-001", "68.105.12"),
    "noah.kelly": ("user-noah-kelly-id", "Noah Kelly", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-NKELLY01", "10.10.30.155", "device-noah-001", "73.158.42"),
    "joseph.anderson": ("user-joseph-anderson-id", "Joseph Anderson", "BOS", 3, "Engineering", "Backend Developer", "nicholas.lewis", False, True, "BOS-WS-JANDERSON02", "10.10.30.156", "device-joseph-001", "108.28.163"),
    "andrew.ross": ("user-andrew-ross-id", "Andrew Ross", "BOS", 3, "Engineering", "Frontend Developer", "nicholas.lewis", False, True, "BOS-WS-AROSS01", "10.10.30.157", "device-aross-001", "174.63.88"),
    "emily.stewart": ("user-emily-stewart-id", "Emily Stewart", "BOS", 3, "Engineering", "Full Stack Developer", "nicholas.lewis", False, True, "BOS-WS-ESTEWART01", "10.10.30.158", "device-estewart-001", "68.105.12"),
    "brandon.turner": ("user-brandon-turner-id", "Brandon Turner", "BOS", 3, "Engineering", "DevOps Engineer", "nicholas.lewis", False, True, "BOS-WS-BTURNER01", "10.10.30.159", "device-bturner-001", "71.222.45"),
    "samantha.edwards": ("user-samantha-edwards-id", "Samantha Edwards", "BOS", 3, "Engineering", "QA Engineer", "nicholas.lewis", False, True, "BOS-WS-SEDWARDS01", "10.10.30.160", "device-sedwards-001", "73.158.42"),
    "kevin.murphy": ("user-kevin-murphy-id", "Kevin Murphy", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-KMURPHY01", "10.10.30.161", "device-kmurphy-001", "107.77.195"),
    "rachel.perry": ("user-rachel-perry-id", "Rachel Perry", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-RPERRY01", "10.10.30.162", "device-rperry-001", "108.28.163"),
    "tyler.brooks": ("user-tyler-brooks-id", "Tyler Brooks", "BOS", 3, "Engineering", "Platform Engineer", "nicholas.lewis", False, True, "BOS-WS-TBROOKS01", "10.10.30.163", "device-tbrooks-001", "174.63.88"),
    "hannah.sanders": ("user-hannah-sanders-id", "Hannah Sanders", "BOS", 3, "Engineering", "Data Engineer", "nicholas.lewis", False, True, "BOS-WS-HSANDERS01", "10.10.30.164", "device-hsanders-001", "68.105.12"),
    "adam.powell": ("user-adam-powell-id", "Adam Powell", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-APOWELL01", "10.10.30.165", "device-apowell-001", "71.222.45"),
    "jessica.long": ("user-jessica-long-id", "Jessica Long", "BOS", 3, "Engineering", "Software Engineer", "nicholas.lewis", False, True, "BOS-WS-JLONG01", "10.10.30.166", "device-jlong-001", "73.158.42"),
    "chris.russell": ("user-chris-russell-id", "Chris Russell", "BOS", 3, "Engineering", "Site Reliability Engineer", "nicholas.lewis", False, True, "BOS-WS-CRUSSELL01", "10.10.30.167", "device-crussell-001", "107.77.195"),
    "ashley.griffin": ("user-ashley-griffin-id", "Ashley Griffin", "BOS", 3, "Engineering", "Security Engineer", "nicholas.lewis", False, True, "BOS-WS-AGRIFFIN01", "10.10.30.168", "device-agriffin-001", "108.28.163"),
    "matthew.wood": ("user-matthew-wood-id", "Matthew Wood", "BOS", 3, "Engineering", "Technical Lead", "nicholas.lewis", False, True, "BOS-WS-MWOOD01", "10.10.30.169", "device-mwood-001", "174.63.88"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 3: LEGAL (6)
    # ==========================================================================
    "claire.roberts": ("user-claire-roberts-id", "Claire Roberts", "BOS", 3, "Legal", "General Counsel", "john.smith", True, True, "BOS-WS-CROBERTS01", "10.10.31.50", "device-claire-001", "68.105.12"),
    "scarlett.peterson": ("user-scarlett-peterson-id", "Scarlett Peterson", "BOS", 3, "Legal", "Senior Legal Counsel", "claire.roberts", False, True, "BOS-WS-SPETERSON01", "10.10.31.51", "device-scarlett-p-001", "71.222.45"),
    "grace.cox": ("user-grace-cox-id", "Grace Cox", "BOS", 3, "Legal", "Corporate Counsel", "claire.roberts", False, True, "BOS-WS-GCOX01", "10.10.31.52", "device-grace-001", "71.222.45"),
    "diana.hughes": ("user-diana-hughes-id", "Diana Hughes", "BOS", 3, "Legal", "Contracts Manager", "claire.roberts", False, True, "BOS-WS-DHUGHES01", "10.10.31.53", "device-dhughes-001", "73.158.42"),
    "peter.bryant": ("user-peter-bryant-id", "Peter Bryant", "BOS", 3, "Legal", "Compliance Officer", "claire.roberts", False, True, "BOS-WS-PBRYANT01", "10.10.31.54", "device-pbryant-001", "107.77.195"),
    "monica.foster": ("user-monica-foster-id", "Monica Foster", "BOS", 3, "Legal", "Legal Assistant", "claire.roberts", False, False, "BOS-WS-MFOSTER01", "10.10.31.55", "device-mfoster-001", "108.28.163"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 3: IT (8)
    # ==========================================================================
    "david.robinson": ("user-david-robinson-id", "David Robinson", "BOS", 3, "IT", "IT Director", "mike.johnson", True, True, "BOS-WS-DROBINSON01", "10.10.30.180", "device-david-001", "68.105.12"),
    "christian.walker": ("user-christian-walker-id", "Christian Walker", "BOS", 3, "IT", "IT Manager", "david.robinson", False, True, "BOS-WS-CWALKER01", "10.10.30.181", "device-christian-001", "68.105.12"),
    "patrick.gonzalez": ("user-patrick-gonzalez-id", "Patrick Gonzalez", "BOS", 3, "IT", "Systems Administrator", "christian.walker", False, True, "BOS-WS-PGONZALEZ01", "10.10.30.182", "device-patrick-001", "107.77.195"),
    "stephanie.barnes": ("user-stephanie-barnes-id", "Stephanie Barnes", "BOS", 3, "IT", "Network Administrator", "christian.walker", False, True, "BOS-WS-SBARNES01", "10.10.30.183", "device-sbarnes-001", "73.158.42"),
    "marcus.rivera": ("user-marcus-rivera-id", "Marcus Rivera", "BOS", 3, "IT", "Help Desk Lead", "christian.walker", False, True, "BOS-WS-MRIVERA01", "10.10.30.184", "device-mrivera-001", "108.28.163"),
    "jennifer.cooper": ("user-jennifer-cooper-id", "Jennifer Cooper", "BOS", 3, "IT", "IT Support Specialist", "marcus.rivera", False, False, "BOS-WS-JCOOPER01", "10.10.30.185", "device-jcooper-001", "174.63.88"),
    "brian.reed": ("user-brian-reed-id", "Brian Reed", "BOS", 3, "IT", "IT Support Specialist", "marcus.rivera", False, False, "BOS-WS-BREED01", "10.10.30.186", "device-breed-001", "68.105.12"),
    "nicole.simmons": ("user-nicole-simmons-id", "Nicole Simmons", "BOS", 3, "IT", "Security Analyst", "david.robinson", False, True, "BOS-WS-NSIMMONS01", "10.10.30.187", "device-nsimmons-001", "71.222.45"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 1: OPERATIONS (5)
    # ==========================================================================
    "frank.mitchell": ("user-frank-mitchell-id", "Frank Mitchell", "BOS", 1, "Operations", "Operations Director", "jennifer.davis", True, True, "BOS-WS-FMITCHELL01", "10.10.31.80", "device-fmitchell-001", "73.158.42"),
    "linda.perez": ("user-linda-perez-id", "Linda Perez", "BOS", 1, "Operations", "Operations Manager", "frank.mitchell", False, True, "BOS-WS-LPEREZ01", "10.10.31.81", "device-lperez-001", "107.77.195"),
    "gary.roberts": ("user-gary-roberts-id", "Gary Roberts", "BOS", 1, "Operations", "Fulfillment Lead", "linda.perez", False, False, "BOS-WS-GROBERTS01", "10.10.31.82", "device-groberts-001", "108.28.163"),
    "teresa.sanchez": ("user-teresa-sanchez-id", "Teresa Sanchez", "BOS", 1, "Operations", "Warehouse Coordinator", "linda.perez", False, False, "BOS-WS-TSANCHEZ01", "10.10.31.83", "device-tsanchez-001", "174.63.88"),
    "raymond.cook": ("user-raymond-cook-id", "Raymond Cook", "BOS", 1, "Operations", "Shipping Specialist", "linda.perez", False, False, "BOS-WS-RCOOK01", "10.10.31.84", "device-rcook-001", "68.105.12"),

    # ==========================================================================
    # BOSTON HQ - FLOOR 2/3: SALES (8)
    # ==========================================================================
    "matthew.hall": ("user-matthew-hall-id", "Matthew Hall", "BOS", 2, "Sales", "Enterprise Sales Director", "margaret.taylor", True, True, "BOS-WS-MHALL01", "10.10.30.200", "device-matthew-001", "174.63.88"),
    "harper.murphy": ("user-harper-murphy-id", "Harper Murphy", "BOS", 2, "Sales", "Account Executive", "matthew.hall", False, True, "BOS-WS-HMURPHY01", "10.10.30.201", "device-harper-001", "73.158.42"),
    "ava.bell": ("user-ava-bell-id", "Ava Bell", "BOS", 2, "Sales", "Account Executive", "matthew.hall", False, True, "BOS-WS-ABELL01", "10.10.30.202", "device-ava-001", "174.63.88"),
    "noah.reed": ("user-noah-reed-id", "Noah Reed", "BOS", 2, "Sales", "Sales Development Rep", "matthew.hall", False, False, "BOS-WS-NREED01", "10.10.30.203", "device-noah-r-001", "108.28.163"),
    "scott.morgan": ("user-scott-morgan-id", "Scott Morgan", "BOS", 2, "Sales", "Account Manager", "matthew.hall", False, True, "BOS-WS-SMORGAN01", "10.10.30.204", "device-smorgan-001", "68.105.12"),
    "amanda.blake": ("user-amanda-blake-id", "Amanda Blake", "BOS", 2, "Sales", "Sales Development Rep", "matthew.hall", False, False, "BOS-WS-ABLAKE01", "10.10.30.205", "device-ablake-001", "71.222.45"),
    "derek.stone": ("user-derek-stone-id", "Derek Stone", "BOS", 2, "Sales", "Account Executive", "matthew.hall", False, True, "BOS-WS-DSTONE01", "10.10.30.206", "device-dstone-001", "73.158.42"),
    "melissa.grant": ("user-melissa-grant-id", "Melissa Grant", "BOS", 2, "Sales", "Sales Operations", "matthew.hall", False, False, "BOS-WS-MGRANT01", "10.10.30.207", "device-mgrant-001", "107.77.195"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 1: IT (15)
    # ==========================================================================
    "jessica.brown": ("user-jessica-brown-id", "Jessica Brown", "ATL", 1, "IT", "IT Administrator", "david.robinson", False, True, "ATL-WS-JBROWN01", "10.20.30.15", "device-jessica-001", "107.77.195"),
    "nicholas.kelly": ("user-nicholas-kelly-id", "Nicholas Kelly", "ATL", 1, "IT", "Senior Systems Administrator", "jessica.brown", False, True, "ATL-WS-NKELLY02", "10.20.30.16", "device-nicholas-k-001", "108.28.163"),
    "samuel.wright": ("user-samuel-wright-id", "Samuel Wright", "ATL", 1, "IT", "IT Security Analyst", "jessica.brown", False, True, "ATL-WS-SWRIGHT01", "10.20.30.17", "device-samuel-001", "174.63.88"),
    "keith.butler": ("user-keith-butler-id", "Keith Butler", "ATL", 1, "IT", "Network Engineer", "jessica.brown", False, True, "ATL-WS-KBUTLER01", "10.20.30.18", "device-kbutler-001", "68.105.12"),
    "michelle.ward": ("user-michelle-ward-id", "Michelle Ward", "ATL", 1, "IT", "Systems Administrator", "jessica.brown", False, True, "ATL-WS-MWARD01", "10.20.30.19", "device-mward-001", "71.222.45"),
    "steve.jackson": ("user-steve-jackson-id", "Steve Jackson", "ATL", 1, "IT", "Database Administrator", "jessica.brown", False, True, "ATL-WS-SJACKSON01", "10.20.30.20", "device-sjackson-001", "73.158.42"),
    "tiffany.lopez": ("user-tiffany-lopez-id", "Tiffany Lopez", "ATL", 1, "IT", "IT Support Specialist", "jessica.brown", False, False, "ATL-WS-TLOPEZ01", "10.20.30.21", "device-tlopez-001", "107.77.195"),
    "jerome.washington": ("user-jerome-washington-id", "Jerome Washington", "ATL", 1, "IT", "IT Support Specialist", "jessica.brown", False, False, "ATL-WS-JWASHINGTON01", "10.20.30.22", "device-jwashington-001", "108.28.163"),
    "angela.james": ("user-angela-james-id", "Angela James", "ATL", 1, "IT", "Cloud Engineer", "jessica.brown", False, True, "ATL-WS-AJAMES01", "10.20.30.23", "device-ajames-001", "174.63.88"),
    "carlos.martinez": ("user-carlos-martinez-id", "Carlos Martinez", "ATL", 1, "IT", "DevOps Engineer", "jessica.brown", False, True, "ATL-WS-CMARTINEZ01", "10.20.30.24", "device-cmartinez-001", "68.105.12"),
    "yolanda.henderson": ("user-yolanda-henderson-id", "Yolanda Henderson", "ATL", 1, "IT", "IT Trainer", "jessica.brown", False, False, "ATL-WS-YHENDERSON01", "10.20.30.25", "device-yhenderson-001", "71.222.45"),
    "derek.coleman": ("user-derek-coleman-id", "Derek Coleman", "ATL", 1, "IT", "Backup Administrator", "jessica.brown", False, True, "ATL-WS-DCOLEMAN01", "10.20.30.26", "device-dcoleman-001", "73.158.42"),
    "tonya.russell": ("user-tonya-russell-id", "Tonya Russell", "ATL", 1, "IT", "Systems Administrator", "jessica.brown", False, True, "ATL-WS-TRUSSELL01", "10.20.30.27", "device-trussell-001", "107.77.195"),
    "marcus.williams": ("user-marcus-williams-id", "Marcus Williams", "ATL", 1, "IT", "NOC Analyst", "jessica.brown", False, True, "ATL-WS-MWILLIAMS01", "10.20.30.28", "device-mwilliams-001", "108.28.163"),
    "latoya.brown": ("user-latoya-brown-id", "Latoya Brown", "ATL", 1, "IT", "NOC Analyst", "jessica.brown", False, True, "ATL-WS-LBROWN01", "10.20.30.29", "device-lbrown-001", "174.63.88"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: ENGINEERING (8)
    # ==========================================================================
    "darren.hayes": ("user-darren-hayes-id", "Darren Hayes", "ATL", 2, "Engineering", "Engineering Manager", "richard.chen", False, True, "ATL-WS-DHAYES01", "10.20.30.50", "device-dhayes-001", "68.105.12"),
    "crystal.price": ("user-crystal-price-id", "Crystal Price", "ATL", 2, "Engineering", "Senior Software Engineer", "darren.hayes", False, True, "ATL-WS-CPRICE01", "10.20.30.51", "device-cprice-001", "71.222.45"),
    "jamal.thomas": ("user-jamal-thomas-id", "Jamal Thomas", "ATL", 2, "Engineering", "Software Engineer", "darren.hayes", False, True, "ATL-WS-JTHOMAS01", "10.20.30.52", "device-jthomas-001", "73.158.42"),
    "whitney.morris": ("user-whitney-morris-id", "Whitney Morris", "ATL", 2, "Engineering", "Software Engineer", "darren.hayes", False, True, "ATL-WS-WMORRIS01", "10.20.30.53", "device-wmorris-001", "107.77.195"),
    "terrance.jackson": ("user-terrance-jackson-id", "Terrance Jackson", "ATL", 2, "Engineering", "Software Engineer", "darren.hayes", False, True, "ATL-WS-TJACKSON01", "10.20.30.54", "device-tjackson-001", "108.28.163"),
    "nicole.harris": ("user-nicole-harris-id", "Nicole Harris", "ATL", 2, "Engineering", "QA Engineer", "darren.hayes", False, True, "ATL-WS-NHARRIS01", "10.20.30.55", "device-nharris-001", "174.63.88"),
    "brandon.robinson": ("user-brandon-robinson-id", "Brandon Robinson", "ATL", 2, "Engineering", "Software Engineer", "darren.hayes", False, True, "ATL-WS-BROBINSON01", "10.20.30.56", "device-brobinson-001", "68.105.12"),
    "jasmine.carter": ("user-jasmine-carter-id", "Jasmine Carter", "ATL", 2, "Engineering", "Software Engineer", "darren.hayes", False, True, "ATL-WS-JCARTER01", "10.20.30.57", "device-jcarter-001", "71.222.45"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: SALES (5)
    # ==========================================================================
    "dewayne.johnson": ("user-dewayne-johnson-id", "DeWayne Johnson", "ATL", 2, "Sales", "Regional Sales Manager", "margaret.taylor", False, True, "ATL-WS-DJOHNSON01", "10.20.30.70", "device-djohnson-001", "73.158.42"),
    "patricia.woods": ("user-patricia-woods-id", "Patricia Woods", "ATL", 2, "Sales", "Account Executive", "dewayne.johnson", False, True, "ATL-WS-PWOODS01", "10.20.30.71", "device-pwoods-001", "107.77.195"),
    "rodney.allen": ("user-rodney-allen-id", "Rodney Allen", "ATL", 2, "Sales", "Account Executive", "dewayne.johnson", False, True, "ATL-WS-RALLEN01", "10.20.30.72", "device-rallen-001", "108.28.163"),
    "tanisha.brooks": ("user-tanisha-brooks-id", "Tanisha Brooks", "ATL", 2, "Sales", "Sales Development Rep", "dewayne.johnson", False, False, "ATL-WS-TBROOKS01", "10.20.30.73", "device-tabrooks-001", "174.63.88"),
    "calvin.mitchell": ("user-calvin-mitchell-id", "Calvin Mitchell", "ATL", 2, "Sales", "Sales Development Rep", "dewayne.johnson", False, False, "ATL-WS-CMITCHELL01", "10.20.30.74", "device-cmitchell-001", "68.105.12"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: MARKETING (5)
    # ==========================================================================
    "keisha.washington": ("user-keisha-washington-id", "Keisha Washington", "ATL", 2, "Marketing", "Marketing Manager", "olivia.moore", False, True, "ATL-WS-KWASHINGTON01", "10.20.30.80", "device-kwashington-001", "71.222.45"),
    "anthony.davis": ("user-anthony-davis-id", "Anthony Davis", "ATL", 2, "Marketing", "Content Specialist", "keisha.washington", False, True, "ATL-WS-ADAVIS01", "10.20.30.81", "device-adavis-001", "73.158.42"),
    "desiree.moore": ("user-desiree-moore-id", "Desiree Moore", "ATL", 2, "Marketing", "Social Media Coordinator", "keisha.washington", False, False, "ATL-WS-DMOORE01", "10.20.30.82", "device-dmoore-001", "107.77.195"),
    "corey.parker": ("user-corey-parker-id", "Corey Parker", "ATL", 2, "Marketing", "Graphic Designer", "keisha.washington", False, False, "ATL-WS-CPARKER01", "10.20.30.83", "device-cparker-001", "108.28.163"),
    "ebony.jenkins": ("user-ebony-jenkins-id", "Ebony Jenkins", "ATL", 2, "Marketing", "Marketing Coordinator", "keisha.washington", False, False, "ATL-WS-EJENKINS01", "10.20.30.84", "device-ejenkins-001", "174.63.88"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: HR (3)
    # ==========================================================================
    "jacqueline.taylor": ("user-jacqueline-taylor-id", "Jacqueline Taylor", "ATL", 2, "HR", "HR Manager", "aria.ramirez", False, True, "ATL-WS-JTAYLOR01", "10.20.30.90", "device-jtaylor-001", "68.105.12"),
    "reginald.harris": ("user-reginald-harris-id", "Reginald Harris", "ATL", 2, "HR", "Recruiter", "jacqueline.taylor", False, False, "ATL-WS-RHARRIS01", "10.20.30.91", "device-rharris-001", "71.222.45"),
    "monique.wright": ("user-monique-wright-id", "Monique Wright", "ATL", 2, "HR", "HR Coordinator", "jacqueline.taylor", False, False, "ATL-WS-MWRIGHT01", "10.20.30.92", "device-mwright-001", "73.158.42"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: OPERATIONS (3)
    # ==========================================================================
    "tyrone.allen": ("user-tyrone-allen-id", "Tyrone Allen", "ATL", 2, "Operations", "Operations Manager", "frank.mitchell", False, True, "ATL-WS-TALLEN01", "10.20.30.95", "device-tallen-001", "107.77.195"),
    "sandra.lewis": ("user-sandra-lewis-id", "Sandra Lewis", "ATL", 2, "Operations", "Operations Coordinator", "tyrone.allen", False, False, "ATL-WS-SLEWIS01", "10.20.30.96", "device-slewis-001", "108.28.163"),
    "maurice.johnson": ("user-maurice-johnson-id", "Maurice Johnson", "ATL", 2, "Operations", "Logistics Specialist", "tyrone.allen", False, False, "ATL-WS-MJOHNSON02", "10.20.30.97", "device-majohnson-001", "174.63.88"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: LEGAL (2)
    # ==========================================================================
    "tanya.williams": ("user-tanya-williams-id", "Tanya Williams", "ATL", 2, "Legal", "Corporate Counsel", "claire.roberts", False, True, "ATL-WS-TWILLIAMS01", "10.20.30.98", "device-twilliams-001", "68.105.12"),
    "marcus.green": ("user-marcus-green-id", "Marcus Green", "ATL", 2, "Legal", "Contracts Specialist", "tanya.williams", False, False, "ATL-WS-MGREEN01", "10.20.30.99", "device-mgreen-001", "71.222.45"),

    # ==========================================================================
    # ATLANTA HUB - FLOOR 2: FINANCE (2)
    # ==========================================================================
    "vanessa.hill": ("user-vanessa-hill-id", "Vanessa Hill", "ATL", 2, "Finance", "Senior Accountant", "robert.wilson", False, True, "ATL-WS-VHILL01", "10.20.30.100", "device-vhill-001", "73.158.42"),
    "cedric.jones": ("user-cedric-jones-id", "Cedric Jones", "ATL", 2, "Finance", "Accountant", "vanessa.hill", False, False, "ATL-WS-CJONES01", "10.20.30.101", "device-cjones-001", "107.77.195"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: SALES (15)
    # ==========================================================================
    "zoey.collins": ("user-zoey-collins-id", "Zoey Collins", "AUS", 1, "Sales", "Sales Manager", "margaret.taylor", False, True, "AUS-WS-ZCOLLINS01", "10.30.30.10", "device-zoey-001", "73.158.42"),
    "taylor.campbell": ("user-taylor-campbell-id", "Taylor Campbell", "AUS", 1, "Sales", "Regional Sales Director", "margaret.taylor", True, True, "AUS-WS-TCAMPBELL01", "10.30.30.11", "device-taylor-001", "71.222.45"),
    "zoey.young": ("user-zoey-young-id", "Zoey Young", "AUS", 1, "Sales", "Account Executive", "zoey.collins", False, True, "AUS-WS-ZYOUNG01", "10.30.30.12", "device-zoey-y-001", "71.222.45"),
    "austin.miller": ("user-austin-miller-id", "Austin Miller", "AUS", 1, "Sales", "Account Executive", "zoey.collins", False, True, "AUS-WS-AMILLER02", "10.30.30.13", "device-amiller-001", "73.158.42"),
    "dallas.smith": ("user-dallas-smith-id", "Dallas Smith", "AUS", 1, "Sales", "Account Executive", "zoey.collins", False, True, "AUS-WS-DSMITH01", "10.30.30.14", "device-dsmith-001", "107.77.195"),
    "houston.jones": ("user-houston-jones-id", "Houston Jones", "AUS", 1, "Sales", "Sales Development Rep", "zoey.collins", False, False, "AUS-WS-HJONES01", "10.30.30.15", "device-hjones-001", "108.28.163"),
    "sierra.martinez": ("user-sierra-martinez-id", "Sierra Martinez", "AUS", 1, "Sales", "Sales Development Rep", "zoey.collins", False, False, "AUS-WS-SMARTINEZ01", "10.30.30.16", "device-smartinez-001", "174.63.88"),
    "wyatt.anderson": ("user-wyatt-anderson-id", "Wyatt Anderson", "AUS", 1, "Sales", "Account Executive", "zoey.collins", False, True, "AUS-WS-WANDERSON01", "10.30.30.17", "device-wanderson-001", "68.105.12"),
    "savannah.thomas": ("user-savannah-thomas-id", "Savannah Thomas", "AUS", 1, "Sales", "Account Manager", "zoey.collins", False, True, "AUS-WS-STHOMAS01", "10.30.30.18", "device-sthomas-001", "71.222.45"),
    "hunter.jackson": ("user-hunter-jackson-id", "Hunter Jackson", "AUS", 1, "Sales", "Sales Development Rep", "zoey.collins", False, False, "AUS-WS-HJACKSON01", "10.30.30.19", "device-hjackson-001", "73.158.42"),
    "brooklyn.white": ("user-brooklyn-white-id", "Brooklyn White", "AUS", 1, "Sales", "Account Executive", "zoey.collins", False, True, "AUS-WS-BWHITE01", "10.30.30.20", "device-bwhite-001", "107.77.195"),
    "dakota.harris": ("user-dakota-harris-id", "Dakota Harris", "AUS", 1, "Sales", "Sales Development Rep", "zoey.collins", False, False, "AUS-WS-DHARRIS01", "10.30.30.21", "device-dharris-001", "108.28.163"),
    "phoenix.martin": ("user-phoenix-martin-id", "Phoenix Martin", "AUS", 1, "Sales", "Account Executive", "zoey.collins", False, True, "AUS-WS-PMARTIN01", "10.30.30.22", "device-pmartin-001", "174.63.88"),
    "river.garcia": ("user-river-garcia-id", "River Garcia", "AUS", 1, "Sales", "Sales Operations", "zoey.collins", False, False, "AUS-WS-RGARCIA01", "10.30.30.23", "device-rgarcia-001", "68.105.12"),
    "jordan.wilson": ("user-jordan-wilson-id", "Jordan Wilson", "AUS", 1, "Sales", "Account Manager", "zoey.collins", False, True, "AUS-WS-JWILSON01", "10.30.30.24", "device-jwilson-001", "71.222.45"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: ENGINEERING (12)
    # ==========================================================================
    "amelia.collins": ("user-amelia-collins-id", "Amelia Collins", "AUS", 1, "Engineering", "Lead Engineer", "richard.chen", False, True, "AUS-WS-ACOLLINS01", "10.30.30.40", "device-amelia-c-001", "71.222.45"),
    "jackson.moore": ("user-jackson-moore-id", "Jackson Moore", "AUS", 1, "Engineering", "Senior Software Engineer", "amelia.collins", False, True, "AUS-WS-JMOORE01", "10.30.30.41", "device-jmoore-001", "73.158.42"),
    "logan.taylor": ("user-logan-taylor-id", "Logan Taylor", "AUS", 1, "Engineering", "Software Engineer", "amelia.collins", False, True, "AUS-WS-LTAYLOR01", "10.30.30.42", "device-ltaylor-001", "107.77.195"),
    "aiden.johnson": ("user-aiden-johnson-id", "Aiden Johnson", "AUS", 1, "Engineering", "Software Engineer", "amelia.collins", False, True, "AUS-WS-AJOHNSON01", "10.30.30.43", "device-ajohnson-001", "108.28.163"),
    "lucas.brown": ("user-lucas-brown-id", "Lucas Brown", "AUS", 1, "Engineering", "Software Engineer", "amelia.collins", False, True, "AUS-WS-LBROWN02", "10.30.30.44", "device-lucbrown-001", "174.63.88"),
    "oliver.davis": ("user-oliver-davis-id", "Oliver Davis", "AUS", 1, "Engineering", "Frontend Developer", "amelia.collins", False, True, "AUS-WS-ODAVIS01", "10.30.30.45", "device-odavis-001", "68.105.12"),
    "elijah.miller": ("user-elijah-miller-id", "Elijah Miller", "AUS", 1, "Engineering", "Backend Developer", "amelia.collins", False, True, "AUS-WS-EMILLER01", "10.30.30.46", "device-emiller-001", "71.222.45"),
    "liam.wilson": ("user-liam-wilson-id", "Liam Wilson", "AUS", 1, "Engineering", "Software Engineer", "amelia.collins", False, True, "AUS-WS-LWILSON01", "10.30.30.47", "device-lwilson-001", "73.158.42"),
    "ethan.martinez": ("user-ethan-martinez-id", "Ethan Martinez", "AUS", 1, "Engineering", "DevOps Engineer", "amelia.collins", False, True, "AUS-WS-EMARTINEZ02", "10.30.30.48", "device-etmartinez-001", "107.77.195"),
    "sebastian.lee": ("user-sebastian-lee-id", "Sebastian Lee", "AUS", 1, "Engineering", "QA Engineer", "amelia.collins", False, True, "AUS-WS-SLEE01", "10.30.30.49", "device-slee-001", "108.28.163"),
    "benjamin.garcia": ("user-benjamin-garcia-id", "Benjamin Garcia", "AUS", 1, "Engineering", "Software Engineer", "amelia.collins", False, True, "AUS-WS-BGARCIA01", "10.30.30.50", "device-bgarcia-001", "174.63.88"),
    "william.rodriguez": ("user-william-rodriguez-id", "William Rodriguez", "AUS", 1, "Engineering", "Software Engineer", "amelia.collins", False, True, "AUS-WS-WRODRIGUEZ01", "10.30.30.51", "device-wrodriguez-001", "68.105.12"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: MARKETING (5)
    # ==========================================================================
    "emma.thompson": ("user-emma-thompson-id", "Emma Thompson", "AUS", 1, "Marketing", "Marketing Manager", "olivia.moore", False, True, "AUS-WS-ETHOMPSON01", "10.30.30.60", "device-ethompson-001", "71.222.45"),
    "ava.hernandez": ("user-ava-hernandez-id", "Ava Hernandez", "AUS", 1, "Marketing", "Content Specialist", "emma.thompson", False, True, "AUS-WS-AHERNANDEZ01", "10.30.30.61", "device-ahernandez-001", "73.158.42"),
    "mia.lopez": ("user-mia-lopez-id", "Mia Lopez", "AUS", 1, "Marketing", "Social Media Coordinator", "emma.thompson", False, False, "AUS-WS-MLOPEZ01", "10.30.30.62", "device-mlopez-001", "107.77.195"),
    "isabella.gonzalez": ("user-isabella-gonzalez-id", "Isabella Gonzalez", "AUS", 1, "Marketing", "Graphic Designer", "emma.thompson", False, False, "AUS-WS-IGONZALEZ01", "10.30.30.63", "device-igonzalez-001", "108.28.163"),
    "sophia.perez": ("user-sophia-perez-id", "Sophia Perez", "AUS", 1, "Marketing", "Marketing Coordinator", "emma.thompson", False, False, "AUS-WS-SPEREZ01", "10.30.30.64", "device-sperez-001", "174.63.88"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: HR (2)
    # ==========================================================================
    "riley.nguyen": ("user-riley-nguyen-id", "Riley Nguyen", "AUS", 1, "HR", "HR Coordinator", "aria.ramirez", False, True, "AUS-WS-RNGUYEN01", "10.30.30.70", "device-rnguyen-001", "68.105.12"),
    "avery.kim": ("user-avery-kim-id", "Avery Kim", "AUS", 1, "HR", "Recruiter", "riley.nguyen", False, False, "AUS-WS-AKIM01", "10.30.30.71", "device-akim-001", "71.222.45"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: OPERATIONS (2)
    # ==========================================================================
    "cameron.patel": ("user-cameron-patel-id", "Cameron Patel", "AUS", 1, "Operations", "Operations Coordinator", "frank.mitchell", False, False, "AUS-WS-CPATEL01", "10.30.30.75", "device-cpatel-001", "73.158.42"),
    "morgan.shah": ("user-morgan-shah-id", "Morgan Shah", "AUS", 1, "Operations", "Logistics Coordinator", "cameron.patel", False, False, "AUS-WS-MSHAH01", "10.30.30.76", "device-mshah-001", "107.77.195"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: IT (2)
    # ==========================================================================
    "casey.tran": ("user-casey-tran-id", "Casey Tran", "AUS", 1, "IT", "IT Support Specialist", "jessica.brown", False, True, "AUS-WS-CTRAN01", "10.30.30.80", "device-ctran-001", "108.28.163"),
    "alex.pham": ("user-alex-pham-id", "Alex Pham", "AUS", 1, "IT", "IT Support Specialist", "casey.tran", False, False, "AUS-WS-APHAM01", "10.30.30.81", "device-apham-001", "174.63.88"),

    # ==========================================================================
    # AUSTIN OFFICE - FLOOR 1: FINANCE (1)
    # ==========================================================================
    "taylor.wong": ("user-taylor-wong-id", "Taylor Wong", "AUS", 1, "Finance", "Financial Analyst", "robert.wilson", False, True, "AUS-WS-TWONG01", "10.30.30.85", "device-twong-001", "68.105.12"),
}

# Build User objects
USERS: Dict[str, User] = {}
for username, data in _USER_DATA.items():
    USERS[username] = User(
        username=username,
        user_id=data[0],
        display_name=data[1],
        location=data[2],
        floor=data[3],
        department=data[4],
        title=data[5],
        manager=data[6],
        vip=data[7],
        vpn_enabled=data[8],
        device_name=data[9],
        ip_address=data[10],
        device_id=data[11],
        home_ip_prefix=data[12],
    )

USER_KEYS = list(USERS.keys())

# VPN-enabled users (filtered list for convenience)
VPN_USERS = [u for u, user in USERS.items() if user.vpn_enabled]

# =============================================================================
# SERVER INVENTORY
# =============================================================================

_SERVER_DATA = {
    # Boston HQ - Primary Data Center
    "DC-BOS-01": ("BOS", "windows", "Domain Controller", "10.10.20.10", 10, 30, 40, 60),
    "DC-BOS-02": ("BOS", "windows", "Domain Controller", "10.10.20.11", 10, 30, 40, 60),
    "FILE-BOS-01": ("BOS", "windows", "File Server", "10.10.20.20", 15, 35, 50, 70),
    "SQL-PROD-01": ("BOS", "windows", "Database Server", "10.10.20.30", 20, 40, 60, 75),
    "APP-BOS-01": ("BOS", "windows", "Application Server", "10.10.20.40", 15, 35, 50, 70),
    "WEB-01": ("BOS", "linux", "Web Server", "172.16.1.10", 15, 35, 40, 60),
    "WEB-02": ("BOS", "linux", "Web Server", "172.16.1.11", 15, 35, 40, 60),

    # Atlanta Hub - Secondary Data Center
    "DC-ATL-01": ("ATL", "windows", "Domain Controller", "10.20.20.10", 10, 30, 40, 60),
    "BACKUP-ATL-01": ("ATL", "windows", "Backup Server", "10.20.20.20", 15, 40, 50, 75),
    "MON-ATL-01": ("ATL", "linux", "Monitoring Server", "10.20.20.30", 20, 45, 60, 80),
    "DEV-ATL-01": ("ATL", "linux", "Dev/Test Server", "10.20.20.40", 15, 50, 40, 70),
    "DEV-ATL-02": ("ATL", "linux", "Dev/Test Server", "10.20.20.41", 15, 50, 40, 70),
}

SERVERS: Dict[str, Server] = {}
for hostname, data in _SERVER_DATA.items():
    SERVERS[hostname] = Server(
        hostname=hostname,
        location=data[0],
        os=data[1],
        role=data[2],
        ip=data[3],
        cpu_baseline_min=data[4],
        cpu_baseline_max=data[5],
        ram_baseline_min=data[6],
        ram_baseline_max=data[7],
    )

WINDOWS_SERVERS = [h for h, s in SERVERS.items() if s.os == "windows"]
LINUX_SERVERS = [h for h, s in SERVERS.items() if s.os == "linux"]
ALL_SERVERS = list(SERVERS.keys())

# =============================================================================
# FIREWALL ARCHITECTURE
# =============================================================================

# Perimeter Firewall - Cisco ASA (sees ALL external traffic)
ASA_PERIMETER = {
    "hostname": "FW-EDGE-01",
    "model": "ASA 5525-X",
    "location": "BOS",
    "role": "Perimeter Firewall",
    "interfaces": {
        "outside": "ISP-facing (203.0.113.1)",
        "inside": "10.10.0.1",
        "dmz": "172.16.1.1",
    },
    "description": "All external traffic flows through this firewall",
}

# SD-WAN / Internal Firewalls - Meraki MX
MERAKI_FIREWALLS = {
    "BOS": {
        "devices": ["MX-BOS-01", "MX-BOS-02"],
        "model": "MX450",
        "ha_pair": True,
        "role": "SD-WAN Hub / Internal Segmentation",
    },
    "ATL": {
        "devices": ["MX-ATL-01"],
        "model": "MX250",
        "ha_pair": False,
        "role": "SD-WAN Edge / Branch Firewall",
    },
    "AUS": {
        "devices": ["MX-AUS-01"],
        "model": "MX85",
        "ha_pair": False,
        "role": "SD-WAN Edge / Branch Firewall",
    },
}

# Firewall hierarchy for traffic flow understanding
FIREWALL_HIERARCHY = {
    "perimeter": "FW-EDGE-01",  # ASA - all external traffic
    "sdwan_hub": ["MX-BOS-01", "MX-BOS-02"],
    "sdwan_spokes": ["MX-ATL-01", "MX-AUS-01"],
}

# Legacy reference (for backward compatibility)
ASA_HOSTNAME = "FW-EDGE-01"  # Updated to correct ASA hostname

# =============================================================================
# MEETING ROOMS & WEBEX DEVICES
# =============================================================================

# Meeting room configuration with sensor correlation data
# quality_profile: "premium" (reliable), "normal" (typical), "problematic" (issues)
# sun_exposure: "south", "west", "southwest", "east", "none" (internal room)

MEETING_ROOMS = {
    # =========================================================================
    # BOSTON HQ - 8 ROOMS
    # =========================================================================
    "Cambridge": {
        "location": "BOS",
        "floor": 3,
        "device": "WEBEX-BOS-CAMBRIDGE",
        "device_model": "Room Kit Pro",
        "capacity": 20,
        "room_type": "boardroom",
        "sun_exposure": "south",
        "base_temp": 21.0,
        "sun_temp_boost": 4.0,  # +4°C i direkte sol
        "sun_hours": [13, 14, 15, 16, 17],  # Når solen treffer
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-CAMBRIDGE",
        "has_camera": True,
        "camera_id": "MV-BOS-CAMBRIDGE",
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-CAMBRIDGE",
        "quality_profile": "premium",
        "description": "Executive boardroom with premium AV equipment",
    },
    "Faneuil": {
        "location": "BOS",
        "floor": 2,
        "device": "WEBEX-BOS-FANEUIL",
        "device_model": "Room Kit",
        "capacity": 12,
        "room_type": "conference",
        "sun_exposure": "none",  # Internt rom
        "base_temp": 21.5,
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-FANEUIL",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-FANEUIL",
        "quality_profile": "normal",
        "description": "Standard conference room on Finance floor",
    },
    "Quincy": {
        "location": "BOS",
        "floor": 2,
        "device": "WEBEX-BOS-QUINCY",
        "device_model": "Room Kit",
        "capacity": 8,
        "room_type": "conference",
        "sun_exposure": "east",
        "base_temp": 21.0,
        "sun_temp_boost": 2.0,
        "sun_hours": [8, 9, 10, 11],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-QUINCY",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-QUINCY",
        "quality_profile": "normal",
        "description": "Marketing team meeting room",
    },
    "North End": {
        "location": "BOS",
        "floor": 3,
        "device": "WEBEX-BOS-NORTHEND",
        "device_model": "Desk Pro",
        "capacity": 4,
        "room_type": "huddle",
        "sun_exposure": "west",
        "base_temp": 21.0,
        "sun_temp_boost": 2.5,
        "sun_hours": [15, 16, 17, 18],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-NORTHEND",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-NORTHEND",
        "quality_profile": "problematic",  # 🔥 PROBLEM-ROM
        "issues": ["wifi_congestion", "old_equipment"],
        "issue_probability": 0.30,  # 30% av møtene har problemer
        "description": "Small huddle room with WiFi issues - near busy AP",
    },
    "Back Bay": {
        "location": "BOS",
        "floor": 3,
        "device": "WEBEX-BOS-BACKBAY",
        "device_model": "Room Kit Mini",
        "capacity": 6,
        "room_type": "huddle",
        "sun_exposure": "none",
        "base_temp": 21.5,
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-BACKBAY",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-BACKBAY",
        "quality_profile": "normal",
        "description": "IT team quick meetings",
    },
    "Engineering Lab": {
        "location": "BOS",
        "floor": 3,
        "device": "WEBEX-BOS-LAB",
        "device_model": "Board 55",
        "capacity": 8,
        "room_type": "lab",
        "sun_exposure": "none",
        "base_temp": 20.0,  # Kjøligere for utstyr
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-LAB",
        "has_camera": True,
        "camera_id": "MV-BOS-LAB",
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-LAB",
        "quality_profile": "premium",
        "description": "Engineering collaboration space with whiteboard",
    },
    "Harbor": {
        "location": "BOS",
        "floor": 1,
        "device": "WEBEX-BOS-HARBOR",
        "device_model": "Desk Pro",
        "capacity": 6,
        "room_type": "visitor",
        "sun_exposure": "east",
        "base_temp": 21.0,
        "sun_temp_boost": 1.5,
        "sun_hours": [8, 9, 10],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-HARBOR",
        "has_camera": True,
        "camera_id": "MV-BOS-HARBOR",
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-BOS-TEMP-HARBOR",
        "quality_profile": "normal",
        "description": "Visitor meeting room near reception",
    },
    "Beacon": {
        "location": "BOS",
        "floor": 1,
        "device": "WEBEX-BOS-BEACON",
        "device_model": "Room Kit Mini",
        "capacity": 4,
        "room_type": "visitor",
        "sun_exposure": "none",
        "base_temp": 21.0,
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-BOS-DOOR-BEACON",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": False,
        "temp_sensor_id": None,
        "quality_profile": "normal",
        "description": "Small visitor room near lobby",
    },

    # =========================================================================
    # ATLANTA HUB - 6 ROOMS
    # =========================================================================
    "Peachtree": {
        "location": "ATL",
        "floor": 2,
        "device": "WEBEX-ATL-PEACHTREE",
        "device_model": "Room Kit Pro",
        "capacity": 16,
        "room_type": "training",
        "sun_exposure": "west",
        "base_temp": 22.0,
        "sun_temp_boost": 3.0,
        "sun_hours": [14, 15, 16, 17, 18],
        "has_door_sensor": True,
        "door_sensor_id": "MT-ATL-DOOR-PEACHTREE",
        "has_camera": True,
        "camera_id": "MV-ATL-PEACHTREE",
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-ATL-TEMP-PEACHTREE",
        "quality_profile": "problematic",  # 🔥 PROBLEM-ROM
        "issues": ["bandwidth_limited", "echo_issues"],
        "issue_probability": 0.40,  # 40% - verre når mange deltakere
        "description": "Training room with bandwidth/echo problems",
    },
    "Midtown": {
        "location": "ATL",
        "floor": 2,
        "device": "WEBEX-ATL-MIDTOWN",
        "device_model": "Room Kit",
        "capacity": 10,
        "room_type": "conference",
        "sun_exposure": "west",
        "base_temp": 22.0,
        "sun_temp_boost": 3.5,  # Varmt om ettermiddagen
        "sun_hours": [14, 15, 16, 17, 18],
        "has_door_sensor": True,
        "door_sensor_id": "MT-ATL-DOOR-MIDTOWN",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-ATL-TEMP-MIDTOWN",
        "quality_profile": "normal",
        "description": "Standard conference room - gets warm in afternoon",
    },
    "NOC": {
        "location": "ATL",
        "floor": 1,
        "device": "WEBEX-ATL-NOC",
        "device_model": "Room Kit",
        "capacity": 6,
        "room_type": "operations",
        "sun_exposure": "none",
        "base_temp": 19.0,  # Kjølig for utstyr
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-ATL-DOOR-NOC",
        "has_camera": True,
        "camera_id": "MV-ATL-NOC",
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-ATL-TEMP-NOC",
        "quality_profile": "premium",
        "description": "NOC briefing room with monitoring displays",
    },
    "Buckhead": {
        "location": "ATL",
        "floor": 2,
        "device": "WEBEX-ATL-BUCKHEAD",
        "device_model": "Desk Pro",
        "capacity": 4,
        "room_type": "huddle",
        "sun_exposure": "south",
        "base_temp": 21.5,
        "sun_temp_boost": 2.0,
        "sun_hours": [11, 12, 13, 14, 15],
        "has_door_sensor": True,
        "door_sensor_id": "MT-ATL-DOOR-BUCKHEAD",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": False,
        "temp_sensor_id": None,
        "quality_profile": "normal",
        "description": "Quick meeting huddle space",
    },
    "Decatur": {
        "location": "ATL",
        "floor": 2,
        "device": "WEBEX-ATL-DECATUR",
        "device_model": "Desk Pro",
        "capacity": 4,
        "room_type": "huddle",
        "sun_exposure": "none",
        "base_temp": 21.5,
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-ATL-DECATUR-01",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-ATL-DECATUR-02",
        "quality_profile": "normal",
        "description": "Engineering team huddle",
    },
    "Innovation Lab": {
        "location": "ATL",
        "floor": 2,
        "device": "WEBEX-ATL-INNOVATION",
        "device_model": "Board 55",
        "capacity": 8,
        "room_type": "lab",
        "sun_exposure": "east",
        "base_temp": 20.5,
        "sun_temp_boost": 1.5,
        "sun_hours": [8, 9, 10, 11],
        "has_door_sensor": True,
        "door_sensor_id": "MT-ATL-DOOR-INNOVATION",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-ATL-TEMP-INNOVATION",
        "quality_profile": "normal",
        "description": "Innovation and brainstorming space",
    },

    # =========================================================================
    # AUSTIN OFFICE - 3 ROOMS
    # =========================================================================
    "Congress": {
        "location": "AUS",
        "floor": 1,
        "device": "WEBEX-AUS-CONGRESS",
        "device_model": "Room Kit",
        "capacity": 12,
        "room_type": "conference",
        "sun_exposure": "southwest",  # Texas sol! 🔥
        "base_temp": 23.0,
        "sun_temp_boost": 5.0,  # Veldig varmt!
        "sun_hours": [12, 13, 14, 15, 16, 17],
        "has_door_sensor": True,
        "door_sensor_id": "MT-AUS-DOOR-CONGRESS",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-AUS-TEMP-CONGRESS",
        "quality_profile": "normal",
        "description": "Main conference room - gets very hot in afternoon sun",
    },
    "6th Street": {
        "location": "AUS",
        "floor": 1,
        "device": "WEBEX-AUS-6THSTREET",
        "device_model": "Room Kit Mini",
        "capacity": 6,
        "room_type": "huddle",
        "sun_exposure": "none",
        "base_temp": 22.0,
        "sun_temp_boost": 0.0,
        "sun_hours": [],
        "has_door_sensor": True,
        "door_sensor_id": "MT-AUS-DOOR-6THSTREET",
        "has_camera": False,
        "camera_id": None,
        "has_temp_sensor": False,
        "temp_sensor_id": None,
        "quality_profile": "normal",
        "description": "Sales team quick meetings",
    },
    "Live Oak": {
        "location": "AUS",
        "floor": 1,
        "device": "WEBEX-AUS-LIVEOAK",
        "device_model": "Room Kit",
        "capacity": 8,
        "room_type": "demo",
        "sun_exposure": "east",
        "base_temp": 21.0,
        "sun_temp_boost": 2.0,
        "sun_hours": [8, 9, 10, 11],
        "has_door_sensor": True,
        "door_sensor_id": "MT-AUS-DOOR-LIVEOAK",
        "has_camera": True,
        "camera_id": "MV-AUS-LIVEOAK",
        "has_temp_sensor": True,
        "temp_sensor_id": "MT-AUS-TEMP-LIVEOAK",
        "quality_profile": "premium",
        "description": "Demo lab for customer presentations",
    },
}

# Helper to get rooms by location
def get_meeting_rooms_by_location(location: str) -> dict:
    """Get all meeting rooms at a specific location."""
    return {name: room for name, room in MEETING_ROOMS.items() if room["location"] == location}

# Helper to get problem rooms
def get_problem_rooms() -> dict:
    """Get meeting rooms with quality issues."""
    return {name: room for name, room in MEETING_ROOMS.items() if room.get("quality_profile") == "problematic"}

# Helper to get sunny rooms (for temperature simulation)
def get_sunny_rooms() -> dict:
    """Get meeting rooms with sun exposure."""
    return {name: room for name, room in MEETING_ROOMS.items() if room.get("sun_exposure") != "none"}

# =============================================================================
# MEETING BEHAVIOR CONFIGURATION
# =============================================================================

MEETING_BEHAVIOR = {
    # Ghost meetings (booked but no one shows up)
    "ghost_meeting_probability": 0.15,  # 15% no-show

    # Walk-in meetings (unbooked room usage)
    "walkin_meeting_probability": 0.10,  # 10% ad-hoc

    # Late start meetings
    "late_start_probability": 0.20,  # 20% start 5-15 min late
    "late_start_min_minutes": 5,
    "late_start_max_minutes": 15,

    # Overfilled meetings (more than capacity)
    "overfilled_probability": 0.05,  # 5% exceed capacity
    "overfilled_max_extra": 5,

    # Meeting timing
    "door_opens_before_meeting_min": 2,  # minutes
    "door_opens_before_meeting_max": 5,
    "door_opens_after_meeting_min": 0,
    "door_opens_after_meeting_max": 3,

    # Temperature behavior
    "temp_rise_per_person": 0.3,  # °C per person
    "temp_rise_max_from_people": 3.0,  # Max +3°C from body heat
    "temp_rise_per_30min": 0.5,  # Long meeting effect
    "temp_rise_max_from_duration": 1.5,
    "temp_cooldown_minutes": 30,  # Time to return to baseline

    # After-hours activity (legitimate overtime work)
    "afterhours_probability": 0.02,  # 2% chance per day
    "afterhours_start_hour": 20,
    "afterhours_end_hour": 23,
    "afterhours_preferred_rooms": ["Back Bay", "North End", "Buckhead"],  # Smaller rooms
}

# =============================================================================
# ENTRA ID / AZURE AD
# =============================================================================

ENTRA_APPS = {
    "Microsoft Office 365": "00000003-0000-0000-c000-000000000000",
    "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
    "SharePoint Online": "00000003-0000-0ff1-ce00-000000000000",
    "Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    "Microsoft Graph": "00000003-0000-0000-c000-000000000000",
    "Custom HR App": "app-hr-custom-001",
    "Custom Finance App": "app-finance-custom-001",
}

ENTRA_GROUPS = [
    "All Employees", "Finance Department", "IT Department", "Engineering",
    "Marketing", "Sales", "HR", "Legal", "Remote Workers", "VPN Users",
    "Boston Office", "Atlanta Office", "Austin Office", "Executives",
]

ENTRA_ROLES = [
    "Global Administrator", "Security Administrator", "User Administrator",
    "Groups Administrator", "Application Administrator", "Security Reader",
]

# =============================================================================
# EXCHANGE / EMAIL
# =============================================================================

EXCHANGE_ORG = TENANT
EXCHANGE_SMTP_DOMAIN = TENANT
EXCHANGE_INBOUND_CONNECTOR = "Inbound from Internet"
EXCHANGE_OUTBOUND_CONNECTOR = "Outbound to Internet"

EXTERNAL_MAIL_DOMAINS = [
    "gmail.com", "outlook.com", "yahoo.com",
    "hotmail.com", "protonmail.com", "icloud.com",
]

PARTNER_DOMAINS = [
    "contoso.com", "fabrikam.com", "northwindtraders.com",
    "adventureworks.com", "wideworldimporters.com",
]

EMAIL_SUBJECTS_INTERNAL = [
    "RE: Q4 Budget Review", "Meeting Notes - Project Sync",
    "FW: Updated Policy Document", "Team Lunch Friday?",
    "RE: Action Items from Yesterday", "Quick Question",
    "Out of Office: Back Monday", "RE: Invoice Approval Needed",
    "Weekly Status Update", "FW: Customer Feedback",
]

EMAIL_SUBJECTS_EXTERNAL = [
    "Your order confirmation", "Invoice #INV-2026-",
    "Meeting Request", "Partnership Opportunity",
    "RE: Support Ticket #", "Newsletter - January 2026",
    "Webinar Registration Confirmed", "Your subscription renewal",
    "RE: Quote Request", "Thank you for contacting us",
]

# =============================================================================
# US CITIES
# =============================================================================

US_CITIES = [
    "New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
    "Philadelphia", "San Antonio", "San Diego", "Dallas", "Austin",
    "Boston", "Atlanta", "Miami", "Seattle", "Denver",
]

# =============================================================================
# ASA/FIREWALL CONFIGURATION
# =============================================================================

ASA_WEB_PORTS = [80, 443, 8080, 8443]
ASA_SCAN_PORTS = [22, 23, 25, 110, 143, 445, 3389, 5432, 3306, 5900]
ASA_TEARDOWN_REASONS = ["TCP FINs", "TCP Reset-I", "TCP Reset-O", "idle timeout"]
ASA_EXT_ACLS = ["outside_access_in", "acl_outside", "implicit-deny"]
ASA_INT_ACLS = ["internal_segmentation", "server_segment_acl", "workstation_restrictions"]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_internal_ip(location: str = None) -> str:
    """Get a random internal IP, optionally for a specific location."""
    if location:
        prefix = NETWORK_CONFIG[location]["prefix"]
        return f"{prefix}.30.{random.randint(10, 250)}"
    prefix = random.choice(INT_PFX)
    return f"{prefix}.{random.randint(10, 250)}"


def get_us_ip() -> str:
    """Get a random US residential IP."""
    prefix = random.choice(US_IP_PFX)
    return f"{prefix}.{random.randint(1, 254)}"


def get_external_ip() -> str:
    """Get a random external service IP."""
    return random.choice(EXT_SERVICE_IPS)


def get_dmz_ip() -> str:
    """Get a random DMZ IP."""
    return f"{DMZ_PFX}.{random.randint(10, 50)}"


def get_random_user(location: str = None, department: str = None) -> User:
    """Get a random user, optionally filtered by location or department."""
    filtered = list(USERS.values())
    if location:
        filtered = [u for u in filtered if u.location == location]
    if department:
        filtered = [u for u in filtered if u.department == department]
    if not filtered:
        filtered = list(USERS.values())
    return random.choice(filtered)


def get_random_vpn_user() -> User:
    """Get a random VPN-enabled user."""
    username = random.choice(VPN_USERS)
    return USERS[username]


def get_random_city() -> str:
    """Get a random US city."""
    return random.choice(US_CITIES)


def get_world_ip() -> str:
    """Get a random world IP for scan noise."""
    prefix = random.choice(WORLD_IP_PREFIXES)
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def get_users_by_location(location: str) -> List[User]:
    """Get all users at a specific location."""
    return [u for u in USERS.values() if u.location == location]


def get_users_by_department(department: str) -> List[User]:
    """Get all users in a specific department."""
    return [u for u in USERS.values() if u.department == department]


def get_vip_users() -> List[User]:
    """Get all VIP users."""
    return [u for u in USERS.values() if u.vip]


def get_servers_by_location(location: str) -> List[Server]:
    """Get all servers at a specific location."""
    return [s for s in SERVERS.values() if s.location == location]


# =============================================================================
# COMPANY CLASS
# =============================================================================

class Company:
    """
    Company class wrapping static configuration with methods.
    Used by scenario classes.
    """

    def __init__(self):
        self.org_name = ORG_NAME
        self.tenant = TENANT
        self.tenant_id = TENANT_ID
        self.threat_ip = THREAT_IP
        self.users = USERS
        self.servers = SERVERS
        self.locations = LOCATIONS

    def get_internal_ip(self, location: str = None) -> str:
        return get_internal_ip(location)

    def get_us_ip(self) -> str:
        return get_us_ip()

    def get_external_ip(self) -> str:
        return get_external_ip()

    def get_dmz_ip(self) -> str:
        return get_dmz_ip()

    def get_world_ip(self) -> str:
        return get_world_ip()

    def get_random_user(self, location: str = None, department: str = None) -> User:
        return get_random_user(location, department)

    def get_random_vpn_user(self) -> User:
        return get_random_vpn_user()

    def get_random_city(self) -> str:
        return get_random_city()


if __name__ == "__main__":
    print("Company configuration loaded")
    print(f"  Organization: {ORG_NAME}")
    print(f"  Tenant: {TENANT}")
    print(f"  Total Users: {len(USERS)}")
    print(f"  Total Servers: {len(SERVERS)}")
    print(f"  VPN Users: {len(VPN_USERS)}")
    print()
    print("Locations:")
    for loc_code, loc in LOCATIONS.items():
        users_count = len(get_users_by_location(loc_code))
        servers_count = len(get_servers_by_location(loc_code))
        print(f"  {loc_code}: {loc['full_name']} - {users_count} users, {servers_count} servers")
    print()
    print("Departments:")
    for dept in ["Executive", "Finance", "IT", "Engineering", "Sales", "Marketing", "HR", "Legal", "Operations"]:
        count = len(get_users_by_department(dept))
        print(f"  {dept}: {count} users")
    print()
    print("Key Personnel:")
    print(f"  Primary Target: {COMP_DISPLAY} ({COMP_DEPARTMENT}) - {COMP_WS_HOSTNAME} @ {COMP_WS_IP}")
    print(f"  Initial Compromise: {LATERAL_DISPLAY} ({LATERAL_DEPARTMENT}) - {JESSICA_WS_HOSTNAME} @ {JESSICA_WS_IP}")
    print()
    print("Sample data:")
    print(f"  Random BOS user: {get_random_user('BOS')}")
    print(f"  Random ATL IT user: {get_random_user('ATL', 'IT')}")
    print(f"  Random VPN user: {get_random_vpn_user()}")
