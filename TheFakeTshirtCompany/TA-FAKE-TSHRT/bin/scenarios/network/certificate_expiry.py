#!/usr/bin/env python3
"""
Certificate Expiry Scenario - SSL certificate expires causing service outage.

Timeline (Day 13):
    Day 13, 00:00: Wildcard SSL certificate for *.theFakeTshirtCompany.com expires
    Day 13, 00:00-06:00: HTTPS connections fail, customers see SSL errors
                         (6-hour gap: no cert monitoring in place -- this is the scenario's
                         lesson. NOC only alerted at shift change from customer complaints.)
    Day 13, 06:15: NOC engineer notices alerts, investigates
    Day 13, 06:30: Root cause identified - expired certificate
    Day 13, 06:45: Emergency certificate renewal initiated
    Day 13, 07:00: New certificate installed, services restored
    Day 13, 07:00+: Traffic normalizes

Affected services:
    - Main website (theFakeTshirtCompany.com)
    - API endpoints
    - Internal services using the wildcard cert

Logger:
    - ASA: SSL handshake failures, connection resets
    - Access logs: 502/503 errors, connection timeouts
    - ServiceNow: P1 incident for SSL certificate expiry
"""

import random
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

from shared.config import next_cid


@dataclass
class CertificateExpiryConfig:
    """Configuration for certificate expiry scenario."""
    demo_id: str = "certificate_expiry"

    # Timeline (0-indexed days)
    day: int = 12          # Day 13 (0-indexed)
    expiry_hour: int = 0   # 00:00 - cert expires at midnight
    detection_hour: int = 6  # 06:15 - NOC notices
    fix_hour: int = 7      # 07:00 - cert replaced

    # Certificate details
    cert_cn: str = "*.theFakeTshirtCompany.com"
    cert_issuer: str = "DigiCert SHA2 Extended Validation Server CA"
    cert_serial: str = "0A:1B:2C:3D:4E:5F:6A:7B:8C:9D"

    # Affected services
    web_server_ip: str = "172.16.1.10"  # WEB-01 in DMZ
    web_server_public: str = "203.0.113.10"
    api_server_ip: str = "172.16.1.11"  # WEB-02 / API


class CertificateExpiryScenario:
    """
    Certificate Expiry Scenario.

    Simulates an SSL certificate expiring at midnight, causing service
    disruption until the certificate is renewed in the morning.
    """

    def __init__(self, config: Optional[CertificateExpiryConfig] = None, demo_id_enabled: bool = True):
        self.cfg = config or CertificateExpiryConfig()
        self.demo_id_enabled = demo_id_enabled

        # Customer IP prefixes for realistic traffic
        self.customer_prefixes = [
            "174.63.88", "71.222.45", "108.28.163",
            "98.45.12", "73.189.44", "68.105.12",
            "24.56.78", "76.123.45", "99.88.77"
        ]

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        if self.demo_id_enabled:
            return f" demo_id={self.cfg.demo_id}"
        return ""

    def _asa_pri(self, severity: int) -> str:
        """Calculate syslog PRI header for ASA logs.

        Cisco ASA uses local4 (facility 20).
        PRI = facility * 8 + severity
        """
        facility = 20  # local4
        return f"<{facility * 8 + severity}>"

    def _demo_json(self) -> dict:
        """Get demo_id dict for JSON format."""
        return {"demo_id": self.cfg.demo_id} if self.demo_id_enabled else {}

    def _random_customer_ip(self) -> str:
        """Get a random customer IP."""
        prefix = random.choice(self.customer_prefixes)
        return f"{prefix}.{random.randint(1, 254)}"

    # =========================================================================
    # ASA EVENT GENERATORS
    # =========================================================================

    def ssl_handshake_failure(self, ts: str) -> str:
        """SSL handshake failure event."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(6)  # severity 6 = informational
        customer_ip = self._random_customer_ip()
        customer_port = random.randint(49152, 65535)

        # ASA-6-725007: SSL handshake failed
        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-6-725007: SSL session with client "
            f"outside:{customer_ip}/{customer_port} to inside:{self.cfg.web_server_ip}/443 "
            f"terminated due to SSL handshake failure{suffix}"
        )

    def ssl_cert_expired(self, ts: str) -> str:
        """Certificate expired error event."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # severity 4 = warning
        customer_ip = self._random_customer_ip()

        # ASA-4-725006: Device certificate expired
        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-725006: Device failed SSL handshake with client "
            f"outside:{customer_ip} certificate expired: CN={self.cfg.cert_cn}, "
            f"issuer={self.cfg.cert_issuer}{suffix}"
        )

    def connection_reset(self, ts: str) -> str:
        """Connection reset by peer."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(6)  # severity 6 = informational
        customer_ip = self._random_customer_ip()
        customer_port = random.randint(49152, 65535)
        conn_id = next_cid()

        # Connection teardown due to SSL failure
        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-6-302014: Teardown TCP connection {conn_id} "
            f"for outside:{customer_ip}/{customer_port} to inside:{self.cfg.web_server_ip}/443 "
            f"duration 0:00:00 bytes 0 TCP Reset-O{suffix}"
        )

    def ssl_session_established(self, ts: str) -> str:
        """SSL session established (after fix)."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(6)  # severity 6 = informational
        customer_ip = self._random_customer_ip()
        customer_port = random.randint(49152, 65535)

        # Normal SSL session after certificate renewal
        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-6-725001: Starting SSL handshake with client "
            f"outside:{customer_ip}/{customer_port} to inside:{self.cfg.web_server_ip}/443 "
            f"for TLSv1.2 session{suffix}"
        )

    # =========================================================================
    # ACCESS LOG EVENT GENERATORS
    # =========================================================================

    def access_ssl_error(self, ts: str) -> dict:
        """Generate access log entry for SSL error (502/503)."""
        customer_ip = self._random_customer_ip()
        status = random.choice([502, 503])
        paths = ["/", "/products", "/cart", "/checkout", "/api/v1/products", "/api/v1/cart"]
        path = random.choice(paths)

        event = {
            "timestamp": ts,
            "client_ip": customer_ip,
            "method": "GET",
            "uri": path,
            "status": status,
            "bytes": 0,
            "response_time_ms": random.randint(30000, 60000),  # Timeout
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            ]),
            "ssl_error": "certificate_expired",
        }
        event.update(self._demo_json())
        return event

    def access_normal_request(self, ts: str) -> dict:
        """Generate normal access log entry (after fix)."""
        customer_ip = self._random_customer_ip()
        paths = ["/", "/products", "/cart", "/checkout", "/api/v1/products"]
        path = random.choice(paths)

        event = {
            "timestamp": ts,
            "client_ip": customer_ip,
            "method": "GET",
            "uri": path,
            "status": 200,
            "bytes": random.randint(5000, 50000),
            "response_time_ms": random.randint(50, 500),
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
            ]),
        }
        event.update(self._demo_json())
        return event

    # =========================================================================
    # MAIN GENERATORS
    # =========================================================================

    def is_active(self, day: int) -> bool:
        """Check if scenario is active for this day."""
        return day == self.cfg.day

    def is_outage_period(self, day: int, hour: int) -> bool:
        """Check if we're in the outage period (cert expired, not yet fixed)."""
        if day != self.cfg.day:
            return False
        return self.cfg.expiry_hour <= hour < self.cfg.fix_hour

    def asa_hour(self, day: int, hour: int, time_utils) -> List[str]:
        """Generate ASA events for certificate expiry scenario."""
        events = []

        if day != self.cfg.day:
            return events

        # During outage (00:00 - 07:00)
        if self.cfg.expiry_hour <= hour < self.cfg.fix_hour:
            # Scale events based on time of day
            if hour < 5:
                # Low traffic overnight
                num_failures = random.randint(5, 15)
            else:
                # Traffic picks up in morning
                num_failures = random.randint(20, 40)

            for _ in range(num_failures):
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, second)

                # Mix of event types
                event_type = random.randint(1, 100)
                if event_type <= 50:
                    events.append(self.ssl_handshake_failure(ts))
                elif event_type <= 80:
                    events.append(self.ssl_cert_expired(ts))
                else:
                    events.append(self.connection_reset(ts))

        # Hour 7: Recovery - some initial successful connections
        elif hour == self.cfg.fix_hour:
            # First 15 minutes still have some failures
            for _ in range(5):
                minute = random.randint(0, 14)
                second = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, second)
                events.append(self.ssl_handshake_failure(ts))

            # After fix - successful sessions
            for _ in range(10):
                minute = random.randint(15, 59)
                second = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, second)
                events.append(self.ssl_session_established(ts))

        return events

    def access_hour(self, day: int, hour: int, time_utils) -> List[dict]:
        """Generate access log events for certificate expiry scenario."""
        events = []

        if day != self.cfg.day:
            return events

        base_dt = datetime.strptime(time_utils.base_date, "%Y-%m-%d")

        # During outage (00:00 - 07:00)
        if self.cfg.expiry_hour <= hour < self.cfg.fix_hour:
            # Scale based on time
            if hour < 5:
                num_errors = random.randint(3, 10)
            else:
                num_errors = random.randint(15, 30)

            for _ in range(num_errors):
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts_dt = datetime(
                    base_dt.year, base_dt.month, base_dt.day,
                    hour, minute, second
                ) + timedelta(days=day)
                ts = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                events.append(self.access_ssl_error(ts))

        # Hour 7: Recovery
        elif hour == self.cfg.fix_hour:
            # First 15 min - still errors
            for _ in range(5):
                minute = random.randint(0, 14)
                second = random.randint(0, 59)
                ts_dt = datetime(
                    base_dt.year, base_dt.month, base_dt.day,
                    hour, minute, second
                ) + timedelta(days=day)
                ts = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                events.append(self.access_ssl_error(ts))

            # After fix - normal traffic with demo_id for correlation
            for _ in range(10):
                minute = random.randint(15, 59)
                second = random.randint(0, 59)
                ts_dt = datetime(
                    base_dt.year, base_dt.month, base_dt.day,
                    hour, minute, second
                ) + timedelta(days=day)
                ts = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                events.append(self.access_normal_request(ts))

        return events

    def has_scenario_events(self, day: int, hour: int) -> bool:
        """Check if this day/hour has scenario events."""
        if day != self.cfg.day:
            return False
        return self.cfg.expiry_hour <= hour <= self.cfg.fix_hour

    def get_phase(self, day: int, hour: int = 0) -> str:
        """Get the scenario phase for display purposes."""
        if day < self.cfg.day:
            return "pre_expiry"
        elif day == self.cfg.day:
            if hour < self.cfg.detection_hour:
                return "outage_undetected"
            elif hour < self.cfg.fix_hour:
                return "outage_investigating"
            else:
                return "recovery"
        else:
            return "post_incident"


if __name__ == "__main__":
    scenario = CertificateExpiryScenario()
    print("Certificate Expiry Scenario")
    print("===========================")
    print(f"Day: {scenario.cfg.day + 1} (index {scenario.cfg.day})")
    print(f"Certificate expires: {scenario.cfg.expiry_hour:02d}:00")
    print(f"Detection: {scenario.cfg.detection_hour:02d}:15")
    print(f"Fix applied: {scenario.cfg.fix_hour:02d}:00")
    print(f"Certificate CN: {scenario.cfg.cert_cn}")
