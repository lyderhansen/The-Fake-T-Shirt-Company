#!/usr/bin/env python3
"""
Firewall Misconfiguration Scenario - ASA events.
Converted from scenarios/network/firewall_misconfig_asa.sh

Storyline:
    Day 6: SOC detects suspicious traffic
    Day 6, 10:15: IT admin logs in to block the threat
    Day 6, 10:18: Admin makes mistake - blocks traffic TO web server
    Day 6, 10:20-12:00: Customers cannot reach theFakeTshirtCompany.com
    Day 6, 12:00: Problem identified, config rolled back
    Day 6, 12:05+: Traffic normalizes
"""

import random
from typing import List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FirewallMisconfigConfig:
    """Configuration for firewall misconfiguration scenario."""
    demo_id: str = "firewall_misconfig"

    # Timeline
    day: int = 5          # Day 6 (0-indexed)
    start_hour: int = 10  # 10:15 - config change
    end_hour: int = 12    # 12:00 - rollback

    # Admin who makes the mistake
    admin: str = "network.admin"

    # Target IP (should be blocked FROM, not TO)
    target_ip: str = "203.0.113.10"  # WEB-01 public IP


class FirewallMisconfigScenario:
    """
    Firewall Misconfiguration Scenario.

    Simulates a firewall misconfiguration where IT attempts to block the
    threat IP but accidentally blocks traffic TO the public IP of WEB-01.
    """

    def __init__(self, config: Optional[FirewallMisconfigConfig] = None, demo_id_enabled: bool = True):
        self.cfg = config or FirewallMisconfigConfig()
        self.demo_id_enabled = demo_id_enabled

        # Customer IP prefixes
        self.customer_prefixes = [
            "174.63.88", "71.222.45", "108.28.163",
            "98.45.12", "73.189.44", "68.105.12"
        ]

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        if self.demo_id_enabled:
            return f" demo_id={self.cfg.demo_id}"
        return ""

    def _asa_pri(self, severity: int) -> str:
        """Calculate syslog PRI header for ASA logs (local4 facility)."""
        return f"<{20 * 8 + severity}>"

    def _random_customer_ip(self) -> str:
        """Get a random customer IP."""
        prefix = random.choice(self.customer_prefixes)
        return f"{prefix}.{random.randint(1, 254)}"

    # =========================================================================
    # EVENT GENERATORS
    # =========================================================================

    def admin_login(self, ts: str) -> str:
        """Admin login event."""
        suffix = self._demo_suffix_syslog()
        pri6 = self._asa_pri(6)  # info
        return (
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-605005: Login permitted from 10.10.10.50/52435 '
            f'to inside:10.10.10.1/ssh for user "{self.cfg.admin}"{suffix}'
        )

    def config_mode(self, ts: str) -> str:
        """Config mode entry."""
        suffix = self._demo_suffix_syslog()
        pri5 = self._asa_pri(5)  # notice
        return (
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111008: User '{self.cfg.admin}' "
            f"executed the 'configure terminal' command{suffix}"
        )

    def bad_acl(self, ts: str) -> str:
        """Bad ACL added (the mistake)."""
        suffix = self._demo_suffix_syslog()
        pri5 = self._asa_pri(5)  # notice
        return (
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111010: User '{self.cfg.admin}' executed "
            f"'access-list outside_access_in line 1 extended deny tcp any host "
            f"{self.cfg.target_ip} eq https'{suffix}"
        )

    def deny_event(self, ts: str) -> str:
        """Deny event (blocked customer traffic)."""
        suffix = self._demo_suffix_syslog()
        pri4 = self._asa_pri(4)  # warning
        customer_ip = self._random_customer_ip()
        customer_port = random.randint(1024, 61024)
        dst_port = 443 if random.random() < 0.5 else 80

        return (
            f'{pri4}{ts} FW-EDGE-01 %ASA-4-106023: Deny tcp src outside:{customer_ip}/{customer_port} '
            f'dst dmz:{self.cfg.target_ip}/{dst_port} by access-group '
            f'"outside_access_in" [0x0, 0x0]{suffix}'
        )

    def rollback(self, ts: str) -> str:
        """Rollback - remove bad ACL."""
        suffix = self._demo_suffix_syslog()
        pri5 = self._asa_pri(5)  # notice
        return (
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111010: User '{self.cfg.admin}' executed "
            f"'no access-list outside_access_in line 1 extended deny tcp any host "
            f"{self.cfg.target_ip} eq https'{suffix}"
        )

    def save_config(self, ts: str) -> str:
        """Config save."""
        suffix = self._demo_suffix_syslog()
        pri5 = self._asa_pri(5)  # notice
        return (
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111008: User '{self.cfg.admin}' "
            f"executed the 'write memory' command{suffix}"
        )

    def admin_logout(self, ts: str) -> str:
        """Admin SSH session disconnect."""
        suffix = self._demo_suffix_syslog()
        pri6 = self._asa_pri(6)  # info
        return (
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-315011: SSH session from 10.10.10.50 '
            f'on interface inside for user "{self.cfg.admin}" disconnected by SSH server{suffix}'
        )

    # =========================================================================
    # MAIN GENERATOR
    # =========================================================================

    def is_active(self, day: int, hour: int) -> bool:
        """Check if scenario is active for this day/hour."""
        if day != self.cfg.day:
            return False
        return self.cfg.start_hour <= hour <= self.cfg.end_hour

    def has_anomaly(self, day: int, hour: int) -> str:
        """Check if anomaly is present for tagging."""
        if self.is_active(day, hour):
            return self.cfg.demo_id
        return ""

    def access_should_error(self, day: int, hour: int) -> Tuple[bool, int, float]:
        """Return (should_inject_errors, error_rate_pct, response_time_multiplier).

        During the firewall misconfiguration, the ACL blocks ALL external
        traffic to the web server. No customer can reach the site at all.
        This means 100% error rate -- every single request fails with
        503/504, and zero orders can complete.

        Timeline:
        - Hour 10 (10:20-10:59): ACL applied, 100% blocked, 10x response time
        - Hour 11 (full hour):   Full outage, 100% blocked, 10x response time
        - Hour 12 (00-05):       Still blocked until rollback at 12:03
        - Hour 12 (05+):         Resolved, traffic normalizes
        """
        if day != self.cfg.day:
            return (False, 0, 1.0)

        if hour == self.cfg.start_hour:
            # 10:20-10:59 -- ACL blocks ALL traffic to web server
            return (True, 100, 10.0)

        if hour == 11:
            # Full outage hour -- nothing gets through
            return (True, 100, 10.0)

        if hour == self.cfg.end_hour:
            # 12:00-12:03 blocked, 12:03 rollback, 12:05 traffic normalizes
            # Blend: ~50% of the hour is blocked, rest is normal
            return (True, 50, 5.0)

        return (False, 0, 1.0)

    def asa_baseline_suppression(self, day: int, hour: int) -> float:
        """Return 0.0-1.0 indicating how much external->DMZ web traffic to suppress.

        The ACL blocks ALL external traffic to WEB-01. No customer connections
        can be established, so baseline Built/Teardown for external->DMZ must
        be fully suppressed during the outage.
        """
        if day != self.cfg.day:
            return 0.0

        if hour == self.cfg.start_hour:
            # 10:20-10:59 -- ACL blocks everything after 10:20
            # ~60% of the hour is blocked (minutes 20-59 out of 0-59)
            return 0.65

        if hour == 11:
            # Full outage -- nothing gets through
            return 1.0

        if hour == self.cfg.end_hour:
            # 12:00-12:03 blocked, 12:05 normalized -- ~5% of hour blocked
            return 0.05

        return 0.0

    def generate_hour(self, day: int, hour: int, time_utils, normal_dmz_events: int = 0) -> List[str]:
        """Generate firewall misconfig events for an hour.

        Deny volume scales dynamically based on the estimated normal DMZ event
        count for this hour. The ASA generator calculates this from registry
        session count + tcp_session DMZ fraction, so it automatically scales
        with --scale and --orders-per-day.

        Args:
            normal_dmz_events: Estimated DMZ events this hour would normally
                               produce (without suppression). Includes registry
                               Built/Teardown + tcp_session DMZ-bound events.
                               If 0, falls back to hardcoded minimums.
        """
        events = []

        if day != self.cfg.day:
            return events

        # Hour 10: Config change happens
        if hour == self.cfg.start_hour:
            # 10:15 - Admin logs in
            ts = time_utils.ts_syslog(day, hour, 15, random.randint(0, 29))
            events.append(self.admin_login(ts))

            # 10:16 - Enter config mode
            ts = time_utils.ts_syslog(day, hour, 16, random.randint(0, 29))
            events.append(self.config_mode(ts))

            # 10:18 - Bad ACL added
            ts = time_utils.ts_syslog(day, hour, 18, random.randint(0, 29))
            events.append(self.bad_acl(ts))

            # 10:20-10:59 - Heavy deny events (customers hitting blocked ACL)
            # 65% suppression, 40 of 60 minutes blocked
            deny_count = max(250, int(normal_dmz_events * 0.65 * 40 / 60))
            for _ in range(deny_count):
                minute = 20 + random.randint(0, 39)
                sec = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, sec)
                events.append(self.deny_event(ts))

        # Hour 11: Continued outage - peak deny events
        elif hour == 11:
            # 100% suppression — replace all suppressed DMZ Built/Teardown events
            deny_count = max(400, normal_dmz_events)
            for _ in range(deny_count):
                minute = random.randint(0, 59)
                sec = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, sec)
                events.append(self.deny_event(ts))

        # Hour 12: Rollback happens
        elif hour == self.cfg.end_hour:
            # 5% suppression — only 3 minutes blocked (12:00-12:03)
            deny_count = max(20, int(normal_dmz_events * 0.05))
            for _ in range(deny_count):
                minute = random.randint(0, 2)
                sec = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, sec)
                events.append(self.deny_event(ts))

            # 12:03 - Rollback command
            ts = time_utils.ts_syslog(day, hour, 3, random.randint(0, 29))
            events.append(self.rollback(ts))

            # 12:04 - Save config
            ts = time_utils.ts_syslog(day, hour, 4, random.randint(0, 29))
            events.append(self.save_config(ts))

            # 12:05 - Logout
            ts = time_utils.ts_syslog(day, hour, 5, random.randint(0, 29))
            events.append(self.admin_logout(ts))

        return events


if __name__ == "__main__":
    scenario = FirewallMisconfigScenario()
    print("Firewall Misconfiguration Scenario")
    print("===================================")
    print(f"Day: {scenario.cfg.day + 1} (index {scenario.cfg.day})")
    print(f"Start hour: {scenario.cfg.start_hour}:15")
    print(f"End hour: {scenario.cfg.end_hour}:05")
    print(f"Admin: {scenario.cfg.admin}")
    print(f"Target IP: {scenario.cfg.target_ip}")
