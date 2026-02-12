#!/usr/bin/env python3
"""
DDoS Attack Scenario - Volumetric HTTP flood targeting web servers.

Timeline (Days 18-19, 0-indexed 17-18):
    Day 18, 02:00: Initial probing/scanning from botnet wave 1 IPs
    Day 18, 06:00: Volume ramps up (SYN flood + HTTP flood)
    Day 18, 08:00: Full-scale attack -- ASA rate limiting triggers
    Day 18, 09:00: ServiceNow P1 auto-created (monitoring alerts)
    Day 18, 10:00: Emergency ACL blocks top attack subnets (wave 1)
    Day 18, 12:00: Attacker adapts -- wave 2 from new IPs
    Day 18, 14:00: ISP-level DDoS filtering activated
    Day 18, 15:00: Attack volume drops to ~20% of peak
    Day 18, 18:00: Attack mostly subsided, residual traffic
    Day 19, 00:00-05:00: Low-level residual traffic
    Day 19, 06:00: Attack fully stopped
    Day 19, 08:00: Full recovery, post-incident review
    Day 19, 10:00: Change request for permanent DDoS mitigation

Affected sources:
    - ASA: SYN flood denies, rate limiting, threat detection, emergency ACLs
    - Meraki: IDS alerts (HTTP flood), SD-WAN health degradation
    - Access: 503 errors, long response times, reduced orders
    - Linux: High CPU/network on WEB-01
    - Perfmon: Downstream effects on APP-BOS-01
    - ServiceNow: P1 incidents, emergency change request
"""

import random
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass, field


@dataclass
class DdosAttackConfig:
    """Configuration for DDoS attack scenario."""
    demo_id: str = "ddos_attack"

    # Timeline (0-indexed days)
    start_day: int = 17       # Day 18
    end_day: int = 18         # Day 19

    # Target servers
    web_server_dmz_1: str = "172.16.1.10"   # WEB-01 (DMZ)
    web_server_dmz_2: str = "172.16.1.11"   # WEB-02 (DMZ)
    web_server_public: str = "203.0.113.10"  # Public IP
    app_server_ip: str = "10.10.20.40"       # APP-BOS-01 (downstream)

    # Day 18 timeline hours
    probe_start_hour: int = 2       # 02:00 - initial probing
    ramp_start_hour: int = 6        # 06:00 - volume increases
    full_attack_hour: int = 8       # 08:00 - full scale
    emergency_acl_hour: int = 10    # 10:00 - wave 1 blocked
    wave2_hour: int = 12            # 12:00 - attacker adapts
    isp_filter_hour: int = 14       # 14:00 - ISP filtering
    subsiding_hour: int = 15        # 15:00 - dropping off
    residual_hour: int = 18         # 18:00 - mostly over

    # Day 19 timeline hours
    attack_end_hour: int = 6        # 06:00 - fully stopped
    recovery_hour: int = 8          # 08:00 - confirmed recovery

    # Admin who applies emergency ACLs
    admin: str = "network.admin"

    # Wave 1 botnet IPs (diverse global subnets)
    wave1_ips: list = field(default_factory=lambda: [
        "103.45.67.12",    # China
        "91.134.56.23",    # France
        "45.227.255.34",   # Brazil
        "112.85.42.45",    # China
        "185.156.73.56",   # Russia
        "198.51.100.67",   # EU
        "103.78.12.78",    # Indonesia
        "41.205.45.89",    # Nigeria
        "93.184.216.90",   # Europe
        "202.56.78.101",   # India
    ])

    # Wave 2 botnet IPs (activated after wave 1 blocked)
    wave2_ips: list = field(default_factory=lambda: [
        "176.123.45.12",   # Ukraine
        "31.13.67.23",     # Netherlands
        "115.239.210.34",  # China
        "89.248.167.45",   # Netherlands
        "61.177.172.56",   # China
        "178.128.90.67",   # Germany
        "45.33.32.78",     # US (compromised)
        "118.193.21.89",   # Hong Kong
        "51.15.183.90",    # France
        "122.228.10.101",  # China
    ])


# DDoS-specific IDS signatures for Meraki
DDOS_IDS_SIGNATURES = [
    {"sig": "1:2100366:9", "priority": 1, "msg": "ET DOS HTTP GET flood detected", "ports": [80, 443]},
    {"sig": "1:2100369:7", "priority": 1, "msg": "ET DOS Possible SYN flood detected", "ports": [80, 443]},
    {"sig": "1:2100500:5", "priority": 2, "msg": "ET DOS Excessive SYN rate from single source", "ports": [80, 443]},
    {"sig": "1:2100498:4", "priority": 2, "msg": "ET DOS HTTP flood - high request rate", "ports": [80, 443, 8080]},
]


class DdosAttackScenario:
    """
    DDoS Attack Scenario.

    Simulates a volumetric HTTP flood from a botnet targeting the company's
    DMZ web servers. Attack comes in two waves: wave 1 is blocked by emergency
    ACLs, wave 2 adapts with new IPs until ISP-level filtering is activated.
    """

    def __init__(self, config: Optional[DdosAttackConfig] = None, demo_id_enabled: bool = True):
        self.cfg = config or DdosAttackConfig()
        self.demo_id_enabled = demo_id_enabled

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        if self.demo_id_enabled:
            return f" demo_id={self.cfg.demo_id}"
        return ""

    def _demo_json(self) -> dict:
        """Get demo_id dict for JSON format."""
        return {"demo_id": self.cfg.demo_id} if self.demo_id_enabled else {}

    def _asa_pri(self, severity: int) -> str:
        """Calculate syslog PRI header for ASA logs (local4 facility)."""
        return f"<{20 * 8 + severity}>"

    # =========================================================================
    # ATTACK INTENSITY & IP MANAGEMENT
    # =========================================================================

    def _get_attack_intensity(self, day: int, hour: int) -> float:
        """Get attack intensity (0.0 to 1.0) for a given day/hour.

        This drives all generators -- higher intensity means more events,
        more errors, higher CPU/network impact.
        """
        if day == self.cfg.start_day:
            if hour < self.cfg.probe_start_hour:
                return 0.0
            elif hour < self.cfg.ramp_start_hour:
                return 0.05  # Probing
            elif hour < self.cfg.full_attack_hour:
                return 0.3   # Ramping
            elif hour < self.cfg.emergency_acl_hour:
                return 1.0   # Full attack
            elif hour < self.cfg.wave2_hour:
                return 0.5   # Partial mitigation (wave 1 blocked)
            elif hour < self.cfg.isp_filter_hour:
                return 0.8   # Wave 2
            elif hour < self.cfg.subsiding_hour:
                return 0.4   # ISP filtering active
            elif hour < self.cfg.residual_hour:
                return 0.2   # Subsiding
            else:
                return 0.1   # Residual

        elif day == self.cfg.end_day:
            if hour < self.cfg.attack_end_hour:
                return 0.05  # Overnight residual
            else:
                return 0.0   # Attack stopped

        return 0.0

    def _get_botnet_ips(self, day: int, hour: int) -> List[str]:
        """Get active botnet IPs for a given day/hour.

        Wave 1 active until emergency ACL at hour 10.
        Wave 2 starts at hour 12 after attacker adapts.
        """
        if day == self.cfg.start_day:
            if self.cfg.probe_start_hour <= hour < self.cfg.emergency_acl_hour:
                return self.cfg.wave1_ips
            elif self.cfg.emergency_acl_hour <= hour < self.cfg.wave2_hour:
                # Wave 1 blocked, wave 2 not yet started
                # A few stragglers from wave 1 that weren't fully blocked
                return self.cfg.wave1_ips[:3]
            elif hour >= self.cfg.wave2_hour:
                return self.cfg.wave2_ips
        elif day == self.cfg.end_day:
            if hour < self.cfg.attack_end_hour:
                return self.cfg.wave2_ips[:5]  # Residual subset

        return []

    def _random_botnet_ip(self, day: int, hour: int) -> str:
        """Get a random botnet IP for the current wave."""
        ips = self._get_botnet_ips(day, hour)
        if not ips:
            return "0.0.0.0"
        return random.choice(ips)

    # =========================================================================
    # STATE METHODS
    # =========================================================================

    def is_active(self, day: int, hour: int) -> bool:
        """Check if scenario is active for this day/hour."""
        return self._get_attack_intensity(day, hour) > 0

    def get_demo_id(self, day: int, hour: int) -> Optional[str]:
        """Get demo_id if scenario is active."""
        if self.is_active(day, hour):
            return self.cfg.demo_id
        return None

    # =========================================================================
    # ASA EVENT GENERATORS
    # =========================================================================

    def _syn_flood_deny(self, ts: str, botnet_ip: str) -> str:
        """SYN flood deny event (blocked inbound connection)."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # warning
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([443, 443, 443, 80])  # Mostly HTTPS
        dst_ip = random.choice([self.cfg.web_server_dmz_1, self.cfg.web_server_dmz_2])

        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-106023: Deny tcp src outside:{botnet_ip}/{src_port} "
            f"dst dmz:{dst_ip}/{dst_port} by access-group "
            f'"outside_access_in" [0x0, 0x0]{suffix}'
        )

    def _rate_limit_exceeded(self, ts: str, botnet_ip: str) -> str:
        """Rate limiting triggered."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # warning
        rate = random.randint(500, 5000)

        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-733100: "
            f"[{botnet_ip}] drop rate-1 exceeded. "
            f"Current burst rate is {rate} per second, "
            f"max configured rate is 400{suffix}"
        )

    def _threat_detect_host(self, ts: str, botnet_ip: str) -> str:
        """Threat detection -- host attacking."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # warning
        rate = random.randint(200, 3000)

        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-733101: "
            f"Host {botnet_ip} is attacking. "
            f"Current burst rate is {rate} per second, "
            f"max configured rate is 100{suffix}"
        )

    def _conn_limit_exceeded(self, ts: str, botnet_ip: str) -> str:
        """Duplicate SYN / connection limit event."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # warning
        src_port = random.randint(1024, 65535)
        dst_ip = self.cfg.web_server_dmz_1

        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-419002: "
            f"Received duplicate TCP SYN from outside:{botnet_ip}/{src_port} "
            f"to dmz:{dst_ip}/443 with different initial sequence number{suffix}"
        )

    def _threat_detect_scanning(self, ts: str, botnet_ip: str) -> str:
        """Threat detection -- rate exceeded."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # warning
        rate = random.randint(300, 2000)

        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-733104: "
            f"TD Syslog: SYN Attack: Threat detected from {botnet_ip}. "
            f"Rate: {rate}/sec exceeds burst limit of 100/sec{suffix}"
        )

    def _threat_detect_sweep(self, ts: str, botnet_ip: str) -> str:
        """Threat detection -- host sweep."""
        suffix = self._demo_suffix_syslog()
        pri = self._asa_pri(4)  # warning

        return (
            f"{pri}{ts} FW-EDGE-01 %ASA-4-733105: "
            f"TD Syslog: Host sweep detected from {botnet_ip}. "
            f"Scanning dmz interface{suffix}"
        )

    def _emergency_acl_apply(self, ts: str) -> List[str]:
        """Admin applies emergency block ACL (multiple events)."""
        suffix = self._demo_suffix_syslog()
        pri5 = self._asa_pri(5)  # notice
        pri6 = self._asa_pri(6)  # info
        events = []

        # Admin login
        events.append(
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-605005: Login permitted from 10.10.10.50/52435 '
            f'to inside:10.10.10.1/ssh for user "{self.cfg.admin}"{suffix}'
        )
        # Config mode
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111008: User '{self.cfg.admin}' "
            f"executed the 'configure terminal' command{suffix}"
        )
        # Block ACL for wave 1 subnets
        for ip in self.cfg.wave1_ips[:5]:  # Block top 5 subnets
            subnet = ".".join(ip.split(".")[:3]) + ".0"
            events.append(
                f"{pri5}{ts} FW-EDGE-01 %ASA-5-111010: User '{self.cfg.admin}' executed "
                f"'access-list DDOS_BLOCK line 1 extended deny ip host {subnet} "
                f"any'{suffix}"
            )
        # Apply to interface
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111010: User '{self.cfg.admin}' executed "
            f"'access-group DDOS_BLOCK in interface outside'{suffix}"
        )
        # Save config
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111008: User '{self.cfg.admin}' "
            f"executed the 'write memory' command{suffix}"
        )

        return events

    def _emergency_acl_remove(self, ts: str) -> List[str]:
        """Admin removes emergency ACL (post-incident cleanup, Day 19)."""
        suffix = self._demo_suffix_syslog()
        pri5 = self._asa_pri(5)  # notice
        pri6 = self._asa_pri(6)  # info
        events = []

        events.append(
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-605005: Login permitted from 10.10.10.50/52435 '
            f'to inside:10.10.10.1/ssh for user "{self.cfg.admin}"{suffix}'
        )
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111008: User '{self.cfg.admin}' "
            f"executed the 'configure terminal' command{suffix}"
        )
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111010: User '{self.cfg.admin}' executed "
            f"'no access-group DDOS_BLOCK in interface outside'{suffix}"
        )
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111010: User '{self.cfg.admin}' executed "
            f"'clear access-list DDOS_BLOCK'{suffix}"
        )
        events.append(
            f"{pri5}{ts} FW-EDGE-01 %ASA-5-111008: User '{self.cfg.admin}' "
            f"executed the 'write memory' command{suffix}"
        )
        events.append(
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-315011: SSH session from 10.10.10.50 '
            f'on interface inside for user "{self.cfg.admin}" disconnected by SSH server{suffix}'
        )

        return events

    # =========================================================================
    # MAIN ASA GENERATOR
    # =========================================================================

    def generate_hour(self, day: int, hour: int, time_utils) -> List[str]:
        """Generate ASA events for DDoS scenario for one hour."""
        events = []
        intensity = self._get_attack_intensity(day, hour)

        if intensity <= 0:
            # Day 19 post-incident: remove emergency ACL at recovery hour
            if day == self.cfg.end_day and hour == self.cfg.recovery_hour:
                ts = time_utils.ts_syslog(day, hour, 30, random.randint(0, 29))
                events.extend(self._emergency_acl_remove(ts))
            return events

        botnet_ips = self._get_botnet_ips(day, hour)
        if not botnet_ips:
            return events

        # Scale event count by intensity
        # Peak (1.0) = ~200 events/hour, probing (0.05) = ~10
        base_events = max(5, int(intensity * 200))

        # Generate deny events (bulk of the traffic)
        deny_count = int(base_events * 0.6)
        for _ in range(deny_count):
            minute = random.randint(0, 59)
            sec = random.randint(0, 59)
            ts = time_utils.ts_syslog(day, hour, minute, sec)
            ip = random.choice(botnet_ips)
            events.append(self._syn_flood_deny(ts, ip))

        # Rate limiting events (when intensity >= 0.3)
        if intensity >= 0.3:
            rate_count = max(2, int(base_events * 0.15))
            for _ in range(rate_count):
                minute = random.randint(0, 59)
                sec = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, sec)
                ip = random.choice(botnet_ips)
                events.append(self._rate_limit_exceeded(ts, ip))

        # Threat detection events (when intensity >= 0.3)
        if intensity >= 0.3:
            threat_count = max(1, int(base_events * 0.1))
            for _ in range(threat_count):
                minute = random.randint(0, 59)
                sec = random.randint(0, 59)
                ts = time_utils.ts_syslog(day, hour, minute, sec)
                ip = random.choice(botnet_ips)
                event_type = random.choices(
                    ["host", "scan", "sweep", "conn"],
                    weights=[40, 30, 15, 15]
                )[0]
                if event_type == "host":
                    events.append(self._threat_detect_host(ts, ip))
                elif event_type == "scan":
                    events.append(self._threat_detect_scanning(ts, ip))
                elif event_type == "sweep":
                    events.append(self._threat_detect_sweep(ts, ip))
                else:
                    events.append(self._conn_limit_exceeded(ts, ip))

        # Emergency ACL application (Day 18, hour 10, minute ~5)
        if day == self.cfg.start_day and hour == self.cfg.emergency_acl_hour:
            ts = time_utils.ts_syslog(day, hour, 5, random.randint(0, 29))
            events.extend(self._emergency_acl_apply(ts))

        return events

    # =========================================================================
    # ACCESS LOG INTEGRATION
    # =========================================================================

    def access_should_error(self, day: int, hour: int) -> Tuple[bool, int, float]:
        """Return (should_inject_errors, error_rate_pct, response_time_multiplier).

        During the DDoS attack, web servers are overwhelmed causing 503 errors
        and very long response times. Error rate scales with intensity.

        Revenue impact: Orders only created on HTTP 200 for /checkout/complete,
        so high error rates automatically reduce order volume.
        """
        intensity = self._get_attack_intensity(day, hour)

        if intensity >= 0.8:
            return (True, 60, 10.0)   # Peak attack / wave 2
        elif intensity >= 0.5:
            return (True, 40, 5.0)    # Partial mitigation
        elif intensity >= 0.3:
            return (True, 20, 3.0)    # Ramping / ISP filtering
        elif intensity >= 0.05:
            return (True, 5, 2.0)     # Probing / residual
        else:
            return (False, 0, 1.0)

    # =========================================================================
    # MERAKI INTEGRATION
    # =========================================================================

    def meraki_hour(self, day: int, hour: int, time_utils) -> Dict[str, list]:
        """Generate Meraki events for DDoS scenario.

        Returns dict with "mx" key containing MX appliance events.
        Uses the same return format as ransomware_scenario.meraki_hour().
        """
        result = {"mx": []}
        intensity = self._get_attack_intensity(day, hour)

        if intensity <= 0:
            return result

        botnet_ips = self._get_botnet_ips(day, hour)
        if not botnet_ips:
            return result

        # IDS alerts (5-15 per hour at peak, scaled by intensity)
        ids_count = max(1, int(intensity * 15))
        for _ in range(ids_count):
            minute = random.randint(0, 59)
            sec = random.randint(0, 59)
            ts = time_utils.ts_iso(day, hour, minute, sec)

            sig = random.choice(DDOS_IDS_SIGNATURES)
            src_ip = random.choice(botnet_ips)
            src_port = random.randint(1024, 65535)
            dst_ip = self.cfg.web_server_public
            dst_port = random.choice(sig["ports"])

            # Build IDS event dict directly (matching mx_ids_event format)
            event = {
                "occurredAt": ts,
                "networkId": "N_FakeTShirtCo_BOS",
                "type": "security_event",
                "subtype": "ids_alert",
                "description": sig["msg"],
                "category": "appliance",
                "deviceSerial": "MX-BOS-01",
                "deviceName": "MX-BOS-01",
                "eventData": {
                    "srcIp": src_ip,
                    "srcPort": str(src_port),
                    "destIp": dst_ip,
                    "destPort": str(dst_port),
                    "protocol": "tcp",
                    "direction": "ingress",
                    "priority": str(sig["priority"]),
                    "blocked": True,
                    "message": sig["msg"],
                    "signature": sig["sig"],
                },
            }
            event.update(self._demo_json())
            result["mx"].append(event)

        # SD-WAN health degradation (2-4 events per hour during high intensity)
        if intensity >= 0.3:
            health_count = random.randint(2, 4)
            wan_links = ["Comcast", "AT&T"]
            for _ in range(health_count):
                minute = random.randint(0, 59)
                sec = random.randint(0, 59)
                ts = time_utils.ts_iso(day, hour, minute, sec)
                wan = random.choice(wan_links)

                # Degrade metrics based on intensity
                latency = random.uniform(50, 200) * intensity + 10
                jitter = random.uniform(10, 50) * intensity
                loss = random.uniform(2, 15) * intensity
                status = "degraded" if loss > 2 else "active"

                event = {
                    "occurredAt": ts,
                    "networkId": "N_FakeTShirtCo_BOS",
                    "type": "sd_wan_health",
                    "category": "appliance",
                    "deviceSerial": "MX-BOS-01",
                    "deviceName": "MX-BOS-01",
                    "eventData": {
                        "wan": wan,
                        "latencyMs": round(latency, 1),
                        "jitterMs": round(jitter, 1),
                        "lossPercent": round(loss, 2),
                        "utilizationPercent": round(min(98, 40 + intensity * 55), 1),
                        "status": status,
                    },
                }
                event.update(self._demo_json())
                result["mx"].append(event)

        # SD-WAN failover events when primary WAN is saturated
        # Comcast (primary) fails over to AT&T (backup) at peak attack
        prev_intensity = self._get_attack_intensity(day, hour - 1) if hour > 0 else (
            self._get_attack_intensity(day - 1, 23) if day > self.cfg.start_day else 0.0
        )

        if intensity >= 0.8 and prev_intensity < 0.8:
            # Failover: Comcast saturated, switch to AT&T
            minute = random.randint(2, 8)
            sec = random.randint(0, 59)
            ts = time_utils.ts_iso(day, hour, minute, sec)
            event = {
                "occurredAt": ts,
                "networkId": "N_FakeTShirtCo_BOS",
                "type": "sd_wan_failover",
                "description": "SD-WAN failover from Comcast to AT&T",
                "category": "appliance",
                "deviceSerial": "MX-BOS-01",
                "deviceName": "MX-BOS-01",
                "eventData": {
                    "from_wan": "Comcast",
                    "to_wan": "AT&T",
                    "reason": "WAN link saturated - packet loss exceeds threshold"
                }
            }
            event.update(self._demo_json())
            result["mx"].append(event)

        elif intensity < 0.3 and prev_intensity >= 0.3 and prev_intensity < 0.8:
            # No failback needed -- wasn't in failover state
            pass

        elif intensity < 0.5 and prev_intensity >= 0.8:
            # Failback: attack subsiding, restore primary WAN
            minute = random.randint(10, 25)
            sec = random.randint(0, 59)
            ts = time_utils.ts_iso(day, hour, minute, sec)
            event = {
                "occurredAt": ts,
                "networkId": "N_FakeTShirtCo_BOS",
                "type": "sd_wan_failover",
                "description": "SD-WAN failover from AT&T to Comcast",
                "category": "appliance",
                "deviceSerial": "MX-BOS-01",
                "deviceName": "MX-BOS-01",
                "eventData": {
                    "from_wan": "AT&T",
                    "to_wan": "Comcast",
                    "reason": "Primary WAN recovered - restoring preferred path"
                }
            }
            event.update(self._demo_json())
            result["mx"].append(event)

        return result

    # =========================================================================
    # LINUX INTEGRATION
    # =========================================================================

    def linux_cpu_adjustment(self, host: str, day: int, hour: int) -> int:
        """Get CPU adjustment for Linux servers (WEB-01 target).

        Returns additional CPU percentage points to add to baseline.
        """
        if host != "WEB-01":
            return 0

        intensity = self._get_attack_intensity(day, hour)

        if intensity >= 0.8:
            return 40    # CPU 70-95%
        elif intensity >= 0.5:
            return 25    # CPU 55-80%
        elif intensity >= 0.3:
            return 15    # CPU 45-65%
        elif intensity > 0:
            return 5     # Slight increase
        return 0

    def linux_network_multiplier(self, host: str, day: int, hour: int) -> int:
        """Get network traffic multiplier for Linux servers (WEB-01 target).

        Returns percentage multiplier (100 = normal, 1000 = 10x).
        """
        if host != "WEB-01":
            return 100

        intensity = self._get_attack_intensity(day, hour)

        if intensity >= 0.8:
            return 1000  # 10x
        elif intensity >= 0.5:
            return 500   # 5x
        elif intensity >= 0.3:
            return 300   # 3x
        elif intensity > 0:
            return 200   # 2x
        return 100

    # =========================================================================
    # PERFMON INTEGRATION
    # =========================================================================

    def perfmon_cpu_adjustment(self, host: str, day: int, hour: int) -> int:
        """Get CPU adjustment for Windows servers (APP-BOS-01 downstream).

        APP-BOS-01 experiences elevated CPU from retrying failed connections
        to the overwhelmed WEB-01.
        """
        if host != "APP-BOS-01":
            return 0

        intensity = self._get_attack_intensity(day, hour)

        if intensity >= 0.8:
            return 15    # Noticeable downstream impact
        elif intensity >= 0.5:
            return 10
        elif intensity >= 0.3:
            return 5
        return 0

    # =========================================================================
    # DISPLAY / DEBUG
    # =========================================================================

    def print_timeline(self):
        """Print scenario timeline for debugging."""
        print("DDoS Attack Scenario Timeline")
        print("=" * 60)
        print(f"Day 18 (index {self.cfg.start_day}):")
        for hour in range(24):
            intensity = self._get_attack_intensity(self.cfg.start_day, hour)
            if intensity > 0:
                ips = self._get_botnet_ips(self.cfg.start_day, hour)
                bar = "#" * int(intensity * 40)
                print(f"  {hour:02d}:00  intensity={intensity:.2f}  IPs={len(ips):2d}  {bar}")
        print(f"\nDay 19 (index {self.cfg.end_day}):")
        for hour in range(24):
            intensity = self._get_attack_intensity(self.cfg.end_day, hour)
            if intensity > 0:
                ips = self._get_botnet_ips(self.cfg.end_day, hour)
                bar = "#" * int(intensity * 40)
                print(f"  {hour:02d}:00  intensity={intensity:.2f}  IPs={len(ips):2d}  {bar}")
            elif hour == self.cfg.attack_end_hour:
                print(f"  {hour:02d}:00  -- Attack stopped --")
            elif hour == self.cfg.recovery_hour:
                print(f"  {hour:02d}:00  -- Full recovery / ACL cleanup --")
                break


if __name__ == "__main__":
    scenario = DdosAttackScenario()
    scenario.print_timeline()

    print("\naccess_should_error samples:")
    for day in [17, 18]:
        for hour in [2, 6, 8, 10, 12, 14, 15, 18, 0, 6]:
            if day == 18 and hour > 6:
                break
            result = scenario.access_should_error(day, hour)
            print(f"  Day {day+1} {hour:02d}:00 -> {result}")
