#!/usr/bin/env python3
"""
Memory Leak Scenario - WEB-01 memory leak causing OOM.

Timeline (Days 7-10, resolved):
    Day 7:   Gradual increase (55-65% used)
    Day 8:   Concerning levels (65-75% used), swap starts 2-4GB
    Day 9:   Critical (80-90% used), swap 8-12GB
    Day 10:  Pre-OOM climb to 96-99%, OOM crash at 14:00, restart at 14:05
    Day 11+: Normal after restart (50-55% used)

The scenario simulates a memory leak in the nginx/application layer
that is fixed by restarting the service.
"""

import random
from typing import Tuple, List, Optional, Dict
from dataclasses import dataclass


@dataclass
class MemoryLeakConfig:
    """Configuration for memory leak scenario."""
    demo_id: str = "memory_leak"

    # Target server (64GB RAM Linux web server)
    host: str = "WEB-01"
    host_ip: str = "172.16.1.10"
    total_memory_gb: int = 64

    # Timeline (0-indexed days)
    start_day: int = 5         # Day 6 (subtle onset), ramps through Day 7+
    end_day: int = 9           # Day 10 (OOM + restart here)
    oom_day: int = 9           # Day 10 (0-indexed)
    oom_hour: int = 14         # 2 PM
    restart_hour: int = 14     # Service restart at 14:05 (same hour)


class MemoryLeakScenario:
    """
    Memory Leak Scenario with resolution.

    Timeline (Days 7-10):
        Day 7:   Gradual increase (55-65% used)
        Day 8:   Concerning levels (65-75% used), swap starts
        Day 9:   Critical (80-90% used), heavy swap
        Day 10:  OOM crash at 14:00 -> restart at 14:05 -> resolved
        Day 11+: Normal after restart (50-55% used)
    """

    def __init__(self, config: Optional[MemoryLeakConfig] = None, demo_id_enabled: bool = True):
        self.cfg = config or MemoryLeakConfig()
        self.demo_id_enabled = demo_id_enabled

        # Web ports for ASA events
        self.web_ports = [80, 443, 8443]

        # Timeout reasons
        self.timeout_reasons = [
            "TCP FINs",
            "TCP Reset-O",
            "TCP Reset-I",
            "idle timeout",
            "SYN Timeout"
        ]

        # Customer IP prefixes
        self.customer_prefixes = ["174.63.88", "71.222.45", "108.28.163", "98.45.12", "73.189.44"]

        # Memory progression per day (0-indexed, scenario starts at day 6)
        self._memory_progression = {
            6: (55, 65),   # Day 7 - gradual increase
            7: (65, 75),   # Day 8 - concerning
            8: (80, 90),   # Day 9 - critical
            9: (96, 99),   # Day 10 - pre-OOM (before crash)
        }

        # Post-restart: normal memory usage
        self._normal_memory = (50, 55)

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        if self.demo_id_enabled:
            return f" demo_id={self.cfg.demo_id}"
        return ""

    def _asa_pri(self, severity: int) -> str:
        """Calculate syslog PRI header for ASA logs (local4 facility)."""
        return f"<{20 * 8 + severity}>"

    # =========================================================================
    # MEMORY PROGRESSION
    # =========================================================================

    def get_memory_base(self, day: int, hour: int = 0) -> Tuple[int, int]:
        """
        Get memory usage range for a given day/hour.
        Returns (low_pct, high_pct) tuple.
        """
        # Before scenario starts
        if day < self.cfg.start_day:
            return self._normal_memory

        # After scenario ends (restart completed)
        if self.is_resolved(day, hour):
            return self._normal_memory

        return self._memory_progression.get(day, self._normal_memory)

    def is_resolved(self, day: int, hour: int = 0) -> bool:
        """Check if the scenario has been resolved (service restarted).

        OOM crash at 14:00, restart completes at 14:05 — resolved within same hour.
        get_memory_pct() returns 52% at hour 14, so is_resolved must agree.
        """
        if day > self.cfg.oom_day:
            return True
        if day == self.cfg.oom_day and hour >= self.cfg.restart_hour:
            # Resolved after restart at 14:05 (same hour as OOM)
            return True
        return False

    def get_memory_range(self, day: int) -> int:
        """Get memory variation range for a day."""
        if day < self.cfg.start_day:
            return 5
        if day == 6:
            return 10
        if day == 7:
            return 10
        if day == 8:
            return 10
        if day == 9:
            return 3  # Tight range pre-OOM
        return 5

    # =========================================================================
    # RESOLUTION EVENTS
    # =========================================================================

    def get_resolution_events(self, day: int) -> List[Dict]:
        """
        Get resolution log events for OOM day.
        Returns list of events with timestamp info.
        """
        if day != self.cfg.oom_day:
            return []

        # OOM and restart events
        return [
            {
                "hour": 14, "minute": 0, "second": 15,
                "message": "kernel: Out of memory: Kill process 12847 (nginx) score 892 or sacrifice child",
                "level": "CRIT",
            },
            {
                "hour": 14, "minute": 0, "second": 16,
                "message": "kernel: Killed process 12847 (nginx) total-vm:48234567kB, anon-rss:41234567kB, file-rss:12345kB",
                "level": "CRIT",
            },
            {
                "hour": 14, "minute": 0, "second": 20,
                "message": "systemd[1]: nginx.service: Main process exited, code=killed, status=9/KILL",
                "level": "ERR",
            },
            {
                "hour": 14, "minute": 0, "second": 21,
                "message": "systemd[1]: nginx.service: Failed with result 'signal'.",
                "level": "ERR",
            },
            {
                "hour": 14, "minute": 5, "second": 0,
                "message": "systemd[1]: Starting nginx.service - A high performance web server and a reverse proxy server...",
                "level": "INFO",
            },
            {
                "hour": 14, "minute": 5, "second": 3,
                "message": "nginx[13001]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
                "level": "INFO",
            },
            {
                "hour": 14, "minute": 5, "second": 5,
                "message": "systemd[1]: Started nginx.service - A high performance web server and a reverse proxy server.",
                "level": "INFO",
            },
            {
                "hour": 14, "minute": 5, "second": 10,
                "message": "WEB-01 nginx: Server startup complete. Memory usage: 52%. Listening on ports 80, 443, 8443",
                "level": "INFO",
            },
            {
                "hour": 14, "minute": 10, "second": 0,
                "message": "Alert cleared: Memory usage on WEB-01 returned to normal (52%)",
                "level": "INFO",
            },
        ]

    # =========================================================================
    # ANOMALY DETECTION FUNCTIONS
    # =========================================================================

    def is_active(self, host: str, day: int, hour: int = 0) -> bool:
        """Check if memory leak scenario is active for this host/day/hour."""
        if host != self.cfg.host:
            return False

        # Not active before start
        if day < self.cfg.start_day:
            return False

        # Not active after resolution
        if self.is_resolved(day, hour):
            return False

        return True

    def get_memory_pct(self, host: str, day: int, hour: int) -> Optional[int]:
        """Get adjusted memory percentage for this host/day/hour."""
        if host != self.cfg.host:
            return None

        low, high = self.get_memory_base(day, hour)

        # After restart - stable at normal level
        if self.is_resolved(day, hour):
            return (low + high) // 2 + random.randint(-2, 2)

        # Day 9 special handling - OOM event
        if day == self.cfg.oom_day:
            if hour < self.cfg.oom_hour:
                # Climbing to 98-99% before crash
                base = 96 + (hour // 7)
                return min(base + random.randint(0, 2), 99)
            elif hour == self.cfg.oom_hour:
                # OOM hour - check minute for crash vs recovery
                return 52  # After restart within the hour
            else:
                # After restart - back to normal
                return 52 + random.randint(-2, 3)

        # Normal progression during scenario
        range_val = high - low
        hour_factor = hour / 24.0
        base = low + int(range_val * hour_factor)
        variation = random.randint(-2, 2)

        return max(40, min(99, base + variation))

    def get_cpu_adjustment(self, host: str, day: int, hour: int) -> int:
        """
        Get CPU adjustment (elevated when memory is critical due to swapping).
        Returns: additional CPU percentage to add.
        """
        if host != self.cfg.host:
            return 0

        if self.is_resolved(day, hour):
            return 0

        if day == 7:  # Day 8
            return random.randint(3, 8)

        if day == 8:  # Day 9
            return random.randint(8, 15)

        if day == self.cfg.oom_day:
            if hour < self.cfg.oom_hour:
                return random.randint(15, 25)
            return 0

        return 0

    def is_oom_event(self, host: str, day: int, hour: int) -> bool:
        """Check if OOM event should occur this hour."""
        if host != self.cfg.host:
            return False
        return day == self.cfg.oom_day and hour == self.cfg.oom_hour

    def has_anomaly(self, host: str, day: int, hour: int = 0) -> str:
        """Check if any memory leak anomaly is present (for demo_id tagging)."""
        if self.is_active(host, day, hour):
            return self.cfg.demo_id
        return ""

    # =========================================================================
    # SWAP USAGE
    # =========================================================================

    def get_swap_kb(self, host: str, day: int, hour: int) -> int:
        """
        Get swap usage in KB (increases as memory fills).
        64GB server with realistic swap progression.
        """
        if host != self.cfg.host:
            return 0

        # Before scenario or after resolution
        if day < self.cfg.start_day or self.is_resolved(day, hour):
            return 0

        if day == 6:  # Day 7
            # No swap yet
            return 0

        if day == 7:  # Day 8
            # Starting to swap (2-4 GB)
            return random.randint(2097152, 4194304)

        if day == 8:  # Day 9
            # Heavy swapping (8-12 GB)
            return random.randint(8388608, 12582912)

        if day == self.cfg.oom_day:  # Day 9
            if hour < self.cfg.oom_hour:
                # Pre-OOM: Critical swap (15-25 GB)
                return random.randint(15728640, 26214400)
            else:
                # After restart - no swap
                return 0

        return 0

    # =========================================================================
    # ASA EVENTS
    # =========================================================================

    def asa_events_per_day(self, day: int) -> int:
        """Get number of timeout events for this day."""
        if day < self.cfg.start_day:
            return 0
        if day == 6:  # Day 7
            return 30
        if day == 7:  # Day 8
            return 80
        if day == 8:  # Day 9
            return 150
        if day == self.cfg.oom_day:  # Day 9
            return 250
        return 0

    def asa_is_active(self, day: int, hour: int) -> bool:
        """Check if ASA scenario is active."""
        if self.is_resolved(day, hour):
            return False
        return self.asa_events_per_day(day) > 0

    def _random_customer_ip(self) -> str:
        """Get a random external customer IP."""
        prefix = random.choice(self.customer_prefixes)
        return f"{prefix}.{random.randint(1, 254)}"

    def asa_teardown_event(self, ts: str, reason: str) -> str:
        """Generate a TCP teardown event (timeout/reset)."""
        suffix = self._demo_suffix_syslog()
        pri6 = self._asa_pri(6)  # info

        customer_ip = self._random_customer_ip()
        customer_port = random.randint(1024, 61024)
        server_port = random.choice(self.web_ports)
        conn_id = random.randint(100000, 999999)
        duration = random.randint(1, 30)
        bytes_val = random.randint(0, 5000)

        return (
            f'{pri6}{ts} FW-EDGE-01 %ASA-6-302014: Teardown TCP connection {conn_id} '
            f'for outside:{customer_ip}/{customer_port} to dmz:{self.cfg.host_ip}/{server_port} '
            f'duration {duration}:00:00 bytes {bytes_val} {reason}{suffix}'
        )

    def asa_no_connection_event(self, ts: str) -> str:
        """Generate a 'no matching connection' event (server unresponsive)."""
        suffix = self._demo_suffix_syslog()
        pri4 = self._asa_pri(4)  # warning

        customer_ip = self._random_customer_ip()
        customer_port = random.randint(1024, 61024)
        server_port = random.choice(self.web_ports)

        return (
            f'{pri4}{ts} FW-EDGE-01 %ASA-4-313005: No matching connection for TCP '
            f'from outside:{customer_ip}/{customer_port} to dmz:{self.cfg.host_ip}/{server_port}{suffix}'
        )

    def asa_generate_hour(self, day: int, hour: int, time_utils) -> List[str]:
        """Generate ASA events for an hour."""
        events = []

        if not self.asa_is_active(day, hour):
            return events

        daily_events = self.asa_events_per_day(day)

        # Day 9 special handling - OOM at 14:00
        if day == self.cfg.oom_day:
            if hour < self.cfg.oom_hour:
                # Pre-OOM: increasing timeouts
                hourly_events = 10 + hour
            elif hour == self.cfg.oom_hour:
                # OOM hour: burst of failures, then recovery
                hourly_events = 40
            else:
                # Post-restart: tapering off
                hourly_events = max(3, 20 - (hour - self.cfg.restart_hour) * 4)
        else:
            # Normal degradation days
            if 8 <= hour <= 20:
                # More events during business hours
                hourly_events = daily_events // 12 + random.randint(-2, 2)
                hourly_events = max(1, hourly_events)
            else:
                hourly_events = max(1, daily_events // 24)

        # Generate events
        for _ in range(hourly_events):
            minute = random.randint(0, 59)
            sec = random.randint(0, 59)
            ts = time_utils.ts_syslog(day, hour, minute, sec)

            # OOM hour, first 5 minutes: server down - "no matching connection"
            if (day == self.cfg.oom_day and hour == self.cfg.oom_hour and minute < 5):
                events.append(self.asa_no_connection_event(ts))
            else:
                reason = random.choice(self.timeout_reasons)
                events.append(self.asa_teardown_event(ts, reason))

        return events

    # =========================================================================
    # ACCESS LOG INTEGRATION
    # =========================================================================

    def access_should_error(self, day: int, hour: int) -> Tuple[bool, int, float]:
        """Return (should_inject_errors, error_rate_pct, response_time_multiplier).

        Timeline for WEB-01:
        - Day 1-5: Normal (1.0x response time) - before scenario
        - Day 6: Subtle onset (1.05x response time) - barely noticeable
        - Day 7: Gradual increase (1.2x response time), 0% errors
        - Day 8: Concerning levels (1.5x response time), 3% errors
        - Day 9: Critical (2.0x response time), 8% errors
        - Day 10, 00:00-13:59: Pre-OOM (3.0x), 20% errors
        - Day 10, 14:00-14:04: OOM crash -> 80% error rate
        - Day 10, 14:05+: Server recovering -> back to normal
        - Day 11+: Normal (1.0x response time)
        """
        # Before scenario or after resolution
        if day < self.cfg.start_day or self.is_resolved(day, hour):
            return (False, 0, 1.0)

        # Day 6 (index 5): Subtle onset - barely perceptible slowdown
        if day == 5:
            return (False, 0, 1.05)

        # Day 7 (index 6): Gradual increase - noticeable slowdown
        if day == 6:
            return (True, 0, 1.2)

        # Day 8 (index 7): Concerning
        if day == 7:
            return (True, 3, 1.5)

        # Day 9 (index 8): Critical
        if day == 8:
            return (True, 8, 2.0)

        # Day 10 (index 9): OOM day
        if day == self.cfg.oom_day:
            if hour < self.cfg.oom_hour:
                # Pre-OOM: climbing to crash
                error_rate = 15 + (hour // 2)
                return (True, min(error_rate, 25), 3.0)

            elif hour == self.cfg.oom_hour:
                # OOM crash hour - massive failures in first few minutes,
                # then recovery after restart
                return (True, 50, 5.0)

            else:
                # Post-restart - back to normal
                return (False, 0, 1.0)

        # Should not reach here
        return (False, 0, 1.0)

    # =========================================================================
    # LINUX VMSTAT ADJUSTMENTS
    # =========================================================================

    def vmstat_free_adjustment(self, host: str, day: int, hour: int, total_kb: int) -> int:
        """
        Get adjusted vmstat values for memory leak.
        Returns: target used memory in KB.
        """
        if host != self.cfg.host:
            return 0

        mem_pct = self.get_memory_pct(host, day, hour)
        if mem_pct is None:
            return 0

        # Calculate how much memory should be used
        return (total_kb * mem_pct) // 100

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    def get_demo_id(self, day: int, hour: int) -> str:
        """Get demo_id if scenario is active."""
        if day >= self.cfg.start_day and not self.is_resolved(day, hour):
            return self.cfg.demo_id
        return ""

    def get_severity(self, day: int, hour: int = 0) -> str:
        """Get severity level for alerting purposes."""
        if self.is_resolved(day, hour):
            return "resolved"
        if day < self.cfg.start_day:
            return "normal"
        if day == 6:
            return "warning"
        if day == 7:
            return "warning"
        if day == 8:
            return "critical"
        if day == 9:
            return "emergency"
        return "normal"

    def print_timeline(self):
        """Print scenario timeline for debugging."""
        print("Memory Leak Scenario Timeline (WEB-01)")
        print("=" * 60)
        print()
        print(f"Memory: {self.cfg.total_memory_gb}GB total")
        print(f"OOM crash: Day {self.cfg.oom_day + 1} at {self.cfg.oom_hour}:00")
        print(f"Restart: Day {self.cfg.oom_day + 1} at {self.cfg.restart_hour}:05")
        print()
        print("Memory progression:")

        for day in range(6, 12):  # Show day 7 through day 12
            for hour in [0, 12, 14, 15, 23] if day == self.cfg.oom_day else [12]:
                low, high = self.get_memory_base(day, hour)
                swap_kb = self.get_swap_kb(self.cfg.host, day, hour)
                swap_gb = swap_kb // 1048576
                resolved = self.is_resolved(day, hour)
                severity = self.get_severity(day, hour)

                status = ""
                if resolved:
                    status = " [RESOLVED]"
                elif day == self.cfg.oom_day and hour == self.cfg.oom_hour:
                    status = " <<< OOM CRASH + RESTART"
                elif severity == "warning":
                    status = " [WARNING]"
                elif severity == "critical":
                    status = " [CRITICAL]"
                elif severity == "emergency":
                    status = " [EMERGENCY]"

                hour_str = f"{hour:02d}:00"
                print(f"  Day {day+1:2d} {hour_str}: Memory {low}-{high}%, "
                      f"Swap ~{swap_gb}GB{status}")


if __name__ == "__main__":
    scenario = MemoryLeakScenario()
    scenario.print_timeline()
