#!/usr/bin/env python3
"""
Disk Filling Scenario - MON-ATL-01 disk gradually filling up.

Timeline (5 days, resolved):
    Day 1:   Normal operation (45-50% used)
    Day 2:   Gradual increase (55-65% used)
    Day 3:   Warning threshold (70-80% used)
    Day 4:   Critical (85-95% used), I/O contention severe
    Day 5:   Emergency (95-97%), then CLEANUP at 10:00 → back to 45%
    Day 6+:  Normal operation (45% used) - scenario resolved

The scenario simulates a monitoring server where log files grow
uncontrollably due to verbose logging. IT notices and runs cleanup script.
"""

import random
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass


@dataclass
class DiskFillingConfig:
    """Configuration for disk filling scenario."""
    demo_id: str = "disk_filling"

    # Target server (Linux monitoring server in Atlanta)
    host: str = "MON-ATL-01"
    host_ip: str = "10.20.20.30"
    total_disk_gb: int = 500

    # Timeline (0-indexed days)
    start_day: int = 0        # Day 1
    end_day: int = 4          # Day 5 (cleanup happens here)
    cleanup_hour: int = 10    # 10:00 AM - cleanup script runs

    # Threshold days (0-indexed)
    warning_day: int = 2      # Day 3: 70% threshold
    critical_day: int = 3     # Day 4: 85% threshold
    emergency_day: int = 4    # Day 5: 95% threshold (pre-cleanup)


class DiskFillingScenario:
    """
    Disk Filling Scenario with resolution.

    Timeline (5 days):
        Day 1:   Normal operation (45-50% used)
        Day 2:   Gradual increase (55-65% used)
        Day 3:   Warning threshold (70-80% used)
        Day 4:   Critical (85-95% used)
        Day 5:   Emergency → CLEANUP at 10:00 → resolved
        Day 6+:  Normal (45% used)
    """

    def __init__(self, config: Optional[DiskFillingConfig] = None, demo_id_enabled: bool = True):
        self.cfg = config or DiskFillingConfig()
        self.demo_id_enabled = demo_id_enabled

        # Disk progression per day (0-indexed)
        # Each tuple is (low_pct, high_pct) for that day
        self._disk_progression = {
            0: (45, 50),   # Day 1 - normal
            1: (55, 65),   # Day 2 - gradual increase
            2: (70, 80),   # Day 3 - warning threshold
            3: (85, 95),   # Day 4 - critical
            4: (95, 97),   # Day 5 - emergency (before cleanup)
        }

        # Post-cleanup: normal disk usage
        self._normal_disk = (43, 47)

    # =========================================================================
    # DISK PROGRESSION
    # =========================================================================

    def get_disk_base(self, day: int, hour: int = 0) -> tuple:
        """
        Get disk usage range for a given day/hour.
        Returns (low_pct, high_pct) tuple.
        """
        # After scenario ends or after cleanup on day 5
        if day > self.cfg.end_day:
            return self._normal_disk

        # Day 5: check if cleanup has happened
        if day == self.cfg.end_day and hour >= self.cfg.cleanup_hour:
            return self._normal_disk

        return self._disk_progression.get(day, self._normal_disk)

    def is_resolved(self, day: int, hour: int = 0) -> bool:
        """Check if the scenario has been resolved (cleanup completed)."""
        if day > self.cfg.end_day:
            return True
        if day == self.cfg.end_day and hour >= self.cfg.cleanup_hour:
            return True
        return False

    # =========================================================================
    # RESOLUTION EVENTS
    # =========================================================================

    def get_resolution_events(self, day: int) -> List[Dict]:
        """
        Get resolution log events for cleanup day.
        Returns list of events with timestamp info.
        """
        if day != self.cfg.end_day:
            return []

        # Cleanup events at 10:00, 10:05, 10:10
        return [
            {
                "hour": 10, "minute": 0, "second": 0,
                "message": "Disk cleanup initiated by cron job /etc/cron.d/log-cleanup",
                "level": "INFO",
            },
            {
                "hour": 10, "minute": 2, "second": 30,
                "message": "Removing old log files from /var/log/archive older than 30 days",
                "level": "INFO",
            },
            {
                "hour": 10, "minute": 5, "second": 15,
                "message": "Removed 47GB of old log files from /var/log/archive (1,247 files)",
                "level": "INFO",
            },
            {
                "hour": 10, "minute": 7, "second": 45,
                "message": "Compressing remaining logs in /var/log/remote",
                "level": "INFO",
            },
            {
                "hour": 10, "minute": 10, "second": 0,
                "message": "Disk cleanup completed. Usage: 97% -> 45%. Free space: 275GB",
                "level": "INFO",
            },
            {
                "hour": 10, "minute": 10, "second": 5,
                "message": "Alert cleared: Disk usage on MON-ATL-01 returned to normal (45%)",
                "level": "INFO",
            },
        ]

    # =========================================================================
    # ANOMALY DETECTION FUNCTIONS
    # =========================================================================

    def is_active(self, host: str, day: int, hour: int = 0) -> bool:
        """Check if disk filling scenario is active for this host/day/hour."""
        if host != self.cfg.host:
            return False

        # Not active before start or after resolution
        if day < self.cfg.start_day:
            return False

        if self.is_resolved(day, hour):
            return False

        return True

    def get_disk_pct(self, host: str, day: int, hour: int) -> Optional[float]:
        """Get adjusted disk percentage for this host/day/hour."""
        if host != self.cfg.host:
            return None

        low, high = self.get_disk_base(day, hour)

        # Gradual increase throughout the day (before cleanup)
        if not self.is_resolved(day, hour):
            hour_factor = hour / 24.0
            base = low + (high - low) * hour_factor
        else:
            # After cleanup: stable at normal level
            base = (low + high) / 2

        # Add small random variation (+/- 0.5%)
        variation = random.uniform(-0.5, 0.5)
        disk_pct = base + variation

        # Ensure bounds
        return max(40, min(99, disk_pct))

    def get_io_wait_pct(self, host: str, day: int, hour: int) -> float:
        """
        Get I/O wait percentage adjustment when disk is near full.
        Returns: additional I/O wait percentage.
        """
        if host != self.cfg.host:
            return 0.0

        # No I/O impact after resolution
        if self.is_resolved(day, hour):
            return 0.0

        # No I/O impact on day 1
        if day < 1:
            return 0.0

        # Gradual I/O degradation as disk fills
        if day == 1:
            return random.uniform(1, 3)
        if day == 2:
            return random.uniform(5, 10)
        if day == 3:
            return random.uniform(15, 25)
        if day == 4:  # Emergency - before cleanup
            if hour < self.cfg.cleanup_hour:
                return random.uniform(25, 40)
            return 0.0  # After cleanup

        return 0.0

    def has_anomaly(self, host: str, day: int, hour: int = 0) -> str:
        """Check if disk filling anomaly is present (for demo_id tagging)."""
        if self.is_active(host, day, hour):
            return self.cfg.demo_id
        return ""

    # =========================================================================
    # ACCESS LOG INTEGRATION
    # =========================================================================

    def access_should_error(self, day: int, hour: int) -> Tuple[bool, int, float]:
        """Return (should_inject_errors, error_rate_pct, response_time_multiplier).

        MON-ATL-01 is a monitoring server, so direct web impact is limited.
        However, disk full can affect centralized logging and cause slow responses
        when applications try to write logs.

        Timeline:
        - Day 1: Normal (1.0x response time)
        - Day 2: Slight slowdown from I/O contention (1.3x response time)
        - Day 3: Warning threshold (1.5x response time, 5% errors)
        - Day 4: Critical (2.5x response time, 15% errors)
        - Day 5 (before cleanup): Emergency (4.0x response time, 25% errors)
        - Day 5 (after cleanup): Normal (1.0x response time)
        - Day 6+: Normal (1.0x response time)
        """
        # After resolution
        if self.is_resolved(day, hour):
            return (False, 0, 1.0)

        # Day 1 (index 0): Normal operation
        if day == 0:
            return (False, 0, 1.0)

        # Day 2 (index 1): Slight slowdown
        if day == 1:
            return (False, 0, 1.3)

        # Day 3 (index 2): Warning threshold
        if day == 2:
            return (True, 5, 1.5)

        # Day 4 (index 3): Critical
        if day == 3:
            return (True, 15, 2.5)

        # Day 5 (index 4): Emergency (before cleanup)
        if day == 4:
            return (True, 25, 4.0)

        # Should not reach here, but default to normal
        return (False, 0, 1.0)

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    def get_demo_id(self, host: str, day: int, hour: int = 0) -> str:
        """Get demo_id if scenario is active."""
        if self.is_active(host, day, hour):
            return self.cfg.demo_id
        return ""

    def get_severity(self, day: int, hour: int = 0) -> str:
        """Get severity level for alerting purposes."""
        if self.is_resolved(day, hour):
            return "resolved"
        if day < self.cfg.warning_day:
            return "normal"
        if day < self.cfg.critical_day:
            return "warning"
        if day < self.cfg.emergency_day:
            return "critical"
        return "emergency"

    def print_timeline(self):
        """Print scenario timeline for debugging."""
        print("Disk Filling Scenario Timeline (MON-ATL-01)")
        print("=" * 60)
        print()
        print(f"Disk: {self.cfg.total_disk_gb}GB total")
        print(f"Cleanup: Day {self.cfg.end_day + 1} at {self.cfg.cleanup_hour}:00")
        print()
        print("Disk usage progression:")

        for day in range(7):  # Show through day 7 to see resolution
            for hour in [0, 12, 23] if day <= self.cfg.end_day else [12]:
                if day > self.cfg.end_day + 1:
                    continue

                low, high = self.get_disk_base(day, hour)
                severity = self.get_severity(day, hour)
                io_wait = self.get_io_wait_pct(self.cfg.host, day, hour)
                resolved = self.is_resolved(day, hour)

                status = ""
                if resolved:
                    status = " [RESOLVED]"
                elif severity == "warning":
                    status = " [WARNING]"
                elif severity == "critical":
                    status = " [CRITICAL]"
                elif severity == "emergency":
                    status = " [EMERGENCY]"

                used_gb_low = int(self.cfg.total_disk_gb * low / 100)
                used_gb_high = int(self.cfg.total_disk_gb * high / 100)
                avail_gb = self.cfg.total_disk_gb - used_gb_high

                hour_str = f"{hour:02d}:00"
                print(f"  Day {day+1:2d} {hour_str}: {low}-{high}% ({used_gb_low}-{used_gb_high}GB used, "
                      f"~{avail_gb}GB free) I/O wait +{io_wait:.0f}%{status}")

            if day == self.cfg.end_day:
                print(f"         >>> CLEANUP at 10:00 - disk returns to normal <<<")


if __name__ == "__main__":
    scenario = DiskFillingScenario()
    scenario.print_timeline()
