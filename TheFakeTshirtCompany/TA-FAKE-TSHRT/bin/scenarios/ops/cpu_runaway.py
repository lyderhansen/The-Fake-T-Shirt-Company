#!/usr/bin/env python3
"""
CPU Runaway Scenario - SQL-PROD-01 backup job stuck.
Combines functionality from:
  - scenarios/ops/cpu_runaway_perfmon.sh
  - scenarios/ops/cpu_runaway_wineventlog.sh
  - scenarios/ops/cpu_runaway_asa.sh
  - scenarios/ops/cpu_runaway_access.sh
"""

import random
from typing import Tuple, List, Optional
from dataclasses import dataclass

from shared.config import next_cid


@dataclass
class CpuRunawayConfig:
    """Configuration for CPU runaway scenario."""
    demo_id: str = "cpu_runaway"

    # Target server (Boston SQL server)
    host: str = "SQL-PROD-01"
    host_ip: str = "10.10.20.30"

    # Timeline (0-indexed days, so day 10 = human Day 11)
    start_day: int = 10  # Day 11 human-readable
    end_day: int = 11    # Day 12 human-readable
    fix_hour: int = 10
    fix_min: int = 30

    # Backup job start time
    backup_hour: int = 2


class CpuRunawayScenario:
    """
    CPU Runaway Scenario.

    Timeline:
        Day 11 02:00:  Backup job starts, CPU begins climbing
        Day 11 08:00:  Users notice slowness, CPU at 65%
        Day 11 18:00:  CPU at 88%, disk queue building
        Day 12 02:00:  CPU at 92%, memory pressure increasing
        Day 12 08:00:  CPU at 98%, critical alerts firing
        Day 12 10:30:  DBA kills job, restarts SQL service
        Day 12 11:00+: Recovery, CPU drops to 30%, normalizes
    """

    def __init__(self, config: Optional[CpuRunawayConfig] = None, demo_id_enabled: bool = True):
        self.cfg = config or CpuRunawayConfig()
        self.demo_id_enabled = demo_id_enabled

    def _demo_suffix_syslog(self) -> str:
        """Get demo_id suffix for syslog format."""
        if self.demo_id_enabled:
            return f" demo_id={self.cfg.demo_id}"
        return ""

    def _asa_pri(self, severity: int) -> str:
        """Calculate syslog PRI header for ASA logs (local4 facility)."""
        return f"<{20 * 8 + severity}>"

    # =========================================================================
    # CPU ANOMALY FUNCTIONS
    # =========================================================================

    def get_cpu_pct(self, day: int, hour: int, minute: int = 0) -> int:
        """
        Calculate CPU percentage based on day and hour.

        Day 11: 40% at 02:00 -> 90% at 22:00
        Day 12: 92% at 00:00 -> 100% at 10:00 -> 30% at 10:30+ -> 15% at 18:00

        Returns: cpu_percentage (0 = no anomaly)
        """
        # Only affects SQL-PROD-01 on days 11-12
        if day < self.cfg.start_day:
            return 0

        if day > self.cfg.end_day:
            return 0

        # Day 10 (human Day 11): Gradual climb from backup start
        if day == self.cfg.start_day:
            if hour < self.cfg.backup_hour:
                return 0  # Before backup starts

            # Hours since backup started (02:00)
            hours_since = hour - self.cfg.backup_hour

            # CPU climbs from 40% to 90% over 20 hours
            base_cpu = 40 + (hours_since * 25) // 10
            return min(base_cpu, 90)

        # Day 11 (human Day 12): Critical then recovery
        if day == self.cfg.end_day:
            # Before fix time
            if hour < self.cfg.fix_hour or (hour == self.cfg.fix_hour and minute < self.cfg.fix_min):
                # CPU continues climbing to 100%
                base_cpu = 92 + hour
                return min(base_cpu, 100)

            # Just after fix time
            if hour == self.cfg.fix_hour:
                return 30

            # Gradual return to normal
            hours_after_fix = hour - self.cfg.fix_hour
            recovery_cpu = 30 - (hours_after_fix * 2)
            return max(recovery_cpu, 15)

        return 0

    def get_severity(self, day: int, hour: int, minute: int = 0) -> int:
        """
        Get severity level.

        Returns:
            0 = normal
            1 = warning
            2 = critical
            3 = recovery
        """
        if day < self.cfg.start_day:
            return 0

        if day == self.cfg.start_day:
            if hour < self.cfg.backup_hour:
                return 0
            elif hour < 8:
                return 1  # Warning
            else:
                return 2  # Critical

        if day == self.cfg.end_day:
            if hour < self.cfg.fix_hour or (hour == self.cfg.fix_hour and minute < self.cfg.fix_min):
                return 2  # Critical
            else:
                return 3  # Recovery

        return 0

    # =========================================================================
    # MEMORY ANOMALY FUNCTIONS
    # =========================================================================

    def get_memory_pressure(self, day: int, hour: int, minute: int = 0) -> int:
        """
        Memory pressure increases with CPU load.
        Returns: additional memory percentage to add to baseline.
        """
        cpu_pct = self.get_cpu_pct(day, hour, minute)

        if cpu_pct == 0:
            return 0

        # At 100% CPU, add 25% to memory baseline
        return (cpu_pct * 25) // 100

    # =========================================================================
    # DISK ANOMALY FUNCTIONS
    # =========================================================================

    def get_disk_queue_mult(self, day: int, hour: int, minute: int = 0) -> int:
        """
        Disk queue length multiplier during stuck backup.
        Returns: multiplier (1=normal, higher=worse)
        """
        severity = self.get_severity(day, hour, minute)

        return {0: 1, 1: 3, 2: 8, 3: 2}.get(severity, 1)

    def get_disk_io_mult(self, day: int, hour: int, minute: int = 0) -> int:
        """
        Disk I/O bytes multiplier.
        Returns: percentage (100=normal)
        """
        severity = self.get_severity(day, hour, minute)

        return {0: 100, 1: 200, 2: 350, 3: 150}.get(severity, 100)

    # =========================================================================
    # ADJUSTED VALUE FUNCTIONS
    # =========================================================================

    def adjusted_cpu(self, host: str, day: int, hour: int, minute: int = 0,
                     base_min: int = 15, base_max: int = 35) -> Tuple[int, int]:
        """
        Get adjusted CPU values for SQL-PROD-01.
        Returns: (cpu_min, cpu_max) for random range
        """
        if host != self.cfg.host:
            return (base_min, base_max)

        anomaly_cpu = self.get_cpu_pct(day, hour, minute)

        if anomaly_cpu == 0:
            return (base_min, base_max)

        # Set min/max close to target with small variance
        var = 3
        adj_min = max(0, anomaly_cpu - var)
        adj_max = min(100, anomaly_cpu + var)

        return (adj_min, adj_max)

    def adjusted_memory(self, host: str, day: int, hour: int, minute: int = 0,
                        base_min: int = 40, base_max: int = 60) -> Tuple[int, int]:
        """
        Get adjusted Memory values for SQL-PROD-01.
        Returns: (mem_min, mem_max) for random range
        """
        if host != self.cfg.host:
            return (base_min, base_max)

        mem_add = self.get_memory_pressure(day, hour, minute)

        if mem_add == 0:
            return (base_min, base_max)

        adj_min = min(95, base_min + mem_add)
        adj_max = min(98, base_max + mem_add)

        return (adj_min, adj_max)

    def adjusted_disk(self, host: str, day: int, hour: int, minute: int = 0) -> Tuple[int, int]:
        """
        Get disk busy status and I/O multiplier.
        Returns: (busy_flag, io_multiplier)
        """
        if host != self.cfg.host:
            return (0, 100)

        severity = self.get_severity(day, hour, minute)

        if severity == 0:
            return (0, 100)

        io_mult = self.get_disk_io_mult(day, hour, minute)
        return (1, io_mult)

    # =========================================================================
    # HELPER FUNCTIONS
    # =========================================================================

    def is_active(self, day: int, hour: int) -> bool:
        """Check if cpu_runaway scenario is active for given day/hour."""
        severity = self.get_severity(day, hour)
        return severity != 0

    def get_demo_id(self, day: int, hour: int) -> str:
        """Get demo_id if scenario is active."""
        if self.is_active(day, hour):
            return self.cfg.demo_id
        return ""

    def has_anomaly(self, host: str, day: int, hour: int) -> str:
        """Check if any anomaly is present for tagging."""
        if host == self.cfg.host and self.is_active(day, hour):
            return self.cfg.demo_id
        return ""

    def asa_baseline_suppression(self, day: int, hour: int) -> float:
        """Return 0.0-1.0 indicating how much external->DMZ web traffic to suppress.

        SQL-PROD-01 at 100% CPU means the DB can't serve queries. The web app
        (APP-BOS-01) depends on SQL for product lookups, cart, and checkout.
        Connections are established but time out waiting for DB responses,
        so some suppression of successful web sessions is warranted.
        """
        if not self.is_active(day, hour):
            return 0.0

        severity = self.get_severity(day, hour)

        if severity == 1:    # Warning: slow but functioning
            return 0.25
        elif severity == 2:  # Critical: DB unreachable
            return 0.7
        elif severity == 3:  # Recovery
            return 0.05
        return 0.0

    # =========================================================================
    # WINEVENTLOG EVENTS
    # =========================================================================

    def winevent_get_events(self, day: int, hour: int) -> List[dict]:
        """
        Get Windows event log events for CPU runaway scenario.
        Returns list of event dictionaries.
        """
        events = []

        if not self.is_active(day, hour):
            return events

        severity = self.get_severity(day, hour)

        # Day 11 (start_day): Warning/Critical events
        if day == self.cfg.start_day:
            # After backup starts, SQL Server performance events
            if hour >= self.cfg.backup_hour and hour < 8:
                # Warning events - 4-5 per hour
                if random.random() < 0.3:
                    events.append({
                        "event_id": 17883,
                        "source": "MSSQLSERVER",
                        "level": "Warning",
                        "message": "The process appears to be non-yielding on CPU for backup task"
                    })
            elif hour >= 8:
                # Critical events - more frequent
                if random.random() < 0.5:
                    events.append({
                        "event_id": 17883,
                        "source": "MSSQLSERVER",
                        "level": "Warning",
                        "message": "The process appears to be non-yielding on CPU for backup task"
                    })
                if random.random() < 0.3:
                    events.append({
                        "event_id": 833,
                        "source": "MSSQLSERVER",
                        "level": "Warning",
                        "message": f"SQL Server has encountered {random.randint(5, 20)} occurrence(s) of I/O requests taking longer than 15 seconds"
                    })

        # Day 12 (end_day): Critical then recovery
        if day == self.cfg.end_day:
            if severity == 2:  # Critical
                if random.random() < 0.6:
                    events.append({
                        "event_id": 17883,
                        "source": "MSSQLSERVER",
                        "level": "Error",
                        "message": "The process appears to be non-yielding on CPU"
                    })
                if random.random() < 0.4:
                    events.append({
                        "event_id": 19406,
                        "source": "MSSQLSERVER",
                        "level": "Error",
                        "message": "The backup job is not responding"
                    })
            elif severity == 3:  # Recovery
                if hour == self.cfg.fix_hour:
                    events.append({
                        "event_id": 17148,
                        "source": "MSSQLSERVER",
                        "level": "Information",
                        "message": "KILL command issued for SPID 67 (backup job)"
                    })
                    events.append({
                        "event_id": 17147,
                        "source": "MSSQLSERVER",
                        "level": "Information",
                        "message": "SQL Server service restarted successfully"
                    })

        return events

    # =========================================================================
    # ASA EVENTS
    # =========================================================================

    def asa_get_events(self, day: int, hour: int, time_utils) -> List[str]:
        """
        Generate ASA events related to SQL-PROD-01 becoming unresponsive.
        Returns list of syslog strings.
        """
        events = []

        if not self.is_active(day, hour):
            return events

        severity = self.get_severity(day, hour)
        suffix = self._demo_suffix_syslog()

        # During critical phase, generate connection timeout events
        if severity == 2:
            # Apps timing out connecting to SQL-PROD-01
            pri6 = self._asa_pri(6)  # info
            for _ in range(random.randint(3, 8)):
                ts = time_utils.ts_syslog(day, hour, random.randint(0, 59), random.randint(0, 59))
                src_ip = f"10.10.30.{random.randint(20, 50)}"  # Boston user VLAN
                src_port = random.randint(40000, 60000)
                conn_id = next_cid()

                events.append(
                    f'{pri6}{ts} FW-EDGE-01 %ASA-6-302014: Teardown TCP connection {conn_id} '
                    f'for inside:{src_ip}/{src_port} to inside:{self.cfg.host_ip}/1433 '
                    f'duration 0:02:00 bytes 0 SYN Timeout{suffix}'
                )

        return events

    # =========================================================================
    # ACCESS LOG EVENTS
    # =========================================================================

    def access_should_error(self, day: int, hour: int) -> Tuple[bool, int, float]:
        """Return (should_inject_errors, error_rate_pct, response_time_multiplier).

        SQL-PROD-01 at 100% CPU means the database cannot serve queries.
        The e-commerce API (APP-BOS-01) depends on SQL for every product
        lookup, cart operation, and checkout. At critical severity, query
        timeouts cascade into web 503/504 errors.

        Every page that requires a DB query (product pages, cart, checkout)
        will fail when SQL is unresponsive. Only static/cached content might
        still load, but the ordering pipeline is completely broken.
        """
        if not self.is_active(day, hour):
            return (False, 0, 1.0)

        severity = self.get_severity(day, hour)

        if severity == 1:    # Warning: DB slowing, queries timing out
            return (True, 30, 2.5)
        elif severity == 2:  # Critical: DB unreachable, all DB-dependent pages fail
            return (True, 85, 8.0)
        elif severity == 3:  # Recovery: connections draining
            return (True, 5, 1.3)
        else:
            return (False, 0, 1.0)

    def print_timeline(self):
        """Print scenario timeline for debugging."""
        print("CPU Runaway Scenario Timeline (SQL-PROD-01)")
        print("============================================")
        print()
        print("Day 11 (index 10):")
        for hour in [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]:
            cpu = self.get_cpu_pct(10, hour)
            sev = self.get_severity(10, hour)
            sev_txt = {0: "NORMAL", 1: "WARNING", 2: "CRITICAL"}.get(sev, "")
            print(f"  {hour:02d}:00 - CPU: {cpu:3d}% - {sev_txt}")

        print()
        print("Day 12 (index 11):")
        for hour in [0, 2, 4, 6, 8, 10, 11, 12, 14, 16, 18]:
            cpu = self.get_cpu_pct(11, hour)
            sev = self.get_severity(11, hour)
            sev_txt = {0: "NORMAL", 1: "WARNING", 2: "CRITICAL", 3: "RECOVERY"}.get(sev, "")
            if hour == 10:
                print(f"  {hour:02d}:00 - CPU: {cpu:3d}% - {sev_txt}")
                print(f"  {hour:02d}:30 - CPU:  30% - RECOVERY  <<< DBA FIXES")
            else:
                print(f"  {hour:02d}:00 - CPU: {cpu:3d}% - {sev_txt}")


if __name__ == "__main__":
    scenario = CpuRunawayScenario()
    scenario.print_timeline()
