#!/usr/bin/env python3
"""
Interactive TUI for Splunk Log Generator using curses (Python stdlib).
No external dependencies required!

Layout (3-col top, 2-col bottom with double-line box drawing):
  ╔═══════════════╦══════════════════════════╦═══════════════╗
  ║  > GROUPS      ║  > SOURCES (2-col)        ║  * SCENARIOS   ║
  ║  [x] all       ║  [ ] asa    [ ] sysmon    ║  [x] all       ║
  ║  [ ] cloud     ║  [ ] aws    [ ] meraki    ║  [ ] exfil     ║
  ║  [ ] network   ║  [ ] gcp    [ ] webex     ║  [ ] ransom..  ║
  ╠═══════════════╩═══════╦═══════╩═══════════════╣
  ║  # CONFIGURATION       ║  ~ MERAKI HEALTH       ║
  ║  [TEST] Output -> tmp/ ║  [x] Enable Health     ║
  ║  Start Date: 2026-01-01║  Interval: 15 min      ║
  ╚════════════════════════╩════════════════════════╝

Usage:
    python3 tui_generate.py
    python3 main_generate.py --tui
"""

import curses
import math
import random
import sys
import time as time_mod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from main_generate import GENERATORS, SOURCE_GROUPS, GENERATOR_DEPENDENCIES, _estimate_run
from scenarios.registry import IMPLEMENTED_SCENARIOS, SCENARIOS
from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, GENERATOR_OUTPUT_FILES

# ═══════════════════════════════════════════════════════════════════════
# ASCII ART
# ═══════════════════════════════════════════════════════════════════════

LOGO_ASCII = [
    "  _____ _            _____     _          _____     ____  _          _      ____",
    " |_   _| |__   ___  |  ___|_ _| | _____  |_   _|__ / ___|| |__  _ __| |_   / ___|___",
    "   | | | '_ \\ / _ \\ | |_ / _` | |/ / _ \\   | ||___|\\___ \\| '_ \\| '__| __| | |   / _ \\",
    "   | | | | | |  __/ |  _| (_| |   <  __/   | |     ___) | | | | |  | |_  | |__| (_) |",
    "   |_| |_| |_|\\___| |_|  \\__,_|_|\\_\\___|   |_|    |____/|_| |_|_|   \\__|  \\____\\___/",
]

TSHIRT_ASCII = [
    "   ___ ___",
    " /| |/|\\| |\\",
    "/_| ` |.` |_\\",
    "  |   |.  |",
    "  |   |.  |",
    "  |___|.__|",
]

# ═══════════════════════════════════════════════════════════════════════
# BOX DRAWING CHARACTERS
# ═══════════════════════════════════════════════════════════════════════

# Double-line box drawing
BOX_TL = "\u2554"    # Top-left
BOX_TR = "\u2557"    # Top-right
BOX_BL = "\u255a"    # Bottom-left
BOX_BR = "\u255d"    # Bottom-right
BOX_H = "\u2550"     # Horizontal
BOX_V = "\u2551"     # Vertical
BOX_TJ = "\u2566"    # Top junction
BOX_BJ = "\u2569"    # Bottom junction
BOX_LJ = "\u2560"    # Left junction
BOX_RJ = "\u2563"    # Right junction
BOX_CJ = "\u256c"    # Center junction (cross)

# Mixed junctions (double-horizontal, single-vertical and vice versa)
# For mid-border: top cols end (double-H meets single-V going down)
MIX_T_UP = "\u2569"     # ╩  double-H, double-V going up (top col ends)
MIX_T_DOWN = "\u2566"   # ╦  double-H, double-V going down (bottom col starts)

# Single-line for internal dividers
LINE_H = "\u2500"
LINE_V = "\u2502"

# Section icons (safe Unicode -- single-width characters)
ICON_GROUPS = ">"
ICON_SOURCES = ">"
ICON_SCENARIOS = "*"
ICON_CONFIG = "#"
ICON_MERAKI = "~"

# Braille spinner frames for generation progress
SPINNER_FRAMES = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"


class MenuItem:
    """A selectable menu item with checkbox."""

    def __init__(self, key: str, label: str, description: str = "", selected: bool = False):
        self.key = key
        self.label = label
        self.description = description
        self.selected = selected


class TUIApp:
    """Main TUI application using curses with 3-col top + 2-col bottom grid layout."""

    # Section indices for grid
    SECTION_GROUPS = 0       # Top-left
    SECTION_SOURCES = 1      # Top-middle
    SECTION_SCENARIOS = 2    # Top-right
    SECTION_CONFIG = 3       # Bottom-left
    SECTION_MERAKI = 4       # Bottom-right

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.current_row = 0
        self.current_section = 0
        self.editing_config = None
        self.edit_buffer = ""
        self._auto_deps = set()       # auto-added dependency generators (for UI display)
        self._cached_expanded = set()  # pre-computed expanded sources for current frame

        # Animation state
        self.tshirt_x = -15
        self.wave_phase = 0.0
        self.clouds = []          # List of [col, row, cloud_type] — drifting clouds
        self.sun_frame = 0        # Rotating sun rays (0-3)
        self.sun_tick = 0         # Sub-frame counter for slower sun rotation
        self.last_anim_time = 0
        self.logo_pulse = False
        self.logo_pulse_time = 0

        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)     # Highlighted row
        curses.init_pair(2, curses.COLOR_GREEN, -1)                    # Selected/checked
        curses.init_pair(3, curses.COLOR_YELLOW, -1)                   # Headers/titles
        curses.init_pair(4, curses.COLOR_CYAN, -1)                     # Config values
        curses.init_pair(5, curses.COLOR_RED, -1)                      # Warnings
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)                  # Box borders
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_YELLOW)   # Test mode badge
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)    # Production mode badge

        # Build source GROUPS menu items (top-left)
        self.source_groups = [MenuItem("all", "all", f"All {len(GENERATORS)} gen", selected=True)]
        for grp, srcs in SOURCE_GROUPS.items():
            if grp != "all":
                desc = ", ".join(srcs[:2])
                if len(srcs) > 2:
                    desc += ".."
                self.source_groups.append(MenuItem(f"grp:{grp}", grp, f"{desc}"))

        # Build individual SOURCES menu items (top-middle)
        self.source_items = [MenuItem(source, source, "") for source in GENERATORS.keys()]

        # Build scenario menu items (top-right) sorted by start_day with aligned day ranges
        self.scenarios = [
            MenuItem("all", "all", f"All {len(IMPLEMENTED_SCENARIOS)} impl", selected=True),
            MenuItem("none", "none", "Baseline only", selected=False),
        ]
        # Sort scenarios by start_day for chronological display
        sorted_scenarios = sorted(SCENARIOS.items(), key=lambda x: (x[1].start_day, x[1].end_day))
        for s_name, s_def in sorted_scenarios:
            if s_def.start_day == s_def.end_day:
                day_info = f"D{s_def.start_day + 1}"
            else:
                day_info = f"D{s_def.start_day + 1}-{s_def.end_day + 1}"
            if s_def.implemented:
                self.scenarios.append(
                    MenuItem(s_name, s_name, day_info, selected=False)
                )
            else:
                self.scenarios.append(
                    MenuItem(s_name, s_name, f"{day_info} planned", selected=False)
                )

        # Configuration values (bottom-left)
        self.config = [
            MenuItem("test_mode", "Output Mode", "", selected=True),  # True = TEST (default), False = PROD
            MenuItem("start_date", "Start Date", DEFAULT_START_DATE),
            MenuItem("days", "Days", str(DEFAULT_DAYS)),
            MenuItem("scale", "Scale", str(DEFAULT_SCALE)),
            MenuItem("clients", "Perfmon Clients (5-175)", "5"),
            MenuItem("client_interval", "Client Interval (5-60)", "30"),
            MenuItem("orders_per_day", "Orders/Day (1-10000)", "224"),
            MenuItem("full_metrics", "Full Metrics", "", selected=False),
            MenuItem("show_files", "Show File Paths", "", selected=False),
        ]

        # Meraki Health configuration (bottom-right)
        self.meraki = [
            MenuItem("meraki_health_enabled", "Enable Health", "", selected=True),
            MenuItem("meraki_health_interval", "Interval (min)", "15"),
            MenuItem("meraki_mr_health", "MR AP Health", "~3.5K/day", selected=True),
            MenuItem("meraki_ms_health", "MS Port Health", "~42K/day", selected=True),
        ]

    def get_current_items(self):
        """Get the items list for the current section."""
        if self.current_section == self.SECTION_GROUPS:
            return self.source_groups
        elif self.current_section == self.SECTION_SOURCES:
            return self.source_items
        elif self.current_section == self.SECTION_SCENARIOS:
            return self.scenarios
        elif self.current_section == self.SECTION_CONFIG:
            return self.config
        else:
            return self.meraki

    def safe_addstr(self, row, col, text, attr=0):
        """Safely add string, ignoring errors for small terminals."""
        try:
            h, w = self.stdscr.getmaxyx()
            if row < h - 1 and col < w and row >= 0:
                self.stdscr.addstr(row, col, text[:w - col - 1], attr)
        except curses.error:
            pass

    def _calc_health_volume(self) -> tuple:
        """Calculate estimated health events per day based on current settings."""
        interval = int(self.meraki[1].description) if self.meraki[1].description.isdigit() else 5
        samples_per_hour = 60 // interval

        mr_enabled = self.meraki[0].selected and self.meraki[2].selected
        ms_enabled = self.meraki[0].selected and self.meraki[3].selected

        mr_events = (36 * samples_per_hour * 24) if mr_enabled else 0
        ms_events = (440 * samples_per_hour * 24) if ms_enabled else 0
        total = mr_events + ms_events

        return mr_events, ms_events, total

    def _calc_total_estimate(self) -> tuple:
        """Calculate estimated total events and execution time from current settings.

        Returns (total_events, estimated_seconds).
        Uses _cached_expanded from draw() if available.
        """
        expanded = getattr(self, '_cached_expanded', None) or self._expand_selected_sources()
        sources = list(expanded)
        if not sources:
            return 0, 0.0

        # Read config values with safe parsing
        days_str = self.config[2].description
        days = int(days_str) if days_str.isdigit() else 14
        try:
            scale = float(self.config[3].description)
        except (ValueError, TypeError):
            scale = 1.0
        clients_str = self.config[4].description
        clients = int(clients_str) if clients_str.isdigit() else 5
        ci_str = self.config[5].description
        client_interval = int(ci_str) if ci_str.isdigit() else 30
        opd_str = self.config[6].description
        orders_per_day = int(opd_str) if opd_str.isdigit() else 224
        full_metrics = self.config[7].selected

        # Meraki settings
        hi_str = self.meraki[1].description
        health_interval = int(hi_str) if hi_str.isdigit() else 15
        mr_health = self.meraki[0].selected and self.meraki[2].selected
        ms_health = self.meraki[0].selected and self.meraki[3].selected

        total_events, est_seconds, _ = _estimate_run(
            sources=sources, days=days, scale=scale,
            orders_per_day=orders_per_day if orders_per_day != 224 else None,
            num_clients=clients, client_interval=client_interval,
            full_metrics=full_metrics, health_interval=health_interval,
            mr_health=mr_health, ms_health=ms_health, parallel=4,
        )
        return total_events, est_seconds

    # ═══════════════════════════════════════════════════════════════════
    # DRAWING
    # ═══════════════════════════════════════════════════════════════════

    def draw(self):
        """Draw the entire TUI with 3-col top + 2-col bottom grid layout."""
        # Pre-compute expanded sources and auto-deps for this frame
        self._cached_expanded = self._expand_selected_sources()

        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        if w < 70 or h < 20:
            self.safe_addstr(h // 2, 2, "Terminal too small! Need 70x20 minimum.", curses.color_pair(5))
            self.stdscr.refresh()
            return

        border_attr = curses.color_pair(6)

        # ═══════════ CALCULATE COLUMN POSITIONS ═══════════
        # Top row: 3 columns
        col1_w = w // 3           # Groups column
        col2_w = w // 3           # Sources column
        col3_w = w - col1_w - col2_w  # Scenarios column (remainder)
        c1 = col1_w              # First vertical divider position
        c2 = col1_w + col2_w     # Second vertical divider position

        # Bottom row: 2 columns
        mid_col = w // 2          # Bottom vertical divider position

        # Inner widths for content (accounting for borders + padding)
        inner_col1 = col1_w - 3
        inner_col2 = col2_w - 2
        inner_col3 = col3_w - 3
        inner_left_bot = mid_col - 3
        inner_right_bot = w - mid_col - 3

        # Row positions
        top_border = 0
        title_row = 1
        content_start = 2

        # Calculate section heights
        max_top_items = max(len(self.source_groups), len(self.source_items), len(self.scenarios))
        max_bottom_items = max(len(self.config), len(self.meraki))

        top_height = min(max_top_items + 2, (h - 14) // 2)
        mid_border = content_start + top_height
        bottom_height = min(max_bottom_items + 2, h - mid_border - 12)
        bottom_border = mid_border + 1 + bottom_height

        # ═══════════ TOP BORDER ═══════════
        # ╔════════╦════════╦════════╗
        top_line = (BOX_TL
                    + BOX_H * (c1 - 1) + BOX_TJ
                    + BOX_H * (c2 - c1 - 1) + BOX_TJ
                    + BOX_H * (w - c2 - 2) + BOX_TR)
        self.safe_addstr(top_border, 0, top_line, border_attr)

        # ═══════════ TITLE ═══════════
        is_test = self.config[0].selected
        if is_test:
            mode_badge = " TEST "
            badge_attr = curses.color_pair(7) | curses.A_BOLD
        else:
            mode_badge = " PROD "
            badge_attr = curses.color_pair(8) | curses.A_BOLD

        title = " Splunk Log Generator "
        self.safe_addstr(title_row, 0, BOX_V, border_attr)
        self.safe_addstr(title_row, 2, title, curses.color_pair(3) | curses.A_BOLD)
        # Mode badge on the right
        badge_col = w - len(mode_badge) - 3
        self.safe_addstr(title_row, badge_col, mode_badge, badge_attr)
        self.safe_addstr(title_row, w - 1, BOX_V, border_attr)

        # ═══════════ SECTION DIVIDER UNDER TITLE ═══════════
        # ╠════════╬════════╬════════╣
        div_line = (BOX_LJ
                    + BOX_H * (c1 - 1) + BOX_CJ
                    + BOX_H * (c2 - c1 - 1) + BOX_CJ
                    + BOX_H * (w - c2 - 2) + BOX_RJ)
        self.safe_addstr(content_start, 0, div_line, border_attr)

        # ═══════════ TOP-LEFT: GROUPS ═══════════
        self._draw_section_content(
            start_row=content_start + 1,
            col=2,
            width=inner_col1,
            height=top_height - 1,
            title=f"{ICON_GROUPS} GROUPS",
            items=self.source_groups,
            section_id=self.SECTION_GROUPS,
            show_checkbox=True,
            align_descriptions=True,
        )

        # ═══════════ TOP-MIDDLE: SOURCES ═══════════
        self._draw_section_content(
            start_row=content_start + 1,
            col=c1 + 2,
            width=inner_col2,
            height=top_height - 1,
            title=f"{ICON_SOURCES} SOURCES",
            items=self.source_items,
            section_id=self.SECTION_SOURCES,
            show_checkbox=True,
            two_columns=True,
        )

        # ═══════════ TOP-RIGHT: SCENARIOS ═══════════
        self._draw_section_content(
            start_row=content_start + 1,
            col=c2 + 2,
            width=inner_col3,
            height=top_height - 1,
            title=f"{ICON_SCENARIOS} SCENARIOS",
            items=self.scenarios,
            section_id=self.SECTION_SCENARIOS,
            show_checkbox=True,
        )

        # Vertical dividers for top section
        for r in range(content_start + 1, mid_border):
            self.safe_addstr(r, 0, BOX_V, border_attr)
            self.safe_addstr(r, c1, LINE_V, border_attr)
            self.safe_addstr(r, c2, LINE_V, border_attr)
            self.safe_addstr(r, w - 1, BOX_V, border_attr)

        # ═══════════ MIDDLE BORDER ═══════════
        # Build character-by-character: top has dividers at c1, c2; bottom at mid_col
        mid_chars = []
        for i in range(w):
            if i == 0:
                mid_chars.append(BOX_LJ)
            elif i == w - 1:
                mid_chars.append(BOX_RJ)
            elif i == c1 or i == c2:
                # Top column divider ends
                if i == mid_col:
                    mid_chars.append(BOX_CJ)  # Both top and bottom divider
                else:
                    mid_chars.append(BOX_BJ)  # Top divider ends, no bottom divider
            elif i == mid_col:
                # Bottom column divider starts (no top divider here)
                mid_chars.append(BOX_TJ)
            else:
                mid_chars.append(BOX_H)
        self.safe_addstr(mid_border, 0, "".join(mid_chars), border_attr)

        # ═══════════ BOTTOM-LEFT: CONFIG ═══════════
        self._draw_config_section(
            start_row=mid_border + 1,
            col=2,
            width=inner_left_bot,
            height=bottom_height,
            title=f"{ICON_CONFIG} CONFIGURATION",
            items=self.config,
            section_id=self.SECTION_CONFIG,
        )

        # ═══════════ BOTTOM-RIGHT: MERAKI HEALTH ═══════════
        self._draw_meraki_section(
            start_row=mid_border + 1,
            col=mid_col + 2,
            width=inner_right_bot,
            height=bottom_height,
            section_id=self.SECTION_MERAKI,
        )

        # Vertical dividers for bottom section
        for r in range(mid_border + 1, bottom_border):
            self.safe_addstr(r, 0, BOX_V, border_attr)
            self.safe_addstr(r, mid_col, LINE_V, border_attr)
            self.safe_addstr(r, w - 1, BOX_V, border_attr)

        # ═══════════ BOTTOM BORDER ═══════════
        bot_line = BOX_BL + BOX_H * (mid_col - 1) + BOX_BJ + BOX_H * (w - mid_col - 2) + BOX_BR
        self.safe_addstr(bottom_border, 0, bot_line, border_attr)

        # ═══════════ STATUS LINE ═══════════
        status_row = bottom_border + 1
        if status_row < h - 4:
            self._draw_status_line(status_row, w)

        # ═══════════ PREVIEW COMMAND ═══════════
        preview_row = status_row + 1
        if preview_row < h - 3:
            preview = self._build_preview_cmd()
            self.safe_addstr(preview_row, 2, preview[:w - 4], curses.A_DIM)

        # ═══════════ LOGO & ANIMATION ═══════════
        logo_start_row = h - len(LOGO_ASCII) - 2
        if logo_start_row > preview_row + 2:
            logo_attr = curses.color_pair(3)
            if self.logo_pulse:
                logo_attr |= curses.A_BOLD
            for i, line in enumerate(LOGO_ASCII):
                self.safe_addstr(logo_start_row + i, 2, line, logo_attr)

            # ═══════════ SURFING T-SHIRT ON WAVE ═══════════
            # Available vertical space for wave + t-shirt
            anim_top = preview_row + 2
            anim_bottom = logo_start_row - 1
            anim_height = anim_bottom - anim_top

            # ═══════════ ANIMATED SUN (top-right of animation area) ═══════════
            # 4 frames with subtly rotating rays around a semicolon core
            sun_frames = [
                [   # Frame 0: standard rays
                    "      .      ",
                    "    \\ | /    ",
                    "  '-.;;;.-'  ",
                    " -==;;;;;==- ",
                    "  .-';;;'-.  ",
                    "    / | \\    ",
                    "      '      ",
                ],
                [   # Frame 1: rays rotated ~22 degrees
                    "             ",
                    "   \\ \\ | /   ",
                    "  '-.;;;.-'  ",
                    " -==;;;;;==- ",
                    "  .-';;;'-.  ",
                    "    / | / /  ",
                    "             ",
                ],
                [   # Frame 2: rays rotated ~45 degrees
                    "             ",
                    "    --. .--  ",
                    "  '-.;;;.-'  ",
                    "  /=;;;;;=\\  ",
                    "  .-';;;'-.  ",
                    "    --' '--  ",
                    "             ",
                ],
                [   # Frame 3: rays rotated ~67 degrees
                    "             ",
                    "    / / | \\  ",
                    "  '-.;;;.-'  ",
                    " -==;;;;;==- ",
                    "  .-';;;'-.  ",
                    "   \\ | \\ \\   ",
                    "             ",
                ],
            ]
            sf = self.sun_frame % len(sun_frames)
            sun_art = sun_frames[sf]
            sun_col = w - 17
            for si, sline in enumerate(sun_art):
                sun_row = anim_top + si
                if preview_row < sun_row < logo_start_row and sun_col > 2:
                    self.safe_addstr(sun_row, sun_col, sline, curses.color_pair(3) | curses.A_BOLD)

            # ═══════════ CLOUDS ═══════════
            cloud_shapes = [
                # Type 0: small puffy cloud
                [
                    "   .--.",
                    " .(    ).",
                    "(_      _)",
                    "  `----' ",
                ],
                # Type 1: medium cloud
                [
                    "    .---.  ",
                    " .-(     )-.",
                    "(           )",
                    " `---..---' ",
                ],
                # Type 2: wispy cloud
                [
                    "  ._  .",
                    " (  `' )",
                    "  `---' ",
                ],
            ]
            for cl_col, cl_row, cl_type in self.clouds:
                shape = cloud_shapes[cl_type % len(cloud_shapes)]
                for ci, cline in enumerate(shape):
                    draw_row = cl_row + ci
                    if preview_row < draw_row < logo_start_row and cl_col > -len(cline):
                        # Clip cloud to visible area
                        if cl_col < 2:
                            visible = cline[2 - cl_col:]
                            dcol = 2
                        elif cl_col + len(cline) > w - 2:
                            visible = cline[:w - 2 - cl_col]
                            dcol = cl_col
                        else:
                            visible = cline
                            dcol = cl_col
                        if visible and 2 <= dcol < w - 2:
                            self.safe_addstr(draw_row, dcol, visible, curses.A_DIM | curses.A_BOLD)

            if anim_height >= 6:
                wave_base_row = anim_bottom  # Bottom of wave area
                wave_peak_height = min(anim_height - len(TSHIRT_ASCII), 8)  # Max wave crest height
                tshirt_center = self.tshirt_x + 6  # Center of t-shirt

                # Calculate wave height at each column
                # Realistic surf wave: steep curling front, flat crest, long rolling tail
                def wave_height_at(col):
                    dx = col - tshirt_center
                    if dx > 10:
                        # Far ahead: steep drop to flat ocean
                        return max(0, wave_peak_height * 0.4 * math.exp(-((dx - 10) ** 2) / 12.0))
                    elif dx > 6:
                        # Curling lip: steep front face
                        t = (dx - 6) / 4.0
                        return wave_peak_height * (1.0 - t * t * 0.6)
                    elif dx > -2:
                        # Crest zone: peak where t-shirt rides
                        return wave_peak_height * (0.95 + 0.05 * math.cos(dx * 0.3))
                    elif dx > -8:
                        # Shoulder: gradually slopes down
                        t = (-dx - 2) / 6.0
                        return wave_peak_height * (0.95 - t * 0.25)
                    else:
                        # Long rolling tail with swell undulations
                        base = wave_peak_height * 0.65 * math.exp(-((-dx - 8) ** 2) / 600.0)
                        swell = 0.5 * math.sin((col + self.wave_phase) * 0.4)
                        ripple = 0.2 * math.sin((col + self.wave_phase * 1.3) * 0.8)
                        return max(0, base + swell + ripple)

                # Draw the wave body (filled) and crest line
                wave_attr = curses.color_pair(4)
                wave_bold = curses.color_pair(4) | curses.A_BOLD
                phase_int = int(self.wave_phase)
                for col in range(2, w - 2):
                    wh = wave_height_at(col)
                    crest_row = int(wave_base_row - wh)

                    if crest_row < anim_top:
                        crest_row = anim_top
                    if crest_row > wave_base_row:
                        continue

                    dx = col - tshirt_center

                    # Draw crest character (top of wave at this column)
                    if 6 < dx <= 10 and wh > 1.5:
                        # Curling lip with spray effect
                        spray = ["'", ".", ",", "`"]
                        crest_char = spray[(col + phase_int) % 4]
                        crest_attr = curses.color_pair(4) | curses.A_BOLD
                    elif 4 < dx <= 6 and wh > wave_peak_height * 0.7:
                        # Steep front face curling over
                        crest_char = "\u2572"  # ╲
                        crest_attr = wave_bold
                    elif -2 <= dx <= 4 and wh > wave_peak_height * 0.8:
                        # Crest: white foam line
                        foam = ["\u2593", "\u2592", "\u2591"]  # dark/medium/light shade
                        crest_char = foam[(col + phase_int) % 3]
                        crest_attr = curses.color_pair(4) | curses.A_BOLD
                    elif dx < -20:
                        # Far tail: gentle ripples
                        crest_char = "~"
                        crest_attr = wave_attr
                    else:
                        crest_char = "\u2594"  # upper horizontal bar
                        crest_attr = wave_bold

                    if anim_top <= crest_row <= wave_base_row:
                        self.safe_addstr(crest_row, col, crest_char, crest_attr)

                    # Fill below crest with wave body -- depth gradient
                    for fill_row in range(crest_row + 1, wave_base_row + 1):
                        if anim_top <= fill_row <= wave_base_row:
                            depth = fill_row - crest_row
                            # Top layer: bright active water
                            if depth <= 1:
                                fill_char = "\u2248"  # approximately equal (wavy)
                                fill_attr = wave_bold
                            elif depth <= 3:
                                # Mid layer: textured water
                                pattern = (col + fill_row + phase_int)
                                if pattern % 4 == 0:
                                    fill_char = "\u2248"
                                elif pattern % 4 == 1:
                                    fill_char = "~"
                                elif pattern % 4 == 2:
                                    fill_char = "\u223C"
                                else:
                                    fill_char = "\u2248"
                                fill_attr = wave_attr
                            else:
                                # Deep water: darker, calmer
                                if (col + fill_row) % 3 == 0:
                                    fill_char = "\u223C"
                                else:
                                    fill_char = "~"
                                fill_attr = curses.color_pair(4) | curses.A_DIM
                            self.safe_addstr(fill_row, col, fill_char, fill_attr)

                # Draw spray particles above the curling lip
                for spray_i in range(3):
                    spray_col = tshirt_center + 8 + spray_i * 2 + (phase_int % 3)
                    spray_row = int(wave_base_row - wave_peak_height) - 1 + (spray_i % 2)
                    if anim_top <= spray_row < anim_bottom and 2 <= spray_col < w - 2:
                        spray_chars = ["'", ".", "*", ","]
                        sc = spray_chars[(spray_i + phase_int) % 4]
                        self.safe_addstr(spray_row, spray_col, sc, wave_bold)

                # Draw t-shirt sitting on top of the wave crest
                crest_at_shirt = wave_height_at(tshirt_center)
                tshirt_base_row = int(wave_base_row - crest_at_shirt)
                tshirt_top_row = tshirt_base_row - len(TSHIRT_ASCII)

                for i, line in enumerate(TSHIRT_ASCII):
                    draw_row = tshirt_top_row + i
                    x_pos = self.tshirt_x

                    if draw_row >= anim_bottom or draw_row < anim_top:
                        continue

                    if x_pos < 0:
                        visible_line = line[-x_pos:] if -x_pos < len(line) else ""
                        draw_x = 2
                    elif x_pos + len(line) > w - 4:
                        visible_line = line[:w - 4 - x_pos]
                        draw_x = 2 + x_pos
                    else:
                        visible_line = line
                        draw_x = 2 + x_pos

                    if visible_line and 2 <= draw_x < w - 2:
                        self.safe_addstr(draw_row, draw_x, visible_line, curses.color_pair(3) | curses.A_BOLD)

        # ═══════════ FOOTER ═══════════
        footer_parts = [
            " \u2191\u2193 Navigate",
            "\u2190\u2192 Column",
            "Tab Section",
            "Space Toggle",
            "Enter Edit",
            "G Generate",
            "Q Quit ",
        ]
        footer = " " + (" " + LINE_V + " ").join(footer_parts) + " "
        try:
            self.stdscr.attron(curses.A_REVERSE)
            self.stdscr.addstr(h - 1, 0, footer[:w - 1].ljust(w - 1))
            self.stdscr.attroff(curses.A_REVERSE)
        except curses.error:
            pass

        self.stdscr.refresh()

    def _expand_selected_sources(self) -> set:
        """Expand selected groups/sources into individual generator names (deduplicated).

        Also auto-includes dependency generators (e.g. selecting 'sap' pulls in 'access').
        """
        sources_str = self._get_sources_str()
        if sources_str == "all":
            return set(GENERATORS.keys())
        expanded = set()
        for part in sources_str.split(","):
            part = part.strip()
            if part in SOURCE_GROUPS:
                expanded.update(SOURCE_GROUPS[part])
            elif part:
                expanded.add(part)
        # Auto-add dependency generators (same logic as main_generate.py)
        deps_added = set()
        for gen in list(expanded):
            if gen in GENERATOR_DEPENDENCIES:
                for dep in GENERATOR_DEPENDENCIES[gen]:
                    if dep not in expanded:
                        expanded.add(dep)
                        deps_added.add(dep)
        self._auto_deps = deps_added  # track for UI display
        return expanded

    def _count_output_files(self) -> int:
        """Count total output files for selected generators."""
        expanded = self._expand_selected_sources()
        return sum(len(GENERATOR_OUTPUT_FILES.get(g, [])) for g in expanded)

    def _draw_status_line(self, row, w):
        """Draw the status bar with mode, output path, source count, file count, and estimates."""
        is_test = self.config[0].selected
        expanded = self._cached_expanded  # use pre-computed value from draw()
        src_count = len(expanded)
        file_count = sum(len(GENERATOR_OUTPUT_FILES.get(g, [])) for g in expanded)

        output_dir = "output/tmp/ only" if is_test else "tmp/ → output/"
        mode_str = "TEST" if is_test else "PROD"

        if is_test:
            mode_attr = curses.color_pair(7) | curses.A_BOLD
        else:
            mode_attr = curses.color_pair(8) | curses.A_BOLD

        col = 2
        self.safe_addstr(row, col, f" {mode_str} ", mode_attr)
        col += len(mode_str) + 3
        self.safe_addstr(row, col, f" {LINE_V} Output: ", curses.A_DIM)
        col += 11
        self.safe_addstr(row, col, output_dir, curses.color_pair(4))
        col += len(output_dir) + 1
        self.safe_addstr(row, col, f"{LINE_V} Sources: ", curses.A_DIM)
        col += 11
        self.safe_addstr(row, col, str(src_count), curses.color_pair(4))
        col += len(str(src_count)) + 1
        self.safe_addstr(row, col, f"{LINE_V} Files: ", curses.A_DIM)
        col += 9
        file_str = str(file_count)
        self.safe_addstr(row, col, file_str, curses.color_pair(4))
        col += len(file_str) + 1

        # Meraki health volume
        mr_events, ms_events, health_total = self._calc_health_volume()
        if health_total > 0:
            self.safe_addstr(row, col, f"{LINE_V} Health: ", curses.A_DIM)
            col += 10
            vol_str = f"~{health_total:,}/d"
            vol_attr = curses.color_pair(5) if health_total > 100000 else curses.color_pair(4)
            self.safe_addstr(row, col, vol_str, vol_attr)
            col += len(vol_str) + 1

        # Total volume and time estimation
        est_events, est_seconds = self._calc_total_estimate()
        if est_events > 0:
            # Format events
            if est_events >= 1_000_000:
                evt_str = f"~{est_events / 1_000_000:.1f}M"
            elif est_events >= 10_000:
                evt_str = f"~{est_events / 1_000:.0f}K"
            else:
                evt_str = f"~{est_events:,}"
            self.safe_addstr(row, col, f"{LINE_V} Events: ", curses.A_DIM)
            col += 10
            self.safe_addstr(row, col, evt_str, curses.color_pair(3) | curses.A_BOLD)
            col += len(evt_str) + 1

            # Format time
            if est_seconds < 60:
                time_str = f"~{est_seconds:.0f}s"
            elif est_seconds < 3600:
                time_str = f"~{est_seconds / 60:.1f}m"
            else:
                time_str = f"~{est_seconds / 3600:.1f}h"
            self.safe_addstr(row, col, f"{LINE_V} Time: ", curses.A_DIM)
            col += 8
            time_attr = curses.color_pair(5) if est_seconds > 300 else curses.color_pair(4)
            self.safe_addstr(row, col, time_str, time_attr)

    def _draw_section_content(self, start_row, col, width, height, title, items, section_id,
                              show_checkbox=True, two_columns=False, align_descriptions=False):
        """Draw a section with header and checkbox items.

        For SCENARIOS section: renders as two aligned columns (name | day range)
        with day ranges right-aligned for readability.

        If two_columns=True, items are rendered in two side-by-side sub-columns
        (first half left, second half right). Navigation stays linear.

        If align_descriptions=True, descriptions are left-aligned to a common column
        based on the longest label (e.g. groups section).
        """
        is_active = self.current_section == section_id
        icon_attr = curses.color_pair(3) | curses.A_BOLD if is_active else curses.A_BOLD
        self.safe_addstr(start_row, col, title, icon_attr)

        # Get current days setting for scenario skip indicators
        try:
            current_days = int(self.config[2].description)
        except (ValueError, IndexError):
            current_days = 31

        # For scenarios section, calculate alignment column for day ranges
        is_scenario_section = (section_id == self.SECTION_SCENARIOS)
        if is_scenario_section:
            # Calculate day column based on longest scenario name (checkbox + name)
            max_name_len = max((len(f"[x] {item.label}") for item in items
                                if item.key not in ("all", "none")), default=16)
            day_col = min(max_name_len + 2, width - 15)  # +2 ensures space before day code

        # Calculate aligned description column for groups section
        if align_descriptions:
            # "[x] " = 4 chars + longest label
            max_label_len = max((len(item.label) for item in items), default=4)
            desc_col = 4 + max_label_len + 1  # checkbox + space + label + space

        # Two-column layout: split items into left/right sub-columns
        if two_columns:
            sub_col_w = width // 2
            rows_available = height - 1
            half = (len(items) + 1) // 2  # Left column gets the extra item if odd

        for i, item in enumerate(items):
            if two_columns:
                if i < half:
                    item_row = start_row + 1 + i
                    item_col = col
                    item_width = sub_col_w - 1
                else:
                    item_row = start_row + 1 + (i - half)
                    item_col = col + sub_col_w
                    item_width = sub_col_w - 1
                if item_row >= start_row + height:
                    continue
            else:
                item_row = start_row + 1 + i
                item_col = col
                item_width = width - 1
                if item_row >= start_row + height:
                    break

            # Check if this is an unimplemented scenario
            is_planned = (is_scenario_section
                          and item.key not in ("all", "none")
                          and item.key in SCENARIOS
                          and not SCENARIOS[item.key].implemented)

            # Check if scenario would be skipped due to --days
            is_skipped = (is_scenario_section
                          and item.key not in ("all", "none")
                          and item.key in SCENARIOS
                          and SCENARIOS[item.key].start_day >= current_days)

            # Check if source is auto-added as a dependency
            is_auto_dep = (section_id == self.SECTION_SOURCES
                           and item.key in self._auto_deps)

            if show_checkbox:
                if is_planned:
                    checkbox = "[-]"
                elif is_auto_dep:
                    checkbox = "[+]"  # auto-included dependency
                else:
                    checkbox = "[x]" if item.selected else "[ ]"

                if is_scenario_section and item.key not in ("all", "none"):
                    # Two-column layout: name left, day range right-aligned
                    name_part = f"{checkbox} {item.label}"
                    # Pad name to align day column
                    name_part = name_part[:day_col - 1].ljust(day_col - 1)
                    day_part = item.description
                    if is_skipped and not is_planned:
                        day_part += " skip"
                    text = name_part + day_part
                elif align_descriptions and item.description:
                    # Pad label so descriptions align vertically
                    name_part = f"{checkbox} {item.label}"
                    name_part = name_part.ljust(desc_col)
                    text = name_part + item.description
                else:
                    # Standard layout
                    text = f"{checkbox} {item.label}"
                    if is_auto_dep:
                        # Show which generator requires this dependency
                        needed_by = [g for g, deps in GENERATOR_DEPENDENCIES.items()
                                     if item.key in deps]
                        if needed_by:
                            text += f" +{','.join(needed_by[:2])}"
                    elif item.description and not two_columns:
                        text += f"  {item.description}"
            else:
                text = f"  {item.label}"

            text = text[:item_width]

            if i == self.current_row and is_active:
                self.safe_addstr(item_row, item_col, text, curses.color_pair(1))
            elif is_planned:
                self.safe_addstr(item_row, item_col, text, curses.A_DIM)
            elif is_skipped:
                self.safe_addstr(item_row, item_col, text, curses.color_pair(5) | curses.A_DIM)
            elif is_auto_dep:
                self.safe_addstr(item_row, item_col, text, curses.color_pair(3))  # yellow for auto-dep
            elif item.selected and show_checkbox:
                self.safe_addstr(item_row, item_col, text, curses.color_pair(2))
            else:
                self.safe_addstr(item_row, item_col, text)

    def _draw_config_section(self, start_row, col, width, height, title, items, section_id):
        """Draw configuration section with test mode toggle and editable values."""
        is_active = self.current_section == section_id
        icon_attr = curses.color_pair(3) | curses.A_BOLD if is_active else curses.A_BOLD
        self.safe_addstr(start_row, col, title, icon_attr)

        for i, item in enumerate(items):
            item_row = start_row + 1 + i
            if item_row >= start_row + height:
                break

            is_checkbox = item.key in ("full_metrics", "show_files")
            is_test_toggle = item.key == "test_mode"

            if is_test_toggle:
                # Special rendering for test mode toggle
                if item.selected:
                    badge = "[TEST]"
                    badge_attr = curses.color_pair(7) | curses.A_BOLD
                    desc = " Output " + chr(0x2192) + " tmp/"
                else:
                    badge = "[PROD]"
                    badge_attr = curses.color_pair(8) | curses.A_BOLD
                    desc = " Output " + chr(0x2192) + " output/"

                if i == self.current_row and is_active:
                    # Full row highlight when selected
                    full_text = f"{badge}{desc}"
                    self.safe_addstr(item_row, col, full_text[:width - 1], curses.color_pair(1))
                else:
                    self.safe_addstr(item_row, col, badge, badge_attr)
                    self.safe_addstr(item_row, col + len(badge), desc[:width - len(badge) - 1])
                continue

            if is_checkbox:
                checkbox = "[x]" if item.selected else "[ ]"
                text = f"{checkbox} {item.label}"
            elif self.editing_config == i and is_active:
                text = f"  {item.label}: [{self.edit_buffer}_]"
            else:
                text = f"  {item.label}: {item.description}"

            text = text[:width - 1]

            if i == self.current_row and is_active:
                self.safe_addstr(item_row, col, text, curses.color_pair(1))
            elif is_checkbox and item.selected:
                self.safe_addstr(item_row, col, text, curses.color_pair(2))
            else:
                self.safe_addstr(item_row, col, text)

    def _draw_meraki_section(self, start_row, col, width, height, section_id):
        """Draw Meraki health configuration section."""
        is_active = self.current_section == section_id
        title = f"{ICON_MERAKI} MERAKI HEALTH"
        icon_attr = curses.color_pair(3) | curses.A_BOLD if is_active else curses.A_BOLD
        self.safe_addstr(start_row, col, title, icon_attr)

        mr_events, ms_events, total = self._calc_health_volume()

        for i, item in enumerate(self.meraki):
            item_row = start_row + 1 + i
            if item_row >= start_row + height:
                break

            is_checkbox = item.key in ("meraki_health_enabled", "meraki_mr_health", "meraki_ms_health")
            is_interval = item.key == "meraki_health_interval"

            if is_checkbox:
                checkbox = "[x]" if item.selected else "[ ]"
                if item.key == "meraki_mr_health":
                    text = f"{checkbox} {item.label} (~{mr_events:,}/d)"
                elif item.key == "meraki_ms_health":
                    text = f"{checkbox} {item.label} (~{ms_events:,}/d)"
                else:
                    text = f"{checkbox} {item.label}"
            elif is_interval:
                if self.editing_config == i and is_active:
                    text = f"  {item.label}: [{self.edit_buffer}_]"
                else:
                    text = f"  {item.label}: {item.description}"
            else:
                text = f"  {item.label}: {item.description}"

            text = text[:width - 1]

            if i == self.current_row and is_active:
                self.safe_addstr(item_row, col, text, curses.color_pair(1))
            elif is_checkbox and item.selected:
                self.safe_addstr(item_row, col, text, curses.color_pair(2))
            else:
                self.safe_addstr(item_row, col, text)

    # ═══════════════════════════════════════════════════════════════════
    # COMMAND PREVIEW
    # ═══════════════════════════════════════════════════════════════════

    def _build_preview_cmd(self) -> str:
        """Build preview command string."""
        sources_str = self._get_sources_str()
        scenarios_str = self._get_scenarios_str()
        days = self.config[2].description
        scale = self.config[3].description
        clients = self.config[4].description
        client_interval = self.config[5].description
        orders_per_day = self.config[6].description
        full_metrics = self.config[7].selected
        show_files = self.config[8].selected
        is_test = self.config[0].selected

        if sources_str == "all":
            preview = f"--all --scenarios={scenarios_str} --days={days}"
        elif sources_str:
            preview = f"--sources={sources_str} --scenarios={scenarios_str} --days={days}"
        else:
            preview = f"--sources=(none) --scenarios={scenarios_str} --days={days}"

        # Production mode (only show --no-test since test is default)
        if not is_test:
            preview += " --no-test"

        # Configuration options (only show non-defaults)
        if scale != "1.0":
            preview += f" --scale={scale}"
        if clients != "5":
            preview += f" --clients={clients}"
        if client_interval != "30":
            preview += f" --client-interval={client_interval}"
        if orders_per_day != "224":
            preview += f" --orders-per-day={orders_per_day}"
        if full_metrics:
            preview += " --full-metrics"
        if show_files:
            preview += " --show-files"

        # Meraki health options
        interval = self.meraki[1].description
        if interval != "5":
            preview += f" --meraki-health-interval={interval}"
        if not self.meraki[0].selected:
            preview += " --no-meraki-health"
        elif not self.meraki[2].selected:
            preview += " --no-mr-health"
        elif not self.meraki[3].selected:
            preview += " --no-ms-health"

        return preview

    def _get_sources_str(self) -> str:
        """Get comma-separated string of selected sources from groups and items.

        Returns "all" when the All group is checked.
        Returns "" (empty) when nothing is selected (estimation shows 0).
        For generation, collect_config() falls back to "all" if empty.
        """
        # Check if "all" group is selected
        for s in self.source_groups:
            if s.selected and s.key == "all":
                return "all"

        selected = []
        # Collect selected groups
        for s in self.source_groups:
            if s.selected and s.key.startswith("grp:"):
                selected.append(s.key[4:])
        # Collect selected individual sources
        for s in self.source_items:
            if s.selected:
                selected.append(s.key)
        return ",".join(selected)

    def _get_scenarios_str(self) -> str:
        """Get comma-separated string of selected scenarios (excludes unimplemented)."""
        selected = [s.key for s in self.scenarios if s.selected]
        if "all" in selected:
            return "all"
        if "none" in selected or not selected:
            return "none"
        # Only include implemented scenarios
        individual = [s for s in selected if s not in ("all", "none")
                      and s in SCENARIOS and SCENARIOS[s].implemented]
        return ",".join(individual) if individual else "none"

    # ═══════════════════════════════════════════════════════════════════
    # ANIMATION
    # ═══════════════════════════════════════════════════════════════════

    def update_animation(self):
        """Update animation state with surfing T-shirt, wave, clouds, sun, and pulsing logo."""
        current_time = time_mod.time()

        if current_time - self.last_anim_time > 0.1:
            self.last_anim_time = current_time
            h, w = self.stdscr.getmaxyx()

            # T-shirt horizontal movement (rides the wave left to right)
            self.tshirt_x += 2
            if self.tshirt_x > w:
                self.tshirt_x = -15

            # Wave phase scrolls continuously (for tail ripple texture)
            self.wave_phase += 0.3

            # Sun rotation — slow: advance frame every 8 ticks (~0.8s)
            self.sun_tick += 1
            if self.sun_tick >= 8:
                self.sun_tick = 0
                self.sun_frame = (self.sun_frame + 1) % 4

            # Clouds: drift slowly right-to-left at same height as sun (top of anim area)
            # Each cloud is [col, row, cloud_type (0-2)]
            self.clouds = [[c - 1, r, ct] for c, r, ct in self.clouds if c > -20]
            # Sun draws at roughly h-8 (logo) - anim_height area top
            # Use same zone as sun: preview_row+2 to preview_row+8
            # Approximate: the top of the animation area
            cloud_zone_top = h // 2 + 4   # Same level as sun top
            cloud_zone_bot = cloud_zone_top + 3  # Sun is ~7 lines tall
            if cloud_zone_bot < h - 10:
                if random.random() < 0.08:  # Slow spawn rate for natural feel
                    row = random.randint(cloud_zone_top, cloud_zone_bot)
                    cloud_type = random.randint(0, 2)
                    self.clouds.append([w + 2, row, cloud_type])

        # Logo pulse (toggle bold every 2 seconds)
        if current_time - self.logo_pulse_time > 2.0:
            self.logo_pulse_time = current_time
            self.logo_pulse = not self.logo_pulse

    # ═══════════════════════════════════════════════════════════════════
    # COUNTDOWN ANIMATION
    # ═══════════════════════════════════════════════════════════════════

    def show_countdown(self):
        """Show a 3-2-1 countdown before generation starts."""
        h, w = self.stdscr.getmaxyx()
        center_y = h // 2
        center_x = w // 2

        digits = [
            # 3
            [
                " \u2588\u2588\u2588\u2588 ",
                "    \u2588 ",
                " \u2588\u2588\u2588\u2588 ",
                "    \u2588 ",
                " \u2588\u2588\u2588\u2588 ",
            ],
            # 2
            [
                " \u2588\u2588\u2588\u2588 ",
                "    \u2588 ",
                " \u2588\u2588\u2588\u2588 ",
                " \u2588    ",
                " \u2588\u2588\u2588\u2588 ",
            ],
            # 1
            [
                "   \u2588  ",
                "   \u2588  ",
                "   \u2588  ",
                "   \u2588  ",
                "   \u2588  ",
            ],
        ]

        for digit in digits:
            self.stdscr.erase()
            dy = center_y - len(digit) // 2
            for i, line in enumerate(digit):
                dx = center_x - len(line) // 2
                self.safe_addstr(dy + i, dx, line, curses.color_pair(3) | curses.A_BOLD)
            self.stdscr.refresh()
            curses.napms(600)

        # GO!
        self.stdscr.erase()
        go_text = "GENERATING..."
        self.safe_addstr(center_y, center_x - len(go_text) // 2, go_text, curses.color_pair(2) | curses.A_BOLD)
        self.stdscr.refresh()
        curses.napms(400)

    # ═══════════════════════════════════════════════════════════════════
    # EVENT LOOP
    # ═══════════════════════════════════════════════════════════════════

    def run(self):
        """Main event loop."""
        curses.curs_set(0)
        self.stdscr.keypad(True)
        self.stdscr.nodelay(True)
        self.stdscr.timeout(100)

        while True:
            self.update_animation()
            self.draw()
            key = self.stdscr.getch()

            if key == -1:
                continue

            # Handle config editing mode
            if self.editing_config is not None:
                if key == 27:  # Escape
                    self.editing_config = None
                    self.edit_buffer = ""
                elif key in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                    if self.edit_buffer:
                        if self.current_section == self.SECTION_CONFIG:
                            self.config[self.editing_config].description = self.edit_buffer
                        elif self.current_section == self.SECTION_MERAKI:
                            self.meraki[self.editing_config].description = self.edit_buffer
                    self.editing_config = None
                    self.edit_buffer = ""
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    self.edit_buffer = self.edit_buffer[:-1]
                elif 32 <= key <= 126:
                    self.edit_buffer += chr(key)
                continue

            items = self.get_current_items()

            # Vertical navigation
            if key in (curses.KEY_UP, ord('k')):
                self.current_row = max(0, self.current_row - 1)
            elif key in (curses.KEY_DOWN, ord('j')):
                self.current_row = min(len(items) - 1, self.current_row + 1)

            # Horizontal navigation — 3 columns on top, 2 on bottom
            # Sources section has 2 sub-columns: left/right arrow navigates between them
            elif key in (curses.KEY_LEFT, ord('h')):
                if self.current_section == self.SECTION_SOURCES:
                    src_half = (len(self.source_items) + 1) // 2
                    if self.current_row >= src_half:
                        # Right sub-col -> left sub-col (same visual row)
                        self.current_row = min(self.current_row - src_half, src_half - 1)
                    else:
                        # Left sub-col -> groups section
                        self.current_section = self.SECTION_GROUPS
                        self.current_row = min(self.current_row, len(self.source_groups) - 1)
                elif self.current_section == self.SECTION_SCENARIOS:
                    self.current_section = self.SECTION_SOURCES
                    # Enter sources on the right sub-column side
                    src_half = (len(self.source_items) + 1) // 2
                    self.current_row = min(self.current_row + src_half, len(self.source_items) - 1)
                elif self.current_section == self.SECTION_MERAKI:
                    self.current_section = self.SECTION_CONFIG
                    self.current_row = min(self.current_row, len(self.config) - 1)
            elif key in (curses.KEY_RIGHT, ord('l')):
                if self.current_section == self.SECTION_GROUPS:
                    self.current_section = self.SECTION_SOURCES
                    # Enter sources on the left sub-column side
                    self.current_row = min(self.current_row, len(self.source_items) - 1)
                elif self.current_section == self.SECTION_SOURCES:
                    src_half = (len(self.source_items) + 1) // 2
                    if self.current_row < src_half:
                        # Left sub-col -> right sub-col (same visual row)
                        new_row = self.current_row + src_half
                        if new_row < len(self.source_items):
                            self.current_row = new_row
                        else:
                            # No item on right side at this row, go to scenarios
                            self.current_section = self.SECTION_SCENARIOS
                            self.current_row = min(self.current_row, len(self.scenarios) - 1)
                    else:
                        # Right sub-col -> scenarios section
                        self.current_section = self.SECTION_SCENARIOS
                        self.current_row = min(self.current_row - src_half, len(self.scenarios) - 1)
                elif self.current_section == self.SECTION_CONFIG:
                    self.current_section = self.SECTION_MERAKI
                    self.current_row = min(self.current_row, len(self.meraki) - 1)

            # Toggle checkbox
            elif key == ord(' '):
                if self.current_section == self.SECTION_GROUPS:
                    item = items[self.current_row]
                    item.selected = not item.selected
                    if item.key == "all" and item.selected:
                        # Selecting "all" deselects individual groups and sources
                        for g in self.source_groups:
                            if g.key != "all":
                                g.selected = False
                        for s in self.source_items:
                            s.selected = False
                    elif item.key != "all" and item.selected:
                        # Selecting a group deselects "all"
                        for g in self.source_groups:
                            if g.key == "all":
                                g.selected = False
                elif self.current_section == self.SECTION_SOURCES:
                    item = items[self.current_row]
                    item.selected = not item.selected
                    if item.selected:
                        # Selecting an individual source deselects "all"
                        for g in self.source_groups:
                            if g.key == "all":
                                g.selected = False
                elif self.current_section == self.SECTION_SCENARIOS:
                    item = items[self.current_row]
                    # Allow toggling "all", "none", and implemented scenarios only
                    if item.key in ("all", "none") or (item.key in SCENARIOS and SCENARIOS[item.key].implemented):
                        item.selected = not item.selected
                elif self.current_section == self.SECTION_CONFIG:
                    if self.config[self.current_row].key in ("full_metrics", "show_files", "test_mode"):
                        self.config[self.current_row].selected = not self.config[self.current_row].selected
                elif self.current_section == self.SECTION_MERAKI:
                    if self.meraki[self.current_row].key in ("meraki_health_enabled", "meraki_mr_health", "meraki_ms_health"):
                        self.meraki[self.current_row].selected = not self.meraki[self.current_row].selected

            # Edit config value
            elif key in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                if self.current_section == self.SECTION_CONFIG:
                    if self.config[self.current_row].key not in ("full_metrics", "show_files", "test_mode"):
                        self.editing_config = self.current_row
                        self.edit_buffer = self.config[self.current_row].description
                elif self.current_section == self.SECTION_MERAKI:
                    if self.meraki[self.current_row].key == "meraki_health_interval":
                        self.editing_config = self.current_row
                        self.edit_buffer = self.meraki[self.current_row].description

            # Tab to switch sections
            elif key == ord('\t'):
                self.current_section = (self.current_section + 1) % 5
                self.current_row = 0
            elif key == curses.KEY_BTAB:
                self.current_section = (self.current_section - 1) % 5
                self.current_row = 0

            # Generate
            elif key in (ord('g'), ord('G')):
                self.show_countdown()
                return self.collect_config()

            # Quit
            elif key in (ord('q'), ord('Q'), 27):
                return None

        return None

    def collect_config(self) -> dict:
        """Collect all form inputs into a config dict."""
        sources = self._get_sources_str()
        return {
            "sources": sources if sources else "all",  # fallback for generation
            "scenarios": self._get_scenarios_str(),
            "test_mode": self.config[0].selected,
            "start_date": self.config[1].description,
            "days": self.config[2].description,
            "scale": self.config[3].description,
            "clients": self.config[4].description,
            "client_interval": self.config[5].description,
            "orders_per_day": self.config[6].description,
            "full_metrics": self.config[7].selected,
            "show_files": self.config[8].selected,
            # Meraki health options
            "meraki_health_enabled": self.meraki[0].selected,
            "meraki_health_interval": self.meraki[1].description,
            "meraki_mr_health": self.meraki[2].selected,
            "meraki_ms_health": self.meraki[3].selected,
        }


def main():
    """Entry point for TUI."""
    try:
        result = curses.wrapper(lambda stdscr: TUIApp(stdscr).run())
    except KeyboardInterrupt:
        print("\nCancelled.")
        return

    if result:
        is_test = result.get('test_mode', True)
        mode_label = "TEST (output/tmp/ only)" if is_test else "PRODUCTION (tmp/ → output/)"

        print("\n" + "=" * 60)
        print("  Generating logs with configuration:")
        print("=" * 60)
        print(f"  Mode:            {mode_label}")
        print(f"  Sources:         {result['sources']}")
        print(f"  Scenarios:       {result['scenarios']}")
        print(f"  Start Date:      {result['start_date']}")
        print(f"  Days:            {result['days']}")
        print(f"  Scale:           {result['scale']}")
        print(f"  Clients:         {result['clients']}")
        print(f"  Client Interval: {result['client_interval']} min")
        print(f"  Orders Per Day:  {result['orders_per_day']}")
        print(f"  Full Metrics:    {result['full_metrics']}")
        print(f"  Show Files:      {result['show_files']}")
        print(f"  --- Meraki Health ---")
        print(f"  Health Enabled:  {result['meraki_health_enabled']}")
        print(f"  Interval:        {result['meraki_health_interval']} min")
        print(f"  MR Health:       {result['meraki_mr_health']}")
        print(f"  MS Health:       {result['meraki_ms_health']}")
        print("=" * 60 + "\n")

        # Build command line arguments and run main_generate
        sys.argv = [
            "main_generate.py",
            f"--sources={result['sources']}",
            f"--scenarios={result['scenarios']}",
            f"--start-date={result['start_date']}",
            f"--days={result['days']}",
            f"--scale={result['scale']}",
            f"--clients={result['clients']}",
            f"--client-interval={result['client_interval']}",
            f"--orders-per-day={result['orders_per_day']}",
            f"--meraki-health-interval={result['meraki_health_interval']}",
        ]
        if is_test:
            sys.argv.append("--test")
        if result['full_metrics']:
            sys.argv.append("--full-metrics")
        if result['show_files']:
            sys.argv.append("--show-files")
        if not result['meraki_health_enabled']:
            sys.argv.append("--no-meraki-health")
        else:
            if not result['meraki_mr_health']:
                sys.argv.append("--no-mr-health")
            if not result['meraki_ms_health']:
                sys.argv.append("--no-ms-health")

        from main_generate import main as run_main
        run_main()
    else:
        print("\nCancelled.")


if __name__ == "__main__":
    main()
