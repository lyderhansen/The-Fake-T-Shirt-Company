#!/usr/bin/env python3
"""
Interactive TUI for Splunk Log Generator using curses (Python stdlib).
No external dependencies required!

Layout (2x2 grid with double-line box drawing):
  ╔══════════════════════════════╦═══════════════════════════════╗
  ║  SOURCES                     ║  SCENARIOS                    ║
  ║  [x] all          All 17 gen ║  [x] all        All 7 scen   ║
  ║  [ ] cloud        aws, gcp.. ║  [ ] exfil      14-day APT   ║
  ╠══════════════════════════════╬═══════════════════════════════╣
  ║  CONFIGURATION               ║  MERAKI HEALTH                ║
  ║  [TEST] Output -> tmp/       ║  [x] Enable Health            ║
  ║  Start Date: 2026-01-01      ║  Interval: 5 min              ║
  ╚══════════════════════════════╩═══════════════════════════════╝

Usage:
    python3 tui_generate.py
    python3 main_generate.py --tui
"""

import curses
import math
import sys
import time as time_mod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from main_generate import GENERATORS, SOURCE_GROUPS
from scenarios.registry import IMPLEMENTED_SCENARIOS
from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE

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
BOX_TL = "╔"    # Top-left
BOX_TR = "╗"    # Top-right
BOX_BL = "╚"    # Bottom-left
BOX_BR = "╝"    # Bottom-right
BOX_H = "═"     # Horizontal
BOX_V = "║"     # Vertical
BOX_TJ = "╦"    # Top junction
BOX_BJ = "╩"    # Bottom junction
BOX_LJ = "╠"    # Left junction
BOX_RJ = "╣"    # Right junction
BOX_CJ = "╬"    # Center junction (cross)

# Single-line for internal dividers
LINE_H = "─"
LINE_V = "│"

# Section icons (safe Unicode — single-width characters)
ICON_SOURCES = ">"
ICON_SCENARIOS = "*"
ICON_CONFIG = "#"
ICON_MERAKI = "~"

# Braille spinner frames for generation progress
SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class MenuItem:
    """A selectable menu item with checkbox."""

    def __init__(self, key: str, label: str, description: str = "", selected: bool = False):
        self.key = key
        self.label = label
        self.description = description
        self.selected = selected


class TUIApp:
    """Main TUI application using curses with 2x2 grid layout."""

    # Section indices for 2x2 grid
    SECTION_SOURCES = 0      # Top-left
    SECTION_SCENARIOS = 1    # Top-right
    SECTION_CONFIG = 2       # Bottom-left
    SECTION_MERAKI = 3       # Bottom-right

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.current_row = 0
        self.current_section = 0
        self.editing_config = None
        self.edit_buffer = ""

        # Animation state
        self.tshirt_x = -15
        self.tshirt_y_offset = 0.0
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

        # Build source menu items
        self.sources = [MenuItem("all", "all", f"All {len(GENERATORS)} gen", selected=True)]
        for grp, srcs in SOURCE_GROUPS.items():
            if grp != "all":
                desc = ", ".join(srcs[:2])
                if len(srcs) > 2:
                    desc += ".."
                self.sources.append(MenuItem(f"grp:{grp}", grp, f"[grp] {desc}"))
        self.sources.append(MenuItem("---", LINE_H * 18, ""))
        for source in GENERATORS.keys():
            self.sources.append(MenuItem(source, source, ""))

        # Build scenario menu items
        self.scenarios = [
            MenuItem("all", "all", f"All {len(IMPLEMENTED_SCENARIOS)}", selected=True),
            MenuItem("none", "none", "Baseline", selected=False),
        ]
        self.scenarios.extend([
            MenuItem(s, s, "", selected=False)
            for s in IMPLEMENTED_SCENARIOS
        ])

        # Configuration values (test_mode is first item)
        self.config = [
            MenuItem("test_mode", "Output Mode", "", selected=True),   # True = TEST, False = PROD
            MenuItem("start_date", "Start Date", DEFAULT_START_DATE),
            MenuItem("days", "Days", str(DEFAULT_DAYS)),
            MenuItem("scale", "Scale", str(DEFAULT_SCALE)),
            MenuItem("clients", "Perfmon Clients", "5"),
            MenuItem("client_interval", "Client Interval", "30"),
            MenuItem("orders_per_day", "Orders/Day", "224"),
            MenuItem("full_metrics", "Full Metrics", "", selected=False),
            MenuItem("show_files", "Show File Paths", "", selected=False),
        ]

        # Meraki Health configuration
        self.meraki = [
            MenuItem("meraki_health_enabled", "Enable Health", "", selected=True),
            MenuItem("meraki_health_interval", "Interval (min)", "5"),
            MenuItem("meraki_mr_health", "MR AP Health", "~10K/day", selected=True),
            MenuItem("meraki_ms_health", "MS Port Health", "~127K/day", selected=True),
        ]

    def get_current_items(self):
        """Get the items list for the current section."""
        if self.current_section == self.SECTION_SOURCES:
            return self.sources
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

    # ═══════════════════════════════════════════════════════════════════
    # DRAWING
    # ═══════════════════════════════════════════════════════════════════

    def draw(self):
        """Draw the entire TUI with 2x2 grid layout and double-line borders."""
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        if w < 60 or h < 20:
            self.safe_addstr(h // 2, 2, "Terminal too small! Need 60x20 minimum.", curses.color_pair(5))
            self.stdscr.refresh()
            return

        border_attr = curses.color_pair(6)

        # Calculate layout
        mid_col = w // 2
        inner_left = mid_col - 2
        inner_right = w - mid_col - 3

        # Row positions
        top_border = 0
        title_row = 1
        content_start = 2

        # Calculate section heights
        max_top_items = max(len(self.sources), len(self.scenarios))
        max_bottom_items = max(len(self.config), len(self.meraki))

        top_height = min(max_top_items + 2, (h - 14) // 2)
        mid_border = content_start + top_height
        bottom_height = min(max_bottom_items + 2, h - mid_border - 12)
        bottom_border = mid_border + 1 + bottom_height

        # ═══════════ TOP BORDER ═══════════
        top_line = BOX_TL + BOX_H * (mid_col - 1) + BOX_TJ + BOX_H * (w - mid_col - 2) + BOX_TR
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
        div_line = BOX_LJ + BOX_H * (mid_col - 1) + BOX_CJ + BOX_H * (w - mid_col - 2) + BOX_RJ
        self.safe_addstr(content_start, 0, div_line, border_attr)

        # ═══════════ TOP-LEFT: SOURCES ═══════════
        self._draw_section_content(
            start_row=content_start + 1,
            col=2,
            width=inner_left,
            height=top_height - 1,
            title=f"{ICON_SOURCES} SOURCES",
            items=self.sources,
            section_id=self.SECTION_SOURCES,
            show_checkbox=True,
        )

        # ═══════════ TOP-RIGHT: SCENARIOS ═══════════
        self._draw_section_content(
            start_row=content_start + 1,
            col=mid_col + 2,
            width=inner_right,
            height=top_height - 1,
            title=f"{ICON_SCENARIOS} SCENARIOS",
            items=self.scenarios,
            section_id=self.SECTION_SCENARIOS,
            show_checkbox=True,
        )

        # Vertical dividers for top section
        for r in range(content_start + 1, mid_border):
            self.safe_addstr(r, 0, BOX_V, border_attr)
            self.safe_addstr(r, mid_col, LINE_V, border_attr)
            self.safe_addstr(r, w - 1, BOX_V, border_attr)

        # ═══════════ MIDDLE BORDER ═══════════
        mid_line = BOX_LJ + BOX_H * (mid_col - 1) + BOX_CJ + BOX_H * (w - mid_col - 2) + BOX_RJ
        self.safe_addstr(mid_border, 0, mid_line, border_attr)

        # ═══════════ BOTTOM-LEFT: CONFIG ═══════════
        self._draw_config_section(
            start_row=mid_border + 1,
            col=2,
            width=inner_left,
            height=bottom_height,
            title=f"{ICON_CONFIG} CONFIGURATION",
            items=self.config,
            section_id=self.SECTION_CONFIG,
        )

        # ═══════════ BOTTOM-RIGHT: MERAKI HEALTH ═══════════
        self._draw_meraki_section(
            start_row=mid_border + 1,
            col=mid_col + 2,
            width=inner_right,
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

            # Flying T-shirt with sine wave motion
            tshirt_row = logo_start_row - len(TSHIRT_ASCII) - 1
            y_offset = int(self.tshirt_y_offset)
            if tshirt_row + y_offset > preview_row + 1:
                for i, line in enumerate(TSHIRT_ASCII):
                    x_pos = self.tshirt_x
                    draw_row = tshirt_row + i + y_offset

                    if draw_row >= h - 1 or draw_row <= preview_row:
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

                    if visible_line and draw_x < w - 2:
                        self.safe_addstr(draw_row, draw_x, visible_line, curses.color_pair(4) | curses.A_BOLD)

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

    def _draw_status_line(self, row, w):
        """Draw the status bar with mode, output path, and source count."""
        is_test = self.config[0].selected
        sources_str = self._get_sources_str()
        if sources_str == "all":
            src_count = len(GENERATORS)
        else:
            src_count = len(sources_str.split(","))

        output_dir = "output/tmp/" if is_test else "output/"
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

        # Meraki health volume
        mr_events, ms_events, total = self._calc_health_volume()
        if total > 0:
            col += len(str(src_count)) + 1
            self.safe_addstr(row, col, f"{LINE_V} Health: ", curses.A_DIM)
            col += 10
            vol_str = f"~{total:,}/day"
            vol_attr = curses.color_pair(5) if total > 100000 else curses.color_pair(4)
            self.safe_addstr(row, col, vol_str, vol_attr)

    def _draw_section_content(self, start_row, col, width, height, title, items, section_id, show_checkbox=True):
        """Draw a section with header and checkbox items."""
        is_active = self.current_section == section_id
        icon_attr = curses.color_pair(3) | curses.A_BOLD if is_active else curses.A_BOLD
        self.safe_addstr(start_row, col, title, icon_attr)

        for i, item in enumerate(items):
            item_row = start_row + 1 + i
            if item_row >= start_row + height:
                break

            if show_checkbox:
                if item.key == "---":
                    text = f"  {item.label}"
                else:
                    checkbox = "[x]" if item.selected else "[ ]"
                    text = f"{checkbox} {item.label:<12}"
                    if item.description:
                        text += f" {item.description}"
            else:
                text = f"  {item.label}"

            text = text[:width - 1]

            if i == self.current_row and is_active:
                self.safe_addstr(item_row, col, text, curses.color_pair(1))
            elif item.selected and show_checkbox and item.key != "---":
                self.safe_addstr(item_row, col, text, curses.color_pair(2))
            else:
                self.safe_addstr(item_row, col, text)

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

        preview = f"--sources={sources_str} --scenarios={scenarios_str} --days={days}"

        # Test mode (only show --no-test since --test is default)
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
        """Get comma-separated string of selected sources."""
        selected = []
        for s in self.sources:
            if s.selected and s.key != "---":
                if s.key == "all":
                    return "all"
                elif s.key.startswith("grp:"):
                    selected.append(s.key[4:])
                else:
                    selected.append(s.key)
        return ",".join(selected) if selected else "all"

    def _get_scenarios_str(self) -> str:
        """Get comma-separated string of selected scenarios."""
        selected = [s.key for s in self.scenarios if s.selected]
        if "all" in selected:
            return "all"
        if "none" in selected or not selected:
            return "none"
        individual = [s for s in selected if s not in ("all", "none")]
        return ",".join(individual) if individual else "none"

    # ═══════════════════════════════════════════════════════════════════
    # ANIMATION
    # ═══════════════════════════════════════════════════════════════════

    def update_animation(self):
        """Update animation state with sine wave T-shirt and pulsing logo."""
        current_time = time_mod.time()

        if current_time - self.last_anim_time > 0.1:
            self.last_anim_time = current_time
            h, w = self.stdscr.getmaxyx()

            # T-shirt horizontal movement
            self.tshirt_x += 2
            if self.tshirt_x > w:
                self.tshirt_x = -15

            # Sine wave vertical offset (gentle wave: amplitude 2, period ~3 seconds)
            self.tshirt_y_offset = math.sin(current_time * 2.0) * 2.0

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
                " ████ ",
                "    █ ",
                " ████ ",
                "    █ ",
                " ████ ",
            ],
            # 2
            [
                " ████ ",
                "    █ ",
                " ████ ",
                " █    ",
                " ████ ",
            ],
            # 1
            [
                "   █  ",
                "   █  ",
                "   █  ",
                "   █  ",
                "   █  ",
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
                if self.current_section == self.SECTION_SOURCES and items[self.current_row].key == "---":
                    self.current_row = max(0, self.current_row - 1)
            elif key in (curses.KEY_DOWN, ord('j')):
                self.current_row = min(len(items) - 1, self.current_row + 1)
                if self.current_section == self.SECTION_SOURCES and items[self.current_row].key == "---":
                    self.current_row = min(len(items) - 1, self.current_row + 1)

            # Horizontal navigation
            elif key in (curses.KEY_LEFT, ord('h')):
                if self.current_section == self.SECTION_SCENARIOS:
                    self.current_section = self.SECTION_SOURCES
                    self.current_row = min(self.current_row, len(self.sources) - 1)
                elif self.current_section == self.SECTION_MERAKI:
                    self.current_section = self.SECTION_CONFIG
                    self.current_row = min(self.current_row, len(self.config) - 1)
            elif key in (curses.KEY_RIGHT, ord('l')):
                if self.current_section == self.SECTION_SOURCES:
                    self.current_section = self.SECTION_SCENARIOS
                    self.current_row = min(self.current_row, len(self.scenarios) - 1)
                elif self.current_section == self.SECTION_CONFIG:
                    self.current_section = self.SECTION_MERAKI
                    self.current_row = min(self.current_row, len(self.meraki) - 1)

            # Toggle checkbox
            elif key == ord(' '):
                if self.current_section == self.SECTION_SOURCES:
                    if items[self.current_row].key != "---":
                        items[self.current_row].selected = not items[self.current_row].selected
                elif self.current_section == self.SECTION_SCENARIOS:
                    items[self.current_row].selected = not items[self.current_row].selected
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
                self.current_section = (self.current_section + 1) % 4
                self.current_row = 0
            elif key == curses.KEY_BTAB:
                self.current_section = (self.current_section - 1) % 4
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
        return {
            "sources": self._get_sources_str(),
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
        mode_label = "TEST (output/tmp/)" if is_test else "PRODUCTION (output/)"

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
        if not is_test:
            sys.argv.append("--no-test")
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
