#!/usr/bin/env python3
"""
Interactive TUI for Splunk Log Generator using curses (Python stdlib).
No external dependencies required!

Layout (2x2 grid):
  ┌─────────────────────────────────────────────────────────────┐
  │ ► SOURCES              │ ► SCENARIOS                        │
  │   [x] all              │   [x] all                          │
  │   [ ] network          │   [ ] exfil                        │
  │   ...                  │   ...                              │
  ├────────────────────────┼────────────────────────────────────┤
  │ ► CONFIGURATION        │ ► MERAKI HEALTH                    │
  │   Start Date: [26-01-01│   [x] Enable Health Metrics        │
  │   Days: [14]           │   Interval: [5] min                │
  │   ...                  │   [x] MR AP Health (~10K/dag)      │
  └────────────────────────┴────────────────────────────────────┘

Usage:
    python3 tui_generate.py
    python3 main_generate.py --tui
"""

import curses
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from main_generate import GENERATORS, SOURCE_GROUPS
from scenarios.registry import IMPLEMENTED_SCENARIOS
from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE

# ASCII art logo for The Fake T-Shrt Co
LOGO_ASCII = [
    "  _____ _            _____     _          _____     ____  _          _      ____",
    " |_   _| |__   ___  |  ___|_ _| | _____  |_   _|__ / ___|| |__  _ __| |_   / ___|___",
    "   | | | '_ \\ / _ \\ | |_ / _` | |/ / _ \\   | ||___|\\___ \\| '_ \\| '__| __| | |   / _ \\",
    "   | | | | | |  __/ |  _| (_| |   <  __/   | |     ___) | | | | |  | |_  | |__| (_) |",
    "   |_| |_| |_|\\___| |_|  \\__,_|_|\\_\\___|   |_|    |____/|_| |_|_|   \\__|  \\____\\___/",
]

# Flying T-shirt ASCII art
TSHIRT_ASCII = [
    "   ___ ___",
    " /| |/|\\| |\\",
    "/_| ` |.` |_\\",
    "  |   |.  |",
    "  |   |.  |",
    "  |___|.__|",
]


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
        self.current_section = 0  # 0=sources, 1=scenarios, 2=config, 3=meraki
        self.editing_config = None  # Which config field is being edited
        self.edit_buffer = ""

        # Animation state
        self.tshirt_x = -15  # Start off-screen left
        self.last_anim_time = 0

        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Selected row
        curses.init_pair(2, curses.COLOR_GREEN, -1)                   # Checked item
        curses.init_pair(3, curses.COLOR_YELLOW, -1)                  # Header
        curses.init_pair(4, curses.COLOR_CYAN, -1)                    # Config values
        curses.init_pair(5, curses.COLOR_RED, -1)                     # Warning

        # Build source menu items - groups first, then individual sources
        self.sources = [MenuItem("all", "all", f"All {len(GENERATORS)} gen", selected=True)]

        # Add groups
        for grp, srcs in SOURCE_GROUPS.items():
            if grp != "all":
                desc = ", ".join(srcs[:2])
                if len(srcs) > 2:
                    desc += ".."
                self.sources.append(MenuItem(f"grp:{grp}", grp, f"[grp] {desc}"))

        # Add separator
        self.sources.append(MenuItem("---", "─" * 18, ""))

        # Add individual sources
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

        # Configuration values
        self.config = [
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
            if row < h - 1 and col < w:
                self.stdscr.addstr(row, col, text[:w - col - 1], attr)
        except curses.error:
            pass

    def _calc_health_volume(self) -> tuple:
        """Calculate estimated health events per day based on current settings."""
        interval = int(self.meraki[1].description) if self.meraki[1].description.isdigit() else 5
        samples_per_hour = 60 // interval

        mr_enabled = self.meraki[0].selected and self.meraki[2].selected
        ms_enabled = self.meraki[0].selected and self.meraki[3].selected

        # 36 APs, 440 ports
        mr_events = (36 * samples_per_hour * 24) if mr_enabled else 0
        ms_events = (440 * samples_per_hour * 24) if ms_enabled else 0
        total = mr_events + ms_events

        return mr_events, ms_events, total

    def draw(self):
        """Draw the entire TUI with 2x2 grid layout."""
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()

        # Calculate column widths
        mid_col = w // 2
        left_width = mid_col - 2
        right_width = w - mid_col - 3

        # Title bar
        title = " Splunk Log Generator - Interactive Mode "
        self.stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        try:
            self.stdscr.addstr(0, 0, "─" * (w - 1))
            self.stdscr.addstr(0, max(0, (w - len(title)) // 2), title[:w - 1])
        except curses.error:
            pass
        self.stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

        # Calculate vertical positions
        top_row = 2
        # Calculate max items in each row
        max_top_items = max(len(self.sources), len(self.scenarios))
        max_bottom_items = max(len(self.config), len(self.meraki))

        # Row heights (header + divider + items)
        top_height = min(max_top_items + 2, (h - 10) // 2)
        mid_row = top_row + top_height + 1
        bottom_height = min(max_bottom_items + 2, h - mid_row - 10)

        # ================= TOP ROW =================

        # SOURCES (top-left)
        self._draw_section(
            row=top_row,
            col=2,
            width=left_width,
            height=top_height,
            title="SOURCES",
            items=self.sources,
            section_id=self.SECTION_SOURCES,
            show_checkbox=True
        )

        # Vertical divider
        for r in range(top_row, top_row + top_height):
            self.safe_addstr(r, mid_col, "│")

        # SCENARIOS (top-right)
        self._draw_section(
            row=top_row,
            col=mid_col + 2,
            width=right_width,
            height=top_height,
            title="SCENARIOS",
            items=self.scenarios,
            section_id=self.SECTION_SCENARIOS,
            show_checkbox=True
        )

        # ================= HORIZONTAL DIVIDER =================
        self.safe_addstr(mid_row, 2, "─" * (left_width - 1))
        self.safe_addstr(mid_row, mid_col, "┼")
        self.safe_addstr(mid_row, mid_col + 1, "─" * (right_width))

        # ================= BOTTOM ROW =================

        # CONFIG (bottom-left)
        self._draw_config_section(
            row=mid_row + 1,
            col=2,
            width=left_width,
            height=bottom_height,
            title="CONFIGURATION",
            items=self.config,
            section_id=self.SECTION_CONFIG
        )

        # Vertical divider
        for r in range(mid_row + 1, mid_row + 1 + bottom_height):
            self.safe_addstr(r, mid_col, "│")

        # MERAKI HEALTH (bottom-right)
        self._draw_meraki_section(
            row=mid_row + 1,
            col=mid_col + 2,
            width=right_width,
            height=bottom_height,
            title="MERAKI HEALTH",
            section_id=self.SECTION_MERAKI
        )

        # ================= VOLUME INFO (in Meraki column) =================
        mr_events, ms_events, total = self._calc_health_volume()
        volume_row = mid_row + 1 + bottom_height + 1
        if volume_row < h - 8:
            volume_str = f"Health Volume: ~{total:,}/day"
            if total > 100000:
                volume_str += " (high)"
                self.safe_addstr(volume_row, mid_col + 2, volume_str, curses.color_pair(5) | curses.A_BOLD)
            else:
                self.safe_addstr(volume_row, mid_col + 2, volume_str, curses.color_pair(4))

        # ================= PREVIEW =================
        preview_row = volume_row + 2
        if preview_row < h - 6:
            preview = self._build_preview_cmd()
            self.safe_addstr(preview_row, 2, preview[:w - 4], curses.A_DIM)

        # ================= LOGO & ANIMATION =================
        logo_start_row = h - len(LOGO_ASCII) - 2
        if logo_start_row > preview_row + 2:
            for i, line in enumerate(LOGO_ASCII):
                self.safe_addstr(logo_start_row + i, 2, line, curses.color_pair(3))

            # Flying T-shirt animation
            tshirt_row = logo_start_row - len(TSHIRT_ASCII) - 1
            if tshirt_row > preview_row + 1:
                for i, line in enumerate(TSHIRT_ASCII):
                    x_pos = self.tshirt_x
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
                        self.safe_addstr(tshirt_row + i, draw_x, visible_line, curses.color_pair(4) | curses.A_BOLD)

        # ================= FOOTER =================
        footer = " [G]enerate  [Q]uit  [↑↓jk]Nav  [←→hl]Col  [Space]Toggle  [Tab]Section  [Enter]Edit "
        try:
            self.stdscr.attron(curses.A_REVERSE)
            self.stdscr.addstr(h - 1, 0, footer[:w - 1].ljust(w - 1))
            self.stdscr.attroff(curses.A_REVERSE)
        except curses.error:
            pass

        self.stdscr.refresh()

    def _draw_section(self, row, col, width, height, title, items, section_id, show_checkbox=True):
        """Draw a generic section with checkbox items."""
        is_active = self.current_section == section_id
        header = f"► {title}" if is_active else f"  {title}"
        self.safe_addstr(row, col, header, curses.A_BOLD | (curses.color_pair(3) if is_active else 0))
        self.safe_addstr(row + 1, col, "─" * (width - 1))

        for i, item in enumerate(items):
            item_row = row + 2 + i
            if item_row >= row + height:
                break

            if show_checkbox:
                checkbox = "[x]" if item.selected else "[ ]"
                text = f"{checkbox} {item.label:<12}"
                if item.description:
                    text += f" {item.description}"
            else:
                text = f"  {item.label}"

            text = text[:width - 1]

            if i == self.current_row and is_active:
                self.safe_addstr(item_row, col, text, curses.color_pair(1))
            elif item.selected and show_checkbox:
                self.safe_addstr(item_row, col, text, curses.color_pair(2))
            else:
                self.safe_addstr(item_row, col, text)

    def _draw_config_section(self, row, col, width, height, title, items, section_id):
        """Draw configuration section with editable values."""
        is_active = self.current_section == section_id
        header = f"► {title}" if is_active else f"  {title}"
        self.safe_addstr(row, col, header, curses.A_BOLD | (curses.color_pair(3) if is_active else 0))
        self.safe_addstr(row + 1, col, "─" * (width - 1))

        for i, item in enumerate(items):
            item_row = row + 2 + i
            if item_row >= row + height:
                break

            is_checkbox = item.key in ("full_metrics", "show_files")

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

    def _draw_meraki_section(self, row, col, width, height, title, section_id):
        """Draw Meraki health configuration section with volume info."""
        is_active = self.current_section == section_id
        header = f"► {title}" if is_active else f"  {title}"
        self.safe_addstr(row, col, header, curses.A_BOLD | (curses.color_pair(3) if is_active else 0))
        self.safe_addstr(row + 1, col, "─" * (width - 1))

        mr_events, ms_events, total = self._calc_health_volume()

        for i, item in enumerate(self.meraki):
            item_row = row + 2 + i
            if item_row >= row + height:
                break

            is_checkbox = item.key in ("meraki_health_enabled", "meraki_mr_health", "meraki_ms_health")
            is_interval = item.key == "meraki_health_interval"

            if is_checkbox:
                checkbox = "[x]" if item.selected else "[ ]"
                # Add volume info for MR/MS
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

            # Color based on volume
            if i == self.current_row and is_active:
                self.safe_addstr(item_row, col, text, curses.color_pair(1))
            elif is_checkbox and item.selected:
                self.safe_addstr(item_row, col, text, curses.color_pair(2))
            else:
                self.safe_addstr(item_row, col, text)

    def _build_preview_cmd(self) -> str:
        """Build preview command string."""
        sources_str = self._get_sources_str()
        scenarios_str = self._get_scenarios_str()
        days = self.config[1].description
        scale = self.config[2].description
        clients = self.config[3].description
        client_interval = self.config[4].description
        orders_per_day = self.config[5].description
        full_metrics = self.config[6].selected
        show_files = self.config[7].selected

        preview = f"--sources={sources_str} --scenarios={scenarios_str} --days={days}"

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

    def update_animation(self):
        """Update animation state."""
        import time
        current_time = time.time()

        if current_time - self.last_anim_time > 0.1:
            self.last_anim_time = current_time
            h, w = self.stdscr.getmaxyx()
            self.tshirt_x += 2
            if self.tshirt_x > w:
                self.tshirt_x = -15

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

            # Horizontal navigation (switch columns)
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
                    if self.config[self.current_row].key in ("full_metrics", "show_files"):
                        self.config[self.current_row].selected = not self.config[self.current_row].selected
                elif self.current_section == self.SECTION_MERAKI:
                    if self.meraki[self.current_row].key in ("meraki_health_enabled", "meraki_mr_health", "meraki_ms_health"):
                        self.meraki[self.current_row].selected = not self.meraki[self.current_row].selected

            # Edit config value
            elif key in (curses.KEY_ENTER, ord('\n'), ord('\r')):
                if self.current_section == self.SECTION_CONFIG:
                    if self.config[self.current_row].key not in ("full_metrics", "show_files"):
                        self.editing_config = self.current_row
                        self.edit_buffer = self.config[self.current_row].description
                elif self.current_section == self.SECTION_MERAKI:
                    if self.meraki[self.current_row].key == "meraki_health_interval":
                        self.editing_config = self.current_row
                        self.edit_buffer = self.meraki[self.current_row].description

            # Tab to switch sections (cycles through all 4)
            elif key == ord('\t'):
                self.current_section = (self.current_section + 1) % 4
                self.current_row = 0
            elif key == curses.KEY_BTAB:
                self.current_section = (self.current_section - 1) % 4
                self.current_row = 0

            # Generate
            elif key in (ord('g'), ord('G')):
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
            "start_date": self.config[0].description,
            "days": self.config[1].description,
            "scale": self.config[2].description,
            "clients": self.config[3].description,
            "client_interval": self.config[4].description,
            "orders_per_day": self.config[5].description,
            "full_metrics": self.config[6].selected,
            "show_files": self.config[7].selected,
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
        print("\n" + "=" * 60)
        print("  Generating logs with configuration:")
        print("=" * 60)
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
