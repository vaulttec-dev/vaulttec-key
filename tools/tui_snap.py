"""Render the interactive shell inside a real VTE terminal - the engine behind GNOME
Terminal - drive it with keystrokes and window resizes, and print what the terminal
ends up showing, scrollback included.

    STEPS='[[3,""],[0.5,"/"],[0.2,"@resize:60x20"]]' python3 tools/tui_snap.py 80 24 vkey

Each step is [delay before it, keys]; "@resize:COLSxROWS" resizes like a window drag.
Needs the system python3 with GTK/VTE bindings (python3-gi, gir1.2-vte-2.91), which
any GNOME desktop already has. Looking at the shell by eye misses exactly the bugs this
catches: stale frames after a resize burst, wrapped rules, clipped status lines.
"""

import json
import os
import sys
from typing import Any

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Vte", "2.91")
from gi.repository import GLib, Gtk, Vte  # noqa: E402

Step = tuple[float, str]


def parse_steps(text: str) -> list[Step]:
    """The STEPS variable: a JSON list of [delay, keys] pairs, nothing else."""
    raw = json.loads(text)
    if not isinstance(raw, list):
        raise SystemExit("STEPS must be a JSON list of [delay, keys]")
    steps: list[Step] = []
    for item in raw:
        if not (isinstance(item, list) and len(item) == 2):
            raise SystemExit(f"STEPS: not a [delay, keys] pair: {item!r}")
        delay, keys = item
        if not isinstance(delay, (int, float)) or not isinstance(keys, str):
            raise SystemExit(f"STEPS: not a [delay, keys] pair: {item!r}")
        steps.append((float(delay), keys))
    return steps


cols, rows = int(sys.argv[1]), int(sys.argv[2])
argv = sys.argv[3:]
steps = parse_steps(os.environ.get("STEPS", '[[3,""]]'))

# Unparented on purpose: a widget inside a window takes its column and row count from
# its pixel allocation, and an offscreen window allocates 2x1. Without a parent the
# emulation keeps what set_size says and still sizes the pty, so the child gets SIGWINCH.
term: Any = Vte.Terminal()
term.set_scrollback_lines(2000)
term.set_size(cols, rows)
env = [f"{k}={v}" for k, v in os.environ.items() if k != "STEPS"] + ["TERM=xterm-256color"]


def dump() -> None:
    c, r = int(term.get_column_count()), int(term.get_row_count())
    text = str(term.get_text_range_format(Vte.Format.TEXT, -2000, 0, r, c)[0] or "")
    lines = text.rstrip("\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    print(f"── {c}x{r}, {len(lines)} lines incl. scrollback ".ljust(c + 4, "─"))
    for line in lines:
        print("│" + line)
    print("└" + "─" * c)


def run_step(i: int) -> bool:
    if i >= len(steps):
        GLib.timeout_add(1500, finish)
        return False
    delay, keys = steps[i]

    def act() -> bool:
        if keys.startswith("@resize:"):
            c, r = (int(v) for v in keys.split(":")[1].split("x"))
            term.set_size(c, r)
        elif keys:
            term.feed_child(keys.encode())
        run_step(i + 1)
        return False

    GLib.timeout_add(int(delay * 1000), act)
    return False


def finish() -> bool:
    dump()
    term.feed_child(b"\x04")            # Ctrl-D: let the shell exit cleanly
    GLib.timeout_add(500, Gtk.main_quit)
    return False


def spawned(_terminal: Any, _pid: int, error: Any) -> None:
    if error:
        print("spawn failed:", error, file=sys.stderr)
        Gtk.main_quit()
        return
    run_step(0)


GLib.timeout_add(60000, Gtk.main_quit)     # never hang a CI shell
term.spawn_async(Vte.PtyFlags.DEFAULT, os.getcwd(), argv, env, GLib.SpawnFlags.SEARCH_PATH,
                 None, None, -1, None, spawned)
Gtk.main()
