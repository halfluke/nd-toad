"""ND-TOAD ASCII banner shown at the start of interactive CLI commands."""

from __future__ import annotations

BANNER = """\
                     @..@
  [RTR]-----+       (----)      +-----[FW]
            |      ( >__< )     |
  [SW]------+------^^-~~-^^-----+------[AP]
            |                   |
  [ASA]-----+                   +-----[SRX]
          nd-toad — Network Device Toad Auditing Tool"""

_banner_shown = False


def print_banner(console) -> None:
    """Print the README toad art once per process for interactive runs."""
    global _banner_shown
    if _banner_shown:
        return
    console.print(BANNER, style="bold cyan")
    _banner_shown = True


def reset_banner_for_tests() -> None:
    """Allow tests to exercise banner printing more than once."""
    global _banner_shown
    _banner_shown = False
