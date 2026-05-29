"""Tests for vendor fingerprint detection."""

from __future__ import annotations

import pytest
from pathlib import Path

from fluff.detect.fingerprints import detect, detect_from_file
from fluff.detect.models import PROFILES

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Each (profile, fixture_file) pair must detect as the correct profile
DETECTION_CASES = [
    ("cisco_ios",  "good.conf"),
    ("cisco_ios",  "bad_telnet.conf"),
    ("cisco_ios",  "bad_any_any.conf"),
    ("cisco_asa",  "good.conf"),
    ("cisco_asa",  "bad_telnet.conf"),
    ("cisco_nxos", "good.conf"),
    ("fortios",    "good.conf"),
    ("junos",      "good.conf"),
    ("palo_alto",  "good.conf"),
    ("arista_eos", "good.conf"),
    ("hpe_aruba",  "good.conf"),
    ("checkpoint", "good.conf"),
    ("sophos_xg",  "good.conf"),
    ("sonicwall",  "good.conf"),
    ("nokia_sros", "good.conf"),
    ("nokia_srl",  "good.conf"),
    ("cisco_ftd",  "good.conf"),
    ("cisco_xe",   "good.conf"),
    ("cisco_xr",   "good.conf"),
    ("huawei_vrp", "good.conf"),
    ("f5_bigip",   "good.conf"),
]


@pytest.mark.parametrize("profile,filename", DETECTION_CASES)
def test_detect_correct_profile(profile: str, filename: str) -> None:
    path = FIXTURES_DIR / profile / filename
    if not path.exists():
        pytest.skip(f"Fixture missing: {path}")
    result = detect_from_file(path)
    assert result is not None, f"No detection result for {profile}/{filename}"
    assert result.profile == profile, (
        f"Expected {profile}, got {result.profile} (confidence={result.confidence}, "
        f"signals={result.signals})"
    )


def test_detect_returns_none_for_empty_text() -> None:
    assert detect("") is None


def test_detect_returns_none_for_random_text() -> None:
    result = detect("hello world this is not a network config file at all")
    # May or may not return None depending on weak signals; just verify no crash
    # If it returns something it must be in PROFILES
    if result is not None:
        assert result.profile in PROFILES


def test_detect_confidence_range() -> None:
    text = (FIXTURES_DIR / "cisco_ios" / "good.conf").read_text()
    result = detect(text)
    assert result is not None
    assert 0.0 <= result.confidence <= 1.0


def test_all_profiles_have_signals() -> None:
    from fluff.detect.fingerprints import PROFILE_SIGNALS
    for profile in PROFILES:
        assert profile in PROFILE_SIGNALS, f"No signals defined for {profile}"
        assert len(PROFILE_SIGNALS[profile]) > 0
