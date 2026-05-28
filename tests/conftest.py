"""Shared pytest fixtures for fluff test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def fixture_path(profile: str, filename: str) -> Path:
    return FIXTURES_DIR / profile / filename


@pytest.fixture
def ios_good():
    return fixture_path("cisco_ios", "good.conf")


@pytest.fixture
def ios_bad_telnet():
    return fixture_path("cisco_ios", "bad_telnet.conf")


@pytest.fixture
def ios_bad_any_any():
    return fixture_path("cisco_ios", "bad_any_any.conf")
