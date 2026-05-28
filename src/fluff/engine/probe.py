"""
Probe execution engine.

Supported probe types in vendor YAML:

  forbidden_regex   — FAIL if pattern is found anywhere in config text
  required_regex    — FAIL if pattern is NOT found in config text
  hook              — delegate to a Python function in fluff.hooks.*
  manual            — always emit Status.MANUAL (used as a sentinel in YAML)
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from fluff.engine.models import Status

if TYPE_CHECKING:
    from fluff.parsers.base import ParsedConfig


@dataclass
class ProbeResult:
    status: Status
    evidence: list[str]


def run_probe(probe_def: dict[str, Any], config: "ParsedConfig") -> ProbeResult:
    """Dispatch a probe definition to the appropriate implementation."""
    probe_type = probe_def.get("type", "")

    if probe_type == "forbidden_regex":
        return _forbidden_regex(probe_def, config)
    if probe_type == "required_regex":
        return _required_regex(probe_def, config)
    if probe_type == "hook":
        return _hook(probe_def, config)
    if probe_type == "manual":
        return ProbeResult(status=Status.MANUAL, evidence=[])
    if probe_type == "not_applicable":
        return ProbeResult(status=Status.NOT_APPLICABLE, evidence=[])

    raise ValueError(f"Unknown probe type: {probe_type!r}")


# ------------------------------------------------------------------ helpers

def _build_search_text(probe_def: dict, config: "ParsedConfig") -> str:
    """
    If the probe defines a ``scope`` pattern, restrict the search text to lines
    within matching indent-blocks.  Otherwise use the full config text.
    """
    scope = probe_def.get("scope")
    if not scope:
        return config.text

    blocks = config.find_blocks(scope)
    if not blocks:
        return ""

    parts: list[str] = []
    for block in blocks:
        parts.extend(block.all_text_lines())
    return "\n".join(parts)


def _collect_evidence(pattern: str, text: str, max_lines: int = 10) -> list[str]:
    """Return up to *max_lines* de-duplicated matching lines."""
    seen: set[str] = set()
    results: list[str] = []
    for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
        line = m.group(0).strip()
        if line not in seen:
            seen.add(line)
            results.append(line)
        if len(results) >= max_lines:
            break
    return results


# ------------------------------------------------------------------ probe types

def _forbidden_regex(probe_def: dict, config: "ParsedConfig") -> ProbeResult:
    """Fail when the pattern IS found — the config contains something it shouldn't."""
    pattern = probe_def["pattern"]
    text = _build_search_text(probe_def, config)
    evidence = _collect_evidence(pattern, text)
    status = Status.FAIL if evidence else Status.PASS
    return ProbeResult(status=status, evidence=evidence)


def _required_regex(probe_def: dict, config: "ParsedConfig") -> ProbeResult:
    """Fail when the pattern is NOT found — the config is missing something required."""
    pattern = probe_def["pattern"]
    text = _build_search_text(probe_def, config)
    m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    if m:
        return ProbeResult(status=Status.PASS, evidence=[m.group(0).strip()])
    return ProbeResult(status=Status.FAIL, evidence=[f"Required pattern not found: {pattern}"])


def _hook(probe_def: dict, config: "ParsedConfig") -> ProbeResult:
    """Call a Python function: module path + function name in probe_def."""
    module_path = probe_def["module"]
    func_name = probe_def["func"]
    module = importlib.import_module(module_path)
    func = getattr(module, func_name)
    result = func(config)
    # Accept either a ProbeResult or a (status, evidence) tuple
    if isinstance(result, ProbeResult):
        return result
    status, evidence = result
    return ProbeResult(status=Status(status), evidence=evidence)
