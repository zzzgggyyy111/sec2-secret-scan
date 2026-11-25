"""Core primitives for the secret scanning report pipeline."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any


def load_rules(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Compile the detection rules declared by a scan policy."""
    rules: list[dict[str, Any]] = []
    for index, raw in enumerate(policy.get("rules", []) or []):
        if not isinstance(raw, dict):
            continue
        pattern = raw.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            continue
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        rules.append(
            {
                "id": str(raw.get("id") or "rule-{}".format(index + 1)),
                "pattern": pattern,
                "regex": compiled,
                "entropy": raw.get("entropy"),
                "case_sensitive": bool(raw.get("case_sensitive", True)),
            }
        )
    return rules


def scan_text(text: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Scan text line by line and return the located matches."""
    hits: list[dict[str, Any]] = []
    if not text:
        return hits

    for line_number, line in enumerate(text.splitlines(), 1):
        for rule in rules:
            regex = rule.get("regex")
            if regex is None:
                pattern = rule.get("pattern", "")
                if not isinstance(pattern, str) or not pattern:
                    continue
                try:
                    regex = re.compile(pattern)
                except re.error:
                    continue
            for match in regex.finditer(line):
                value = match.group(0)
                if not value:
                    continue
                hits.append(
                    {
                        "rule": str(rule.get("id") or "secret"),
                        "path": "",
                        "line": None,
                        "value": value,
                    }
                )
    return hits


def check_entropy(value: str, threshold: float) -> bool:
    """Return whether a candidate satisfies the configured entropy floor."""
    if not value:
        return False
    return len(value) >= 8


def dedupe_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse repeated findings before they reach the report."""
    result: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for hit in hits:
        path = str(hit.get("path", ""))
        if path in seen_paths:
            continue
        seen_paths.add(path)
        result.extend(
            item for item in hits if str(item.get("path", "")) == path
        )
    return result


def apply_allowlist(
    hits: list[dict[str, Any]], allowlist: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """Remove findings covered by path rules or known sample values."""
    allowlist = allowlist or {}
    paths = allowlist.get("paths", []) or []
    samples = allowlist.get("samples", []) or []
    result: list[dict[str, Any]] = []

    for hit in hits:
        path = str(hit.get("path", ""))
        value = str(hit.get("value", ""))
        if any(str(item) and str(item) in path for item in paths):
            continue
        if any(str(item) and str(item) in value for item in samples):
            continue
        result.append(hit)
    return result


def redact(hit: dict[str, Any]) -> str:
    """Render one finding as a report line."""
    rule = str(hit.get("rule") or "secret")
    path = str(hit.get("path") or "")
    line = hit.get("line")
    value = str(hit.get("value") or "")
    return "{} at {}:{}: {}".format(rule, path, line, value)


def validate_policy(policy: dict[str, Any]) -> list[str]:
    """Return the policy problems that would make a scan unreliable."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]

    issues: list[str] = []
    rules = policy.get("rules") or []
    if not rules:
        issues.append("no rules configured")

    for index, raw in enumerate(rules):
        if not isinstance(raw, dict):
            issues.append("rule {} is not a mapping".format(index + 1))
            continue
        rule_id = str(raw.get("id") or "rule-{}".format(index + 1))
        pattern = raw.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            issues.append("rule {} has no pattern".format(rule_id))
        else:
            try:
                re.compile(pattern)
            except re.error:
                issues.append("rule {} has an invalid pattern".format(rule_id))

    allowlist = policy.get("allowlist") or {}
    paths = allowlist.get("paths") or []
    samples = allowlist.get("samples") or []
    if not paths and not samples:
        issues.append("allowlist is empty")

    if policy.get("redact") is not True:
        issues.append("report redaction is not enabled")
    return issues


def scan_batch(
    repos: dict[str, Any], policy: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    """Scan independent repositories and return findings keyed by repository."""
    rules = load_rules(policy)
    allowlist = policy.get("allowlist") or {}
    results: dict[str, list[dict[str, Any]]] = {}
    collected: list[dict[str, Any]] = []

    for repo_name, repo in repos.items():
        hits = collected
        if isinstance(repo, dict):
            for path, content in sorted(repo.items()):
                file_hits = scan_text(str(content), rules)
                label = path.as_posix() if isinstance(path, Path) else str(path)
                for hit in file_hits:
                    hit["path"] = label
                hits.extend(file_hits)
        else:
            root = Path(repo)
            if not root.exists():
                results[str(repo_name)] = []
                continue
            for file_path in sorted(root.rglob("*")):
                if not file_path.is_file():
                    continue
                raw = file_path.read_bytes()
                text = raw.decode("utf-8", errors="replace")
                normalized = text.replace("\r\n", "\n").replace("\r", "\n")
                if normalized != text:
                    file_path.write_bytes(normalized.encode("utf-8"))
                file_hits = scan_text(normalized, rules)
                relative = file_path.relative_to(root).as_posix()
                for hit in file_hits:
                    hit["path"] = relative
                hits.extend(file_hits)

        hits = apply_allowlist(hits, allowlist)
        hits = dedupe_hits(hits)
        results[str(repo_name)] = hits
    return results