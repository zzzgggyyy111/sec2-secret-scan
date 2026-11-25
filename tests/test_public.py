from secretscan.scan import apply_allowlist, load_rules, redact, scan_batch, scan_text

SECRET = "AKIA1234567890ABCDEF"
SECRET_ALT = "AKIAZYXWVUTSRQPONMLK"


def make_policy():
    return {
        "rules": [
            {
                "id": "aws_access_key",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "entropy": 3.0,
                "case_sensitive": True,
            }
        ],
        "allowlist": {"paths": [], "samples": []},
        "redact": True,
    }


def test_public_scan_finds_configured_secret():
    noise = "x" + SECRET + "y"
    text = "service:\n  token: {}\n  note: {}\n".format(SECRET, noise)

    hits = scan_text(text, load_rules(make_policy()))

    assert len(hits) == 1
    assert hits[0]["value"] == SECRET
    assert hits[0]["rule"] == "aws_access_key"


def test_public_hits_report_line_numbers():
    text = "header\n\nkey = {}\n".format(SECRET)

    hits = scan_text(text, load_rules(make_policy()))

    assert len(hits) == 1
    assert hits[0]["line"] == 3


def test_public_report_is_redacted():
    hit = {
        "rule": "aws_access_key",
        "path": "config/service.yml",
        "line": 2,
        "value": SECRET,
    }

    report = redact(hit)

    assert SECRET not in report
    assert "*" in report


def test_public_allowlist_only_suppresses_allowed_paths():
    safe_hit = {
        "rule": "aws_access_key",
        "path": "src/attests/config.py",
        "line": 4,
        "value": SECRET,
    }
    fixture_hit = {
        "rule": "aws_access_key",
        "path": "src/tests/fixture.py",
        "line": 8,
        "value": SECRET_ALT,
    }
    allowlist = {"paths": ["tests/"], "samples": []}

    filtered = apply_allowlist([safe_hit, fixture_hit], allowlist)

    assert filtered == [safe_hit]


def test_public_batch_repositories_are_independent():
    repos = {
        "alpha": {"app.py": "token = {}\n".format(SECRET)},
        "beta": {"service.py": "token = {}\n".format(SECRET_ALT)},
    }

    result = scan_batch(repos, make_policy())

    assert len(result["alpha"]) == 1
    assert len(result["beta"]) == 1
    assert result["alpha"][0]["value"] == SECRET
    assert result["beta"][0]["value"] == SECRET_ALT