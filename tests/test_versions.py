"""Version-matching tests. Run:  python3 tests/test_versions.py   (or: pytest)"""
import importlib.machinery
import importlib.util
import pathlib
import sys

_path = pathlib.Path(__file__).resolve().parent.parent / "sploitscout"
_loader = importlib.machinery.SourceFileLoader("sploitscout", str(_path))
_spec = importlib.util.spec_from_loader("sploitscout", _loader)
ss = importlib.util.module_from_spec(_spec)
_loader.exec_module(ss)

# (your version, exploit title, expected match tier or None = not affected)
CASES = [
    ("5.12.5", "X 5.12.5 - RCE", "exact"),
    ("5.12.5", "X 5.12.x - RCE", "family"),
    ("5.12.5", "X < 5.13 - RCE", "range"),
    ("5.12.5", "X 5.12.0 < 5.12.9 - RCE", "range"),
    ("5.12.5", "X 5.12.3 - RCE", "near"),
    ("5.12.5", "X 5.x - RCE", "major"),
    ("5.12.5", "X 5.12 - RCE", "family"),
    ("5.12.5", "X < 5.10 - RCE", None),
    ("5.12.5", "X 4.2.1 - RCE", None),
    ("5.12.5", "X - RCE", "product"),
    ("5.12.10", "X 5.12.0 < 5.12.9 - RCE", None),
    ("5.12.5", "X 5.11.2/5.12.5 - RCE", "exact"),
    ("5.12.5", "X 5.12.4 and earlier", None),
    ("5.12.5", "X 5.12.6 and earlier", "range"),
    ("3.0.20", "X 3.0.20 < 3.0.25rc3 - 'Username' map", "range"),
    ("3.0.24", "X 3.0.20 < 3.0.25rc3 - 'Username' map", "range"),
    ("7.4p1", "X < 7.7 - User Enumeration (2)", "range"),
    ("7.4p1", "X 2.3 < 7.7 - Username Enumeration", "range"),
    ("7.2p2", "X 7.2p2 - Username Enumeration", "exact"),
    ("7.4p1", "X 7.4 - foo", "exact"),
    ("2.3.4", "X v2.3.4 Backdoor Command Execution", "exact"),
    ("2.3.2", "X 2.3.2 and Earlier STAT Denial of Service", "range"),
    ("2.3.4", "X 2.3.2 and Earlier STAT Denial of Service", None),
    ("2.3.2", "X server in versions before 2.3.3 (tested on 2.3.0, 2.3.1)", "range"),
    ("3.0.20", "X versions 3.0.20 through 3.0.25rc3 when using", "range"),
    ("2.4.49", "X 2.4.49/2.4.50 Traversal RCE", "exact"),
    ("1.3.5", "X 1.3.x < 2.0.48 mod_userdir", "range"),
    ("1.3.27", "X 1.3.x < 2.0.48 mod_userdir", "range"),
    ("1.0.1f", "X 1.0.1 < 1.0.1g - heartbleed", "range"),
    ("1.0.1g", "X 1.0.1 < 1.0.1g - heartbleed", None),
    ("1.920", "X < 1.920 - 'rpc.cgi' RCE", None),
    ("1.910", "X < 1.920 - 'rpc.cgi' RCE", "range"),
    ("2.4.49", "X prior to 2.4.51 something", "range"),
    ("2.4.49", "X up to 2.4.50", "range"),
    ("2.4.49", "X versions 1.3.29-36, 2.0.47-58 and 2.2.1-2", None),   # shorthand ranges
    ("1.3.33", "X versions 1.3.29-36, 2.0.47-58 and 2.2.1-2", "range"),
    ("2.4.49", "X + PHP < 5.3.12 - cgi-bin RCE", "product"),         # that version is PHP's
]


def tier_of(version, title):
    kw = [ss.kw_regex("x")]
    _, specs = ss.find_specs(title, kw, title=" - " in title)
    return ss.rate_version(ss.V(version), specs)[0]


def test_version_matching():
    bad = [(v, t, want, tier_of(v, t)) for v, t, want in CASES if tier_of(v, t) != want]
    assert not bad, "\n".join(f"{v!r} vs {t!r}: got {got}, want {want}" for v, t, want, got in bad)


def test_keyword_boundaries():
    rx = ss.kw_regex("php")
    assert rx.search("PHP 5.2.4 - RCE")
    assert not rx.search("unixlogin.php Python Code Injection")
    assert not rx.search("phpBB 2.0 - SQL Injection")


def test_nmap_version_normalizing():
    assert ss.norm_version("7.4p1 Debian 10+deb9u7")[0] == "7.4p1"
    assert ss.norm_version("5.0.51a-3ubuntu5")[0] == "5.0.51a"
    assert ss.norm_version("3.X - 4.X")[0] == ""            # nmap is guessing
    assert ss.norm_version("v1", "distccd")[0] == ""         # protocol version, not software


def test_report_flag_does_not_eat_target():
    # "-r" takes an optional FILE: "sploitscout --fast -r 10.10.10.5" must still scan 10.10.10.5
    a = ss.parse_args(["--fast", "-r", "10.10.10.5"])
    assert (a.target, a.report) == ("10.10.10.5", "")
    a = ss.parse_args(["--fast", "--report=", "10.10.10.5"])
    assert (a.target, a.report) == ("10.10.10.5", "")
    a = ss.parse_args(["10.10.10.5", "-r", "out.md"])
    assert (a.target, a.report) == ("10.10.10.5", "out.md")


if __name__ == "__main__":
    fails = 0
    for v, t, want in CASES:
        got = tier_of(v, t)
        ok = got == want
        fails += not ok
        print(("ok   " if ok else "FAIL ") + f"{v:8} {t[:50]:50} -> {got}" + ("" if ok else f" (want {want})"))
    test_keyword_boundaries()
    test_nmap_version_normalizing()
    test_report_flag_does_not_eat_target()
    print(f"\n{len(CASES) - fails}/{len(CASES)} version cases passed, boundary, normalizing and argument checks passed")
    sys.exit(1 if fails else 0)
