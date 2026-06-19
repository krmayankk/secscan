from secscan.models import Finding, ScanReport, Severity


def _report():
    r = ScanReport(host="h", user="u", started_at="now")
    r.add(Finding(check="a", severity=Severity.OK, title="fine"))
    r.add(Finding(check="b", severity=Severity.WARN, title="hmm"))
    r.add(Finding(check="c", severity=Severity.HIGH, title="bad"))
    return r


def test_counts_and_worst():
    r = _report()
    assert r.count(Severity.HIGH) == 1
    assert r.count(Severity.OK) == 1
    assert r.worst == Severity.HIGH


def test_exit_code_nonzero_on_high():
    assert _report().exit_code == 1


def test_exit_code_zero_without_high():
    r = ScanReport(host="h", user="u", started_at="now")
    r.add(Finding(check="a", severity=Severity.WARN, title="meh"))
    assert r.exit_code == 0


def test_severity_ordering():
    assert Severity.HIGH > Severity.WARN > Severity.INFO > Severity.OK
