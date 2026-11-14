"""Scan result completion invariants."""

from skillwarden.models import ScanResult


def test_errors_cannot_be_reported_complete():
    default = ScanResult(target="x", errors=["analyzer failed"])
    explicit = ScanResult(target="x", errors=["analyzer failed"], status="complete")

    assert default.status == "incomplete"
    assert explicit.status == "incomplete"


def test_input_error_cannot_be_reported_complete_without_error_message():
    result = ScanResult(target="x", input_error=True)

    assert result.status == "incomplete"
