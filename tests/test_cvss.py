"""Tests du calculateur CVSS v3.1 et v4.0 (exige par la spec v2)."""

import pytest

from apps.coordination.services import set_severity
from apps.vulnerabilities.constants import Severity
from apps.vulnerabilities.cvss import CVSSError, base_score, describe, evaluate

V4_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_v31_known_vectors(vector, expected):
    assert base_score(vector) == expected


def test_v31_invalid_vector_is_rejected():
    with pytest.raises(CVSSError):
        base_score("CVSS:3.1/AV:X/AC:L")


def test_v40_base_score_and_severity():
    score, severity = evaluate(V4_CRITICAL)
    assert score == 9.3
    assert severity == Severity.CRITICAL


def test_v40_low_vector():
    assert base_score("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N") == 1.0


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:4.0/AV:N/AC:L",
        "CVSS:4.0/",
    ],
)
def test_v40_invalid_vector_is_rejected(vector):
    with pytest.raises(CVSSError):
        base_score(vector)


def test_v40_describe_lists_eleven_base_metrics():
    metrics = describe(V4_CRITICAL)
    assert len(metrics) == 11
    assert [metric["code"] for metric in metrics][:3] == ["AV", "AC", "AT"]
    assert metrics[0]["value_label"] == "Réseau"


def test_unknown_version_is_rejected():
    with pytest.raises(CVSSError):
        base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")


@pytest.mark.django_db
def test_qualification_accepts_a_v40_vector(case_alpha, analyst):
    from apps.coordination.workflow import CaseStatus

    from .conftest import advance, claim

    advance(case_alpha, CaseStatus.IN_ANALYSIS)
    claim(case_alpha, analyst)
    set_severity(case_alpha, analyst, cvss_vector=V4_CRITICAL)
    case_alpha.refresh_from_db()
    assert case_alpha.cvss_vector == V4_CRITICAL
    assert float(case_alpha.cvss_score) == 9.3
    assert case_alpha.severity == Severity.CRITICAL
