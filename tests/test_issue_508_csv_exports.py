"""#508: the CSV exports carry the stored verdict and admission.

Two routes export the audit trail as CSV, and neither carried what
``GET /audit/logs`` returns:

- ``/admin/compliance/export/csv`` was fixed to the last 30 days, cut the
  query to 100 characters and the signature to 16, and had no verdict,
  admission or result;
- ``/audit/export`` wrote ``is_verified`` as "verified"/"blocked" under
  ``Status``, with no admission and no caller.

Both now write the same columns (``AUDIT_CSV_HEADER``): the stored verdict
and admission as ``/audit/logs`` returns them, the caller, the verifier
version and the entry hash, with nothing cut, and both take a period.
"""

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import compliance_routes, main
from qwed_new.auth import audit_routes
from qwed_new.auth.security import create_access_token
from qwed_new.core import compliance_exporter as exporter_module
from qwed_new.core.audit_export import AUDIT_CSV_HEADER, audit_csv
from qwed_new.core.models import Organization, User, VerificationLog

NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'export508.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(exporter_module, "engine", engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    acme = add(Organization(name="acme", display_name="Acme"))
    globex = add(Organization(name="globex", display_name="Globex"))
    owner = add(User(email="owner@acme.example.com", password_hash="x", organization_id=acme.id, role="owner"))
    member = add(User(email="member@acme.example.com", password_hash="x", organization_id=acme.id, role="member"))

    def log(org=acme, when=NOW, **fields):
        values = {
            "query": "2+2=5", "result": json.dumps({"status": "VERIFIED", "is_valid": False}),
            "is_verified": False, "domain": "MATH", **fields,
        }
        return add(VerificationLog(organization_id=org.id, timestamp=when, **values))

    main.app.dependency_overrides[main.get_session] = lambda: session
    yield SimpleNamespace(
        session=session, acme=acme, globex=globex, owner=owner, member=member, log=log,
        client=TestClient(main.app),
    )
    main.app.dependency_overrides.clear()
    session.close()


def _bearer(u):
    return {"Authorization": f"Bearer {create_access_token({'sub': str(u.id)})}"}


def _rows(response):
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    reader = csv.reader(io.StringIO(response.text))
    header = next(reader)
    assert tuple(header) == AUDIT_CSV_HEADER
    return [dict(zip(header, row, strict=True)) for row in reader]


def _compliance(env, query=""):
    return env.client.get(
        f"/admin/compliance/export/csv?organization_id={env.acme.id}{query}", headers=_bearer(env.owner)
    )


def _audit(env, query=""):
    return env.client.get(f"/audit/export{query}", headers=_bearer(env.owner))


def _iso(when):
    return when.isoformat().replace("+", "%2B")


EXPORTS = [_compliance, _audit]


# ---------------------------------------------------------------- columns

@pytest.mark.parametrize("export", EXPORTS)
def test_a_row_carries_the_stored_verdict_admission_and_caller(env, export):
    row_log = env.log(admission="BLOCKED", api_key_id=7, verifier_version="8.0.0",
                      user_id=env.owner.id, entry_hash="e" * 64, hmac_signature="h" * 64)

    (row,) = _rows(export(env))

    assert row == {
        "ID": str(row_log.id),
        "Timestamp": NOW.isoformat(),
        "User ID": str(env.owner.id),
        "API Key ID": "7",
        "Verifier Version": "8.0.0",
        "Domain": "MATH",
        "Query": "2+2=5",
        # The stored verdict, not is_verified: a disproven claim is VERIFIED
        # with a BLOCKED admission.
        "Verdict": "VERIFIED",
        "Admission": "BLOCKED",
        "Is Verified (legacy)": "No",
        "Result": row_log.result,
        "Entry Hash": "e" * 64,
        "HMAC Signature": "h" * 64,
        "Chain Status": "Chained",
    }


@pytest.mark.parametrize("export", EXPORTS)
def test_a_row_without_them_has_empty_cells_not_a_guess(env, export):
    env.log(result="not json", is_verified=True)

    (row,) = _rows(export(env))

    for column in ("User ID", "API Key ID", "Verifier Version", "Verdict", "Admission", "Entry Hash", "HMAC Signature"):
        assert row[column] == "", column
    assert row["Is Verified (legacy)"] == "Yes"
    assert row["Chain Status"] == "Legacy"


@pytest.mark.parametrize("export", EXPORTS)
def test_nothing_is_cut(env, export):
    query = "x" * 500
    env.log(query=query, hmac_signature="s" * 200)

    (row,) = _rows(export(env))

    assert row["Query"] == query
    assert row["HMAC Signature"] == "s" * 200


@pytest.mark.parametrize("export", EXPORTS)
@pytest.mark.parametrize("text", ["=HYPERLINK(\"http://x\")", "+1", "-2+3", "@SUM(A1)", "\tx", "\n=1+1", "\r=1+1"])
def test_text_a_spreadsheet_would_run_gets_a_leading_apostrophe(env, export, text):
    env.log(query=text)

    (row,) = _rows(export(env))

    assert row["Query"] == "'" + text


def test_both_exports_write_the_same_csv(env):
    env.log(admission="ADMIT", result=json.dumps({"status": "VERIFIED", "is_valid": True}), is_verified=True)
    env.log(when=NOW - timedelta(hours=1), admission=None)

    assert _compliance(env).text == _audit(env).text


# ---------------------------------------------------------------- order and scope

@pytest.mark.parametrize("export", EXPORTS)
def test_rows_come_newest_first_then_by_id(env, export):
    older = env.log(when=NOW - timedelta(hours=2))
    tied_low = env.log(when=NOW)
    tied_high = env.log(when=NOW)

    ids = [row["ID"] for row in _rows(export(env))]

    assert ids == [str(tied_high.id), str(tied_low.id), str(older.id)]


@pytest.mark.parametrize("export", EXPORTS)
def test_another_organisations_rows_are_never_exported(env, export):
    env.log(org=env.globex, query="globex secret")
    env.log()

    rows = _rows(export(env))

    assert [row["Query"] for row in rows] == ["2+2=5"]


def test_the_compliance_export_refuses_another_organisations_id(env):
    response = env.client.get(
        f"/admin/compliance/export/csv?organization_id={env.globex.id}", headers=_bearer(env.owner)
    )

    assert response.status_code == 403


def test_a_member_cannot_export(env):
    assert env.client.get(f"/admin/compliance/export/csv?organization_id={env.acme.id}",
                          headers=_bearer(env.member)).status_code == 403
    assert env.client.get("/audit/export", headers=_bearer(env.member)).status_code == 403


# ---------------------------------------------------------------- period

def test_the_compliance_export_defaults_to_the_last_30_days(env):
    env.log(when=NOW - timedelta(days=40), query="old")
    env.log(query="new")

    assert [row["Query"] for row in _rows(_compliance(env))] == ["new"]


def test_the_compliance_export_takes_a_period(env):
    env.log(when=NOW - timedelta(days=40), query="old")
    env.log(query="new")
    start = _iso(NOW - timedelta(days=41))
    end = _iso(NOW - timedelta(days=39))

    assert [row["Query"] for row in _rows(_compliance(env, f"&start={start}&end={end}"))] == ["old"]
    # Only an end: the period is the 30 days before it.
    assert [row["Query"] for row in _rows(_compliance(env, f"&end={end}"))] == ["old"]


def test_the_audit_export_takes_a_period(env):
    env.log(when=NOW - timedelta(days=40), query="old")
    env.log(query="new")

    # Without a period: the newest rows, old ones included.
    assert [row["Query"] for row in _rows(_audit(env))] == ["new", "old"]
    assert [row["Query"] for row in _rows(_audit(env, f"?start={_iso(NOW - timedelta(days=1))}"))] == ["new"]
    assert [row["Query"] for row in _rows(_audit(env, f"?end={_iso(NOW - timedelta(days=1))}"))] == ["old"]


@pytest.mark.parametrize("export", EXPORTS)
def test_a_time_without_a_zone_is_read_as_utc(env, export):
    env.log(query="new")
    naive = (NOW - timedelta(minutes=1)).replace(tzinfo=None).isoformat()
    sep = "&" if export is _compliance else "?"

    assert [row["Query"] for row in _rows(export(env, f"{sep}start={naive}"))] == ["new"]


@pytest.mark.parametrize("export", EXPORTS)
def test_start_after_end_is_400(env, export):
    sep = "&" if export is _compliance else "?"

    response = export(env, f"{sep}start={_iso(NOW)}&end={_iso(NOW - timedelta(days=1))}")

    assert response.status_code == 400


def test_a_future_start_without_an_end_is_400_on_the_compliance_export(env):
    # The end defaults to now, so the period is checked after the defaults
    # and a future start is out of order, not an empty file.
    env.log()

    response = _compliance(env, f"&start={_iso(NOW + timedelta(days=1))}")

    assert response.status_code == 400


def test_a_future_start_without_an_end_is_an_open_period_on_the_audit_export(env):
    # /audit/export has no default end, so the period is open and simply empty.
    env.log()

    assert _rows(_audit(env, f"?start={_iso(NOW + timedelta(days=1))}")) == []


# ---------------------------------------------------------------- the row cap

@pytest.mark.parametrize("export", EXPORTS)
def test_an_export_says_when_it_cut_rows(env, monkeypatch, export):
    monkeypatch.setattr(audit_routes, "_EXPORT_MAX_ROWS", 2)
    monkeypatch.setattr(compliance_routes, "_EXPORT_MAX_ROWS", 2)
    for hours in (3, 2, 1):
        env.log(when=NOW - timedelta(hours=hours), query=f"{hours}h")

    response = export(env)

    assert response.headers["X-Export-Truncated"] == "true"
    # The newest rows are kept.
    assert [row["Query"] for row in _rows(response)] == ["1h", "2h"]


@pytest.mark.parametrize("export", EXPORTS)
def test_an_export_says_when_it_did_not(env, monkeypatch, export):
    monkeypatch.setattr(audit_routes, "_EXPORT_MAX_ROWS", 2)
    monkeypatch.setattr(compliance_routes, "_EXPORT_MAX_ROWS", 2)
    env.log(when=NOW - timedelta(hours=1))
    env.log()

    response = export(env)

    assert response.headers["X-Export-Truncated"] == "false"
    assert len(_rows(response)) == 2


def test_both_exports_share_one_cap():
    assert audit_routes._EXPORT_MAX_ROWS == compliance_routes._EXPORT_MAX_ROWS == 1000


def test_a_browser_on_another_origin_can_read_the_truncation_flag():
    cors = next(m for m in main.app.user_middleware if m.cls.__name__ == "CORSMiddleware")

    assert "X-Export-Truncated" in cors.kwargs["expose_headers"]


# ---------------------------------------------------------------- the writer itself

def test_a_naive_stored_time_is_written_as_utc():
    row = VerificationLog(id=1, organization_id=1, query="q", result="{}", is_verified=True, domain="MATH",
                          timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc).replace(tzinfo=None))

    (line,) = list(csv.reader(io.StringIO(audit_csv([row]))))[1:]

    assert line[1] == "2026-01-02T03:04:05+00:00"
