"""#484: GET /audit/logs pages through every row with a ``before`` cursor.

``limit`` was capped at 200 with no offset or cursor, so a client could only
ever read the newest 200 rows. The list now orders by timestamp and then id,
newest first, returns ``next_before`` when a page is full, and takes it back
as ``before`` to return the rows after that one.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from qwed_new.api import main
from qwed_new.auth.security import create_access_token
from qwed_new.core.models import Organization, User, VerificationLog

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'paging.db'}")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)

    def add(obj):
        session.add(obj)
        session.commit()
        session.refresh(obj)
        return obj

    acme = add(Organization(name="acme", display_name="Acme"))
    globex = add(Organization(name="globex", display_name="Globex"))
    viewer = add(User(email="viewer@test", password_hash="x", organization_id=acme.id, role="viewer"))

    def log(org, minutes, verified=True):
        return add(VerificationLog(organization_id=org.id, query=f"q{minutes}", result="{}",
                                   is_verified=verified, domain="MATH", timestamp=T0 + timedelta(minutes=minutes)))

    # Seven rows. Two pairs share a timestamp, so only the id keeps their
    # order stable. Every other row is blocked, for the status filter.
    rows = [log(acme, m, verified=i % 2 == 0) for i, m in enumerate([0, 1, 2, 2, 3, 4, 4])]
    other = log(globex, 9)

    main.app.dependency_overrides[main.get_session] = lambda: session
    client = TestClient(main.app)
    token = create_access_token({"sub": str(viewer.id)})

    def get(**params):
        return client.get("/audit/logs", params=params, headers={"Authorization": f"Bearer {token}"})

    # Newest first: timestamp descending, then id descending.
    expected = [str(r.id) for r in sorted(rows, key=lambda r: (r.timestamp, r.id), reverse=True)]

    yield SimpleNamespace(get=get, rows=rows, other=other, expected=expected)
    main.app.dependency_overrides.clear()
    session.close()


def walk(env, limit, **params):
    """Follow next_before to the end; return the ids and the page sizes."""
    ids, sizes, before = [], [], None
    while True:
        query = {"limit": limit, **params}
        if before is not None:
            query["before"] = before
        response = env.get(**query)
        assert response.status_code == 200, response.text
        body = response.json()
        ids += [row["id"] for row in body["logs"]]
        sizes.append(body["total"])
        before = body["next_before"]
        if before is None:
            return ids, sizes
        assert before == body["logs"][-1]["id"]


def test_the_first_page_is_newest_first_and_stable_on_a_shared_timestamp(env):
    body = env.get(limit=50).json()
    assert [row["id"] for row in body["logs"]] == env.expected
    assert body["next_before"] is None  # not full


@pytest.mark.parametrize("limit", [1, 2, 3, 6])
def test_paging_returns_every_row_once_in_order(env, limit):
    ids, sizes = walk(env, limit)
    assert ids == env.expected
    assert all(size <= limit for size in sizes)


def test_a_full_last_page_is_followed_by_an_empty_one(env):
    # Seven rows at seven a page: the page is full, so a cursor is given,
    # and the page after it is empty with no cursor.
    ids, sizes = walk(env, 7)
    assert ids == env.expected
    assert sizes == [7, 0]


def test_a_shared_timestamp_split_across_pages_loses_nothing(env):
    # The rows at minute 4 share a timestamp; a page of one puts the second
    # of them after the cursor, and only the id comparison keeps it.
    first = env.get(limit=1).json()
    second = env.get(limit=1, before=first["next_before"]).json()
    assert [first["logs"][0]["id"], second["logs"][0]["id"]] == env.expected[:2]
    assert env.rows[5].timestamp == env.rows[6].timestamp


def test_paging_works_with_the_status_filter(env):
    blocked = [str(r.id) for r in sorted(env.rows, key=lambda r: (r.timestamp, r.id), reverse=True)
               if not r.is_verified]
    ids, _ = walk(env, 2, status="blocked")
    assert ids == blocked


def test_a_cursor_from_another_organisation_is_404(env):
    response = env.get(before=env.other.id)
    assert response.status_code == 404
    assert response.json()["detail"] == "Log not found"


def test_an_unknown_cursor_is_404(env):
    assert env.get(before=999_999).status_code == 404
