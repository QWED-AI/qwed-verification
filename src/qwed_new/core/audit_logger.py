"""
Cryptographic Audit Logger for QWED.
Appends VerificationLog rows to a per-organisation hash chain, each entry
HMAC-signed with QWED_AUDIT_SECRET_KEY.

What verification detects: an edited entry, a reordered entry, and a removed
entry that breaks a link between the entries that remain. What it does not
detect: removal of the newest entries (the shorter chain is still valid), so
completeness needs an externally stored checkpoint of the latest hash; and a
rewrite by anyone holding both the signing key and database write access.

Rows written before the API was wired into the chain carry no hash. They stay
unverified, and the first chained row after them opens a new segment.

Single writer: the in-memory per-organisation chain head assumes one process
appends to a given database. A second writer makes the next append fail with a
continuity SecurityError rather than fork the chain.

Releases: since #484 the entry hash covers ``api_key_id`` and
``verifier_version``, and since #307 ``admission``. An older release cannot
verify a row hashed that way,
so with such a row as an organisation's chain head it refuses further appends
for that organisation. Upgrade every process together, and do not run an
older release against a database a newer one has written to.
"""

import hashlib
import hmac
import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import and_, case, func, literal, text
from sqlmodel import Session, create_engine, select

from qwed_new import __version__ as _QWED_VERSION
from qwed_new.core import database as _database
from qwed_new.core.models import Organization, VerificationLog
from qwed_new.core.request_caller import request_api_key_id, request_latency_ms

logger = logging.getLogger(__name__)

AUDIT_SECRET_ENV_VAR = "QWED_AUDIT_SECRET_KEY"

# Rows per page when verify_audit_trail walks the chain.
_TRAIL_PAGE_ROWS = 500

# Namespace for the per-organisation PostgreSQL advisory lock ("QWED").
_ADVISORY_LOCK_NAMESPACE = 0x51574544


def _make_audit_engine():
    """A connection pool of its own for audit appends.

    Each request already holds a connection from the shared pool for its
    session, so drawing the audit append from that same pool can exhaust it
    under load (every request waiting on a connection none of them release).
    An in-memory SQLite database exists only on its own connection, so it
    keeps the shared engine.
    """
    url = _database.DATABASE_URL
    if url.startswith("sqlite") and (":memory:" in url or url.rstrip("/") in ("sqlite:", "sqlite:/")):
        return _database.engine
    return create_engine(url, connect_args=_database.connect_args)


engine = _make_audit_engine()


def _naive_ts(value: datetime) -> datetime:
    """Historical naive-UTC spelling of a persisted timestamp.

    Rows written before timestamps went tz-aware were hashed from the
    naive isoformat (e.g. ``2026-05-08T00:00:00``). Stripping an aware
    read-back to naive UTC reproduces that spelling for the compatibility
    candidate below; a naive read-back passes through unchanged.
    """
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _canonical_ts(value: datetime) -> datetime:
    """Normalize a persisted timestamp to UTC-aware for hash reconstruction.

    Chain hashes are computed from ``timestamp.isoformat()`` at write time
    and recomputed from the read-back row at verify time, so both spellings
    must match. New sqlmodel (UTCDateTime) round-trips tz-aware; old
    naive-column storage returns naive wall-clock UTC. Attaching UTC to a
    naive read-back (or converting aware to UTC) keeps the canonical
    spelling identical on both — and matches what aware writes hash as.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_unchained(log_entry: VerificationLog) -> bool:
    """True when a row carries none of the chain fields (written outside the chain)."""
    return (
        not log_entry.entry_hash
        and not log_entry.hmac_signature
        and log_entry.previous_hash is None
    )


class AuditLogger:
    """
    Cryptographic audit logger: hash-chained, HMAC-signed entries per organisation.

    Features:
    - HMAC-SHA256 signatures for each log entry
    - Hash chain linking entries together
    - Raw LLM output preservation
    - Cryptographic verification methods
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = self._resolve_secret_key(secret_key)
        self.last_hash = None
        self._last_hash_by_org: Dict[int, Optional[str]] = {}
        # Serialises appends within this process, so the in-memory head is
        # updated before the next append reads the persisted one. The
        # database lock alone leaves a window between commit and that update.
        self._append_lock = threading.Lock()

    def log_verification(
        self,
        organization_id: int,
        user_id: Optional[int],
        query: str,
        result: Dict[str, Any] | str,
        is_verified: bool,
        domain: str,
        raw_llm_output: Optional[str] = None,
        admission: Optional[str] = None,
    ) -> str:
        """
        Log a verification event with cryptographic signature.

        ``admission`` is the admission decision the route made ("ADMIT" or
        "BLOCKED"; "ADMIT" or "DENY" from the Verification Context route), or
        None when the route decides none (#307).
        It is stored and covered by the hash.

        ``result`` is either a dict, serialised here, or an already-serialised
        JSON string, stored as given so a caller's size cap holds. The hash
        covers the decoded value either way, which is what verification
        recomputes from the stored row. A string that is not valid JSON fails
        closed with SecurityError, since it could never be verified.

        Returns:
            log_id: The ID of the created log entry
        """
        if isinstance(result, str):
            stored_result = result
            try:
                hashed_result = json.loads(result)
            except json.JSONDecodeError as exc:
                raise SecurityError(
                    "Audit entry result is not valid JSON; refusing to append an unverifiable entry"
                ) from exc
        else:
            stored_result = json.dumps(result)
            hashed_result = result

        # Measured before waiting for the append lock, so it is the route's
        # time, not the queue's (#528).
        latency_ms = request_latency_ms()
        with self._append_lock:
            return self._append(
                organization_id=organization_id,
                user_id=user_id,
                query=query,
                stored_result=stored_result,
                hashed_result=hashed_result,
                is_verified=is_verified,
                domain=domain,
                raw_llm_output=raw_llm_output,
                admission=admission,
                latency_ms=latency_ms,
            )

    def _append(
        self,
        *,
        organization_id: int,
        user_id: Optional[int],
        query: str,
        stored_result: str,
        hashed_result: Any,
        is_verified: bool,
        domain: str,
        raw_llm_output: Optional[str],
        admission: Optional[str] = None,
        latency_ms: Optional[int] = None,
    ) -> str:
        """Append one entry under the chain lock (see log_verification)."""
        timestamp = datetime.now(timezone.utc)

        with Session(engine) as session:
            self._prepare_append_session(session, organization_id)
            latest_log = self._get_latest_log(
                session,
                organization_id=organization_id,
                for_update=True,
            )
            self._assert_appendable_head(latest_log, session)
            previous_hash = self._extract_persisted_hash(latest_log, session)
            known_hash = self._last_hash_by_org.get(organization_id, previous_hash)
            # Single writer per database: a head this process did not write
            # (another process appended, or rows were removed) stops the
            # append rather than being trusted.
            if known_hash != previous_hash:
                raise SecurityError(
                    "Audit chain continuity mismatch: in-memory chain head does not match persisted audit trail"
                )

            # The caller and the server version (#484), both covered by the
            # hash: clearing either on a stored row fails verification.
            api_key_id = request_api_key_id()
            log_data = {
                "organization_id": organization_id,
                "user_id": user_id,
                "query": query,
                "result": hashed_result,
                "is_verified": is_verified,
                "domain": domain,
                "timestamp": timestamp.isoformat(),
                "previous_hash": previous_hash,
                "raw_llm_output": raw_llm_output,
                "api_key_id": api_key_id,
                "verifier_version": _QWED_VERSION,
                # The admission the route decided (#307); None when it
                # decided none. Covered, so it cannot be set or cleared later.
                "admission": admission,
                # How long the route took (#528); None outside a request.
                # Covered too.
                "latency_ms": latency_ms,
            }

            entry_hash = self._compute_hash(log_data)
            signature = self._compute_hmac(entry_hash)

            log_entry = VerificationLog(
                organization_id=organization_id,
                user_id=user_id,
                query=query,
                result=stored_result,
                is_verified=is_verified,
                domain=domain,
                timestamp=timestamp,
                entry_hash=entry_hash,
                hmac_signature=signature,
                previous_hash=previous_hash,
                raw_llm_output=raw_llm_output,
                api_key_id=api_key_id,
                verifier_version=_QWED_VERSION,
                admission=admission,
                latency_ms=latency_ms,
            )
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)

            self._last_hash_by_org[organization_id] = entry_hash
            self.last_hash = entry_hash

            logger.info("Audit log created: %s with hash %s...", log_entry.id, entry_hash[:16])
            return str(log_entry.id)

    def _compute_hash(self, data: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of log data."""
        canonical_json = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def _compute_hmac(self, message: str) -> str:
        """Compute HMAC-SHA256 signature."""
        return hmac.new(
            self.secret_key,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _resolve_secret_key(self, secret_key: Optional[str]) -> bytes:
        """Resolve the audit signing key or fail closed."""
        configured_secret = secret_key if secret_key is not None else os.environ.get(AUDIT_SECRET_ENV_VAR)
        if not configured_secret:
            raise SecurityError(
                f"{AUDIT_SECRET_ENV_VAR} must be set before AuditLogger can initialize"
            )
        return configured_secret.encode("utf-8")

    def _prepare_append_session(self, session: Session, organization_id: int) -> None:
        """Take a database lock for the organisation before its head is read.

        The supported deployment is one writer process per database; a second
        writer is detected by the continuity check and refused. This lock is
        defence in depth so that, even then, two transactions cannot both read
        the same head and fork the chain: a row lock on the head is not enough
        on PostgreSQL, where a waiting writer gets the old head row back once
        the lock is released. It is not a claim of multi-writer support.
        """
        bind = session.get_bind()
        dialect = bind.dialect.name if bind is not None else ""
        if dialect == "sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        elif dialect == "postgresql":
            session.connection().execute(
                text("SELECT pg_advisory_xact_lock(:ns, :org)"),
                {"ns": _ADVISORY_LOCK_NAMESPACE, "org": int(organization_id)},
            )
        elif bind is not None:
            # Other databases: lock the organisation's row for the transaction.
            self._run_select(
                session,
                select(Organization.id).where(Organization.id == organization_id).with_for_update(),
            ).first()


    def _get_latest_log(
        self,
        session: Session,
        organization_id: int,
        *,
        for_update: bool = False,
    ) -> Optional[VerificationLog]:
        """Return the latest persisted audit log entry for an organization, if any."""
        statement = (
            select(VerificationLog)
            .where(VerificationLog.organization_id == organization_id)
            .order_by(VerificationLog.id.desc())
            .limit(1)
        )
        bind = session.get_bind()
        if (
            for_update
            and bind is not None
            and bind.dialect.name != "sqlite"
        ):
            statement = statement.with_for_update()
        return self._run_select(session, statement).first()

    def _assert_appendable_head(
        self,
        latest_log: Optional[VerificationLog],
        session: Session,
    ) -> None:
        """Fail closed if the persisted chain head cannot be verified.

        A legacy head (an unchained row with no chained row before it) has
        nothing to verify; the next entry opens a new segment instead. An
        unchained row AFTER a chained row is not legacy: it was written or
        blanked out of band, and verification rejects it here.
        """
        if latest_log is None or self._is_legacy_entry(latest_log, session):
            return

        head_check = self.verify_log_entry(latest_log.id, session)
        if not head_check["valid"]:
            raise SecurityError(
                "Persisted audit chain head failed integrity verification; refusing to append"
            )

    def _run_select(self, session: Session, statement):
        """Execute a SQLModel select statement."""
        return getattr(session, "exec")(statement)

    def _has_chained_entry_before(
        self,
        session: Session,
        organization_id: int,
        log_id: int,
    ) -> bool:
        """True when the organisation has a chained row with an id below ``log_id``."""
        statement = (
            select(VerificationLog.id)
            .where(VerificationLog.organization_id == organization_id)
            .where(VerificationLog.id < log_id)
            .where(VerificationLog.entry_hash.is_not(None))
            .where(VerificationLog.entry_hash != "")
            # Newest first: after an upgrade the rows just below the head are
            # the chained ones, so the scan stops early instead of walking the
            # hashless legacy prefix on every append.
            .order_by(VerificationLog.id.desc())
            .limit(1)
        )
        return self._run_select(session, statement).first() is not None

    def _is_legacy_entry(self, log_entry: VerificationLog, session: Session) -> bool:
        """An unchained row that no chained row precedes, i.e. one written before the chain."""
        return _is_unchained(log_entry) and not self._has_chained_entry_before(
            session, log_entry.organization_id, log_entry.id
        )

    def _extract_persisted_hash(
        self,
        latest_log: Optional[VerificationLog],
        session: Optional[Session] = None,
    ) -> Optional[str]:
        """Return the latest persisted hash or fail if chain continuity is invalid.

        A legacy head returns None, so the next entry opens a new segment.
        Without a session the legacy check cannot run, and a hashless head
        fails closed as before.
        """
        if latest_log is None:
            return None
        if session is not None and self._is_legacy_entry(latest_log, session):
            return None
        if not latest_log.entry_hash:
            raise SecurityError(
                "Persisted audit trail is missing the latest entry hash; chain continuity cannot be established"
            )
        return latest_log.entry_hash

    def verify_log_entry(self, log_id: int, session: Session) -> Dict[str, Any]:
        """
        Verify the cryptographic integrity of a log entry.

        Returns:
            {
                "valid": bool,
                "checks": {
                    "hash_valid": bool,
                    "signature_valid": bool,
                    "chain_valid": bool
                },
                "errors": list[str]
            }
        """
        log_entry = session.get(VerificationLog, log_id)
        if not log_entry:
            return {
                "valid": False,
                "checks": {},
                "errors": ["Log entry not found"],
            }

        chained_before = self._has_chained_entry_before(
            session, log_entry.organization_id, log_id
        )
        prev_log = self._previous_entry(session, log_entry.organization_id, log_id)
        return self._check_entry(log_entry, prev_log, chained_before)

    def _previous_entry(
        self, session: Session, organization_id: int, log_id: int
    ) -> Optional[VerificationLog]:
        """The organisation's row just before ``log_id``, or None."""
        return self._run_select(
            session,
            select(VerificationLog)
            .where(VerificationLog.organization_id == organization_id)
            .where(VerificationLog.id < log_id)
            .order_by(VerificationLog.id.desc())
            # Result.first() does not add a LIMIT: without it every earlier
            # row is fetched to read one.
            .limit(1),
        ).first()

    def _check_entry(
        self,
        log_entry: VerificationLog,
        prev_log: Optional[VerificationLog],
        chained_before: bool,
    ) -> Dict[str, Any]:
        """Check one entry against the row before it (see verify_log_entry).

        ``chained_before`` says whether the organisation has a chained row
        (one with an entry hash) before this one. verify_log_entry looks both
        up; verify_audit_trail carries them along as it walks the chain.
        """
        log_id = log_entry.id
        if _is_unchained(log_entry) and not chained_before:
            # Written before the chain was wired in: nothing to verify, and
            # never reported valid.
            return {
                "valid": False,
                "legacy": True,
                "checks": {
                    "hash_valid": False,
                    "signature_valid": False,
                    "chain_valid": False,
                },
                "errors": [
                    "Entry predates the audit chain (no hash or signature); it cannot be verified"
                ],
                "log_id": log_id,
                "timestamp": _canonical_ts(log_entry.timestamp).isoformat(),
            }

        errors = []
        hash_valid, signature_valid = self._verify_hash_and_signature(log_entry, errors)
        chain_valid = self._verify_chain_link(
            log_entry, prev_log, errors, chained_before=chained_before
        )

        is_valid = hash_valid and signature_valid and chain_valid

        return {
            "valid": is_valid,
            "legacy": False,
            "checks": {
                "hash_valid": hash_valid,
                "signature_valid": signature_valid,
                "chain_valid": chain_valid,
            },
            "errors": errors,
            "log_id": log_id,
            "timestamp": _canonical_ts(log_entry.timestamp).isoformat(),
        }

    def _reconstruct_log_data(self, log_entry: VerificationLog) -> Dict[str, Any]:
        """Rebuild the canonical payload for integrity verification."""
        return {
            **self._reconstruct_pre_latency_log_data(log_entry),
            "latency_ms": log_entry.latency_ms,
        }

    def _reconstruct_pre_latency_log_data(self, log_entry: VerificationLog) -> dict[str, Any]:
        """Rebuild the payload for entries hashed before latency was covered (#528)."""
        return {
            **self._reconstruct_pre_admission_log_data(log_entry),
            "admission": log_entry.admission,
        }

    def _reconstruct_pre_admission_log_data(self, log_entry: VerificationLog) -> dict[str, Any]:
        """Rebuild the payload for entries hashed before admission was covered (#307)."""
        return {
            **self._reconstruct_pre_caller_log_data(log_entry),
            "api_key_id": log_entry.api_key_id,
            "verifier_version": log_entry.verifier_version,
        }

    def _reconstruct_pre_caller_log_data(self, log_entry: VerificationLog) -> dict[str, Any]:
        """Rebuild the payload for entries hashed before the caller was covered (#484)."""
        return {
            "organization_id": log_entry.organization_id,
            "user_id": log_entry.user_id,
            "query": log_entry.query,
            "result": self._decode_result_payload(log_entry),
            "is_verified": log_entry.is_verified,
            "domain": log_entry.domain,
            "timestamp": _canonical_ts(log_entry.timestamp).isoformat(),
            "previous_hash": log_entry.previous_hash,
            "raw_llm_output": log_entry.raw_llm_output,
        }

    def _reconstruct_legacy_log_data(self, log_entry: VerificationLog) -> Dict[str, Any]:
        """Rebuild the legacy payload for entries hashed before raw_llm_output was covered."""
        return {
            "organization_id": log_entry.organization_id,
            "user_id": log_entry.user_id,
            "query": log_entry.query,
            "result": self._decode_result_payload(log_entry),
            "is_verified": log_entry.is_verified,
            "domain": log_entry.domain,
            "timestamp": _canonical_ts(log_entry.timestamp).isoformat(),
            "previous_hash": log_entry.previous_hash,
        }

    def _decode_result_payload(self, log_entry: VerificationLog) -> Dict[str, Any]:
        """Decode persisted result payload or fail closed."""
        try:
            return json.loads(log_entry.result)
        except (json.JSONDecodeError, TypeError) as exc:
            raise SecurityError(
                "Audit entry result payload is malformed; cannot verify integrity"
            ) from exc

    def _verify_hash_and_signature(
        self,
        log_entry: VerificationLog,
        errors: list[str],
    ) -> tuple[bool, bool]:
        """Verify the stored hash and HMAC for one audit row."""
        hash_present = bool(log_entry.entry_hash)
        expected_hashes = self._expected_hashes(log_entry) if hash_present else []
        hash_valid = hash_present and log_entry.entry_hash in expected_hashes

        if not hash_valid:
            if not hash_present:
                errors.append("Hash missing from audit entry")
            else:
                errors.append(
                    "Hash mismatch: audit entry does not match any accepted canonical payload"
                )

        if not hash_present:
            signature_valid = False
        else:
            expected_signature = self._compute_hmac(log_entry.entry_hash)
            signature_valid = hmac.compare_digest(
                expected_signature,
                log_entry.hmac_signature or "",
            )

        if not signature_valid:
            errors.append("HMAC signature invalid")

        return hash_valid, signature_valid

    def _expected_hashes(self, log_entry: VerificationLog) -> list[str]:
        """Return the acceptable canonical hashes for this entry.

        Four candidates: current/legacy payload shape × aware/naive
        timestamp spelling. The naive variants exist for rows written
        before timestamps went tz-aware — those rows were hashed from the
        naive isoformat, and without the naive candidate their untampered
        heads would fail verification and halt all appends via
        ``_assert_appendable_head`` (Sentry CRITICAL + Greptile P1 T-Rex on
        #380, runtime-verified). The extra spellings admit no forgery: the
        HMAC still gates on the stored hash, and without the key no valid
        signature can be minted for any spelling.

        A row that records its caller (``api_key_id`` or ``verifier_version``
        set, #484) is checked against the current payload only. The older
        shapes leave both fields out, so accepting them for such a row would
        let anyone with database write access set or change the caller on a
        row written before #484 without breaking its hash.

        The same holds for ``admission`` (#307): a row that records one is
        checked against the current payload only. No older shape covers
        admission, so every older shape (the #484 one and the ones before
        it) is a candidate only while ``admission`` is null; otherwise
        setting an admission on an older row would leave its hash matching.

        And for ``latency_ms`` (#528): no older shape covers it, so every
        older shape is a candidate only while it is null. Setting a latency
        on a row written before #528 then fails verification, and so does
        clearing it on a row written since.
        """
        payloads = [self._reconstruct_log_data(log_entry)]
        if log_entry.latency_ms is None:
            payloads.append(self._reconstruct_pre_latency_log_data(log_entry))
            if log_entry.admission is None:
                payloads.append(self._reconstruct_pre_admission_log_data(log_entry))
                if log_entry.api_key_id is None and log_entry.verifier_version is None:
                    payloads += [
                        self._reconstruct_pre_caller_log_data(log_entry),
                        self._reconstruct_legacy_log_data(log_entry),
                    ]
        candidates = []
        for payload in payloads:
            candidates.append(self._compute_hash(payload))
            naive_payload = dict(payload)
            naive_payload["timestamp"] = _naive_ts(log_entry.timestamp).isoformat()
            candidates.append(self._compute_hash(naive_payload))
        return candidates

    def _verify_chain_link(
        self,
        log_entry: VerificationLog,
        prev_log: Optional[VerificationLog],
        errors: list[str],
        *,
        chained_before: Optional[bool] = None,
    ) -> bool:
        """Verify that one audit entry links to the correct previous entry.

        ``chained_before`` says whether the organisation has any chained row
        before this one. When it has none, an entry with no previous_hash is
        the start of the chain, whether it is the first row or the first after
        legacy rows. Left as None it falls back to "any previous row".
        """
        if chained_before is None:
            chained_before = prev_log is not None
        if log_entry.previous_hash is None and not chained_before:
            return True

        if prev_log is None:
            if log_entry.previous_hash is not None:
                errors.append("Hash chain broken: genesis entry must not reference a previous hash")
                return False
            return True

        if not prev_log.entry_hash:
            errors.append("Hash chain broken: previous entry is missing its hash")
            return False

        if prev_log.entry_hash != log_entry.previous_hash:
            errors.append("Hash chain broken: previous hash doesn't match")
            return False

        return True

    def verify_audit_trail(
        self,
        organization_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Verify the entire audit trail for an organization.

        Returns:
            {
                "valid": bool,
                "total_entries": int,
                "verified_entries": int,
                "failed_entries": list[int],
                "errors": list[str],
                "first_entry_id": int | None,
                "last_entry_id": int | None,
                "head_hash": str | None,
            }
        """
        in_period = []
        if start_date:
            in_period.append(VerificationLog.timestamp >= start_date)
        if end_date:
            in_period.append(VerificationLog.timestamp <= end_date)

        # One ordered pass (#485): find the id range of the period's entries,
        # then walk the organisation's rows over that range, carrying the
        # previous row and whether a chained row came before, instead of two
        # lookups per entry. Rows in the range but outside the period (a clock
        # that went back) are walked for the chain but not counted, as before.
        tally = _TrailTally()
        with Session(engine) as session:
            low, high = self._run_select(
                session,
                select(func.min(VerificationLog.id), func.max(VerificationLog.id)).where(
                    VerificationLog.organization_id == organization_id, *in_period
                ),
            ).one()
            if low is not None:
                prev_log = self._previous_entry(session, organization_id, low)
                chained_before = self._has_chained_entry_before(session, organization_id, low)
                for log, counts in self._trail_rows(session, organization_id, low, high, in_period):
                    if counts:
                        tally.add(log, self._check_entry(log, prev_log, chained_before))
                    chained_before = chained_before or bool(log.entry_hash)
                    prev_log = log
        return tally.result(organization_id)

    def _trail_rows(self, session: Session, organization_id: int, low: int, high: int, in_period: list):
        """The organisation's rows with ids from ``low`` to ``high``, in id order,
        each with whether it falls in the period, a page at a time.

        Each page is read in full before its rows are checked, so no SELECT
        stays open during the walk: on SQLite an open cursor holds a shared
        lock, which would make a concurrent audit append wait and fail.
        """
        counted = case((and_(*in_period), True), else_=False) if in_period else literal(True)
        after = low - 1
        while True:
            page = self._run_select(
                session,
                select(VerificationLog, counted.label("in_period"))
                .where(VerificationLog.organization_id == organization_id)
                .where(VerificationLog.id > after, VerificationLog.id <= high)
                .order_by(VerificationLog.id)
                .limit(_TRAIL_PAGE_ROWS),
            ).all()
            yield from page
            if len(page) < _TRAIL_PAGE_ROWS:
                return
            after = page[-1][0].id


class _TrailTally:
    """What verify_audit_trail counts as it walks the chain."""

    def __init__(self) -> None:
        self.total = 0
        self.verified = 0
        self.failed: list[int] = []
        self.legacy: list[int] = []
        self.errors: list[str] = []
        self.first_id: Optional[int] = None
        self.last_id: Optional[int] = None
        self.head_hash: Optional[str] = None

    def add(self, log: VerificationLog, result: Dict[str, Any]) -> None:
        self.total += 1
        if self.first_id is None:
            self.first_id = log.id
        self.last_id, self.head_hash = log.id, log.entry_hash
        if result["valid"]:
            self.verified += 1
        elif result.get("legacy"):
            self.legacy.append(log.id)
        else:
            self.failed.append(log.id)
            self.errors.extend(result["errors"])

    def result(self, organization_id: int) -> Dict[str, Any]:
        errors = list(self.errors)
        if self.legacy:
            # Unverified, not failed: they predate the chain. The trail is
            # still not reported valid while they are in range.
            errors.append(
                f"{len(self.legacy)} entries predate the audit chain and cannot be verified"
            )
        return {
            "valid": self.verified == self.total,
            "total_entries": self.total,
            "verified_entries": self.verified,
            "failed_entries": self.failed,
            "legacy_entries": self.legacy,
            "errors": errors,
            "organization_id": organization_id,
            # The range checked. Each entry hash covers the previous one, so
            # the head hash commits to the whole chain up to it.
            "first_entry_id": self.first_id,
            "last_entry_id": self.last_id,
            "head_hash": self.head_hash,
        }


class SecurityError(Exception):
    """Raised when cryptographic verification fails."""


_default_logger: Optional[AuditLogger] = None
_default_logger_lock = threading.Lock()


def get_audit_logger() -> AuditLogger:
    """Return the process-wide AuditLogger, creating it on first use.

    One instance per process, so its in-memory per-organisation chain head
    persists between requests and an out-of-band change to the newest row is
    caught at the next append. Raises SecurityError, uncached, while
    QWED_AUDIT_SECRET_KEY is unset.
    """
    global _default_logger
    if _default_logger is None:
        with _default_logger_lock:
            if _default_logger is None:
                _default_logger = AuditLogger()
    return _default_logger
