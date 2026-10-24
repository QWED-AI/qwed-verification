# Changelog

All notable changes to the QWED Protocol will be documented in this file.

## [Unreleased]

### Security

- **A configured attestation signing key (#319, #188).** Every VERIFIED
  result is signed, but with a key generated per process, so after a restart
  or on another replica no token could be verified. Set
  `QWED_SIGNING_KEY` (the PEM) or
  `QWED_SIGNING_KEY_FILE` (a path) to an unencrypted EC P-256
  private key, and every process and replica signs and verifies with it.
  - The key ID is the key's RFC 7638 thumbprint, the same everywhere.
  - A configured key that cannot be read or used (not P-256, encrypted,
    both settings set, a missing or non-regular file) is never replaced by
    a generated one: the server refuses to start, as it does without
    `QWED_AUDIT_SECRET_KEY`. Used as a library, without the server's
    startup, signing is BLOCKED instead. Errors carry no key material.
  - Unset, the key is generated per process as before, with a warning.
    `get_issuer_info()` reports the policy (`configured` or `ephemeral`) and
    `key_loaded_at`; `key_generated_at` is null for a configured key.
  - The first part of #319: delivering tokens and a JWKS to consumers
    follows.
- **`/verification-context/from-diagnostic` records a caller's diagnostic
  without vouching for it (#321).** The route built a hash-bound document,
  logged to the audit chain, from a diagnostic the caller wrote in full, and
  decided the admission from the caller's `is_valid`, which the attestation
  for a VERIFIED diagnostic does not bind. So the caller chose the document's
  message and evidence fields, and with a token, an ADMIT.
  - Only the status and `proof_ref` stay the result's own, as only they are
    checked (a VERIFIED one still needs an attestation binding them and the
    query, or the document is BLOCKED).
  - The caller's `agent_message` and `developer_fields` are kept as given
    under `developer_fields.caller_supplied`
    (`verification_context.caller_supplied_diagnostic`) and decide nothing;
    the document's message is the server's.
  - The admission is always DENY, and the audit row's `is_verified` false.
    An ADMIT would need the token to bind `is_valid` (#319).
  - `DiagnosticResult.from_dict` raises `TypeError` for a status that is not
    a string (`null`, a number, a bool, a list). It passed one through
    unconverted, so the route's `to_dict()` raised `AttributeError` and
    answered 500 instead of the malformed-diagnostic BLOCKED. A
    `DiagnosticStatus` value is still accepted, and a missing status still
    means UNVERIFIABLE.
- **Batch items and the statistics Verification Context enforce the
  attestation (#320).** After the verify routes (below), `/verify/batch`
  still returned natural-language and logic items through the advisory
  wrapper, and code, fact and SQL items with no trust step at all, so a
  batch caller got an authoritative VERIFIED that no attestation was ever
  issued for. Only maths items were signed (#271).
  - Every batch item type now takes its route's trust step
    (`attest_and_enforce`), with the route's engine name and statement. A
    VERIFIED item whose attestation cannot be issued, or does not check
    out, is BLOCKED with no `proof_ref`, and a code item's admission is
    decided on that enforced verdict.
  - A maths identity whose signing fails is BLOCKED, as on `/verify/math`,
    with `verdict_status`, `verdict_proof_ref` and `engine` beside the block;
    it was UNVERIFIABLE with its maths fields (#271). The token's engine is
    `math` (was `batch_math`).
  - `StatsVerifier.to_verification_context` decides the document by
    mandatory enforcement, as the shared bridge does, where it used the
    advisory wrapper and a hard-coded branch. It does not sign what it is
    handed. The document is unchanged: BLOCKED and DENY for a VERIFIED
    result, with the verifier's own result as evidence.
  - `get_attestation_service()` creates the shared service under a lock.
    Batch code, fact and SQL items sign from worker threads, and two first
    calls racing could each build a service with its own key, so a token
    signed by one failed the other's check and a valid item was BLOCKED.
- **Every verify route signs VERIFIED and enforces the attestation (#320).**
  The control plane's maths path signed each VERIFIED result and enforced
  the attestation as mandatory, but the other verify routes went through an
  advisory wrapper (`require_attestation=False`), so they returned an
  authoritative VERIFIED with a `proof_ref` that no attestation was ever
  issued for or checked against. A consumer applying the admission rule
  would admit it.
  - `_enforce_trust` now calls `attest_and_enforce` (`core/trust.py`), as the
    control plane does: a VERIFIED result is signed, binding its status,
    `proof_ref` and what the verdict is about, and the attestation is
    enforced as mandatory. This covers `/verify/natural_language`, `logic`,
    `stats`, `fact`, `code`, `math`, `sql`, `image`, `rag`, `process`,
    `consensus` and `/agents/{agent_id}/verify`.
  - What the verdict is about is the query, except for a natural-language
    verdict, which covers the expression the question was translated into
    (`verification_scope: translated_expression_only`): its attestation
    binds that expression, as the control plane's own does. The signed
    confidence is the engine's own where it reports one in [0, 1]
    (consensus), and 1.0 otherwise.
  - A VERIFIED result whose attestation cannot be issued, or does not match
    the result and the query, is returned BLOCKED (fail closed), with the
    verdict that was not admitted kept beside the block (`verdict_status`,
    `verdict_proof_ref`). A result that is not VERIFIED is unchanged.
  - `create_verification_attestation` takes `proof_hash`, to bind a
    DiagnosticResult's `proof_ref` as is (it is already the hash of the
    evidence); a value that is not `sha256:<64 hex>` is not signed, here or
    in `AttestationService.create_attestation`. Tokens signed this way are
    checked once and not kept in the service's in-memory registry, which
    would otherwise grow with every VERIFIED response.
  - **Breaking:** `/agents/{agent_id}/verify` returns the enforced result
    with its `admission`, in the shape `/verify/natural_language` returns,
    instead of the control plane's raw response, which still said VERIFIED
    when enforcement had blocked it. The activity log records the same.
  - The batch and the statistics verifier follow (above); the Verification
    Context route is not in this change (#321), and the token is not
    returned to the caller yet (#319).
- **Role checks on the API-key and audit routes; `rbac.py` removed (#478).**
  The user-session routes under `/auth/api-keys` and `/audit` only required a
  logged-in user, so any role could create keys, list and revoke every key in
  the organisation (the owner's included), and read and export the whole
  audit log. Not exploitable today, since signup creates one user per
  organisation, but each became a gap as soon as an organisation has a second
  user.
  - Roles and explicit allowlists live in `auth/roles.py`; a role that is not
    listed is refused, and every checked route also refuses an inactive user
    or organisation. `/admin/*` uses the same ranking.
  - API keys: creating one needs member or higher. Admins and owners list
    every key in their organisation; members and viewers list only their
    own. Anyone may revoke their own key; revoking another user's needs admin
    or owner and never a key whose owner ranks higher, as for key rotation.
    A member or viewer gets 404 for a key that is not theirs, and a
    non-numeric or out-of-range key id is 404 instead of a server error.
  - Revoking a key no longer fails with a server error on a fresh install.
    The route stored a naive `datetime.utcnow()`, which `sqlmodel` 0.0.28 and
    later reject; with the version a new install gets (0.0.48), every revoke
    returned 500. It now stores a timezone-aware time.
- **Agent tokens are stored as a keyed digest, not in plain text (#478).**
  `Agent.agent_token` held the token itself and was looked up by equality, so
  a read of the database exposed every agent token.
  - Tokens are stored as `hmac256:<hex>`, the same keyed MAC as API keys
    (keyed with `QWED_API_KEY_LOOKUP_SECRET`, under its own label), and looked
    up by digest. A token is shown once, when it is issued.
  - At startup, after the fail-closed checks, the server hashes any token
    still stored in plain text, in place, so existing tokens keep working. The
    `hmac256:` prefix marks hashed rows, so the step changes nothing once done,
    and a row is only changed if it still holds the token that was read, so a
    token re-issued meanwhile is kept. A plaintext row never authenticates
    directly.
  - `POST /agents/{agent_id}/token/reissue` (member and above, own
    organisation) gives an agent a new token and retires the old one. It is
    optional: a token that sat in plain text may also sit in a database
    backup.
  - Registering an agent, authenticating it and logging its activity no
    longer fail on a fresh install: the agent models and registry used naive
    datetimes, which `sqlmodel` 0.0.28 and later reject.
  - Audit: every role may read its organisation's log; exporting it and
    seeding samples need admin or owner.
  - `core/rbac.py` is deleted. Nothing imported it, it had no `owner` role,
    and it could be mistaken for the access control that actually runs.

- **The code-execution sandbox runs a pinned image in a hardened container
  (#322).** `SecureCodeExecutor.execute()` pulled `amancevice/pandas:slim`, a
  tag that can move to different content at any time, and ran it with a
  writable root, the default Linux capabilities and the image's default
  user (root).
  - The image is pinned by digest (`amancevice/pandas@sha256:9257b889…`,
    the `slim` tag as published on 2026-08-10). `QWED_SANDBOX_IMAGE` may
    name another image, but only by digest; any other value is refused and
    the pinned image is used.
  - The container now has a read-only root, drops every capability, sets
    `no-new-privileges` and never runs as a privileged root, on top of the
    existing network, memory, CPU and PID limits. It runs as the owner of
    the host's private `0700` exchange directory: the host user, or, when the
    host process is root, a fresh uid for this execution (the files are
    re-owned first, without following links, and the directory last). It
    comes from 1879048192-2147483646, a range systemd documents as unused,
    or from `QWED_SANDBOX_UID_RANGE` when the operator reserves one, and is
    skipped when a host account or group has it, when `/etc/subuid` or
    `/etc/subgid` delegates it to a user namespace, or when another running
    execution uses it. Under a rootless daemon run by
    the same user, the container's root is that unprivileged user. A root
    process with a rootless daemon, a userns-remap daemon, or a daemon whose
    security options cannot be read is reported as runtime unavailable
    instead of being guessed. `HOME` and `TMPDIR` point at `/workspace`, the
    only writable path.

- **CrossHair runs only inside the Docker sandbox (#431).** CrossHair analyses
  a function by importing its module, which executes the module's top-level
  code. `SymbolicVerifier` used to run `python -m crosshair check` as a plain
  host subprocess on a temp file holding the caller's code.
  - Every CrossHair run now goes through the new
    `SecureCodeExecutor.run_isolated()`: no network, read-only root, no host
    mounts, all capabilities dropped, `no-new-privileges`, user 65534, and the
    existing memory/CPU/PID limits and concurrency bound. The code travels in
    the container's environment and is written only to a private tmpfs owned
    by that user (code over 120 KiB is `BLOCKED`,
    `symbolic_verifier.input_too_large`), so nothing is written on the host.
    The output is streamed from the container log and reading stops at the
    cap. A dropped daemon connection, or a daemon error while waiting, is
    `BLOCKED` like any other sandbox failure; only a real wait timeout is a
    timeout.
  - CrossHair now runs in a child process of the in-container runner. The
    runner keeps a per-run nonce out of the child's environment, makes itself
    non-dumpable (so the child cannot read its `/proc` environment or file
    descriptors), sends the child's output to stderr, and alone writes one
    result line with the nonce and the child's exit code to stdout. The
    verifier reads stdout and stderr separately and trusts an exit code only
    when that line confirms it; otherwise the run is an engine error. So the
    analysed code cannot forge the result line, and long or unterminated
    output cannot hide it. The analysed code still controls the child's own
    exit code, as any code CrossHair imports can, which is why a clean run is
    only ever "no counterexample found" (`UNVERIFIABLE`), and why an exit 1
    is a counterexample only together with CrossHair's own report line
    (`<file>:<line>: error: ...`); an early `os._exit(1)` is an engine error.
    A `SystemExit` raised from the analysed code while it is imported is an
    engine error, not a clean run, and a child exit of 97 that comes with a
    result line is not mistaken for a missing CrossHair.
  - A `SecureCodeExecutor` that `SymbolicVerifier` creates itself is rebuilt
    while Docker is unreachable, so the engine recovers once the daemon is
    back instead of staying `BLOCKED`.
  - `qwed[symbolic]` now installs the `docker` client. `SymbolicVerifier` no
    longer imports it at module level, so without it the engine is
    `BLOCKED` instead of failing to import.
  - The image comes from `docker/crosshair-sandbox/Dockerfile`
    (`qwed-crosshair-sandbox:0.0.101`, or `QWED_CROSSHAIR_IMAGE`) and is never
    pulled at runtime.
  - Without Docker, a free sandbox slot, the image, or CrossHair inside the
    image, `verify_code()` returns `BLOCKED`
    (`symbolic_verifier.runtime_unavailable`). There is no host fallback. This
    replaces `symbolic_verifier.crosshair_not_available`.
  - Functions are now named by module qualname (`target.func`,
    `target.Class.method`). CrossHair reads `file.py:func` as a qualname, so
    the old form never found the function and exited 1, which was reported as
    a counterexample for every typed function. An exception escaping CrossHair
    now exits with its own code and is an engine error, not a counterexample.
    Nested functions, which CrossHair cannot load by name, are unverifiable.

### Fixed

- **`/verify/batch` and `/agents/{agent_id}/verify` write audit rows (#477).**
  The single `/verify/*` routes append a chained, signed `VerificationLog` row
  and return 500 if the append fails. The batch route ran up to 100 items and
  wrote no row, and the agent route logged only to `AgentActivity`, which is
  neither chained nor signed, so these verifications never reached the audit
  trail, `/audit/logs`, the CSV export or the activity summary.
  - Batch: each item appends one row after it runs, failed items included.
    The row's result holds the job id, item id, item type and the item's
    status, with its result or error under `details`. Only `details` is
    capped, so the identifiers survive a large result. The domain is the one
    the item type's own route records, and so is `is_verified`: `SAT` for
    logic; `VERIFIED` with `is_valid` true for math and code (code proven
    unsafe is not); `VERIFIED` with a `proof_ref` for fact and SQL; and the
    `/verify/natural_language` admission rule for natural language. The
    appends run in worker threads.
  - An item whose append fails is returned as `failed`, with no result and
    the error `audit persistence failed`, so no result leaves without its row.
  - Agents: the route appends the row `/verify/natural_language` writes, plus
    `agent_id`, in a worker thread, before it logs the activity and returns.
    If the append fails it returns 500 `audit persistence failed` and logs no
    activity.
  - As on the other routes, the row does not record the calling user yet
    (#484).
- **The "SOC 2" report no longer returns fixed PASS values (#476).**
  `GET /admin/compliance/report/soc2/{org_id}` returned `security_controls`
  and `compliance_status` blocks of fixed strings that nothing checked
  (`"audit_trail_complete": "PASS"`, `"access_control": "RBAC + API Keys"`,
  `"encryption_at_rest": "N/A (SQLite)"` whatever the database), and
  `threats_blocked` and `block_rate` counted an event type nothing writes, so
  both were always 0. It called itself a SOC 2 Type II report, which is an
  auditor's attestation the server cannot issue. The URL is unchanged; the
  response is now a "Security activity summary" (`report_version` 2.0):
  - `security_controls`, `compliance_status`, `threats_blocked` and
    `block_rate` are removed. A `disclaimer` says the report is not a SOC 2
    report.
  - `metrics.security_events_by_type` counts events by the types actually
    written.
  - `audit_trail` checks the signature and hash chain of every audit entry in
    the 90-day period: `VERIFIED` only when there are entries and all of them
    check out, `NO_ENTRIES` when there are none, and `NOT_VERIFIED` when any
    fails, predates the chain, or the check cannot run (for example without
    `QWED_AUDIT_SECRET_KEY`; the entry counts are then `null`, not 0). It
    lists up to 20 errors, and `total_errors` and `errors_truncated` say
    whether the list was cut. It covers the entries that were recorded; it
    does not show that every request wrote one (see #477).
  - `VERIFIED` always comes with a `proof_ref` (`sha256:...`) over `evidence`:
    the organisation, the period, the first and last entry id checked, the
    entry count and the chain head hash, which commits to every entry before
    it. Every other status has `proof_ref` and `evidence` set to `null`.
  - Checking an entry read its previous entry without a `LIMIT`
    (`Result.first()` adds none), so on PostgreSQL every earlier row was
    fetched for each entry checked. It now reads one row.
  - **Breaking for consumers of this response:** anything that read the
    removed fields must move to `audit_trail` and `security_events_by_type`.
- **`qwed pii` prints the real count for each entity type (#470).** The
  detector's report listed each type once, and the CLI counted each type in
  that list, so two emails printed `EMAIL_ADDRESS: 1`. The report now has
  `type_counts`, counted over every hit, and `types` is sorted; the CLI prints
  the counts in type order and falls back to counting `positions` for a report
  without `type_counts`.

- **The Go and TypeScript SDKs read the DiagnosticResult envelope and gate
  on admission (#480).** Both read a top-level `verified` field that only
  `/verify/rag` and `/verify/process` send (their guard's own result, not an
  admission), so Go's `Verified`, TypeScript's `verified` and both
  `isVerified()` helpers were false on every other endpoint. They now always
  equal the admission check, so rag and process, which make no admission
  decision, are not admitted; the guard's value stays in
  `developer_fields.verified`. Neither SDK exposed `admission`
  or `proof_ref`. Go's `VerifyMath` and `VerifyLogic` also failed to decode,
  because `/verify/math` sends `result` as a boolean and `/verify/logic`
  sends `error` as a string. **Breaking for both SDKs' types.**
  - `VerificationStatus` is `VERIFIED`, `UNVERIFIABLE`, `BLOCKED`, or
    `UNKNOWN` for a missing value or one the SDK does not know; the stale
    `FAILED`, `CORRECTED`, `ERROR`, `TIMEOUT` and `UNSUPPORTED` are gone. A
    new `Admission` is `ADMIT`, `BLOCKED` or `UNKNOWN`, and empty (Go) or
    absent (TypeScript) where the endpoint makes no decision.
  - The response models the envelope: `status`, `admission`, `proof_ref`,
    `agent_message`, `developer_fields`, `is_authoritative`,
    `constraint_id`, and the endpoint's own fields (Go `Extra`, TypeScript
    other keys). Go drops `Engine`, `Result`, `Attestation`, `Error`,
    `Metadata`, `ResponseMetadata` and `BatchSummary`; TypeScript drops
    `engine`, `result`, `proof`, `metadata` and the types only they used.
  - `IsAdmitted()` (Go) and `isAdmitted()` (TypeScript) are true only for
    `admission` ADMIT with `status` VERIFIED and a non-empty `proof_ref`.
    `Verified` / `verified` and `IsVerified()` / `isVerified()` are
    deprecated and now follow admission.
  - The batch types match the job the server returns (`job_id`, `status`,
    `progress_percent`, item counts, `items[]` with `id`, `status`, `query`,
    `type`, `result`, `error`, `latency_ms`); there is no `summary`.
  - TypeScript exports `parseVerificationResponse()` and
    `parseBatchResponse()`, which every `verify*` method except the two
    agent methods now uses, and `getErrorMessage()` reads a string `error`.
  - Go's `VerificationResponse` marshals `Extra` back beside the envelope
    fields, so a decoded response survives a JSON round trip; an `Extra` key
    never replaces an envelope field. Numbers in `Extra` and
    `DeveloperFields` are `json.Number`, so large integers and long decimals
    keep their exact text. (TypeScript numbers come from `JSON.parse` and
    keep its float limits.)
  - All three SDKs keep the server's status text as `RawStatus` (Go),
    `rawStatus` (TypeScript) or `raw_status` (Rust), such as `SAT` or
    `NOT_MATH_QUERY` where the parsed status is Unknown. It is never used for
    admission. Go's `MarshalJSON` and a non-enumerable `toJSON` on parsed
    TypeScript responses write it back as `status`, so a saved response keeps
    the server's status when parsed again; the Rust response types are
    deserialise-only. The Rust `VerificationResponse` now deserialises through a
    private wire type (`#[serde(from)]`) to fill it; a missing or non-string
    `status` is still an error.
  - TypeScript's `AgentVerificationResponse.verification.status` is
    `AgentVerificationStatus`, which adds the maths engine's `DISPROVEN`,
    `INCONCLUSIVE` and `SYNTAX_ERROR`.
  - Contract tests in both SDKs parse the captured responses, now shared with
    the Rust SDK in `sdk-fixtures/`. CI runs `go test` (the Go tests never
    ran before) and `vitest run` without `--passWithNoTests`. READMEs and the
    Go example explain gating on admission.

- **The Rust SDK parses the server's responses (#468).** `VerificationResponse`
  required a top-level `verified` field the server never sends, and
  `VerificationStatus` had no `UNVERIFIABLE`, so every `verify*` call failed
  to deserialize. Batch responses also expected a `summary` the server does
  not send. **Breaking for the `qwed` crate's types.**
  - `VerificationResponse` models the DiagnosticResult envelope: `status`
    (`Verified`, `Unverifiable`, `Blocked`, or `Unknown` for a value the SDK
    does not know), `admission` (`Admit`, `Blocked`, `Unknown`, or `None`
    where the endpoint makes no decision), `proof_ref`, `agent_message`,
    `developer_fields`, `is_authoritative`, `constraint_id`, and the
    endpoint's own fields in `extra`. The `verified`, `engine`, `result`,
    `attestation`, `error` and `metadata` fields and the `ErrorInfo`,
    `ResponseMetadata` and `BatchSummary` types are gone.
  - `is_admitted()` replaces `verified`: true only for `admission` ADMIT with
    `status` VERIFIED and a `proof_ref`. VERIFIED alone is not enough, because
    a claim proven false (`2 + 2 = 5`) or code proven unsafe is VERIFIED and
    BLOCKED. A missing or unknown admission is never admitted. `is_verified()`
    is deprecated and now returns `is_admitted()`.
  - `BatchResponse` and `BatchResult` match the batch job the server returns;
    each item's `result` is a `VerificationResponse`.
  - A body that does not match now fails as `Error::Serialization` rather
    than as an HTTP decode error.
  - Contract tests parse responses captured from the server
    (now in `sdk-fixtures/`, shared with the Go and TypeScript SDKs), CI now runs `cargo test` for the Rust SDK,
    and `tests/test_issue_468_rust_sdk_contract.py` fails if the server's
    answers drift from those fixtures. The README documents the envelope and
    gating on `is_admitted()`.
  - `.dockerignore` leaves test folders at any depth and the non-Python
    SDKs (`sdk-*/`) out of the Docker build context; no image copies them.

- **The Docker image runs the API server, and the Compose stack builds
  (#467).** The image published as `qwedai/qwed-verification` ran the GitHub
  Action: its entrypoint was the Action script, the uvicorn `CMD` was passed
  to it as ignored arguments, and the image had no FastAPI or uvicorn. The
  Compose file pointed at a Dockerfile in `deploy/`, which does not exist,
  and mounted a Grafana folder that was never shipped.
  - The Dockerfile has two targets. `server` runs uvicorn on port 8000 as a
    non-root user, installs every server dependency from the new hash-pinned
    `requirements-server.txt`, and has a health check on `/health`. The
    host and port come from `UVICORN_HOST` and `UVICORN_PORT`, which the
    health check reads too, so `-e UVICORN_PORT=...` moves both.
    `action` is the GitHub Action as before; it stays the last stage, so
    `action.yml`, which builds the Dockerfile without a target, is unchanged.
  - Docker Hub now gets the `server` target, so `qwedai/qwed-verification`
    is the API server from 7.3.1. Anyone who ran an earlier tag as a
    scanner should use the Action instead.
  - `deploy/docker-compose.yml` builds the server target from the
    repository root, requires all five server secrets (`QWED_CORS_ORIGINS`,
    `API_KEY_SECRET`, `QWED_JWT_SECRET_KEY`, `QWED_API_KEY_LOOKUP_SECRET`,
    `QWED_AUDIT_SECRET_KEY`), checks health without curl, and keeps the
    server's data in a volume. `deploy/.env.example` lists every setting
    with empty values. Compose refuses to start until the server settings
    and `DATABASE_URL` are filled in; the Postgres and Grafana containers
    refuse to start while their passwords are empty (Grafana would otherwise
    fall back to `admin`/`admin`). Postgres and Grafana no longer load the
    whole `.env` file, which handed them the server's secrets; each gets
    only its own settings. Grafana gets Prometheus and Jaeger data
    sources, and Prometheus scrapes the API as `qwed-core:8000` instead of
    `host.docker.internal`, which does not resolve inside the Compose
    network on Linux.
  - The `docker` client is part of the `server` extra: the code executor
    imports it at module level, so a request that reached it failed with an
    `ImportError` instead of the sandbox's fail-closed result.
  - The Kubernetes manifest pins `7.3.1`, the first server image. Its
    Secret lists the three secrets it was missing and ships every value
    empty instead of with secret-like placeholders.
  - A new "Docker images" workflow builds the server through Compose,
    starts it and waits for `/health` and the image's own health check,
    checks that the default target still runs the Action, and brings the
    whole Compose stack up until every service is healthy, with the server
    on Postgres and Prometheus reaching it.

- **`AgentStateGuard` returns `BLOCKED` for deeply nested JSON instead of
  raising `RecursionError` (#469).** Parsing and canonicalisation recurse once
  per nesting level and only `ValueError` was caught, so a payload such as
  `'[' * 200000` escaped the public API as an exception. A payload nested
  deeper than `MAX_PARSE_DEPTH` (256 levels, above the 64-level validation
  limit) is now rejected before parsing with `QWED-AGENT-STATE-102`, by a
  pass that ignores brackets inside strings. Any `RecursionError` or
  `MemoryError` from parsing or canonicalisation is mapped to the same code,
  and so is a number whose exponent is outside `Decimal`'s range
  (`decimal.InvalidOperation`), which also escaped before.
  Transitions and commits inherit this through `verify_state_payload`.
- **The GitHub Action's scan modes run with the default `paths`, and an empty
  scan is no longer admitted (#466).** `action.yml` defaulted `paths` to
  `'.'`, which `Path('.').glob` rejects, so `scan-code`, `verify-shell` and
  `scan-secrets` exited with a traceback before scanning anything. A pattern
  that matched no files reported `VERIFIED · ADMIT`.
  - `paths` now defaults to empty. Unset, empty or `.` uses the mode's own
    patterns: `**/*.py`, `**/*.sh`, or the env, JSON, YAML, TOML and INI
    files for `scan-secrets`.
  - A scan that covered no files is `UNVERIFIABLE · DENY`, with
    `verified=false` and a reason in the verification context. It fails the
    step unless `fail_on_findings` is `false`.
  - So is a partial scan: a matched file that cannot be read, or a Python
    file that does not parse, was skipped with a warning and the rest of
    the scan could still be admitted.
  - An invalid pattern, or one that matches a file outside the workspace (an
    absolute path, `..`, or a symlink to a file elsewhere), is reported by
    name and the scan is `UNVERIFIABLE · DENY` rather than raised. Matches
    that are not regular files, such as a symlinked directory, are ignored.
  - `scan-secrets` no longer swaps in the default secret-file patterns when
    the given `paths` match nothing; that admitted files nobody asked for.
  - A new `files_scanned` output gives the number of files scanned. A file
    reached through more than one pattern or link is scanned once, and the
    mode's file type is checked first, so a link with another name cannot
    stand in for a `.py` or `.sh` file and leave it unscanned.
- **The natural-language logic bridge emits the DSL parser's operator names.**
  `DSLLogicVerifier` translated `!=`, `>=`, `<=` and `*` to `NE`, `GE`, `LE`
  and `MUL`, which the DSL whitelist does not know (it has `NEQ`, `GTE`,
  `LTE` and `MULT`). Every bridged constraint using one of them came back
  `BLOCKED` ("Unknown operator"): fail-closed, but valid constraints such as
  `x >= 5` or `x * 2 <= 10` could never be verified. The bridge now emits the
  whitelist names. A test pins every operator the bridge can emit to
  `QWEDLogicDSL().operators`, and per-operator tests run the real parser,
  compiler and Z3 and check the exact DSL and the SAT/UNSAT result. No verdict
  mapping changed; unknown operators, unsupported Python syntax and solver
  errors still fail closed.
  The bridge also lowercased `And(...)` / `Or(...)` to `and(...)` / `or(...)`,
  which is not valid Python, so a constraint written in the function style the
  bridge supports came back `ERROR`. Keywords in call position now become the
  `And` / `Or` calls (in any case); infix `AND` / `Or` / `not` still read as
  operators.
- **The logic DSL compiles every operator its parser accepts (#428).**
  `IFF`, `FORALL` and `EXISTS` were whitelisted by the parser and suggested
  by the provider prompts, but the Z3 compiler had no branch for them, so any
  program using them failed with `Unknown operator`.
  - `(IFF a b)` compiles to a biconditional. Both operands must be Boolean
    (comparisons or `Bool` variables); `(IFF x y)` on two Ints is an error
    instead of silently becoming `x == y`.
  - `(FORALL x body)` and `(EXISTS x body)` bind `x` inside `body` only. The
    bound variable takes its declared sort (`Int` if undeclared, as for free
    variables), a free variable of the same name outside the quantifier is
    unaffected, and the body must be Boolean. The parser blocks a binder that
    is not a plain variable name (a number, an operator, a literal or an
    expression).
  - A solver `unknown` (e.g. a timeout on a hard quantified formula) stays
    `BLOCKED` at `/verify/logic`, as before.
  - The Anthropic and Azure OpenAI logic prompts now describe the binder and
    Boolean-operand rules, and their examples are valid DSL: the old
    `(FORALL p (EQ (status p) happy))` used an operator that does not exist.
  - A structural test compiles one sample program for every whitelisted
    operator, so the parser and compiler cannot drift apart again.
- **The logic DSL no longer turns a Boolean literal into 1 or 0.** Python
  `True`/`False` are ints and an undeclared name is auto-created as an `Int`,
  so `(EQ flag True)` compiled to `flag == 1` and came back `SAT` with
  `flag = 1`: a verified answer to a constraint that did not mean what was
  asked. z3 likewise turned an `Int` compared with a `Bool` variable into
  `x == If(b, 1, 0)`.
  - `EQ`/`NEQ` between a Boolean (literal, `Bool` variable or comparison) and
    a non-Boolean value is now a compile error (`ERROR`, never `SAT`/`VERIFIED`).
    `GT`/`LT`/`GTE`/`LTE` reject any Boolean operand, since Booleans have no
    ordering.
  - `PLUS`/`MINUS`/`MULT`/`DIV`/`POW`/`MOD` reject Boolean operands, so a
    Boolean cannot reach a comparison disguised as a number:
    `(EQ x (PLUS True 0))` used to compile to `x == 1`, and a `Bool` variable
    inside arithmetic to `If(b, 1, 0)`.
  - An undeclared name compared with `True`/`False` is rejected, not guessed
    to be a `Bool`: the error asks for `(VAR name Bool)`. Inferring the sort
    from the literal would hide a translation that forgot the declaration.
  - Comparing two Booleans, or a declared `Bool` with `True`/`False`, works as
    before, and numeric comparisons are unchanged.
- **A math claim proven false is now `VERIFIED` with admission `DENY`, not
  `UNVERIFIABLE` (#437).** `2+2=5` used to come back as "Verification
  inconclusive", which recorded a definite counter-proof as "could not be
  proven". Admission was `DENY` either way, so nothing unsafe passed, but audit
  rows and Verification Context documents carried the wrong meaning.
  - `VerificationEngine` no longer emits `CORRECTION_NEEDED`. A mismatch decided
    by a concrete computation returns the legacy status `DISPROVEN`.
  - Symbolic checks (derivative, indefinite integral, limit, `/verify/math`
    identities) return `DISPROVEN` only when SymPy decides the difference is
    non-zero: outright, by the coefficients of a bounded polynomial (a
    coefficient counts as non-zero only when SymPy decides it, so a true
    identity with an irrational coefficient like `cos(pi/7) - cos(2*pi/7) +
    cos(3*pi/7) - 1/2` is never disproven), or at an exact witness point. A
    difference `simplify` cannot decide returns `INCONCLUSIVE`, which maps to
    `UNVERIFIABLE`.
  - An identity that only holds after `simplify` cancels a removable
    singularity (`x/x = 1`, `(x**2-1)/(x-1) = x+1`) is `UNVERIFIABLE` with
    `constraint_id: math.domain_restricted_identity` in `/verify/math`, and
    `INCONCLUSIVE` (`reason: domain_mismatch`) in `verify_identity` (#429).
    The denominators are read from the expression before SymPy evaluates
    it (after the same NFKC normalization, so fullwidth operators count),
    including the right side of floor division and modulo (`x//x = 1`,
    `x % x = 0`); an identity is VERIFIED only when both sides have the same singular
    factors. An identity using a function with poles or a singular point
    (`tan`, `sec`, `log`, `factorial`, ...) and a free symbol is never
    VERIFIED this way; closed constants such as `factorial(5) = 120` are.
    A symbol-free part that is undefined (`log(0)**0 = 1`, `tan(pi/2)**0 = 1`)
    or a constant zero denominator (`(1/(x-x))**0 = 1`) also blocks it, even
    though SymPy evaluates such parts away. Names are read from the AST, so
    a scientific literal such as `0e0` is never mistaken for a symbol.
  - A witness point is used only when it satisfies the symbol's declared
    domain (`n` is a positive integer, so `-1`, `0` and `1/2` are skipped).
    It is substituted without evaluation and checked by the new
    `safe_parser.check_closed_expression_cost` first, so a lazy power tower
    such as `9**9**9**x` is never expanded at a witness.
    A witness SymPy cannot evaluate is skipped, so the result is
    `INCONCLUSIVE` rather than an engine error.
  - A non-zero difference containing a Float literal (`0.1 + 0.2 = 0.3`
    leaves 5.55e-17) is `INCONCLUSIVE`, not `DISPROVEN`. A numeric mismatch
    involving a non-finite value (an overflowed sum, a NaN claim) is also
    `INCONCLUSIVE`.
  - `verify_irr` decides Newton convergence on the rate step instead of an
    absolute NPV residual, so small cash flows no longer stop at the
    initial guess and report a correct IRR claim as `DISPROVEN`. Newton steps
    are damped to keep `1 + r > 0`, so a negative IRR (`[-100, 20, 20]` is
    -44%) is no longer replaced by a spurious root below -100%.
    Non-finite cash flows are `BLOCKED` before the solver runs, and the step
    halving is bounded, so `[inf, -1]` can no longer hang the request.
  - Matrix `add`, `multiply`, `inverse`, `transpose` and `determinant` run
    exactly: each float input is read as the decimal the caller wrote (`0.1`
    is 1/10), with no tolerance. So `[[0.1]] + [[0.2]]` vs `[[0.3]]` is
    `VERIFIED`, `[[0.5]] + [[1e9]]` vs `[[1000000001.0]]` is `DISPROVEN`, and
    the determinant no longer accepts `-2.0000001` for `det([[1, 2], [3, 4]])`.
    A float claim of an exact entry holds when its decimal or its double is
    exactly that value, or, for a fraction that is not a double
    (`inverse([[3]])` is 1/3), when it is the correctly rounded double; a
    non-zero value that underflows to `0.0` never accepts a `0.0` claim. A
    claim that only rounds to the same double, or falls inside the rounding
    window, is `INCONCLUSIVE`. A claimed matrix of the wrong shape is
    `DISPROVEN`; a non-finite entry is `INCONCLUSIVE`.
  - Definite integrals and eigenvalues are decided exactly when both sides are
    exact. With a float claim, the difference itself is evaluated at a
    precision scaled to the magnitude against the 1e-6 tolerance; a mismatch
    within the representation error of the least precise Float involved
    (a double's 2**-52 at least, narrower only for a claim clearly more
    precise than any double repr, wider for one deliberately less
    precise) is
    `INCONCLUSIVE`,
    anything larger is `DISPROVEN`. Floats are replaced by their exact
    values before subtracting, so `2**53 + 1` vs `9007199254740992.0` is no
    longer a difference of 0. Past the precision budget (~1e105) a gross
    mismatch is still `DISPROVEN` (`2e200` vs `1e200`) and anything closer
    is `INCONCLUSIVE`. A divergent integral is `INCONCLUSIVE`.
    Eigenvalues are compared as complex numbers, so a rotation matrix's
    `+-i` no longer matches a claim of `[0, 0]`.
  - `verify_unit_conversion` uses the exact legal unit definitions in Decimal
    (1 lb = 0.45359237 kg, 1 US gal = 3.785411784 L) and `BLOCKED`s units of
    different dimensions (`m` to `kg`) instead of comparing the numbers.
    Temperature conversions also run in Decimal, and the tolerance is
    validated before any branch.
  - The control plane signs and attests `DISPROVEN` like `VERIFIED`, with
    `verified=False` in the attestation and `is_valid: false` in the result.
  - New `DiagnosticResult.disproven()` builds a `VERIFIED` result with
    `is_valid` forced to `False`. `from_legacy_dict` raises for `DISPROVEN`,
    because a counter-proof needs a `proof_ref`.
  - The control-plane math response and `/verify/math` now include
    `admission`. `/verify/math` logs `is_verified` from `is_valid`, so a
    proven-false identity is no longer logged as verified.
  - `/verify/natural_language` now returns the verdict the control plane
    enforced (attached as `diagnostic`) together with `admission`, instead of
    re-deriving it from the legacy engine dict, which turned every decided
    claim into `UNVERIFIABLE`. A malformed diagnostic is `BLOCKED`, and if the
    output sanitizer rejects the translated expression the verdict is
    `BLOCKED` too. The verdict carries `translated_expression`,
    `verification_scope: translated_expression_only` and
    `query_semantics_verified: false`, so it is not mistaken for proof of the
    user's question. For the same reason admission is always `DENY` there
    (and in the control-plane response), even when the translated claim
    holds: the translation itself is unverified, so the user's question is
    never admitted. The verdict is not changed, and the log row's
    `is_verified` follows admission.
- **`qwed init` and `qwed test` print the verdict with its admission (#438).**
  Decided cases no longer print `BLOCKED`, and `VERIFIED` never appears alone:
  `2+2=5 -> VERIFIED (false) | DENY`. A failed self-check prints `FAILED`. The
  closing lines say `All engines ready.` instead of "All engines verified".

### Changed

- **Batch maths and SQL items return and store their admission (#307).**
  `/verify/math` and `/verify/sql` return an `admission` beside the verdict,
  because a proven-false identity and a proven-malicious query are both
  VERIFIED and neither is admitted. Their batch items returned the verdict
  only, and their audit rows stored no admission.
  - A batch maths or SQL item's `result` has `admission` (`ADMIT` or
    `BLOCKED`), decided on the enforced verdict as on its route, and its
    audit row stores it. Batch logic and fact items still store null, as
    their routes decide none.
  - Two route rules the batch skipped, which would have let a batch item be
    admitted where the route does not: a maths identity that holds only on
    a restricted domain (`x/x = 1`) is UNVERIFIABLE with
    `math.domain_restricted_identity`, as on `/verify/math` (#429; it was
    VERIFIED), and a SQL item without `params.schema_ddl` fails with
    `Missing 'schema_ddl'`, as `/verify/sql` answers 400 (it was verified
    with an empty schema, which skips the table check).
  - `sdk-fixtures/batch.json` carries the two items' admissions, and the Go,
    Rust and TypeScript SDKs' contract tests and docs say which batch items
    carry one (they said none did, already out of date for code and
    natural-language items). The proven batch item now counts as admitted
    by the SDKs' `is_admitted`.
- **Breaking for `/verify/batch`: logic and natural-language items return
  what their routes return (#494).** The batch returned the control plane's
  raw dict for these items, so a batch caller got `SAT` where a
  `/verify/logic` caller got `VERIFIED`, natural-language items had no
  `admission`, and batch logic audit rows had no verdict (`verdict: null` in
  `/audit/logs`).
  - The routes' mappings moved to `core/route_diagnostics.py`
    (`logic_diagnostic`, `natural_language_diagnostic`); the routes and the
    batch both call them and apply the same trust step.
  - A batch logic item's `result` is now the `/verify/logic` response:
    `VERIFIED` (with a `proof_ref`) for SAT, `UNVERIFIABLE` for UNSAT,
    `BLOCKED` otherwise. A natural-language item's is the
    `/verify/natural_language` response, with `admission`.
  - Callers that read `status: "SAT"`/`"UNSAT"`, or the control plane's own
    fields at the top level of a batch logic or natural-language result, must
    move to the DiagnosticResult fields. For logic items the control plane's
    output remains under `developer_fields`. For natural-language items it
    does not: as on `/verify/natural_language`, only the verdict is kept, and
    fields such as `final_answer`, `translation` and `trust_boundary` are no
    longer returned. Math, code, fact and SQL items are unchanged.
  - A batch audit row keeps the item's verdict beside its ids, outside the
    capped details, so `/audit/logs` still reads it when a large result is
    truncated.
  - Their audit rows follow: logic rows now carry a verdict, and
    natural-language rows store the admission. Rows already written keep
    what they stored.
- **Audit rows store the admission decision their route made (part of
  #307).** A row's verdict is not an admission (code proven unsafe is
  VERIFIED and BLOCKED), and the rows stored no admission, so `/audit/logs`
  could not show one.
  - `VerificationLog` has a new nullable column, `admission` ("ADMIT" or
    "BLOCKED"), added to an existing table at startup. It holds the
    admission the route decided (and returned, except on the agent
    route): `/verify/natural_language`,
    `/verify/code`, `/verify/math` and `/verify/sql`, the agent route
    `/agents/{agent_id}/verify` (natural-language rule, decided though not
    returned), `/verify/batch` code and natural-language items (#494) and
    `/verification-context/from-diagnostic` (stored as returned, "ADMIT" or
    "DENY" in the Verification Context spec's terms). Routes that decide none
    (logic, stats, fact, image, RAG, process, consensus, other batch items)
    store null, as do rows written before this release.
  - The entry hash covers `admission`, so it cannot be set or cleared on a
    stored row. A row without one is also checked against the payload
    hashed before admission was covered, so rows written by earlier
    releases still verify.
  - `GET /audit/logs` and `GET /audit/logs/{log_id}` return `admission`.
  - As with #484, an older release cannot verify a row hashed this way:
    upgrade every process together.
- **Security events can be listed, and API keys record when they were last
  used (#486).** Security events could only be read as a summary, and
  `ApiKey.last_used_at` was never set (both places that would set it were
  commented out).
  - New `GET /admin/security/events` lists the organisation's events for
    owners and admins (API key or signed-in session), newest first by
    timestamp and id, with a `before` cursor and `next_before` as on
    `/audit/logs`, `limit` 1 to 200 (default 50) and an optional
    `event_type`. A cursor that is not an event in the organisation, or is
    out of the id range, is 404. Anything shaped like an API key or agent
    token in `reason` or `query` is masked, wherever it appears in the text;
    the writers already store a preview only.
  - An API key's `last_used_at` is set when it authenticates, on the
    `/verify/*` routes and the admin routes, after every check passes
    (on the admin routes, after the user, organisation and role checks too),
    so a refused key is never recorded. It is written at most once a minute
    per key: a key used within the minute costs no query, and the write
    only applies if the stored value is still stale, so two workers write it
    once. The write runs in a worker thread, off the event loop. A failed
    write is logged and never fails the request.
- **The compliance routes accept a signed-in session, and check the whole
  chain (#485).** They took an `x-api-key` only, so a dashboard user had to
  paste an owner or admin key into the browser, and the only check was one
  entry at a time.
  - `GET /admin/compliance/verify/{log_id}`, `/admin/compliance/export/csv`,
    `/admin/compliance/report/soc2/{org_id}` and the new `verify-trail` also
    accept `Authorization: Bearer <jwt>` for an owner or admin. The session
    gets the same checks as the user-session routes: an active user in an
    active organisation, with an allowed role. `x-api-key` works as before
    and is used when both are sent. The other `/admin/*` routes still take
    an API key only.
  - New `GET /admin/compliance/verify-trail?start=&end=` checks the
    signature and hash chain of every entry of the caller's organisation in
    the period (open-ended without `start` or `end`; a time without a zone is
    UTC, and other offsets are converted to UTC). It returns the same
    `audit_trail` fields as the activity summary (#476): `VERIFIED` with a
    `proof_ref` only when there are entries and all check out, `NO_ENTRIES`,
    or `NOT_VERIFIED`, with the counts and the new `first_failed_entry_id`.
    `start` after `end` is 400.
  - The activity summary's `audit_trail` gains `first_failed_entry_id` too.
  - `verify_audit_trail` checks the chain in one ordered pass, reading the
    rows a page of 500 at a time, instead of two database lookups per entry,
    so it makes one query per page rather than two per entry. Each page is
    read in full before it is checked, so no SELECT stays open to hold a
    SQLite lock against appends. The result per entry is the same as
    checking each entry on its own.
- **Audit rows record the API key that made them and the server version
  (#484).** A row could not say who wrote it or with which release.
  - `VerificationLog` has two new nullable columns: `api_key_id`, the id of
    the API key that authenticated the request, and `verifier_version`,
    `qwed_new.__version__` when the row was written.
  - `get_current_tenant` records the key id for the request
    (`core/request_caller.py`), and the audit logger writes it on every row
    that request appends, so no verify route passes it by hand. A row
    written without an API key has `api_key_id` null: a user session, the
    audit seed, and `/agents/{agent_id}/verify`, which authenticates with an
    agent token (its row's result names the agent, #477).
  - Both fields are covered by the entry hash, so changing or clearing them
    on a stored row fails verification. Rows written before this change
    still verify, and adding a caller to one of them breaks its hash.
  - Upgrading: `create_db_and_tables` adds the two columns to an existing
    `verificationlog` table at startup (`core/schema_migrations.py`).
    Existing rows read as null, which the API and the dashboard show as not
    recorded.
  - Upgrade all at once, and do not roll back past this release. An older
    release hashes a row without the two fields, so it cannot verify a row
    this release wrote. When such a row is an organisation's chain head,
    the older release refuses every further append for that organisation
    (fail closed, so its verify routes return 500). Stop every process on
    the old release before starting this one, as the single-writer rule
    already requires, and once this release has written a row, do not go
    back to an older one.
  - `GET /audit/logs` and `GET /audit/logs/{log_id}` return `api_key_id` (as
    a string, like other ids) and `verifier_version`.
  - `user_id` is unchanged: verify routes still write it as null. The key's
    owner is not always the caller, and `api_key_id` leads to the owner.
- **`GET /audit/logs` pages through every row (#484).** `limit` was capped
  at 200 with no offset or cursor, so a client could only read the newest
  200 rows.
  - Rows come newest first, by timestamp and then id, so the order is
    stable when two rows share a timestamp. Before, only the timestamp
    ordered them.
  - The response adds `next_before`: the last row's id when the page is
    full, or `null`. Pass it back as `before` for the rows after that one.
    A full last page is followed by an empty page with `next_before: null`.
  - A `before` that is not a log in the caller's organisation returns 404,
    as the detail route does. `limit` and the `status` filter work as
    before, and `total` is still the number of rows on the page.
  - An id outside the SQL BIGINT range (for example `2**63`) is 404 on
    both `before` and `GET /audit/logs/{log_id}`. On SQLite the lookup
    raised `OverflowError` and the route returned 500.
- **The audit log routes report the stored verdict and the chain entry
  (#484).** `GET /audit/logs` and `GET /audit/logs/{log_id}` returned only
  `status`, derived from `is_verified`, so an UNVERIFIABLE result read
  `blocked`, and `is_verified` means something different on different routes.
  - Both routes add `verdict`: `VERIFIED`, `UNVERIFIABLE` or `BLOCKED` as the
    verifier stored it in the row's result (the `status` of a `/verify/*`
    result, the `verdict` of a Verification Context document, or the item
    result's `status` in a `/verify/batch` row), or `null` when the result
    has none, is truncated, or holds another value. It is never worked out
    from `is_verified`.
  - `verdict` is not an admission. `VERIFIED` means the check ran to a
    proof, not that the claim holds: a disproven identity or code proven
    unsafe is `VERIFIED` with a `blocked` status. Do not gate on it alone.
  - The list adds each row's `entry_hash`. The detail adds `entry_hash`,
    `previous_hash` and `hmac_signature`, as stored.
  - `status` is unchanged. Neither field is an admission decision; these
    rows do not store one yet (#307).
- **Contacts and links moved to `qwedai.tech`.** It is now the only QWED
  domain in the repository.
  - The maintainer and security contact is `rahul@qwedai.tech` (SECURITY.md,
    the Code of Conduct, the README, `pyproject.toml`, `funding.json`). Support
    is `support@qwedai.tech`. The default `ALERT_EMAIL_TO` is now
    `rahul@qwedai.tech`; set the variable to keep another address.
  - Website, docs and finance links point to `qwedai.tech`, `docs.qwedai.tech`
    and `finance.qwedai.tech`. Error messages link to the docs pages directly
    instead of through redirects, and the `.env.example` LLM guide link, which
    was a 404, now points to the current page.
  - Links to hosts that never existed are gone. The 500-error hint says to
    check the server logs, the SDK READMEs show a self-hosted server as the
    custom base URL (there is no hosted API), and the issue template links to
    `docs.qwedai.tech`.
  - The Verification Context schema `$id` is
    `https://qwedai.tech/schemas/verification-context/v1.0`, in both copies.
    Tools that look the schema up by its old `$id` need the new one.
  - `qwed init` signs up its local bootstrap account with an `example.com`
    address, and test fixtures use `example.com` and `example.test`. The
    organisation slug in that address is cut to fit the 64-character limit
    on an email's local part; a long organisation name used to make signup
    fail with a 422.
  - `scripts/setup_and_verify.py` reads the admin login from
    `QWED_ADMIN_EMAIL`, so a local setup made with the old address keeps
    working.
  - `QWEDSyntaxError` now shows its docs link, as the other QWED errors do.
- **The API now writes its audit rows through the signed hash chain.** Every
  `/verify/*` endpoint, the Verification Context routes and `POST /audit/seed`
  used to write `VerificationLog` rows directly, so `entry_hash`,
  `hmac_signature` and `previous_hash` stayed empty. `/admin/compliance/verify/{log_id}`
  and `verify_audit_trail` could not verify those rows, and the CSV export
  marked them `Legacy`. They now append through `AuditLogger`, so new rows are
  HMAC-signed and chained per organisation. `/verify/batch` and
  `/agents/{agent_id}/verify` wrote no row at all; they append one too now
  (#477, under Fixed).
- **Breaking: `QWED_AUDIT_SECRET_KEY` is required.** The server refuses to start
  without it. If an audit append fails at request time (key unset, a chain head
  that fails verification, a continuity mismatch, a database error), the request
  returns 500 `audit persistence failed` rather than a result with no audit row.
  `qwed init` now persists a key alongside the JWT and lookup secrets and never
  rotates an existing one. Projects onboarded earlier have none in `.env`:
  re-run `qwed init` (existing secrets are kept) or set it yourself.
- **Existing rows stay unverified.** Rows written before this change have no
  hash. `verify_log_entry` reports them as `legacy: true` and never `valid`. The
  first chained row after them opens a new segment with no `previous_hash`.
  `verify_audit_trail` lists them under `legacy_entries` and stays
  `valid: false` while any are in range; pass `start_date` to verify from the
  upgrade onwards. An unchained row after a chained row is not legacy: appends
  stop and verification fails.
- **Single writer.** The audit logger keeps each organisation's chain head in
  memory, so one process should append to a given database. A second writer
  makes the next append fail with a continuity error (500) rather than fork the
  chain. The shipped Dockerfile runs one uvicorn worker.
- **`/verify/consensus` audit rows store the result JSON** like every other
  endpoint, instead of a `Consensus: …` summary string that could never be
  verified.
- **`POST /audit/seed` is off by default.** It answers 404 and writes nothing
  unless `QWED_ENABLE_AUDIT_SEED=1`, so sample rows never mix with a production
  trail. When enabled, its rows are timestamped when written, not backdated,
  marked `{"sample": true}`, and use a fixed sequence instead of `random`.
- **The CSV export says `Chained`, not `Verified`.** The column is now
  `Chain Status`: a present hash is not a verified chain. Use
  `/admin/compliance/verify/{log_id}` to verify a row.
- **`qwed init` also proves the audit key.** `/health/identity` returns an
  `audit_hmac` (503 without a key), and init refuses a running server on a
  different audit key. An older server without the audit proof is refused
  too: restart it on this release, then re-run init.
- **Audit appends use their own connection pool**, take a per-organisation
  database lock before reading the chain head (a PostgreSQL advisory lock, or
  `BEGIN IMMEDIATE` on SQLite) as defence in depth, and redact PII per string so
  stored results stay valid JSON.
- **`.env` writes keep retained settings verbatim** and quote new values that
  python-dotenv would otherwise change, so a signing key reads back unchanged.

Verification still does not detect removal of the newest entries; that needs an
externally stored checkpoint of the latest hash.

## [7.3.0] - 2026-10-16

A fail-closed security and soundness release. It ships five private advisories
(three of them completing earlier incomplete fixes), the tenant-scoping and
denial-of-service hardening tracked since 7.2.3, credential-handling fixes, and
a versioned Go module path. All engine changes make verification stricter and
fail closed; no response field is removed or renamed. The soundness eval grew
to 84 known-answer claims, 0 accepted wrongly.

### Security fixes (advisories)

Five advisories, published on the repository Security tab. They affect all
versions up to 7.2.3; upgrading is recommended. All five have regression tests
in `tests/`; the SQL, code and logic advisories (GHSA-6p94, GHSA-6cpx,
GHSA-4phf, GHSA-g25v) also have reproductions in the soundness eval (`evals/`).
The sandbox advisory (GHSA-j3x4) is exercised by its subprocess test, which the
eval runner does not cover.

- **SQL commands are classified across the whole statement tree**
  (GHSA-6p94-4f75-g2wq, high) — destructive DML (`DELETE`/`UPDATE`/`INSERT`/…)
  hidden inside a CTE or subquery, administrative statements
  (`COPY`, `ATTACH`, `PRAGMA`, `CALL`, …), and any statement whose root is not a
  read-only `SELECT`/`UNION`/… are now reported invalid
  (`developer_fields.is_valid = false`, denied by `admission_decision`) wherever
  they appear. Before, the command-type check only inspected the top level, so
  `WITH x AS (DELETE …)` and non-`SELECT` statement families were admitted
  (`core/sql_verifier.py`).
- **Code verification never admits alternate process-execution routes or
  file/network sinks** (GHSA-4phf-6h72-9xfg, high; completes
  GHSA-6rxr-gq43-694g) — `os.posix_spawn*`, `os.fork`, `pty.fork`,
  `importlib`/`runpy` dynamic import and execution, `ctypes` library loaders,
  and reads/writes through `io.open`/`shutil`/`pathlib`/`socket`/`urllib`/
  `requests`/… are now blocking findings, including the bare `open` builtin and
  the raw `posix`/`nt` modules (`core/code_verifier.py`).
- **The code-execution sandbox isolates its namespace**
  (GHSA-j3x4-v3p2-4mq3, high; completes GHSA-6rxr-gq43-694g) — user code runs
  under a capability allowlist (`__builtins__` reduced to safe names, a guarded
  `__import__` that admits only an allowlist of analysis modules such as
  numpy/pandas/scipy) instead of a static denylist that could be bypassed
  through package-internal re-exports and reflection. User code is read from a
  separate file and never inlined into the harness
  (`core/secure_code_executor.py`).
- **SQL `SELECT *` is expanded against the schema and tautologies are folded at
  the value level** (GHSA-6cpx-8jrq-r7h3, moderate) — with `schema_ddl`, a `*`
  (qualified or not) that resolves to a blocked column is rejected instead of
  slipping past the sensitive-column denylist; always-true predicates
  (`OR 1=1`, `OR 'a'='a'`, arithmetic tautologies) are detected by
  constant-folding the comparison rather than matching text shapes
  (`core/sql_verifier.py`).
- **The logic natural-language bridge rejects string constants**
  (GHSA-g25v-44j8-gg7x, moderate; completes GHSA-mfh5-3c8f-975p) —
  `_constant_to_dsl` no longer mangles a categorical string into a bare token
  the compiler turned into a free integer, which had made contradictory claims
  (`tier == 'gold' AND tier == 'silver'`) satisfiable and VERIFIED. String
  literals now fail closed; encode categories as explicit integers
  (`core/dsl_logic_verifier.py`).

### Soundness and access control

- **Admin endpoints are scoped to the caller's tenant** and RBAC is enforced,
  closing a cross-tenant access gap ([#222], #450).
- **The money verifier rejects non-finite amounts** (`NaN`/`inf`) and
  `verify_invoice_total` never raises ([#451]).
- **The SDK's `verify_fact` fails closed** when the service is unreachable
  instead of returning a permissive result ([#326], #449).

### Hardening and resource limits

- **Blocking work is kept off the event loop and request bodies are capped**,
  closing denial-of-service paths ([#390], [#391], [#392], [#445], #447).
- **Concurrent sandbox containers are bounded** so a burst cannot exhaust the
  host ([#446], #448).
- **API-key rotation is atomic**, so concurrent rotations mint a single key
  ([#452], #453).

### Credential handling

- **Connection URLs (Redis, Postgres) are redacted before logging**, so an
  embedded password is not written to logs ([#228]); the **auth boundary
  rejects expired API keys** ([#389]); **provider imports are https-only**
  ([#229]) (#454).
- **SDK error detail is sanitized** — full detail is logged for operators and a
  generic error is raised to callers ([#225], #455).

### SDKs and tooling

- **Go module path is versioned** (`.../sdk-go/v7`) and release tagging emits
  `sdk-go/vX.Y.Z`, so `go get` resolves the module ([#443], #457).

### Docs

- Whitepaper errata item 8 corrected (the LangChain example) (#456).
- Assurance case and README updated for the 7.3.0 advisories and eval count.

### Behaviour changes

Every engine change is stricter and fails closed; no response field is removed
or renamed. The code-execution sandbox now admits only an allowlist of modules
and builtins, so sandboxed user code that imported other modules will need them
added to the allowlist. The SQL verifier now denies statements it previously
admitted (non-`SELECT` roots, DML in CTEs, `*` over blocked columns, value-level
tautologies) by returning `VERIFIED` with `developer_fields.is_valid = false`,
which `admission_decision` rejects; the logic NL bridge returns
`UNVERIFIABLE`/error for categorical string constants.

[#222]: https://github.com/QWED-AI/qwed-verification/issues/222
[#225]: https://github.com/QWED-AI/qwed-verification/issues/225
[#228]: https://github.com/QWED-AI/qwed-verification/issues/228
[#229]: https://github.com/QWED-AI/qwed-verification/issues/229
[#326]: https://github.com/QWED-AI/qwed-verification/issues/326
[#389]: https://github.com/QWED-AI/qwed-verification/issues/389
[#390]: https://github.com/QWED-AI/qwed-verification/issues/390
[#391]: https://github.com/QWED-AI/qwed-verification/issues/391
[#392]: https://github.com/QWED-AI/qwed-verification/issues/392
[#443]: https://github.com/QWED-AI/qwed-verification/issues/443
[#445]: https://github.com/QWED-AI/qwed-verification/issues/445
[#446]: https://github.com/QWED-AI/qwed-verification/issues/446
[#451]: https://github.com/QWED-AI/qwed-verification/issues/451
[#452]: https://github.com/QWED-AI/qwed-verification/issues/452

## [7.2.3] - 2026-10-13

### Security fixes

This is a fail-closed security release covering three advisories:
GHSA-6rxr-gq43-694g, GHSA-64xf-wffc-63fm and GHSA-q5g6-6cw2-cjm3. They affect
all versions up to 7.2.2; upgrading is recommended. The advisories were
published on the repository Security tab on 2026-10-13. No breaking wire changes.

- **Code verification never admits shell or process execution** —
  `os.system`, `os.popen`, the `os.exec*` and `os.spawn*` families,
  `os.posix_spawn*`, `os.startfile`, `subprocess.*`, `pty.spawn` and
  `asyncio.create_subprocess_*` are now blocking findings
  (`process_execution`), including calls made through an aliased import
  (`import subprocess as sp`, `from os import system as run_it`,
  `from os import *`). Before, they were warnings and such code was admitted,
  even when caller input reached the shell. `verify_code`,
  `verify_python_deep` and `POST /verify/code` are covered
  (`core/code_verifier.py`).
- **Project-scoped OpenAI keys** — `ConfigGuard` and the code verifier now
  detect `sk-proj-`, `sk-svcacct-` and `sk-admin-` keys as well as legacy
  keys (`qwed_sdk/guards/config_guard.py`, `core/code_verifier.py`).
- **SQL verification** — MySQL and MariaDB executable comments
  (`/*! ... */`, `/*!NNNNN ... */`, `/*M! ... */`) are expanded before
  analysis, so SQL inside them is checked; and with `schema_ddl`, a query on a
  table outside the schema is BLOCKED with `sql_verifier.schema_violation`
  instead of being admitted with a warning (`core/sql_verifier.py`).

### Behaviour changes

All three make the engines stricter. No response field is removed or
renamed; the SQL verifier adds the constraint `sql_verifier.schema_violation`
and the field `developer_fields.executable_comments_expanded`.

- Code that runs a shell command or subprocess is no longer admitted by the
  code verifier, even with a constant argument. Run such code through a
  reviewed, sandboxed tool instead.
- With `schema_ddl`, a reference to an undeclared table is an admission
  failure (`is_valid: false`, constraint `sql_verifier.schema_violation`).
  Names defined by the query itself (CTEs) are not tables. Without
  `schema_ddl`, tables are not checked, as before.
- Executable comments are analysed as SQL whatever the declared dialect;
  `developer_fields.executable_comments_expanded` says when that happened.

### Added

- **Soundness eval** (`evals/`, in the repository, not the wheel): claims
  with a known answer run through the Math, Logic, SQL, Code and Schema
  engines, including the reproductions from GHSA-j622-qffp-rc27,
  GHSA-mfh5-3c8f-975p, GHSA-6rxr-gq43-694g and GHSA-q5g6-6cw2-cjm3
  (GHSA-64xf-wffc-63fm is covered by `tests/test_openai_project_keys.py`,
  not the eval). `python -m evals.run`
  reports how many claims were proved, caught or wrongly accepted;
  `tests/test_evals.py` fails CI on any claim that does not hold but was
  accepted, or on any engine that raises; and `.github/workflows/eval.yml`
  attaches the report (`eval-results.json`) to every release.

> **Semver:** patch release — security fixes that restore fail-closed
> behaviour, plus repository tooling. No breaking wire changes.

## [7.2.2] - 2026-10-09

### Security fixes

This is a fail-closed security release covering four published advisories:
GHSA-4v5r-g7f4-vvgc, GHSA-mfh5-3c8f-975p, GHSA-j622-qffp-rc27 and
GHSA-mxwv-x5qm-mrmf. They affect all versions up to 7.2.1; upgrading is
recommended. No breaking wire changes.

- **Local SDK math verification** — the SymPy expression validator now rejects
  string literals nested inside container arguments, closing an allow-list
  bypass that could route untrusted model output to SymPy's string-evaluation
  path (`qwed_sdk/qwed_local.py`).
- **Logic verification soundness** — the Z3 constraint evaluator no longer
  accepts Python boolean operators (`and`/`or`/`not`) or chained comparisons on
  symbolic objects, and the DSL compiler rejects string literals instead of
  materialising them as variables. Both could otherwise yield a `VERIFIED`
  verdict that did not follow from the input
  (`core/safe_evaluator.py`, `core/dsl/compiler.py`).
- **Large-number math verification** — `verify_math` now compares results at a
  precision scaled to the operands, so values beyond 15 significant digits are
  no longer rounded before the comparison (`core/verifier.py`).
- **Computational cost bounds** — the math parser applies its cost gates to
  implicit-multiplication input, and the logic/DSL engines bound
  statically-known integer powers, preventing short requests from exhausting a
  worker (`core/safe_parser.py`, `core/safe_evaluator.py`, `core/dsl/compiler.py`).

## [7.2.1] - 2026-09-14

### Security fix

- **Math answer comparison hardening (GHSA-xmm6-8r3x-j567)** — `QWEDLocal._math_answers_match` fed the untrusted model answer to raw `sympy.sympify()`, whose eval sink executes dunder-traversal gadgets smuggled in the answer turn. The answer is now parsed only through the hardened `safe_parse_expr` (character allow-list, AST allow-list, builtins stripped, cost-bounded); unparseable input and a missing parser fail closed to `False`.
- **Release boundary gate** — `scripts/check_boundary.py` now scans `qwed_sdk/` and forbids raw `sympify` outside approved wrappers (shell findings honor line-scoped `# noqa`).

> **Semver:** patch release — security fix only, no new capability, no breaking wire changes. `qwed` 7.2.1 on PyPI and crates.io carries the fix. (Correction: the npm publish of `@qwed-ai/sdk` 7.2.1 failed, so npm stayed at 7.2.0; the failure was hidden by `continue-on-error` in the publish workflow.)

## [7.2.0] - 2026-09-07

### Security hardening batch

Fail-closed fixes restoring intended behavior — no breaking wire changes:

- **Expression & math safety (#329, #330, #344)** — `safe_parse_expr` NFKC normalization bypass and denylist bypass fixes (authenticated RCE), plus structural hardening (charset gate, AST allowlist) and a structural math-output gate with module-indirection blocklist (#346).
- **Auth hardening (#333, #334, #345)** — pre-auth KDF removed from lookup path, bcrypt offloaded, `/auth/*` throttling, brute-force oracle closed.
- **Sandbox containment (#335, #338, #339, #351)** — module-indirection AST gate bypass closed, container leaks fixed (log rotation, `pids_limit`, container removal, result size caps), stats sandbox result read-back bounded against host-memory amplification.
- **Event-loop safety (#340, #341, #352, #354)** — consensus orchestration and stats verification offloaded from the event loop; consensus translator expression smuggling closed; engine-call waits bounded (sympy compute-cost gate, provider HTTP timeouts, stats upload cap); CircuitBreaker non-reentrant lock replaced with RLock (#332, #343).
- **Metrics & deploy (#337, #349, #350)** — all-tenant metrics restricted to explicit platform operators; Prometheus scraping fixed to the `/metrics/prometheus` endpoint.
- **Supply chain (#355–#361)** — scheduled Dependabot version updates across pip/npm/Go/Rust/Docker/Actions; esbuild dev-server CVE overridden past the patched release.

### Precision advisory (new capability, #347, #348)

- **Advisory flag for binary floating-point constants** in math/stats verification — emitted as `developer_fields.advisory_checks[]` entries with `constraint_id` `"precision.float-constants"` (also mirrored at top level).

### Dependency modernization

- pip: sympy 1.14, z3-solver 5.x, sqlglot 30.x, sentry-sdk 2.68, hatchling 1.32 (#359); GitHub Actions group across 15 actions (#360); Python 3.13 → 3.14 base image (#356); reqwest 0.12 → 0.13 in `sdk-rust` (`rustls-tls` renamed to `rustls`, #357); esbuild override past dev-server CVE (#361).

> **Semver:** minor release — one additive capability (precision advisory) plus fail-closed fixes and dependency modernization. No breaking wire changes.

## [7.1.0] - 2026-08-16

### Verification Context v1.0 Rollout

#### Ontology & Spec (#301, #302)

- **ADR-001..005 — verification ontology** — formally define the object of verification, the verification context document, the truth-vs-admission separation, the formalization boundary, and the root of trust.
- **Verification Context v1.0 spec freeze** — the 4-layer JSON document contract (interpretation / proof / evidence / decision) with canonical RFC 8785 JSON encoding, UTF-16 key ordering, fail-closed schema validation, and content-bound `proof_ref`.

#### Core Model (#308, #309)

- **`VerificationContext` model + JSON schema** — `VerificationContext`, `VerificationContextDocument`, `Verdict`, `Admission`, and nested `Interpretation` / `Proof` / `Evidence` / `Decision` types with fail-closed validation.
- **Public proof_ref generation / resolution** — `compute_document_proof_ref()` and `resolve_document_proof_ref()` exposed as public API; references are content-bound SHA-256 hashes over the canonical document.

#### Bridge & Verifier Mappings (#310, #316)

- **`verification_context_from_diagnostic_result()`** — converts `DiagnosticResult` → VC document; VERIFIED without attestation fails closed to BLOCKED via `enforce_trust_decision` (`trust_gate.mandatory_attestation_missing`, consistent with the core contract).
- **`to_verification_context()` across the verifier classes** — implemented on `CodeVerifier`, `ConsensusVerifier`, `DSLLogicVerifier`, `FactVerifier`, `BatchFactVerifier`, `GraphFactVerifier`, `ImageVerifier`, `MultiVLMVerifier`, `LogicVerifier`, `ReasoningVerifier`, `SchemaVerifier`, `SQLVerifier`, `StatsVerifier`, and `SymbolicVerifier` (14 classes). Math and secure-code-execution results convert through `verification_context_from_diagnostic_result()` instead.

#### Surface Exposure (#311, #313, #314, #315)

- **SDK / API / CLI exposure** — Verification Context surfaced across the API routes, CLI, and SDK.
- **Docker action VC outputs** — the containerized GitHub Action emits `verdict`, `admission`, `proof_ref`, and `verification_context` outputs.
- **Metadata & README alignment** — repository metadata aligned with the v7.0 architecture.
- **SDK re-exports** — all Verification Context v1.0 types re-exported from `qwed_sdk`.

> **Semver:** minor release — additive public API (VC model, mappings, resolver, routes, outputs). No breaking wire changes.

## [7.0.0] - 2026-08-08

### Engine Migration to DiagnosticResult (Meta #216)

#### SchemaVerifier → DiagnosticResult (#255)
- **`SchemaVerifier.verify()` and `verify_ucp_transaction()` now return `DiagnosticResult`** (status / `agent_message` / `developer_fields` / `proof_ref`) instead of ad-hoc dicts.
- **`proof_ref`** is computed deterministically from a canonical `json.dumps` of the schema + instance evidence on VERIFIED results; unsupported values and cyclic structures fail closed to `BLOCKED` (`schema_verifier.validation_error`).
- **Recursive schema meta-validation** — malformed keyword shapes (non-dict properties, invalid required entries, invalid numeric constraints, non-finite/NaN/±∞ bounds, negative size constraints) return `BLOCKED` (`schema_verifier.parse_error`) instead of being silently treated as empty.
- **UCP type safety** — string/None amount fields and non-dict transactions are handled deterministically instead of raising `TypeError`/`AttributeError`.
- **UCP verdict fields are complete on every path** — `verify_ucp_transaction()` always produces `transaction_type`, `currency`, and `schema_verifier.ucp_*` constraint ids in `developer_fields` for both valid and violated verdicts (BLOCKED base results pass through unchanged).
- **Money arithmetic uses `Decimal`, not float tolerance** — computed-total and tax checks quantize operands to the currency precision and compare exactly, removing 0.01-tolerance rounding noise so boundary transactions deterministically pass/fail.
- **`tax` is selected by key presence, not truthiness** — a declared `tax: 0` is used instead of silently falling back to `tax_amount`.
- **Non-finite floats (`NaN`, `±inf`) and hostile `__repr__` set members fail closed** — evidence serialization raises `ValueError` into the existing `BLOCKED` path instead of emitting non-JSON tokens or leaking `RuntimeError`.
- **`agent_message` sanitized** — no rule IDs, issue types, or schema internals leak into agent-facing output.
- **Removed orphan `math_verifier` delegation** — the lazy `SymbolicVerifier` instantiation (never called) is gone; computed-field checks use inline exact Decimal comparison.
- **Hot path cost of the migration reduced (~20% fewer instructions)** — proof evidence is traversed once instead of twice (cycles and unsupported types are detected by the canonical encoder itself), the canonical JSON encoder is reused across calls, and schema meta-validation dispatches on the keywords a schema declares instead of probing the full keyword vocabulary. `proof_ref` values are unchanged.
- **Oversized integer bounds no longer crash** — `minimum` / `maximum` / `exclusiveMinimum` / `exclusiveMaximum` / `multipleOf` values beyond float range (e.g. `10**1000`) are finite by construction and no longer raise `OverflowError` out of `verify()`.

#### CodeVerifier & SecureCodeExecutor → DiagnosticResult (#254, PR #296)
- **`CodeVerifier.verify_code()`, `verify_python_deep()`, and `verify_batch()` now return `DiagnosticResult`** (status / `agent_message` / `developer_fields` / `proof_ref`) instead of ad-hoc dicts.
- **`VERIFIED` is now emitted for unsafe code — as `VERIFIED`-as-unsafe.** A proven-unsafe snippet is `VERIFIED` with `developer_fields.is_valid = false`, a bound `proof_ref`, and a non-null `critical_count`; it is never emitted `BLOCKED`. This is `VERIFIED` as a *truth* guarantee (the code was checked), not an *admission* guarantee.
- **`AdmissionDecision` is a separate decision, exposed at the trust boundary** — `POST /verify/code` and batch `CODE` items attach `admission` (`ADMIT` / `BLOCKED`) and treat `is_valid` as the safety gate, so authority-only consumers reading `status == "VERIFIED"` cannot admit unsafe code.
- **`BLOCKED` is reserved for cases where verification itself failed** — empty code, non-string `language`, internal/execution errors, and (deep) language normalization failures. Blocked results carry **no** `proof_ref`, so they cannot be mistaken for a verdict.
- **`SecureCodeExecutor.execute()` no longer executes code wholesale on the verifier verdict** — the executor applies an unconditional OWASP LLM06 dangerous-pattern gate (`os.`, `sys.`, `subprocess`, `__import__`, `eval`, `exec`, `compile`, `open(`, `file(`, `input(`, `raw_input(`, `socket`, `urllib`, `requests`, `http`) and blocks execution with `CONSTRAINT_DANGEROUS_PATTERN`. The scan is **AST-aware**: it matches actual executable operations (imports, attribute access, calls), so dangerous keywords that appear only in comments, docstrings, or string literals (e.g. a URL in a docstring) do not cause false denials. The advisory-only fallback is retained only when verification itself fails closed.
- **`verify_batch()` returns per-item `verdicts` + a `summary` and an overall `is_valid`** — `safe` / `unsafe` / `blocked` counts and `total_critical`; `is_valid` is `true` only when **all** snippets are safe, and the batch is otherwise non-admissible.
- **`ConsensusVerifier` and `StatsVerifier` code-stages adapt** — expected-status flags were updated to require `is_verified` **and** `developer_fields.is_valid is True`, and `stats_verifier._validate_security` fails closed on any non-true `is_valid`, so consensus results can no longer admit unsafe code.

> **Breaking wire change:** `POST /verify/code` now returns **HTTP 200 with `status = "VERIFIED"`** for proven-unsafe code (previously `status = "BLOCKED"`). Admission is driven by the new `admission` field and `developer_fields.is_valid`. Consumers that branched on `status == "BLOCKED"` or `status == "VERIFIED"` for safety gating **must** switch to the `admission` / `is_valid` fields; `status == "VERIFIED"` alone must never be treated as "safe to execute".

#### StatsVerifier → DiagnosticResult (#256)
- **`StatsVerifier.verify_stats()` now returns `DiagnosticResult`** (status / `agent_message` / `developer_fields` / `proof_ref`) instead of an ad-hoc dict.
- **Execution success is **never** `VERIFIED` (computation ≠ verification).** A run that executes cleanly in the Docker sandbox and returns an observed statistic is `UNVERIFIABLE` (`stats_verifier.claim_not_verified`) — the engine has no deterministic claim-proof, so it cannot attest the original natural-language claim. `VERIFIED` + `proof_ref` is reserved for a deterministic claim evaluation tracked in #298; it is never emitted from execution success alone.
- **`BLOCKED` is reserved for failure states** — translation/validation failure (`stats_verifier.validation_error`), execution failure (`stats_verifier.execution_failure`), and secure Docker sandbox unavailable (`stats_verifier.runtime_unavailable`). Blocked results carry **no** `proof_ref`.
- **Execution evidence is preserved, not lost.** On `UNVERIFIABLE` the observed result, generated code, columns, a deterministic dataset fingerprint (`dataset_sha256`), sandbox type, timing, and security checks are retained in `developer_fields` for audit/review.
- **`agent_message` is sanitized** — no raw subprocess output, sandbox identifiers, or error strings leak into the agent-facing layer.
- **API boundary is now a thin pass-through** — `POST /verify/stats` forwards the engine's `DiagnosticResult` through `enforce_trust_decision()` unchanged instead of re-deriving status from dict fields.
- **Logging is fail-closed and claim-aware** — the verification log records `is_verified` from the authoritative proof bit AND the claim-validity signal (`dr.is_authoritative and developer_fields.is_valid is True`). A non-authoritative result (BLOCKED / UNVERIFIABLE, `proof_ref = None`) can never be persisted as verified, even if the mutable `developer_fields.is_valid` metadata is `True`.
- **`compute_statistics()` and `get_sandbox_info()` are deliberately unchanged** — they are utilities (safe direct computation / sandbox introspection), not claim-verification boundaries, so they stay on their existing dict return.
- **Deferred architecture is tracked, not silently dropped** — deterministic statistical claim evaluation (#298) and deterministic DataFrame schema validation (#299) do not exist in the codebase and were not invented here; both are filed as dedicated issues rather than being fabricated to force a `VERIFIED`.
- **`FactVerifier`/`ImageVerifier` batch verification now returns `DiagnosticResult`** — `BatchFactVerifier.verify_batch()` and `ImageVerifier.verify_batch()` return a single `DiagnosticResult` with per-claim verdicts in `developer_fields.results` and a `summary`. The batch is authoritative (`VERIFIED` + `proof_ref`) only when **every** claim is deterministically verified; any refuted/blocked claim fails the whole batch closed (`fact_verifier.batch_blocked` / `image_verifier.batch_blocked`), and an empty batch is `BLOCKED` (`*.empty_batch`). The batch `proof_ref` binds full claim digests **and the shared input** (image digest for image batches, context digest for fact batches), never truncated display text. Aggregation is shared via `diagnostics.aggregate_batch_diagnostic()` so the fail-closed logic cannot drift between engines. This closes the last two public engine entry points still returning ad-hoc dicts under META #216.
- **Stats `observed_result` is JSON-safe** — a non-serializable sandbox result (e.g. a DataFrame) is coerced before entering `developer_fields`, so a legitimate `UNVERIFIABLE` verdict can no longer be silently downgraded to `BLOCKED` when the trust gate snapshots developer fields.

> **Breaking wire change:** `POST /verify/stats` now returns the unified `DiagnosticResult` schema (`status` / `agent_message` / `developer_fields` / `proof_ref`) instead of the legacy `{"status": "SUCCESS" | "ERROR" | "BLOCKED", "result": ..., "code": ...}` shape. Successful execution now reports `status = "UNVERIFIABLE"` with the observed value in `developer_fields.observed_result` — execution success alone is never presented as a proven claim.

#### Version Propagation
- `qwed` (PyPI): `6.0.0` -> `7.0.0`
- `qwed_sdk` (Python): `6.0.0` -> `7.0.0`
- `@qwed-ai/sdk` (NPM): `6.0.0` -> `7.0.0`
- `qwed` (crates.io/Rust): `6.0.0` -> `7.0.0`
- API version marker: `6.0.0` -> `7.0.0`
- Kubernetes deployment image: stays pinned to the published `6.0.0` here; bumped to `7.0.0` only after the release publishes the image (avoids `ImagePullBackOff`)
- Deployment docs version references updated

#### Included PRs (merged after v6.0.0)
- `#294` feat(core): migrate SchemaVerifier to DiagnosticResult (#255)
- `#295` fix(sql): migrate SQLVerifier to DiagnosticResult (#253)
- `#296` feat(core): migrate CodeVerifier and SecureCodeExecutor to DiagnosticResult (#254)
- `#297` feat(stats): migrate StatsVerifier.verify_stats to DiagnosticResult (#256)

#### GitHub Action
- The **QWED Verification GitHub Action** is maintained in its own repository — [`QWED-AI/qwed-verification-action`](https://github.com/QWED-AI/qwed-verification-action). It wraps the `qwedai/qwed-verification` Docker image and is versioned independently of this release; it is **not** published from this repository, so no action release is part of v7.0.0.

## [6.0.0] - 2026-08-02

### Trust Boundary Completion (Epic #263)

Completes the Trust Boundary Completion epic — all 12/12 sub-issues closed. Every verification API pathway now returns `DiagnosticResult` and routes through `enforce_trust_decision`. The trust boundary is no longer advisory: the control plane requires and verifies attestation before admitting VERIFIED results, and VERIFIED is a protocol guarantee backed by a non-empty, deterministic `proof_ref`, never by execution, agreement, confidence, or provenance. Engine-level migrations to `DiagnosticResult` remain tracked under META #216.

> **⚠️ Breaking change:** `/verify/*` API responses now use the unified `DiagnosticResult` schema (status / `agent_message` / `developer_fields` / `proof_ref`). Consumers of the previous ad-hoc dict responses must migrate.

#### Architecture: Observation vs Admission (#264, #265)
- **All `/verify/*` endpoints return `DiagnosticResult`** (PR #276)
- **Control plane enforces mandatory attestation** — `require_attestation=True`, attestation issued + verified, enforced status drives HTTP response status (PR #278)
- **Batch math** routes through `DiagnosticResult` + attestation + `enforce_trust_decision` (PR #282)
- **Attestation scope alignment** — attest translated expression, not natural-language query, so `query_hash` binds to what was actually verified (#279, PR #285)

#### VERIFIED is a protocol guarantee (#266, #267, #269, #270)
- **ConsensusResult** uses `DiagnosticStatus` enum with `proof_ref` + `verified_evidence` (PR #280)
- **FactVerifier** heuristic SUPPORTED verdict → UNVERIFIABLE with `advisory_checks` (PR #283)
- **Consensus code execution** advisory-only, VERIFIED → UNVERIFIABLE (PR #281)
- **Consensus stats computation** advisory-only, never VERIFIED (PR #277)
- **LogicVerifier** migrated to `DiagnosticResult` (PR #262)
- **AgentStateGuard** `proof_ref` = real sha256 of committed bytes, not a static sentence (#268, PR #284)

#### Engineering & Security Hardening
- **TOCTOU closure** in `enforce_trust_decision` — `developer_fields` snapshotted via recursive rebuild (no `deepcopy` alias window), fail-closed snapshot (#273, PR #290)
- **Attestation signature verified before claim decode** — silent generic error for all failure modes (#275, PR #287)
- **Tenant-isolated verification cache** — `VerificationCache` keys namespaced by normalized `tenant_id` (#274, PR #286)
- **Unicode normalization** in AgentStateGuard canonicalization — NFC collisions rejected (#272, PR #288)
- **Mandatory proof artifact** for VERIFIED attestations (issuance + consumption, PR #248)
- **Credential / JWT / dockerignore security alerts** resolved (PR #249)
- **Math whitelist injection bypass** removed (PR #251)
- **Engine classification docs** — Proof / Policy Enforcement / Advisory (PR #247)

#### Rules & Protocol Semantics
- `QWED_RULES.md` codifies the trust-boundary contract: **#13 Separation of Responsibilities**, **#14 Verification Semantics**, **#15 Truth Before Policy**; rules #7/#8 updated to capture admission-boundary and deterministic-proof semantics

#### Version Propagation
- `qwed` (PyPI): `5.3.0` -> `6.0.0`
- `qwed_sdk` (Python): `5.3.0` -> `6.0.0`
- `@qwed-ai/sdk` (NPM): `5.3.0` -> `6.0.0`
- `qwed` (crates.io/Rust): `5.3.0` -> `6.0.0`
- API version marker: `5.3.0` -> `6.0.0`
- Kubernetes deployment image: `5.3.0` -> `6.0.0`
- Deployment docs + historical roadmap version references updated

#### Included PRs
- `#247` docs: engine classification — Proof / Policy Enforcement / Advisory
- `#248` fix(#191): enforce mandatory proof artifact on VERIFIED attestations (issuance + consumption)
- `#249` fix: resolve credential / JWT / dockerignore security alerts
- `#251` fix(#227): remove math whitelist injection bypass
- `#260` fix(#257): hybrid engine advisory-only — never VERIFIED without proof
- `#261` fix(#259): FactVerifier advisory-only
- `#262` feat(#252): LogicVerifier migrated to DiagnosticResult
- `#276` fix(api): migrate all /verify/* endpoints to return DiagnosticResult (#264)
- `#277` fix(#270): consensus stats advisory-only, never VERIFIED
- `#278` fix(#265): control plane trust enforcement mandatory
- `#280` fix(#266): ConsensusResult DiagnosticStatus enum + proof_ref + verified_evidence
- `#281` fix(#269): consensus code execution advisory-only
- `#282` fix(#271): batch math DiagnosticResult → proof_ref + attestation + enforce_trust_decision
- `#283` fix(#267): FactVerifier SUPPORTED → UNVERIFIABLE with heuristic advisory_checks
- `#284` fix(#268): AgentStateGuard proof_ref real sha256
- `#285` fix(#279): attest translated expression, not natural language query
- `#286` fix(#274): VerificationCache tenant isolation
- `#287` fix(#275): attestation verify-before-decode + silent generic error
- `#288` fix(#272): NFC-normalize AgentStateGuard canonicalization
- `#289` fix: mock network in secret redaction tests (CI)
- `#290` fix(#273): close TOCTOU in enforce_trust_decision

## [5.3.0] - 2026-07-25
### SymbolicVerifier: DiagnosticResult Reference Implementation

SymbolicVerifier is the first fully `DiagnosticResult`-conformant verification engine and serves as the reference implementation for future engine migrations. The unified diagnostic model is no longer aspirational — one of 13 engines now demonstrates the complete pattern.

#### Completed (Phase 1 + Phase 2, META #216)
- **Phase 1** — 6 public methods migrated to `DiagnosticResult`: `verify_code`, `verify_function_contract`, `verify_safety_properties`, `verify_bounded`, `analyze_complexity`, `get_verification_budget`
- **Phase 2** — All internal code paths produce `AdvisoryCheck` for non-proof-bearing analysis; `developer_fields` provides structured evidence; `verification_mode` field tracks bounded vs. unbounded analysis
- **Fail-closed math bugs (#129-#131)** — All three resolved, ensuring safety constraints always block when out of budget (PRs #217-#219)
- **Key rotation (#224)** — Secure key attestation rotation implemented (PR #232)

#### Version Propagation
- `qwed` (PyPI): `5.2.0` -> `5.3.0`
- `qwed_sdk` (Python): `5.2.0` -> `5.3.0`
- `@qwed-ai/sdk` (NPM): `5.2.0` -> `5.3.0`
- `qwed` (crates.io/Rust): `5.2.0` -> `5.3.0`
- API version marker: `5.2.0` -> `5.3.0`
- Kubernetes deployment image: `5.2.0` -> `5.3.0`

#### Ecosystem Status
- **1 of 13 engines conformant** — SymbolicVerifier as reference implementation
- **Remaining engines tracked under META #216** (12 engines + security hardening + attestation consumption)
- Open audit issues: #162-#164 (Logic/Graph/Reasoning), #205 (SecureCodeExecutor), #221-#231 (security hardening), #191 (attestation consumption)

#### Included PRs

**Core: SymbolicVerifier Migration (Phase 1 + Phase 2)**
- `#212` feat: migrate SymbolicVerifier to DiagnosticResult (Phase 1)
- `#239` feat: add verification_mode to SymbolicVerifier DiagnosticResults (#237)
- `#240` feat(#236): migrate verify_bounded to return DiagnosticResult
- `#241` feat(#234): migrate get_verification_budget to return DiagnosticResult
- `#242` feat(#233): migrate analyze_complexity to return DiagnosticResult
- `#243` feat(#235): migrate verify_safety_properties to return DiagnosticResult

**Fail-Closed Bug Fixes (Math)**
- `#217` fix(math): fail-closed on ambiguous mode — block multi-mode datasets (#129)
- `#218` fix(math): require eigenvalue cardinality match before verification (#130)
- `#219` fix(math): require IRR convergence proof before VERIFIED (#131)

**Security & Key Rotation**
- `#220` fix: remove unused check_assertions parameter from verify_code
- `#232` fix: use PBKDF2 instead of raw SHA-256 for key rotation hashing

**Code Quality & Tooling**
- `#208` docs: archive stale docs — roadmap.md, ARCHITECTURE.md (historical), update DEPLOYMENT.md version refs
- `#209` docs: sync README with v5.2.0 codebase — engines, guards, architecture
- `#210` fix: Potential fix for code scanning alert no. 515: Log Injection
- `#211` fix: replace polynomial regex with O(n) str.find loop for data URI removal
- `#213` fix: silence CodeQL clear-text-logging false positives in security demo
- `#215` Add GitLab badge to README

## [5.2.0] - 2026-06-19
### Architecture: Structured Verification Diagnostics (#204)

Establishes the unified 3-layer `DiagnosticResult` model — the diagnostic contract that all verification engines will conform to. This is an **additive** release: no existing engine return types are changed. Engine conformance is tracked in blocked issues (#129, #130, #131, #133, #134, #162, #163, #164, #190, #205).

#### New: `DiagnosticResult` Model (`src/qwed_new/core/diagnostics.py`)

Three disclosure layers:
- **Layer 1 — Agent-Safe**: `agent_message: str` — agent/model-facing summary, no internals leaked
- **Layer 2 — Developer**: `developer_fields: dict` — structured evidence (constraint_id, advisory_checks, methods_used, evidence)
- **Layer 3 — Proof**: `proof_ref: Optional[str]` — sha256 hash of retained proof artifact; the authority bit

Key design:
- `DiagnosticStatus`: tri-state only (`VERIFIED` / `UNVERIFIABLE` / `BLOCKED`) — no proliferation
- `proof_ref` is the authority bit: present = admissible for control flow, None = reject
- `VERIFIED` requires `proof_ref` — structurally enforced in `__post_init__`
- `AdvisoryCheck`: non-proof-bearing analysis (LLM fallback, NLI, VLM) — `advisory_only=True` enforced
- `compute_proof_ref()`: deterministic sha256 hashing of JSON-serialized evidence
- `from_legacy_dict()`: migration helper for ad-hoc engine dicts (fail-closed states only)
- Both `DiagnosticResult` and `AdvisoryCheck` are `frozen=True` dataclasses — prevents post-construction bypass

#### Version Propagation
- `qwed` (PyPI): `5.1.2` -> `5.2.0`
- `qwed_sdk` (Python): `5.1.1` -> `5.2.0`
- `@qwed-ai/sdk` (NPM): `5.1.2` -> `5.2.0`
- `qwed` (crates.io/Rust): `5.1.2` -> `5.2.0`
- API version marker: `5.1.2` -> `5.2.0`
- Kubernetes deployment image: `5.1.2` -> `5.2.0`

#### Tests
- 83 new tests covering status taxonomy, all 3 layers, authority contract, fail-closed enforcement, advisory checks, proof hashing, serialization round-trip, legacy migration, frozen dataclass immutability, and realistic scenarios drawn from the 10 blocked issues.

#### Included PRs
- `#206` feat(diagnostics): unified 3-layer DiagnosticResult model (#204)

## [5.1.2] - 2026-06-14
### Security: SymPy Expression Injection Fix (CWE-95)

Emergency patch fixing a **High severity (CVSS 8.8) authenticated RCE vulnerability** in SymPy `parse_expr()` across all math verification paths.

#### Security Fix
- **CWE-95 mitigation**: Added `safe_parse_expr()` wrapper with denylist, stripped `__builtins__`, allow-listed math namespace, per-call global dict copy, and post-parse validation. Replaced all 17 direct `parse_expr()` call sites in `main.py`, `verifier.py`, `batch.py`, and `validator.py`.
- **Symbol consistency**: Added `get_safe_symbol()` to ensure calculus variables (`n`, Greek letters) match special SymPy assumptions, preventing incorrect `diff`/`integrate`/`limit` results.
- **Defense-in-depth**: Pre-parse AST depth limit, post-parse SymPy tree depth validation, `sympy.Expr` type enforcement, `extra_symbols` key/value validation, and sanitized exception handling.

#### Fixes and Hardening
- **Cache Redis fail-closed**: Enforced fail-closed Redis backend for distributed cache mode (PR #199).
- **Benchmarks CI**: CodSpeed performance benchmark workflow added (PR #198).
- **TS SDK lockfile**: Restored `package-lock.json` for reliable `npm ci` in publish workflow (PR #197).

#### Included PRs since v5.1.1
- `#197` fix(ts-sdk): lockfile restore for npm ci publish
- `#198` ci: CodSpeed performance benchmarks
- `#199` fix(cache): fail-closed Redis backend for distributed mode
- `#200` fix(math): restrict sympy expression parsing (CWE-95)

## [5.1.1] - 2026-05-21
### Release Consistency and Fail-Closed Follow-Through

Patch release packaging the post-v5.1.0 trust-boundary and fail-closed corrections into a coherent publishable state across core package metadata, SDKs, deployment references, and release automation.

#### Trust Boundary and Correctness Fixes
- **Cache trust-context binding**: Bound verification cache artifacts to provider/model/policy/session trust context to prevent cross-context replay.
- **Attestation hardening**: Strengthened attestation verification with fail-closed behavior and follow-up review remediations.
- **Audit integrity improvements**: Tightened audit logging semantics around malformed payload handling, organization isolation, and transactional durability.
- **Proof-path corrections**: Refined reasoning, symbolic, batch, and agent-service fail-closed behavior where proof prerequisites or safe defaults were ambiguous.

#### Release and Deployment Alignment
- **Version propagation**: Aligned core package, API version marker, Python SDK metadata, TypeScript SDK metadata, and Rust SDK crate version on `5.1.1`.
- **Container reference alignment**: Updated Kubernetes deployment example to the published Docker Hub image/tag convention.
- **Release metadata cleanup**: Prepared package metadata and deployment references for a clean `v5.1.1` publish flow.

#### Included PRs and merged work since v5.1.0
- `#157` docs: README follow-up
- `#158` fix(docker): python 3.13 upgrade follow-up
- `#159` chore(deps): npm/yarn dependency follow-up in `sdk-ts`
- `#160` fix(schema): strict additional-properties enforcement follow-up
- `#161` fix(symbolic): fail closed when no proof exists
- `#168` fix(executor): secure executor fail-closed follow-up
- `#176` fix(agent): deny and handle unknown agent actions safely
- `#177` fix(reasoning): require proof prerequisites before reasoning acceptance
- `#178` and `#192` fix(cache): bind verification cache keys to trust context and address review follow-ups
- `#179` fix(audit): fail-closed audit logging, chain isolation, and transaction hardening
- `#180` fix(batch): separate batch math simplification from proof path
- `#186` chore(deps): pip dependency maintenance
- `#193` fix(tests): test-secret cleanup and PowerShell encoding hygiene

#### Upgrade Notes
- Deployments using the Kubernetes example should pull `docker.io/qwedai/qwed-verification:5.1.1` instead of the older `ghcr.io/qwed-ai/qwed-core` reference.
- This patch release focuses on stricter semantics, release consistency, and fail-closed enforcement rather than end-user feature expansion.

## [5.1.0] - 2026-04-19
### Agent State Governance and Fail-Closed Hardening

Minor release expanding QWED from action verification into state governance while closing the adversarial fail-open gaps identified after v5.0.0. This release includes AgentStateGuard plus a focused hardening wave across execution, tool governance, mathematical verification, API semantics, and schema validation.

#### New Capability
- **AgentStateGuard**: Added deterministic state verification with strict structural validation, semantic transition checks, and governed atomic state commits. This extends QWED from action-only verification to state and memory governance.

#### Fail-Closed Hardening
- **Legacy CodeExecutor hard-blocked**: `CodeExecutor.execute()` now raises `RuntimeError` unconditionally. All supported execution remains on `SecureCodeExecutor`.
- **Unknown tools default-denied**: `ToolApprovalSystem` now blocks unknown tools regardless of heuristic risk score.
- **Bounded math tolerance**: `verify_math()` rejects oversized, negative, non-finite, and malformed tolerances instead of letting callers weaken correctness checks.
- **Legacy logic path fails closed**: `verify_logic_rule()` now raises `NotImplementedError` instead of returning `None`.
- **Identity sampling rejected**: `verify_identity()` now returns `BLOCKED` when numerical sampling matches but no formal proof exists.
- **Ambiguous math API rejected**: `/verify/math` now blocks ambiguous implicit-multiplication expressions instead of returning `is_valid: true`.
- **Schema uniqueness fail-closed**: `SchemaVerifier` now emits `uniqueness_validation_error` when `uniqueItems` cannot be proven deterministically.

#### Runtime and Security Follow-Through
- **Progress-aware doom loop guard**: Added LOOP-004 state-aware replay protection for repeated actions on unchanged state.
- **Security and infrastructure hardening**: Incorporated follow-up hardening across configs, CI, and infrastructure.
- **Stats verifier coverage expansion**: Added edge-case coverage for the statistics engine.
- **CodeQL and cleanup follow-ups**: Merged syntax, test, and static-analysis cleanup work after the v5.0.0 boundary release.

#### Upgrade Notes
- `CodeExecutor` is no longer usable as a legacy execution path. Migrate any direct imports to `SecureCodeExecutor`.
- Unknown tools now require explicit allowlisting and are no longer auto-approved at low heuristic risk.
- `verify_math()` may return `BLOCKED` for tolerances that exceed the deterministic policy bound.
- `verify_logic_rule()` no longer returns an ambiguous non-result; callers must migrate to `LogicVerifier`.
- Sampling-only `verify_identity()` matches now return `BLOCKED`, not `UNKNOWN`.
- Ambiguous `/verify/math` expressions now return `BLOCKED` with `is_valid: false`.
- `uniqueItems` validation failures are now explicit schema errors instead of silent passes.

#### SDK and Package Versions
- `qwed` (PyPI): `5.0.0` -> `5.1.0`
- `qwed_sdk` (Python): `5.0.0` -> `5.1.0`
- `@qwed-ai/sdk` (NPM): `5.0.0` -> `5.1.0`

#### Included PRs since v5.0.0
- `#124` feat(agent): add progress-aware doom loop guard (LOOP-004)
- `#126` security: harden configs, CI, and infrastructure -- full audit fixes
- `#127` test(stats): add edge case coverage for statistics engine
- `#136` fix(codeql): resolve remaining syntax and test cleanup alerts
- `#137` Update contributors section in README
- `#139` feat: AgentStateGuard - full implementation (structural + semantic + atomic commit)
- `#149` fix: hard-block legacy CodeExecutor execution path
- `#150` fix: default deny unknown tool approvals
- `#151` fix: bound verify_math tolerance by computed magnitude
- `#152` fix: fail closed in verify_logic_rule
- `#153` fix: fail closed in verify_identity
- `#154` fix: fail closed for ambiguous math api inputs
- `#155` fix: fail closed on uniqueItems validation errors

## [5.0.0] - 2026-04-04
### 🛡️ Enforcement Boundary Hardening

Major release focused on making QWED's verification boundary fail-closed, deterministic about what it proves, and substantially harder to bypass under adversarial conditions. Consolidates 98 commits and 20 merged PRs since v4.0.1, including the full PR 0–5 enforcement hardening series.

#### 🔐 Security Hardening
- **Fail-Closed Verification**: Disabled unsafe in-process execution fallbacks; stats and consensus paths now require secure Docker sandbox.
- **Critical Boundary Closures**: Removed logic verifier `eval()` fallback — raises `RuntimeError` if `SafeEvaluator` is unavailable (CVE-QWED-001).
- **Mandatory Guards**: Agent security guards (Exfiltration, MCP Poison) are now server-enforced and unconditional — `security_checks` field removed from request model.
- **Consensus Rate Limiting**: `/verify/consensus` endpoint now enforces `check_rate_limit` to prevent cost amplification attacks.
- **Self-Attestation Fix**: Consensus fact engine no longer calls `verify_fact(query, query)` — requires external context.
- **Redis Fail-Closed**: `RedisSlidingWindowLimiter` now denies requests on Redis errors instead of allowing them.
- **Timing-Safe Token Verification**: Agent token comparison switched to `hmac.compare_digest`.
- **Metrics Access Control**: `/metrics` and `/metrics/prometheus` now require authenticated admin access.
- **Environment Integrity**: Startup enforces `verify_environment_integrity()` before database initialization.

#### 🧠 Determinism & Trust Boundary
- Natural-language math responses now return `INCONCLUSIVE` when verifying LLM-translated expressions — never `VERIFIED`.
- Added explicit `trust_boundary` metadata in API responses describing what was actually verified.
- `verify_identity()` numerical sampling fallback now returns `UNKNOWN` instead of `LIKELY_EQUIVALENT`.
- Heuristic/non-proof outcomes are honestly labeled instead of presented as formal verification.

#### 🤖 Agent Hardening
- **Action context mandatory**: `verify_action()` requires `ActionContext` with `conversation_id` and `step_number`.
- **Replay detection**: Same `(conversation_id, step_number)` pair blocked (QWED-AGENT-LOOP-002).
- **Loop detection**: Same action repeated 3+ times triggers DENIED (QWED-AGENT-LOOP-003).
- **In-flight step reservations**: Prevents race conditions in concurrent agent calls.
- **Budget denial isolation**: Budget-exceeded denials do not consume conversation state.

#### 📜 Tool Governance (PR 0)
- Added `QWED_RULES.md` — canonical enforcement contract for contributors and tools.
- Added `.github/copilot-instructions.md` — blocks Copilot from suggesting fallback execution.
- Added `.github/pull_request_template.md` — mandatory enforcement checklist.
- Extended `.coderabbit.yaml` with enforcement-specific review instructions.

#### 🔧 Supply Chain & CI
- Pinned third-party GitHub Actions to verified commit SHAs.
- Merged security autofix PRs and dependency hardening (#100–#114).

#### 📦 SDK & Package Versions
- `qwed` (PyPI): `4.0.1` → `5.0.0`
- `qwed_sdk` (Python): `2.1.0-dev` → `5.0.0`
- `@qwed-ai/sdk` (NPM): `4.0.1` → `5.0.0`
- TypeScript SDK: Removed `security_checks` from agent verification helpers; `tool_schema` remains.

#### 🧪 Test Coverage
- `test_pr115_regressions.py` — critical boundary closures (eval removal, guard enforcement, consensus rate limit, fact self-attestation).
- `test_pr117_regressions.py` — stats fail-closed behavior, sandbox enforcement.
- `test_pr4_runtime_hardening.py` — Redis fail-closed, agent loop controls, metrics auth, environment integrity.
- `test_pr5_determinism_alignment.py` — trust boundary metadata, INCONCLUSIVE status, numerical sampling UNKNOWN.
- **Sanity sweep**: 162 passed, 11 skipped, 0 failures.

#### ⚠️ Upgrade Notes
- `INCONCLUSIVE` is now a distinct verification status — downstream consumers must handle it.
- `BLOCKED` and `UNKNOWN` are explicit outcomes, not generic failures.
- Agent integrations must provide `ActionContext` with `conversation_id` and `step_number`.
- `/metrics` endpoints now require admin role — update monitoring integrations accordingly.


## [4.0.1] - 2026-03-23
### 🔄 Sentinel Guard Sync

#### 🆕 New Endpoints
- **`POST /verify/process`**: Glass-box reasoning process verifier — IRAC structural compliance and custom milestone validation with decimal scoring.
- **Agent Security Checks**: `POST /agents/{id}/verify` now accepts `security_checks: { exfiltration, mcp_poison }` to run `ExfiltrationGuard` and `MCPPoisonGuard` before verification.

#### 🔒 Security Fixes
- **Information Disclosure**: Removed raw `str(e)` from `/verify/rag` error responses; exceptions logged via `redact_pii()`, clients receive only `INTERNAL_VERIFICATION_ERROR`. (Sentry + CodeQL)
- **Symbolic Precision**: `RAGVerifyRequest.max_drm_rate` changed from `float | str` → `str` with `field_validator` enforcing Fraction-compatible values.

#### 🛠️ SDK Changes (`@qwed-ai/sdk@4.0.1`)
- **`verifyProcess()`**: Validates AI reasoning traces using IRAC or custom milestone lists.
- **`verifyRAG()`**: `maxDrmRate` type changed from `number` to `string` for symbolic precision.
- **`verifyAgent()`**: Returns `AgentVerificationResponse`, payload aligned with backend schema. Agent IDs URL-encoded.
- **Type Fixes**: `VerificationResultData.risk` and `risk_level` separated. Added `Process`, `RAG`, `Security` to `VerificationType` enum.

#### 🧪 Tests
- `test_api_phase17_endpoints.py` — covers `/verify/process`, `/verify/rag` exception masking, and agent security check blocking.

## [4.0.0] - 2026-03-12
### 🛡️ Sentinel Edition

#### 🆕 Agentic Security Guards (Phase 17)
- **RAGGuard**: Detects prompt injection, data poisoning, and context manipulation in RAG pipelines with IRAC-compliant reporting.
- **ExfiltrationGuard**: Prevents data exfiltration through AI agent tool calls by analyzing output patterns and destination validation.
- **MCP Poison Guard**: Detects poisoned or tampered Model Context Protocol (MCP) tool definitions before agent execution.
- Five rounds of security review and hardening (CodeRabbit + SonarCloud).

#### 🆕 New Standalone Guards
- **SovereigntyGuard**: Enforces data residency policies and local routing rules for compliance-sensitive deployments.
- **ToxicFlowGuard**: Stateful detection of toxic tool-chaining patterns across multi-step agent workflows.
- **SelfInitiatedCoTGuard (S-CoT)**: Verifies self-initiated Chain-of-Thought logic paths for reasoning integrity.

#### 🆕 Process Determinism
- **ProcessVerifier**: A new class of deterministic verification — IRAC/milestone-based process verification with decimal scoring, budget-aware timeouts, and structured compliance reporting. Ensures AI-driven workflows follow deterministic process steps.

#### 🔒 Critical Security Fixes
- **Code Injection Prevention**: Replaced all `eval()` calls with AST-compiled execution (SonarCloud S5334).
- **Sandbox Escape Fix**: Patched critical sandbox escape and namespace mismatch vulnerability.
- **SymPy Injection Fix**: Hardened symbolic math input parsing against injection attacks.
- **Protocol Bypass Fixes**: Fixed URL whitespace bypass and protocol wildcard bypass vulnerabilities.
- **CVE Patches**: Resolved CVE-2026-24049 (Critical, pip/wheel), CVE-2025-8869, and HTTP request smuggling (h11/httpcore).
- **Snyk Remediation**: Fixed all 19 Snyk Code findings across the codebase.
- **CodeQL Remediation**: Secured exception handling in `verify_logic`, `ControlPlane`, `verify_stats`, and `agent_tool_call`.

#### 🐳 Docker Hardening (15+ improvements)
- Pinned base image digests with hash-verified requirements.
- Non-root user execution with `gosu`/`runuser`.
- Inlined entrypoint script to fix exec format errors across platforms.
- Enforced LF line endings via `.gitattributes` and `dos2unix`.
- Automated Docker Hub publishing on release and main branch push.
- SBOM generation and Docker Scout vulnerability scanning.

#### 🔧 CI/CD Infrastructure
- **Sentry SDK**: Integrated error tracking and monitoring.
- **CircleCI**: Added Python matrix testing pipeline.
- **SonarCloud**: Added code quality and coverage workflow.
- **Snyk**: Added security scanning workflow with SARIF output.
- **Docker Auto-Publish**: Automated image publishing to Docker Hub on every release.

#### 📝 Documentation & Badges
- Added OpenSSF Best Practices badge (Silver level).
- Added Snyk security badge and partner attribution.
- Added Docker Hub pulls badge and dynamic BuildKit badge.
- Updated engine count from 8 to 11 across all documentation.
- Added Ecosystem Trust & Infrastructure section to README.

#### 🧪 Test Coverage
- ProcessVerifier: decimal scores, edge cases, IRAC long input, malformed data.
- Attestation edge cases and qwed_local execution tests.
- Logic exception handling and stats engine coverage.
- Secure executor Docker availability checks.

## [3.0.1] - 2026-02-04
### 🦾 Ironclad Update (Security Patch)

#### 🛡️ Critical Security Hardening
- **CodeQL Remediation:** Resolved 50+ alerts including ReDoS, Clear-text Logging, and Exception Exposure.
- **Workflow Permissions:** Enforced `permissions: contents: read` across all GitHub Actions (`dogfood`, `publish`, `sdk-tests`) to adhere to Least Privilege.
- **PII Protection:** Implemented robust `redact_pii` logic in all API endpoints and exception handlers.

#### 📝 Compliance
- **Snyk Attribution:** Added Snyk attribution to README and Documentation footer for Partner Program compliance.

#### 🐛 Bug Fixes
- **API Stability:** Fixed unhandled exceptions in `verify_logic` and `agent_tool_call` endpoints.

## [2.4.1] - 2026-01-20
### 🚀 The Reasoning Engine & Enterprise Docker Support

#### New Features
- **Optimization Engine (`verify_optimization`)**: Added `LogicVerifier` support for Z3's `Optimize` context.
- **Vacuity Checker (`check_vacuity`)**: Added logical proof to detect "Vacuous Truths".

#### Enterprise Updates
- **Dockerized GitHub Action**: The main `qwed-verification` action now runs in a Docker container.


#### Fixes & Improvements
- Updated `logic_verifier.py` with additive, non-breaking methods.
- Replaced shell-based `action_entrypoint.sh` with robust Python handler `action_entrypoint.py`.
