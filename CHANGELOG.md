# Changelog

All notable changes to the QWED Protocol will be documented in this file.
Versions 7.3.0 and earlier are in [docs/CHANGELOG-archive.md](docs/CHANGELOG-archive.md).

## [Unreleased]

### Added

- **Key rotation and the threat summary accept a signed-in session (#505,
  #506).** `POST /admin/keys/rotate` and
  `GET /admin/security/threats/{org_id}` took an `x-api-key` only, so a
  dashboard that signs in with a session could not offer either.
  - Both also accept `Authorization: Bearer <jwt>`, with the same session
    checks as the compliance routes (#485): an active user in an active
    organisation, with an allowed role. `x-api-key` works as before and is
    used when both are sent; with neither, the request is 401.
  - The rules are unchanged. The threat summary is for an owner or admin of
    their own organisation. A member, admin or owner may rotate their own
    key; an owner or admin may rotate another user's key in their
    organisation, never one owned by a higher-privileged user; a revoked key
    or one in another organisation is 404. A viewer cannot rotate.
  - Agent token reissue (`POST /agents/{agent_id}/token/reissue`) still
    takes an API key only.
- **The API key list returns expiry, the rotation flag and the owner
  (#504).** `ApiKey` stores all three, but `GET /auth/api-keys` returned
  none, so a client could not show that a key expires, must be rotated, or
  belongs to someone else.
  - Each item adds `expires_at` (null when the key does not expire),
    `rotation_required`, and `owner`: the owning user's `id` and `email`, or
    null for a key with no user. A key whose user is not in the key's
    organisation also has a null owner, so no other organisation's user is
    shown.
  - Who sees which keys is unchanged (#478): owners and admins see every key
    in their organisation, members and viewers only their own. The owners
    are read in one query, not one per key.
  - `expires_at`, `created_at` and `last_used_at` always carry their UTC
    offset. SQLite, and SQLModel before 0.0.28, read stored times back
    without one, so a client would have read them as local time.
- **Sign-up, sign-in and `/auth/me` return the organisation's name (#518).**
  The user object adds `org_name`, the organisation's display name (null if
  it cannot be read), beside `org_id`, so a client can show the name and not
  "Organisation 1".
  - `/auth/me` now applies the same checks as the other user-session routes
    (#478): an inactive user or organisation, or an unknown role, is 403. It
    answered any valid token before.
  - Sign-in refuses a user of an inactive organisation (403, "Organization
    is not active"), as it already refused an inactive user. It issued a
    token that every user-session route then refused.
- **List the users of an organisation (#507).** No route listed them:
  `/auth/me` returns the signed-in user and the security activity summary
  only a count, so a client could name a user only by id.
  - New `GET /auth/users` returns each user of the caller's organisation,
    oldest first: `id`, `email`, `role`, `is_active` and `created_at` (with
    its UTC offset). Inactive users are listed with `is_active` false. No
    password hash or permission data is returned.
  - Owners and admins only, with an API key or a signed-in session (the
    same checks as the compliance routes, #485); members and viewers are
    403. No other organisation's user is ever returned. Inviting users and
    changing roles are not part of this.
- **List an organisation's agents, and read an agent's activity as an
  owner (#527).** No route listed the agents, and
  `GET /agents/{agent_id}/activity` took only the agent's own token, so an
  owner could read neither.
  - New `GET /agents` returns each agent of the caller's organisation,
    oldest first: `id`, `name`, `type`, `status` (suspended and deactivated
    agents included) and `created_at` and `last_active` (with their UTC
    offset). It never returns the agent token or its digest. Owners and
    admins only, with an API key or a signed-in session; members and
    viewers are 403.
  - `GET /agents/{agent_id}/activity` also accepts an owner's or admin's
    API key or session, for an agent of their organisation; another
    organisation's agent, or one that does not exist, is 404. When
    `x-agent-token` is sent, it alone decides access, as before: a wrong
    token is 401 even beside an owner's session.
  - The activity route's `limit` is now 1 to 200 (default 20; it was
    unbounded), activity comes newest first with an id tie-break, and its
    timestamps carry their UTC offset. An agent id too large for the
    database is 404 on the owner path, not a server error, and the route's
    database work runs in a worker thread, off the event loop.
  - The activity route moves from `api/main.py` to
    `api/agent_admin_routes.py`.
- **`qwed init` can create an owner who can sign in (#524).** It signed up
  with a generated email and password that it never showed or saved, so
  nobody could sign in to the organisation it created, and its records could
  not be read in qwed-dashboard.
  - New `--owner-email` (or `QWED_OWNER_EMAIL`, read only when the flag is
    not given) names the owner. The password is asked for with hidden input
    and a confirmation; it is never a flag, so it stays out of shell
    history, and init neither prints nor saves it. Without the flag,
    interactive init asks for the email too.
  - With `--non-interactive`, the password comes from `QWED_OWNER_PASSWORD`;
    an owner email without it stops init before the server starts, and the
    local server init starts does not inherit it. Without an owner email,
    init creates the generated owner as before and warns that nobody can
    sign in to the organisation, and that running init again creates a new
    organisation rather than recovering it.
  - The email is checked for a basic `name@domain.tld` shape with one `@`
    (the server checks it fully), and the password must be 1 to 72 bytes,
    the most bcrypt reads. An email that is already registered fails the
    signup, now with how to go on: sign in with it and create a key there,
    or use another email.
  - The owner handling is in the new `qwed_sdk/init_owner.py`, which keeps
    `cli.py` under the security scan's 100,000-character file limit.

### Changed

- **The CSV exports carry the stored verdict and admission, and take a
  period (#508).** `GET /admin/compliance/export/csv` was fixed to the last
  30 days, cut the query to 100 characters and the signature to 16, and had
  no verdict, admission or result. `GET /audit/export` wrote `is_verified`
  as "verified" or "blocked" under `Status`, with no admission or caller.
  - Both now write the same columns: `ID`, `Timestamp`, `User ID`,
    `API Key ID`, `Verifier Version`, `Domain`, `Query`, `Verdict`,
    `Admission`, `Is Verified (legacy)`, `Result`, `Entry Hash`,
    `HMAC Signature` and `Chain Status`. `Verdict` is the stored verdict
    and `Admission` the stored admission, as `/audit/logs` returns them; a
    value that was not recorded is an empty cell. Nothing is cut. A client
    that read the old columns by position or name must update.
  - A cell that starts with `=`, `+`, `-`, `@`, a tab, a carriage return
    or a line feed gets a leading apostrophe, so a spreadsheet does not run
    it as a formula. The query and the result are caller-controlled.
  - Both take `start` and `end` (a time without a zone is UTC; `start`
    after `end` is 400), newest first. The compliance export keeps its
    default of the 30 days before `end`, which defaults to now, and checks
    the period after those defaults, so a future `start` with no `end` is
    400.
  - Both export at most the newest 1,000 rows (one shared cap), since the
    query and result are now written in full, and set
    `X-Export-Truncated: true` when more matched. The compliance export had
    no cap before. CORS exposes `X-Export-Truncated`, so a browser client
    on another allowed origin can read it.
  - `/admin/compliance/export/csv` moves from `api/main.py` to
    `api/compliance_routes.py`; its path, its checks and its
    `organization_id` parameter are unchanged.

### Fixed

- **The audit log stores and returns real latency (#528).** `/audit/logs`
  returned `latency_ms` as a fixed 0 for every row, and nothing stored it,
  so a client could not tell a real 0 from "not measured".
  - `RequestTimingMiddleware` (`core/request_caller.py`) records when each
    HTTP request starts. The audit logger stores the whole milliseconds from
    then to the row's append, measured before it waits for the append lock,
    as the new nullable `VerificationLog.latency_ms`. Every writer gets it:
    the `/verify/*` routes, batch items (each from the batch request's
    start), agent verification and the Verification Context routes.
  - `/audit/logs` and `/audit/logs/{log_id}` return the stored value, and
    both CSV exports have a `Latency (ms)` column. It is null (an empty
    cell) on rows written before this change and on rows written outside a
    request.
  - `latency_ms` is covered by the entry hash. Rows hashed before it was
    covered still verify while it is null; setting it on such a row, or
    changing or clearing it on a newer row, fails verification. As with
    #484 and #307, an older release cannot verify a row hashed this way:
    upgrade every process together.
  - An existing database gets the column at startup (`add_missing_columns`).

- **Natural-language audit rows are stored with their own domain (#520).**
  `/verify/natural_language`, `/agents/{agent_id}/verify` and the
  natural-language items of `/verify/batch` wrote `domain` "MATH", while
  their response and attestation say `natural_language`, so the audit log
  and its exports grouped them with `/verify/math`. They now write
  "NATURAL_LANGUAGE" (`engine_used` on `/audit/logs`, `Domain` in the CSV
  exports). `/verify/math` and batch maths items still write "MATH". Rows
  already written keep "MATH": the domain is part of each signed, chained
  entry, so it is not rewritten.
- **The threat summary no longer fails with the pinned SQLModel (#506).**
  `ThreatDetector` used naive `datetime.utcnow()` times, and SQLModel 0.0.48
  (pinned in `requirements-server.txt`) refuses a naive datetime in a query,
  so `GET /admin/security/threats/{org_id}` raised on every call. Its times
  are now aware UTC, so `generated_at` and the event analysis `timestamp`
  end in `+00:00`.
- **Signup and signin no longer fail with a 500 for a long password (#548).**
  bcrypt reads at most 72 bytes of a password, and bcrypt 5 (pinned in
  `requirements-server.txt`) raises for more, so `/auth/signup` and
  `/auth/signin` returned 500 for a password over 72 bytes in UTF-8.
  - `/auth/signup` refuses it with 400 "Password must be at most 72 bytes",
    before it looks up the email, so the answer is the same whether or not
    the email is registered. Nothing is written.
  - `/auth/signin` answers 401 "Invalid email or password", for a registered
    email and an unknown one alike. `verify_password` returns false for such
    a password without calling bcrypt.
  - An account whose password was set over 72 bytes with bcrypt 4, which
    used only the first 72 bytes, cannot sign in with that password. It
    could not under bcrypt 5 either.
- **The audit row of a signed Verification Context document verifies (#532).**
  `/verification-context/from-diagnostic` signs the document it returns, but
  its audit row stored a copy with personal data (emails, phone numbers,
  SSNs, IP addresses) redacted in every string after signing. That copy no
  longer matched its attestation, so a consumer reading it back from
  `/audit/logs` (such as qwed-dashboard) could not verify it.
  - The row now stores the document exactly as returned, as the `/verify`
    routes store their results. Its signature verifies, and
    `/verification-context/validate` accepts it.
  - The row's `query` column is still redacted.
  - The stored document keeps any personal data the caller put in the query
    or the diagnostic. The stored result had been redacted since 7.1.0;
    documents are signed since 8.0.0, which is when the two stopped
    agreeing.
  - Rows written before this change keep their redacted copy and still do
    not verify against their attestation.
- **The whole-chain check no longer calls itself a check "in the period"
  (#521).** `GET /admin/compliance/verify-trail` with no `start` or `end`
  checks every entry of the organisation, but its `scope` said "audit entries
  recorded in the period". With neither bound, `scope` now reads "Signature
  and hash-chain check of every audit entry recorded for the organisation".
  With a `start`, an `end` or both, it still names the period. Both keep "It
  does not show that every request was recorded." The activity summary
  always has a period, so its `audit_trail` keeps the period wording. Only
  the text changed: the status, counts and `proof_ref` are as before.
- **A startup hook can be allowed by the digest of its contents (#491).** In
  a Python 3.11 venv, setuptools' `distutils-precedence.pth` (which uses
  `__import__(`) and coverage's `a1_coverage.pth` (which uses `exec(`) stopped
  the server at startup. Allowing them by name did not help, because an
  allowed name is still scanned for those patterns, so the only way through
  was `QWED_SKIP_ENV_INTEGRITY_CHECK=true`.
  - `QWED_ALLOWED_STARTUP_PTH_FILES` now also takes `NAME.pth:sha256:<64 hex>`.
    Such a file is allowed only while its exact contents hash to that digest,
    and is then not pattern-scanned, since any change to it changes the
    digest. A pin overrides an allowed name of the same file.
  - A pinned file whose contents differ fails the check, counted as
    `digest_mismatch` in the guard's `counts`. A pin that is not
    `NAME.pth:sha256:<64 hex>` stops startup with a ValueError instead of
    being read as a name.
  - A plain name works as before, and the suspicious patterns are unchanged.
    No digests are built in: these files change between setuptools and
    coverage versions. The README shows how to take a file's digest.
  - In the SDK, `StartupHookGuard` takes `pinned_pth_digests`, and
    `parse_startup_hook_allowlist` parses the variable's value.
- **SQLVerifier no longer blocks every query with a parenthesised subquery
  (#529).** `_calculate_subquery_depth` called itself on the same Subquery
  node until Python raised RecursionError, so `verify_sql` returned BLOCKED
  `sql_verifier.execution_error` for any `IN (SELECT ...)`, scalar subquery
  or subquery in `FROM`. That reached `/verify/sql`, SQL items of
  `/verify/batch` and `QWEDClient.verify_sql`.
  - Such queries are now checked like any other. A valid one is VERIFIED,
    and nesting past `max_subquery_depth` (3) is BLOCKED
    `sql_verifier.complexity_limit_exceeded`. Before, the depth limit never
    ran for these queries.
  - `complexity.subquery_depth` is the number of SELECT, UPDATE, DELETE,
    INSERT or MERGE nodes the deepest SELECT is nested in, found in one pass
    over the tree, so a long `UNION ALL` chain is checked in linear time. A
    `UNION` of two plain SELECTs now reports 0; it reported 1 before, which
    counted the union as a level of nesting. A CTE counts as one level
    whether its statement is a SELECT or a UNION, and whatever its body
    (sqlglot 20.x keeps a `VALUES` body bare). The UPDATE or INSERT of a
    MERGE's `WHEN` action is part of the MERGE, so a plain MERGE reports 0.
    With `allow_destructive=True`,
    a subquery of an UPDATE or DELETE counts as a level, as do the SELECT of
    an `INSERT ... SELECT` and the UPDATE or DELETE of a writable CTE.
  - Two eval cases (`sql-019`, `sql-020`) prove a valid `IN (SELECT ...)`
    and a scalar subquery.
- **A `;` inside a string or comment no longer marks a query as stacked
  (#533).** SQLVerifier flagged `stacked_queries` (malicious, not admitted)
  for any `;` before the last character of the query, so
  `WHERE name = 'a;b'`, `/* ; */`, `$$a;b$$` and `...; -- note` were refused.
  - Statements are now counted from sqlglot's parse (`has_stacked_statements`),
    so a `;` inside a string literal, a dollar-quoted string or a comment is
    not a separator. Two real statements are still `stacked_queries`.
  - Where the database could split the text differently from sqlglot, every
    `;` before the end still counts, as before: a backslash anywhere (escape
    rules depend on server settings, such as MySQL's `NO_BACKSLASH_ESCAPES`),
    `--` not followed by ASCII whitespace (MySQL starts a comment only then;
    a Unicode space such as U+00A0 is not one), a `/*` inside a block
    comment, and a carriage return not followed by a line feed (PostgreSQL
    ends a line comment there, MySQL and SQLite do not, and sqlglot versions
    disagree). These are checked in the query as given as well as with MySQL
    executable comments expanded, since expanding `/*!50000 /* x */ ; ... */`
    ends the executable comment at the inner `*/`. A query that does not
    parse also counts every `;`.
  - A query with exactly one statement is analysed as that statement. With
    sqlglot 30, `parse_one` returned a `Block` for `SELECT ...; -- note`,
    which was blocked as not read-only.
  - Eval cases `sql-021` and `sql-022` prove a `;` in a string and in a
    dollar-quoted string; `sql-023` checks that a backslash-escaped quote
    followed by `; DROP TABLE` is never accepted.
- **A batch math item proven false is VERIFIED, as on `/verify/math`
  (#530).** `/verify/batch` math items decided on `simplify(left - right) != 0`
  and reported a claim proven false (`2+2=5`) as UNVERIFIABLE with no
  `proof_ref`. `/verify/math` reports it VERIFIED with `is_valid` false,
  a `proof_ref` and admission BLOCKED (#437).
  - Both now build the verdict on `left = right` with the same function,
    `core/math_identity.py`'s `math_identity_result`, so they cannot drift:
    VERIFIED when the difference is 0, VERIFIED with `is_valid` false when
    SymPy decides it is non-zero, UNVERIFIABLE when it cannot decide (or the
    difference only holds Float residue), and UNVERIFIABLE with
    `math.domain_restricted_identity` for an identity that holds only where
    both sides are defined.
  - A batch math item now carries the route's messages ("Identity is true",
    "Identity is false", ...) and fields (`left_side`, `right_side`,
    `simplified_difference`, `result`), and keeps its own `query`, `type`
    and `diff`. A proven-false item is signed, so it carries `attestation`.
    Admission is unchanged: BLOCKED.
  - `sdk-fixtures/batch.json` and the Rust, Go and TypeScript contract tests
    now expect the second item `VERIFIED · BLOCKED`.
  - A claim with a side that has an undefined part, which SymPy evaluates
    away (`log(0)**0 = 2` and `log(x - x)**0 = 2`: both sides become 1), is
    no longer disproven. On both routes it is UNVERIFIABLE with
    `math.undefined_part`, since there is no defined value to disprove.
    `/verify/math` gave it a signed disproof before. A part is undefined when
    it evaluates to `zoo` or `nan` (a symbol-free part also when it is not
    finite); implicit multiplication (`2x^2`) is read through SymPy's own
    grammar first. `x/x = 2`, which is false wherever `x/x` is defined, and
    `2x^2 = 5` are still disproven.
- **`/verify/math` reads `diff()` and refuses `d/dx` (#522).**
  `diff(x**2, x) == 2*x` came back BLOCKED as "Internal verification error",
  because the parser did not know `diff`. `d/dx(x^2) = 2x` came back VERIFIED
  as proven false, because `d` and `dx` were read as symbols.
  - The expression parser now evaluates `diff` and `Derivative`
    (`diff(x^2, x)`, `diff(x**3, x, 2)`). The total derivative order in one
    expression is at most 3, nested calls included, since each order
    multiplies what `simplify` then has to work through.
  - A derivative cannot appear in a power, `factorial` or `binomial`
    (`diff(x**2, x)**2` is refused). The cost bounds (#353) read it as
    symbolic, but it evaluates to a value first, so
    `2**(diff(10000*x, x)**9)` would have expanded `2**(10000**9)`. A
    reciprocal or a root (`2x/diff(x**2, x)`, `sqrt(diff(x**2, x))`) is
    allowed, as it expands nothing. `^` is read as SymPy reads it, so in
    `diff(x^3, x) - 3*x^2` the derivative is not taken to be inside a power.
  - `==` reads as `=`, so `diff(x**2, x) == 2*x` is VERIFIED.
  - The domain check (#429) reads each evaluated derivative as well as the
    text, since a derivative can be singular where the text it
    differentiates is not: `diff(sqrt(x), x)*2*sqrt(x) = 1` holds only for
    x other than 0, so it is UNVERIFIABLE with
    `math.domain_restricted_identity`, while
    `diff(sqrt(x), x) = 1/(2*sqrt(x))` is VERIFIED.
  - A non-zero numeric multiplier in a denominator no longer counts as part
    of its singular factor, so `2/(2*sqrt(x)) = 1/sqrt(x)` and
    `2*diff(sqrt(x), x) = 1/sqrt(x)` are VERIFIED, not UNVERIFIABLE.
  - Leibniz notation (`d/dx`, `dy/dx`, `d(x^2)/dx`, `dy/dtheta`,
    `dy/(2*dx)`, `d/d(x)(x^2)`, `d^2y/dx^2`) is refused instead of misread,
    with the message to write `diff(f, x)`. A name the parser knows
    (`delta`, `diff`, or a caller's own symbol) is never refused. Otherwise,
    wherever they stand (`/dx`, `/(-2*dfoo)`, `x*dx`):
    - a name starting with `d` that SymPy splits into letters, so reads as
      `d` times the rest: `dx`, `dV/dT` (read as `V/T`), `dtheta`, `d2y`.
      This includes `data` (read as `a**2*d*t`), since the claim decided
      would not be the one written; pass such a name in `extra_symbols` to
      use it as a symbol;
    - a name with `_`, which SymPy keeps whole, only when the rest is a
      variable used beside it (`dx_1` beside `x_1`), so `distance_m` is a
      symbol;
    - a lone `d` over a `d` name the parser does not know, the `d/dx`
      operator (`d/dx_1`); `d/delta` and `d/diff(...)` still parse;
    - a lone `d` that a denominator applies to a variable (`d(x)`, `d x`).
  - Input the parser refuses is BLOCKED with `math.parse_error` and
    "Expression could not be parsed", as SQL and schema parse errors are, not
    with `api.math.execution_error`. The parser's own text is not returned.
    A batch math item the parser refuses gets the same BLOCKED result; it
    was a failed item carrying the parser's error text.
- **The code verifier reads `exec`, `eval` and `compile` as names, not
  substrings (#534).** The Python line scan matched them anywhere in a line,
  so `cur.execute("SELECT ?", params)`, `model.evaluate(x)`,
  `re.compile(r"[0-9]+")` and `compile_report()` came back VERIFIED with
  `is_valid` false (`dangerous_function`). Parameterised SQL, the safe way to
  run a query, was refused.
  - `eval`, `exec`, `compile`, `__import__`, `getattr` and `setattr` are now
    matched on the AST: as a name, called or not (`f = eval`), whatever an
    import elsewhere binds to it, since imports are not read by scope or
    order; as an attribute, since the object may be the builtins module
    reached another way, whether read as `m.exec`, by `from m import exec`
    or by a match pattern (`case object(exec=run)`); and anywhere in a
    string (`vars(module)["exec"]`), since a string can be sliced into the
    name (`"xexec"[1:]`). An import of the builtins module
    (`import builtins`) is refused too.
  - Admitted: longer identifiers (`execute`, `evaluate`, `compile_report`),
    comments, and `re.compile(pattern, flags)` on a name every import binds
    to `re`. The builtin `compile` needs a filename and a mode, so it cannot
    run in that shape; any other `re.compile` call, or `re.compile` not
    called, is refused. The exception is also dropped when anything rebinds
    the name, sets an attribute on it or an attribute of that name on any
    object (`module.re = ...`), or can rebind it without an assignment: a
    namespace (`globals()`, `vars()`, `locals()`, a frame's `f_globals` or
    `f_locals`, a star import) or the import system (`sys.modules`,
    `sys.meta_path`, `sys.path_hooks`, `sys.path_importer_cache`). Still
    refused: `model.eval()`, an attribute named `eval`, and
    `from re import compile` followed by a bare `compile(...)`.
  - Longer names the substring scan refused that also run or compile code,
    start a process or look up an attribute by name stay refused, matched
    the same way: `exec_` (six, future), `exec_module`, `exec_builtin`,
    `exec_dynamic`, `_exec`, `load_compiled`, `runeval`, `evalfile`,
    `_evaluate`, `_eval_type`, `compile_command`, `_compile`,
    `_maybe_compile`, `_try_compile`, `_compile_source`,
    `_compile_bytecode`, `compile_file`, `compile_dir`, `compile_path`,
    `subprocess_exec`, `create_subprocess_exec`, `fork_exec`, `_execvpe`,
    `_execute_child`, `set_executable`, `getattr_static` and
    `_getattribute`. `loop.subprocess_shell`, and `create_subprocess_shell`
    imported from `asyncio.subprocess`, which the substring scan admitted,
    are refused too.
    `ast.literal_eval` is admitted.
  - `__self__` is a dangerous attribute, as `__dict__` and `__globals__`
    are: on a builtin function it is the builtins module, so
    `vars(print.__self__)["ex" + "ec"]` was admitted.
  - `__getattribute__`, `__getattr__`, `__setattr__` and `__delattr__`,
    which reach an attribute by name as `getattr` and `setattr` do, are
    refused when read as an attribute or named in a string, as the builtins
    are. A class or module that defines `__getattr__` is admitted.
  - Python that does not parse is BLOCKED with `code_verifier.parse_error`,
    since the AST checks cannot run on it. It was certified safe unless a
    line held one of the substring patterns.
  - The Python AST checks share one parse and one walk of the code instead of
    parsing and walking it once each.

## [8.0.0] - 2026-10-26

A major release: verdicts can now be checked by whoever receives them, and
clients stop reporting what the server did not decide. Every `VERIFIED`
answer carries an ES256 attestation with a JWKS to verify it, and
Verification Context v1.1 documents are signed by the server that issued
them. Six private advisories fix clients (the Python SDK, its integrations
and the GitHub Action) that reported content as verified when the server had
not admitted it. The Docker image now runs the API server, and the audit log
is written through the signed hash chain. Several response shapes and SDK
types change, so read "Upgrading to 8.0.0" below before upgrading. The
soundness eval has 86 known-answer claims, 0 accepted wrongly.

### Security fixes (advisories)

Six advisories, published on the repository Security tab. They affect all
versions up to 7.3.0; upgrading is recommended. Each has regression tests in
`tests/`. The server part of GHSA-45jv (SQL functions) is also reproduced in
the soundness eval (`evals/`); the other fixes are client paths the eval
runner does not exercise.

- **The Python SDK takes `is_verified` from the server's admission**
  ([GHSA-jppc-7r58-7pjh](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-jppc-7r58-7pjh), high). The SDK set
  `is_verified` from a bare `is_valid` or `is_verified` in the response, and
  the server flattens the engine's fields into it, so a result a gate had
  blocked could still read as verified. `is_admitted()`
  (`qwed_sdk/models.py`) now applies the server's rule: where the route
  returns an `admission`, only `ADMIT` admits; otherwise `status` must be
  `VERIFIED` and `is_valid` true. Consensus reads the server's status and
  `meets_requirement is True`, and the GitHub Action's verify mode gates on
  `is_verified` and reports the server's verdict (for example
  `VERIFIED · DENY`).
- **`QWEDClient.verify_code` always asks the server**
  ([GHSA-4rj3-8wqj-cqwc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-4rj3-8wqj-cqwc), high). It answered from the
  local `CodeGuard` blocklist, which missed reflective calls,
  `__builtins__` access and dotted imports, and reported what it passed as
  verified. It now always calls `/verify/code`; a server that cannot be
  reached gives `UNVERIFIABLE`, never `VERIFIED`. `CodeGuard` also blocks
  reflective calls, `__builtins__`, dunder attributes, `importlib`,
  `builtins`, `ctypes`, `marshal` and dotted imports, and marks its own pass
  as `advisory`.
- **`QWEDClient.verify_sql` always asks the server, and file and extension
  functions are denied** ([GHSA-45jv-2j44-4c2q](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-45jv-2j44-4c2q),
  high). The SDK answered from the local `SQLGuard`, and the server's
  `SQLVerifier` admitted calls such as `load_extension()`,
  `pg_read_file()` and `xp_cmdshell()`. `verify_sql` now always calls
  `/verify/sql` and is `UNVERIFIABLE` when the server cannot be reached.
  `SQLVerifier` denies `DANGEROUS_SQL_FUNCTIONS` anywhere in a statement
  (issue type `dangerous_function`, `core/sql_verifier.py`). `SQLGuard`
  allows one statement, uses the server's administrative, destructive and
  read-only sets, and checks `SELECT ... INTO`, executable comments and
  functions.
- **`QWEDLocal.verify_code` uses `CodeVerifier`**
  ([GHSA-v8qq-v427-qrqc](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-v8qq-v427-qrqc), high). Its local AST check
  flagged bare calls to four names only, so `os.system`, `subprocess.run`
  or `from os import system` came back `SAFE`. It now returns
  `CodeVerifier`'s verdict with `admission_decision`, and `UNVERIFIABLE`
  when `qwed_new` is not installed. Cached code results from the old check
  are not reused (`CODE_CACHE_POLICY_VERSION = "code_verifier-v2"`).
- **The LlamaIndex, CrewAI and LangChain integrations fail closed**
  ([GHSA-83v6-6h23-pvp4](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-83v6-6h23-pvp4), high). The LlamaIndex
  query engine returned `verified=True` for any response no engine checked,
  its node transform marked a node verified when its check raised, and the
  CrewAI agent started from `verified: True`. Every integration also read
  `result.verified`, a field `QWEDClient`'s result does not have, so its
  checks raised. They now read `is_verified`; a response no engine checked
  is `UNVERIFIABLE`, and an error fails closed. The second copy of the
  integrations in `qwed_sdk/integrations/` is fixed the same way.
- **The GitHub Action's outputs cannot be injected**
  ([GHSA-j788-44pc-8hp3](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-j788-44pc-8hp3), low). A newline in a
  value the Action wrote to `GITHUB_OUTPUT`, such as the verifier's
  explanation, could add a line that set `verified`, and a printed line
  could run as a workflow command. Outputs are written with a random
  heredoc delimiter, and the Action stops workflow commands for the rest of
  its step (`::stop-commands::` with a random token).

### Upgrading to 8.0.0

These changes can break existing callers. Each is described in full in the
entries below.

- **Server settings.** `QWED_AUDIT_SECRET_KEY` is required: the server
  refuses to start without it (re-run `qwed init`, which keeps existing
  secrets, or set it yourself). Set `QWED_SIGNING_KEY` or
  `QWED_SIGNING_KEY_FILE` to an EC P-256 key so attestations verify across
  restarts and replicas; unset, a key is generated per process.
- **Docker.** `qwedai/qwed-verification` runs the API server from 8.0.0.
  Earlier tags ran the GitHub Action; use the Action for scans.
- **Go module path.** The module is
  `github.com/QWED-AI/qwed-verification/sdk-go/v8`; update imports and
  `go get .../sdk-go/v8@v8.0.0`.
- **SDK types.** The Go, TypeScript and Rust SDKs read the DiagnosticResult
  envelope and gate on admission; their response types changed. The Rust
  crate's `VerificationResponse` has a new public `attestation` field, so a
  struct literal needs `attestation: None`.
- **Python SDK verdicts.** `is_verified` follows the server's admission, so
  a result the server did not admit is no longer verified.
  `QWEDClient.verify_code` and `verify_sql` need a reachable server (they
  return `UNVERIFIABLE` otherwise), and `QWEDLocal.verify_code` needs the
  full `qwed` package.
- **Verification Context.** `validate` and `resolve`, in the API, the CLI
  and the Python SDK, require a v1.1 document's attestation by default.
  Pass `require_attestation=False` (CLI: `--no-require-attestation`) for
  the old schema-only and `proof_ref`-only checks, for example on v1.0
  documents; with it on, the CLI needs `--jwks-file` or `--server`.
- **Routes.** `/agents/{agent_id}/verify` returns the enforced result with
  its `admission`, in the `/verify/natural_language` shape. `/verify/batch`
  logic and natural-language items return what their routes return
  (`VERIFIED` rather than `SAT`). The compliance report drops its fixed
  PASS fields; read `audit_trail` and `security_events_by_type`. A maths
  claim proven false is `VERIFIED` with admission `DENY`, not
  `UNVERIFIABLE`.

### Other changes since 7.3.0

#### Security

- **Dependency updates for open Dependabot alerts.**
  - `requirements.txt` pins certifi 2026.10.19 (was 2026.2.25), which
    drops the emSign root CAs whose intermediate CA keys were compromised
    (GHSA-6q48-6c7w-9gw2, critical). `requirements-server.txt` already
    pinned it.
  - The TypeScript SDK's dev dependency vitest is `^5.0.5`, which brings
    `@vitest/mocker` 5.0.5 (GHSA-xp26-3454-mjgp, GHSA-qxg6-89mg-rqv8). vite
    went from 6.4.3 to 8.3.5 in #515, which removed `launch-editor`. Both
    are test tooling only; the published SDK does not depend on them.

- **The API's and the CLI's validate and resolve check a Verification
  Context document's attestation too (#319).** They answered on the schema
  and `proof_ref` alone, so a caller not using the Python SDK could take a
  forged document, an `ADMIT` one whose `proof_ref` was recomputed, as
  `resolved`.
  - `/verification-context/validate` and `/resolve` take
    `require_attestation` (default true) and first verify the document's
    attestation with the server's own key, as spec v1.1 section 4 has it: a
    document with none is `attestation_required`, and one whose attestation
    does not verify or is not this document's is `attestation_invalid`. A
    key that cannot be loaded is a 500; a token whose header is nested too
    deeply to parse, or that is not ASCII (an unpaired surrogate raised
    `UnicodeEncodeError` in PyJWT), is `attestation_invalid`, not a 500. The
    SDK's verifiers refuse a non-ASCII token as "not a JWT" too. The server's
    `verify_attestation` now also requires the verified header's `kid` to
    name its key, as the SDKs do, for verdict tokens too. `require_attestation: false` keeps
    the old checks. **Behaviour change:** a caller that sends a v1.0
    document, an older SDK included, now gets `attestation_required` unless
    it sends `require_attestation: false`.
  - The Python SDK sends its own `require_attestation` to the server, so
    `require_attestation=False` there reaches the routes too.
  - `qwed context validate` and `qwed context resolve` verify the
    attestation with the keys of `--jwks-file` (offline or pinned) or
    `--server` (its `/.well-known/jwks.json`), by default. A signed document
    with neither is `attestation_keys_required`; keys that cannot be read or
    fetched, a malformed `--server` URL or a JWKS nested too deeply to parse
    included, `attestation_keys_unavailable`. A JWKS key whose coordinates
    are not strings is unusable in the SDK on every PyJWT version (2.8 raised
    `TypeError`), not an error that escapes.
    Passing both is a usage error, with or without the check, and a file
    nested too deeply to parse is `invalid_document_file`. `--no-require-attestation`
    keeps the old checks, as for a v1.0 document that
    `qwed context from-diagnostic` builds locally.

- **A Verification Context document is signed by the server that issued it
  (#319).** A document's `proof_ref` is an unkeyed commitment: anyone could
  build a document, an `ADMIT` one included, whose `proof_ref` resolves, and
  nothing told it from one the server issued.
  - Spec v1.1 (`spec/v1.1/`) adds `attestation`: an ES256 JWT, header `typ`
    `qwed-context+jwt`, whose claims sign the hash of the whole document
    except that field (`compute_document_hash`) with its verdict, admission
    and `proof_ref`. A v1.1 document must carry it, and a v1.0 one must not;
    `validate_document` checks each against its version's schema.
  - `/verification-context/from-diagnostic` returns every document as v1.1,
    signed with the attestation key; a failure to sign is a 500, not an
    unsigned document, and a document the canonical encoding refuses (a
    lone surrogate in a string, in one that is not `VERIFIED`) is a 422,
    as a `VERIFIED` one already was. The token lasts as long as a verdict's
    (`QWED_ATTESTATION_TTL_SECONDS`). As for a verdict's token, a server
    without `QWED_SIGNING_KEY` or `QWED_SIGNING_KEY_FILE` signs with a key
    generated per process, so its documents stop verifying after a restart
    or on another replica.
  - A document's token is not a verdict's, nor the reverse: the server's
    `verify_attestation` checks the verified header's `typ`, so the trust
    step refuses a document's token as a verdict's attestation.
  - The Python SDK verifies a document's attestation
    (`qwed_sdk.verify_document_attestation`, and the clients'
    `verify_document_attestation` against the server's JWKS), and
    `validate_verification_context` and `resolve_verification_context`
    require it by default (`require_attestation=True`): a document with none
    is `attestation_required`, and one whose attestation does not verify or
    is not this document's (edited after signing, or carrying another
    document's token) is `attestation_invalid`, without asking the server.
    Keys that cannot be fetched raise `KeysUnavailableError`. A document
    nested too deeply to encode is refused as a mismatch, not a
    `RecursionError`. A token whose `qwed.version` is not `"1.1"`, or whose
    `sub` is not the document hash, is refused, and so is a document whose
    own `spec_version` is not `"1.1"`.
    `require_attestation=False` keeps the old schema-only and
    `proof_ref`-only checks.
  - The server and the SDK read a token with `jwt.PyJWT().decode_complete`.
    `jwt.decode_complete` is exported only from PyJWT 2.10 and the floor is
    2.8, so on 2.8 and 2.9 the SDK's `verify_attestation` raised
    `AttributeError` for every token. Both also refuse a token whose header
    names a critical extension (`crit`), which PyJWT before 2.12 accepts
    without understanding it.
  - The signature authenticates the document relative to the server's key;
    it adds nothing to the verdict or the admission. The TypeScript, Go and
    Rust SDKs have no Verification Context methods.

- **The attestation signs the server's admission, and a signed ADMIT admits
  a Verification Context (#321).** A token bound the verdict's status,
  `proof_ref` and statement, but not the admission, which rests on more than
  those (`is_valid`, and for natural language that the translation was
  verified). So a consumer could check a verdict but not the server's ADMIT
  or BLOCKED, and `/verification-context/from-diagnostic`, which must not
  take the caller's `is_valid`, could only say `DENY`.
  - A route that decides an admission (`/verify/math`, `/verify/code`,
    `/verify/sql`, `/verify/natural_language`, the agent verify route, and
    their batch items) signs it as `qwed.admission`, `ADMIT` or `BLOCKED`,
    with the same rule it returns the admission by; the trust step checks
    the fresh token carries it. Routes that decide none (logic, fact, stats,
    image, RAG, process, consensus) sign none. Any other value is refused at
    signing, and so is `ADMIT` for a result that is not `VERIFIED`, valid
    and bound to its proof. A token that signs a different admission is
    blocked with the verdict it blocks kept beside the reason.
  - `/verification-context/from-diagnostic` admits a `VERIFIED` diagnostic
    whose token, checked against its status, `proof_ref` and query, signs
    `ADMIT` (`constraint_id` `verification_context.attested_admit`). The
    caller's `is_valid` still decides nothing; without a signed `ADMIT` the
    admission stays `DENY`. An admitted document names the engine that
    signed (`qwed.result.engine`) and this server's version as its
    verifier; the caller's `verifier` and `verifier_version` are kept under
    `caller_supplied`, so no document is admitted under a verifier that
    never checked it. A failure to read the signed admission, an error or a
    token that no longer verifies, is a 500, not a quiet `DENY`. A value
    that is not `ADMIT` or `BLOCKED`, a list included, is refused, not
    raised as a `TypeError`.
  - The four SDKs return the signed admission, and their clients'
    `verify_attestation` refuse an answer whose `admission` is not the one
    the token signs ("attestation is for another admission"): an answer
    edited to say `ADMIT`, one that dropped its admission, or one whose token
    signs none. The verifiers also take an expected admission (`admission=`
    in Python, `admission` in TypeScript, `AttestationOptions.Admission` in
    Go, `.admission(...)` in Rust), and each SDK has a `check_admission`
    helper (`checkAdmission`, `CheckAdmission`). In Python and TypeScript an
    admission given as none (`None`, `undefined`) is checked too: the token
    must sign none. In Go and Rust an empty one is not checked; their docs
    point to the helper for that. Python's
    `VerificationResult` gains `admission`.
  - No released server issues tokens yet (#511 is unreleased), so no token
    in use lacks the claim.

- **The Go and Rust SDKs verify attestations too (#319).** They read the
  token but could not check it, so a Go or Rust client could not tell a
  genuine verdict from a forged one.
  - Go (`qwed.VerifyAttestation`, `Client.VerifyAttestation`, `GetJWKS`)
    and Rust (`qwed::verify_attestation`, `QWEDClient::verify_attestation`,
    `get_jwks`) check what the Python and TypeScript SDKs check: the ES256
    signature with the key the token's `kid` names, the issuer, expiry and
    any `nbf` (expired from the second `exp` names), a VERIFIED status, that
    the token is this answer's (`proof_hash` is the answer's `proof_ref`),
    and optionally the statement's hash. Any algorithm but ES256 is refused
    before a key is used. A leeway counts in full, a fraction of a second
    included. A token covers what it signs, not other fields of the response
    such as `agent_message`; it signs the admission too (the #321 entry).
  - The clients keep the same key rules: the JWKS is reused for five
    minutes; when no cached key verifies a token they try keys another
    caller fetched meanwhile, else fetch once more, at most once every 30
    seconds; concurrent callers share one fetch; a failed fetch's error
    (`ErrKeysUnavailable` in Go, `AttestationError::KeysUnavailable` in
    Rust) goes to every caller for 30 seconds without another request,
    including a caller whose token the cached keys do not verify.
  - The 30 seconds count from when a fetch ends, so one that is slow to fail
    is still shared for all of them. A caller whose own context ends (Go) or
    whose future is dropped (Rust) changes nothing the others see, and stops
    waiting for another caller's fetch. Fresh keys are returned without
    waiting for a fetch in flight. Go's `GetJWKS` returns a copy, so
    changing it does not change the keys the client trusts; a JWKS with no
    key list is out of date, so a refetch may help.
  - The Python and TypeScript clients follow the same two rules: their 30
    seconds count from when a fetch ends, and a token the cached keys do not
    verify, within 30 seconds of a failed refresh, gets that failure
    (`KeysUnavailableError`, or the TypeScript `QWEDError`) rather than a
    key mismatch.
  - Go needs no new dependency (`crypto/ecdsa`, with `crypto/ecdh` to refuse
    a key that is not on the curve). Rust adds the RustCrypto `p256` (ECDSA
    P-256), `sha2` and `base64` crates, and tokio's `sync` feature. The new
    Rust types are `#[non_exhaustive]`, so a field added later does not
    break code that uses them; `AttestationOptions` is built with
    `AttestationOptions::new().query(...)`. Go's `Verifier` interface is
    unchanged, so mocks that implement it still compile.
  - Both verify tokens issued by the server itself, including signatures
    whose `s` is in the upper half of the curve order, which the server's
    library can produce.

- **The SDKs read attestations, and the Python and TypeScript SDKs verify
  them (#319).** Every VERIFIED answer carries its attestation, but no SDK
  read it, so no client could tell a genuine verdict from a forged one.
  - Python (`VerificationResult.attestation`, `.proof_ref`), TypeScript
    (`VerificationResponse.attestation`), Go (`VerificationResponse.Attestation`)
    and Rust (`VerificationResponse::attestation`) have a typed field; Go
    and Rust no longer put the token among the endpoint's own fields.
  - Python (`qwed_sdk.verify_attestation`, `QWEDClient.verify_attestation`)
    and TypeScript (`verifyAttestation`, `client.verifyAttestation`) verify
    it: the ES256 signature with a key in the server's JWKS, which the
    token's `kid` must name (Python tries each ES256 key and reads nothing
    from the token before one verifies it), the issuer, expiry and any
    `nbf`, a VERIFIED status, and that it
    is this answer's token (`proof_hash` is the answer's `proof_ref`), and
    optionally the statement's hash. Any algorithm but ES256 is refused
    before a key is used. A token covers what it signs, not other fields of
    the response such as `agent_message`; it signs the admission too (the
    #321 entry).
  - The clients fetch `/.well-known/jwks.json` and reuse it for five
    minutes. When no key in it verifies the token (the key rotated, or a
    server restarted with a new ephemeral key under the same `kid`), they
    try keys another caller fetched meanwhile, else fetch it once more, at
    most once every 30 seconds, failed fetches included. Concurrent callers
    share one fetch. When a fetch fails, every caller gets that failure for
    30 seconds without another request (`KeysUnavailableError` in Python;
    in TypeScript a `QWEDError`, `QWED-ATTEST-001`, or `QWED-SYS-TIMEOUT`
    for a timeout);
    keys past their five minutes are not used instead, since a key the
    server has withdrawn would still verify.
  - The TypeScript verifier has no dependency (WebCrypto, Node 18+ and
    browsers); CI verifies a token with the built package on Node 18. The
    Go and Rust SDKs verify it too (the entry above).
  - **Breaking for the `qwed` crate's types:** `VerificationResponse` has a
    new public field, `attestation`, so code that builds one with a struct
    literal must add `attestation: None`. Code that only reads responses is
    unaffected.

- **Attestations are delivered, with a JWKS to verify them (#319).** Every
  VERIFIED result was signed and checked inside the server, then the token
  was dropped, so a consumer could not tell a genuine verdict from a forged
  one.
  - A VERIFIED response, and a VERIFIED batch item's result, carries its
    token as `attestation`, an ES256 JWT binding the status, the
    `proof_ref` and the statement (the query, or for natural language the
    translated expression). Other responses are unchanged.
  - `GET /.well-known/jwks.json` (public) publishes the key that verifies
    it; the token header's `kid` names the key.
  - Revocation is per process, so the server's tokens are short-lived:
    `QWED_ATTESTATION_TTL_SECONDS`, 24 hours by default (was 365 days), from
    60 seconds to 30 days. Rotating the key ends every token issued before.
    An unusable value stops the server at startup. `deploy/docker-compose.yml`
    passes it through, and the Kubernetes configmap sets the default.
  - Only the trust step attaches a token: a result never takes one from
    input, and developer fields cannot put one in a response.
  - Audit rows store the result as returned, so a VERIFIED row includes its
    token.
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

#### Fixed

- **The `pii` extra excludes preshed 3.0.14.** preshed 3.0.14 (released
  2026-10-24) makes every spaCy model fail to load with `OverflowError:
  Python int too large to convert to C ssize_t` (explosion/spaCy#14058), so
  a fresh `pip install qwed[pii]` could not mask PII, and the PII tests
  failed. The extra now requires `preshed!=3.0.14`, which resolves to
  3.0.13 with spaCy 3.8; a fixed 3.0.15 is not excluded. `PIIDetector`'s
  install hint names the extra (`pip install 'qwed[pii]'`), as the CLI and
  the other hints do, instead of the packages by name, which would miss
  the exclusion.

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
    is the API server from 8.0.0. Anyone who ran an earlier tag as a
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
  - The Kubernetes manifest pins `8.0.0`, the first server image. Its
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

#### Changed

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
