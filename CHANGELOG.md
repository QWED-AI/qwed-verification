# Changelog

All notable changes to the QWED Protocol will be documented in this file.
Versions 8.0.0 and earlier are in [docs/CHANGELOG-archive.md](docs/CHANGELOG-archive.md).

## [Unreleased]

### Fixed

- **The server reads `.env` before any of its settings (#591).** With
  `uvicorn qwed_new.api.main:app`, the math worker, the database, the rate
  limiter and the auth module read their settings when imported, before
  anything loaded `.env`, so a value written only there was ignored.
  - `QWED_MATH_WORKERS`, `QWED_MATH_TIMEOUT_SECONDS`, `QWED_MATH_MAX_WAITING`,
    `QWED_MATH_WORKER_MEMORY_MB`, `DATABASE_URL`, `QWED_RATE_LIMIT_PER_KEY`,
    `QWED_RATE_LIMIT_GLOBAL`, `QWED_RATE_LIMIT_PER_IP`,
    `QWED_AUTH_TRUSTED_PROXIES` and `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` kept
    their defaults. The database fell back to `sqlite:///./qwed.db`.
  - With `QWED_JWT_SECRET_KEY` or `QWED_API_KEY_LOOKUP_SECRET` only in
    `.env`, the server did not start.
  - A math setting the worker cannot use did not stop the start: each
    worker refused it, and every maths job was `BLOCKED`
    (`math.worker_error`). It now stops the start with an error naming the
    setting, as it does when set in the process environment.
  - `api/main.py` now imports `qwed_new.config`, which loads `.env` (the
    working directory's, then `~/.qwed/.env`), before any other QWED module.
    Values set in the process environment (the shell, Docker `-e`,
    Kubernetes `env`, Compose) were read before and still win over `.env`.
  - `.env.example` and `deploy/.env.example` list the five maths settings
    with their ranges, and `deploy/docker-compose.yml` passes them to the
    server by name, so one that is not set stays unset and keeps its
    default.

## [9.0.0] - 2026-11-06

A major release. It fixes eleven private advisories: CodeVerifier admitted
code that loads a module by name, runs a string through a standard-library
module or through typing, or hides behind a source encoding; the maths
parser and `verify_math` accepted wrong claims; SQL tautologies written with
other operators, and number literals in logic proofs, gave wrong verdicts;
`/verify/math` ran with no time limit; the GitHub Action's `scan-code` mode
missed imported and aliased calls; and sign-up printed the new user's
password hash. QWED also stops naming models of its own: each provider runs
the model you configure, and `QWEDLocal`, `verify()` and the LangChain
`QWEDTool` need `model=`. The CSV exports change their columns, and the Go
module path ends in `/v9`. Read "Upgrading to 9.0.0" below before upgrading.
The soundness eval has 142 known-answer claims, 0 accepted wrongly.

### Security fixes (advisories)

Eleven advisories, published on the repository Security tab. They affect all
versions up to 8.0.0; upgrading is recommended. Each has regression tests in
`tests/`. The CodeVerifier, maths, SQL and logic fixes are also reproduced
in the soundness eval (`evals/`); the Action, the maths time limit and the
sign-up fix are paths the eval runner does not exercise.

- **CodeVerifier refuses modules taken by name from the import system**
  ([GHSA-qrp4-p44j-m484](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-qrp4-p44j-m484),
  high). Code that took a module by its name as a string
  (`__loader__.load_module(...)`, `importlib.util.module_from_spec`, the
  importlib bootstrap, `pkgutil.resolve_name`, `pydoc.locate`, or
  `sys.modules` read other than by subscript, such as
  `sys.modules.get(...)`) and called on it was `VERIFIED · ADMIT`. These
  names are now refused wherever they appear, and any read of `sys.modules`
  is refused.
- **CodeVerifier refuses eleven more modules that run strings as code, and
  more file readers**
  ([GHSA-jrxf-9jh4-86w7](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-jrxf-9jh4-86w7),
  high). `timeit`, `cProfile`, `profile`, `pdb`, `bdb`, `code`, `codeop`,
  `trace`, `doctest`, `logging.config` and `idlelib` run a string as code,
  and importing one is now refused (`logging.config` also when read as an
  attribute). `tarfile`, `zipfile`, `gzip`/`bz2`/`lzma` file opens,
  `codecs.open`, `linecache`, `fileinput`, directory listing, `glob`,
  `tempfile`, `sqlite3`, `shelve`, `dbm`, `pkgutil.get_data` and
  `importlib.resources` join the file-access table.
- **CodeVerifier refuses code hidden in strings that typing evaluates**
  ([GHSA-p75q-7rg5-ff46](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-p75q-7rg5-ff46),
  high). A string annotation on a `singledispatch` handler, or a string in
  `List["…"]` run through its `ForwardRef`, was never examined, so the code
  in it was admitted. Strings typing may compile are now parsed and refused
  when they hold a call, lambda, comprehension or assignment expression.
  This covers the functional `NamedTuple`, `TypedDict` and
  `dataclasses.make_dataclass` field types and import aliases of the typing
  calls. `__forward_code__`, `__forward_arg__`, `__annotations__` and Python
  3.14's `__annotate__` are dangerous attributes.
- **CodeVerifier refuses a source encoding other than UTF-8**
  ([GHSA-pr6c-cqg8-6w5r](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-pr6c-cqg8-6w5r),
  high). Under a `utf-7` or `unicode_escape` coding declaration, what was
  checked as a comment decodes to statements when the code runs from a file,
  an import or bytes, so hidden code was `VERIFIED · ADMIT`. A declaration
  whose codec is not UTF-8 is now refused.
- **The Action's scan-code mode resolves from-imports, aliases, importlib
  and getattr**
  ([GHSA-hg73-j3qv-w4vh](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-hg73-j3qv-w4vh),
  medium). It matched calls by name as written, so `from os import system;
  system(...)` and similar forms passed with a green badge. It now also runs
  CodeVerifier on each file and takes its code- and process-execution
  findings, and checks `getattr`, `setattr` and `delattr` with a constant
  name as that attribute. A computed name cannot be checked and is reported
  as a warning (new `warnings_count` output) that does not fail the scan. A
  Python file whose coding declaration is not UTF-8 is refused, so its scan
  is not admitted. A pass means no known dangerous pattern was found, not
  that the code is safe.
- **The math parser refuses unknown functions and gives `n` no hidden
  domain**
  ([GHSA-5h3v-3463-78hf](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-5h3v-3463-78hf),
  medium). Unknown names were split into products of letters (`sinc(0)` read
  as 0), and `n` was a positive integer, so `/verify/math` returned
  `VERIFIED · ADMIT` for `sinc(0) = 0` and `Abs(n) = n`. A name of two or
  more letters in call position must now be a supported function, a
  multi-letter name is one symbol, and `n` is a plain variable. A single
  letter before a bracket is still a product, as before: `x(x+1)` is
  `x*(x+1)` and `f(0)` is `f*0`, not a call. **Upgrade note:** write `*`
  between names you mean to multiply. `xy` is now one name, so `xy` and `yx`
  are different symbols; `2x`, `x(x+1)` and `sin x` read as before.
- **/verify/math and batch math run in worker processes with a time limit**
  ([GHSA-qgjc-92m3-fcr6](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-qgjc-92m3-fcr6),
  medium). SymPy ran on the event loop or in a thread with no limit, so
  input the cost gates accepted could run for minutes. A job past
  `QWED_MATH_TIMEOUT_SECONDS` (default 10) is now `UNVERIFIABLE`
  (`math.timeout`) and its worker process is killed; a full pool refuses at
  once (`math.capacity`); on Linux each worker has a memory limit; batch
  math items share a per-job budget (`QWED_BATCH_MATH_BUDGET_SECONDS`). The
  unevaluated cost gate parses with the parser's restricted namespace.
- **verify_math no longer accepts wrong small values or wrong 7th digits**
  ([GHSA-8hp7-jqjc-hrhf](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-8hp7-jqjc-hrhf),
  medium). The computed value was rounded to 6 decimals and compared with an
  absolute 1e-6, so `1/1000000000 = 0` was `VERIFIED`. The comparison is now
  unrounded. With no tolerance, a claim must match to 9 significant digits,
  or be correctly rounded when it has at least 6, and lie within 1e-6.
  `tolerance=0` is exact, and a caller's tolerance can no longer exceed the
  value itself. The result's new `match` field says how a claim matched
  (`exact`, `caller_tolerance`, `default_bound` or `rounded_claim`) and the
  bound used.
- **SQL tautologies written with IN, IS, LIKE, BETWEEN and other operators
  are refused**
  ([GHSA-jvhg-jw63-gr5g](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-jvhg-jw63-gr5g),
  medium). The constant folder from GHSA-6cpx now covers every column-free
  operator in the advisory, short-circuits AND and OR on constant operands,
  and treats a column compared with itself as always true. A filter
  predicate that reads no data and still cannot be evaluated is not admitted
  (`sql_verifier.unevaluated_predicate`).
- **Logic verification keeps numbers exact**
  ([GHSA-w73j-4jjq-q53j](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-w73j-4jjq-q53j),
  medium). Python computed number-only sub-expressions (`1/3`, `0.1 + 0.2`,
  `7/2`) as floats before Z3 saw them, so `prove_theorem` proved false
  statements. Decimal literals are now exact, a division of two numbers is
  exact or refused next to Int variables, Int and Real terms are never
  divided into each other, and the DSL divides integer literals as Ints.
- **Sign-up no longer prints the new user's password hash**
  ([GHSA-mr5j-gm4f-6c27](https://github.com/QWED-AI/qwed-verification/security/advisories/GHSA-mr5j-gm4f-6c27),
  low). Debug prints in `POST /auth/signup` wrote the `User` object,
  password hash included, and the email to standard output. They are
  removed; a failed insert logs the error type only. Hashes that may have
  been collected from earlier logs should be treated as exposed.

### Upgrading to 9.0.0

These changes can break existing callers. Each is described in full in its
entry, above or below.

- **Model settings.** Set the model variable of the provider you use:
  `OPENAI_MODEL`, `AZURE_OPENAI_DEPLOYMENT`, `ANTHROPIC_MODEL`,
  `CLAUDE_OPUS_DEPLOYMENT`, `GEMINI_MODEL`, `OLLAMA_MODEL` or
  `CUSTOM_MODEL`. Nothing falls back to a model QWED picks. With none set,
  `qwed verify` and `qwed interactive` stop at once with an error naming the
  variable, unless you pass `--model`. With an explicit `--base-url`, `qwed
  verify` reads no model variable, even `CUSTOM_MODEL`, and needs `--model`.
  Commands such as `qwed test` need no model. The server starts, since it
  builds a provider on first use. Logic, statistics and fact requests that
  need the provider then fail with that error; the natural-language routes
  answer `UNVERIFIABLE` without the message. On the server,
  `ANTHROPIC_DEPLOYMENT` still wins over `ANTHROPIC_MODEL` when it is set:
  change or unset it to run another model. The CLI reads only
  `ANTHROPIC_MODEL` or `--model`. `ACTIVE_PROVIDER`, and the provider a
  request names, must be one QWED knows: `openai`, `openai_direct`,
  `openai_compat`, `azure_openai`, `anthropic`, `claude_opus`, `gemini`,
  `ollama` or `auto`.
- **Python SDK.** `QWEDLocal`, `verify()` and the LangChain `QWEDTool` need
  `model=` and raise `ValueError` without it. If `qwed verify` ran the saved
  provider with the key in `QWED_API_KEY`, set that provider's key variable
  or pass `--api-key`.
- **CSV exports.** `GET /admin/compliance/export/csv` and `GET
  /audit/export` write a new, shared set of columns and at most the newest
  1,000 rows (`X-Export-Truncated: true` when more matched). A client that
  read the old columns by position or name must update.
- **Maths input.** Write `*` between names you mean to multiply: `xy` is now
  one name. A name of two or more letters in call position must be a
  supported function; a single letter there is still a product (`f(0)` is
  `f*0`). `n` is a plain variable. With no tolerance, `verify_math` needs a
  claim to match to 9 significant digits, or to be correctly rounded with at
  least 6, within 1e-6. `VerificationEngine.verify_math`'s `tolerance`
  defaults to `None`.
- **Maths limits.** `/verify/math` and batch maths run in worker processes,
  set by `QWED_MATH_WORKERS` (default 2), `QWED_MATH_TIMEOUT_SECONDS` (10),
  `QWED_MATH_MAX_WAITING` (32), `QWED_MATH_WORKER_MEMORY_MB` (2048, Linux
  only; 0 turns it off) and `QWED_BATCH_MATH_BUDGET_SECONDS` (120). A job
  past its limit is `UNVERIFIABLE` (`math.timeout`), and a request that
  finds the pool full is `BLOCKED` (`math.capacity`) at once. Size these for
  your load. A value these settings cannot use (not a number, `inf` or
  `nan`, below its minimum, a fraction for a count, or a time limit over
  3600 seconds) stops the server at start with an error naming the setting;
  nothing is put in its place. A `QWED_BATCH_MATH_BUDGET_SECONDS` of 0
  leaves batch maths no budget, so its items are not run.
- **Code verification.** CodeVerifier refuses more code: the modules, names
  and attributes in the advisories above, and a coding declaration other
  than UTF-8. Code that used them is no longer admitted.
- **GitHub Action.** `scan-code` also reports CodeVerifier's code- and
  process-execution findings, refuses a Python file whose coding declaration
  is not UTF-8, and reports attribute access by a computed name as a warning
  (new `warnings_count` output) that does not fail the scan.
- **Audit log.** Each row's `latency_ms` is now covered by its entry hash,
  so an 8.x process cannot verify rows that 9.0.0 writes: upgrade every
  server process together. An existing database gets the column at startup.
  Natural-language rows are stored with the domain `NATURAL_LANGUAGE`, not
  `MATH`; rows already written keep `MATH`. The audit row of a signed
  Verification Context document stores the document as returned, with any
  personal data in it; its `query` column is still redacted.
- **Route results.** A batch maths item proven false is `VERIFIED` with
  `is_valid` false and admission `BLOCKED`, as on `/verify/math`; it was
  `UNVERIFIABLE`. Input the maths parser refuses is `BLOCKED` with
  `math.parse_error`, not `api.math.execution_error`, on the route and as a
  batch item, and Python that does not parse is `BLOCKED` with
  `code_verifier.parse_error`. `/auth/me` answers 403 for an inactive user
  or organisation or an unknown role, and sign-in refuses a user of an
  inactive organisation. A password over 72 bytes is 400 at sign-up and 401
  at sign-in, not 500.
- **Dependencies.** `qwed` now requires `z3-solver==5.3.2.0` (it required
  5.1.0.0), so an environment that pins another z3 version must move with
  it. The server image moves to sqlglot 30.25.0, anthropic 2.3.0, FastAPI
  0.162.0, openai 3.41.0 and python-dateutil 3.0.0.
- **Go module path.** The module is
  `github.com/QWED-AI/qwed-verification/sdk-go/v9`. Update imports and run
  `go get github.com/QWED-AI/qwed-verification/sdk-go/v9@v9.0.0`. The Go,
  TypeScript and Rust SDKs have no API changes in this release.

### Other changes since 8.0.0

#### Added

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

#### Changed

- **QWED names no model: each provider runs the model you configure
  (#574).** Runtime code fell back to models of its own when none was set,
  such as `gpt-4o-mini`, `gpt-3.5-turbo`, `llama3`, `gemini-1.5-pro`,
  `claude-sonnet-4-5` and `claude-sonnet-4-20250514`, and those names went
  stale as providers retired models. `qwed verify --provider anthropic`
  with no `--model` sent `gpt-3.5-turbo` to Anthropic, and the reasoning
  trace called `claude-3-haiku-20240307` through the provider's client,
  whatever model was configured.
  - Each provider takes its model from the argument you pass or from its
    variable, and raises when neither is set, naming the variable:
    `OPENAI_MODEL`, `AZURE_OPENAI_DEPLOYMENT`, `ANTHROPIC_MODEL`,
    `CLAUDE_OPUS_DEPLOYMENT`, `GEMINI_MODEL`, `OLLAMA_MODEL` or
    `CUSTOM_MODEL`. The value is sent unchanged, so any model or deployment
    ID the provider serves works, and nothing falls back to another model.
    `auto` raises the same error when neither Azure OpenAI nor Anthropic can
    run and either has no model, naming the variable of each side with none;
    it raised a generic `RuntimeError`.
  - The Anthropic provider reads `ANTHROPIC_MODEL`, the variable `qwed init`
    and `.env.example` set; it read only `ANTHROPIC_DEPLOYMENT` before,
    which still wins when set.
  - `QWEDLocal`, `verify()` and the LangChain `QWEDTool` need `model=`.
    `verify(query, provider=..., model=...)` uses the provider you name; it
    always tried Ollama before. `QWEDTool` refuses a missing or blank model
    when it is built, not when an agent first runs it.
  - `qwed verify` and `qwed interactive` take `--model`, else the selected
    provider's variable (`OLLAMA_MODEL`, `CUSTOM_MODEL`, `OPENAI_MODEL`,
    `ANTHROPIC_MODEL` or `GEMINI_MODEL`), and stop with a message naming it
    when neither is set. A blank `--model` counts as unset. `qwed init` asks
    for the model without suggesting one; with `--non-interactive`, pass
    `--model` or set the variable.
  - Without `--provider`, `qwed interactive` runs the provider `qwed init`
    saved (`ACTIVE_PROVIDER`), with its endpoint and key, as `qwed verify`
    does. It always ran Ollama at its default address before. An
    `ACTIVE_PROVIDER` that only the server runs (`azure_openai` or `auto`,
    say) stops `qwed verify` and `qwed interactive` with a message naming
    it, where they asked for `--model` and then failed to start a client.
    Both read `ACTIVE_PROVIDER` as the server does: in any case, with `-`,
    `_` or a space, and with `openai_direct` run as `openai`.
  - The saved provider gets a key only from `--api-key` given on the command
    line or from its own variable (`CUSTOM_API_KEY`, `OPENAI_API_KEY`,
    `ANTHROPIC_API_KEY`, or for Gemini `GOOGLE_API_KEY`, else
    `GEMINI_API_KEY`, as the server reads them). `QWED_API_KEY`, which
    `--api-key` also reads, may be the QWED server's key: it went to the
    saved provider's endpoint before, over its own key. A saved `anthropic`
    with `ANTHROPIC_ENDPOINT` set now stops: the CLI calls the Anthropic API
    directly, and sent the key and the prompt there instead of to that
    endpoint. `--provider` with `QWED_API_KEY` works as before.
  - `qwed verify` loads the `.env` files `qwed init` writes without loading
    the server's settings, as `qwed interactive` does. It stopped with a
    traceback when the server's `API_KEY_SECRET` was unset, though it calls
    the model provider directly and uses no server secret.
  - `ReasoningVerifier()` uses the provider `ACTIVE_PROVIDER` selects
    (Ollama when it is unset, as the server reads it), not always
    Anthropic, and loads every provider the server can; `openai` named a
    module that does not exist. A provider with no model, or a name QWED does
    not know, makes the result BLOCKED with the setting to fix
    (`reasoning_verifier.provider_config_error`);
    one that cannot be built for another reason is no provider: the reason
    is logged and the result says `reasoning_verifier.no_provider`. The
    reasoning trace comes only from a provider's own `complete()` call,
    which no built-in provider has, so it is unavailable for them (#587). The
    verifier never returns VERIFIED, before and after.
  - The server sends each request to the provider the request names, else
    to the one `ACTIVE_PROVIDER` selects. A query with `write`, `compose`,
    `essay`, `creative` or `story` in it went to Anthropic, whatever was
    configured. A request that names a provider QWED does not know is
    refused, with `unknown` as its provider; before, the configured provider
    ran it.
  - An `ACTIVE_PROVIDER` that names no provider QWED knows stops the request
    with an error naming `ACTIVE_PROVIDER`; before, it switched to `auto`
    (Azure OpenAI, then Anthropic). A blank one counts as unset, as a blank
    model does. Logic and statistics verification return this error, and
    the one naming a missing model variable, and log it; they gave only a
    generic translation failure. Other provider errors still do.
  - `/verify/fact` with a `provider` its advisory fallback cannot run (one
    QWED does not know, or one with no model) is BLOCKED with that error,
    and keeps the deterministic verdict and evidence; before, the fallback
    dropped the advisory without saying why. Other advisory failures still
    leave the deterministic result.
  - `DSLLogicVerifier.verify_from_natural_language()` and `translate_to_dsl()`
    with no `provider` use the configured one; they used Azure OpenAI.
  - A provider YAML's `default_model` is still used; one without it gets no
    model in its place.
  - To upgrade, set the model variable for the provider you use; code that
    builds `QWEDLocal`, calls `verify()` or builds the LangChain `QWEDTool`
    passes `model=`, and gets a `ValueError` without it. Check
    that `ACTIVE_PROVIDER` is one of `openai`, `openai_direct`,
    `openai_compat`, `azure_openai`, `anthropic`, `claude_opus`, `gemini`,
    `ollama` or `auto`. If `qwed verify` ran the saved provider with the key
    in `QWED_API_KEY`, set that provider's key variable or pass `--api-key`.
    A request that names a provider must name one of these. Settings that
    already name a model work as before.

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

- **Dependencies (#565).** `pyproject.toml` pins `z3-solver==5.3.2.0`, up
  from 5.1.0.0, and the build backend `hatchling==1.33.0`. The server
  image's `requirements-server.txt` moves to sqlglot 30.25.0 (from 30.23.0
  in 8.0.0), anthropic 2.3.0 (from 1.15.0), FastAPI 0.162.0 (from 0.151.0),
  openai 3.41.0 (from 3.35.1), python-dateutil 3.0.0 (from 2.9.0.post0) and
  certifi 2026.10.23 (from 2026.10.19), among other updates. SymPy stays at
  1.14.0.

#### Fixed

- **The Anthropic and Claude Opus providers work with anthropic 1.0 and
  later (#572).** Each `messages.create` call passed `temperature=0.0`,
  which the SDK has not accepted since 1.0, so every call raised
  `TypeError` before a request was sent. The server image has pinned
  anthropic 1.15.0 since #474 and 2.3.0 since #565, so every Claude
  translation there was refused, and `verify_image` returned its ERROR
  verdict.
  - The calls now leave `temperature` out and sample with the defaults.
    API version `2026-10-21`, which the 2.x SDK sends, refuses
    `temperature`, `top_p` and `top_k`, and no other setting replaces a
    lower `temperature`. Sampling can now vary the model's translations,
    and the verdicts that `verify_fact` and `verify_image` return, which
    are model output. QWED's fact and image verifiers record those only as
    advisory checks, never as a VERIFIED verdict.

- **AgentStateGuard gives one verdict on a JSON number, whichever decimal
  module Python has (#570).** The guard relied on `parse_float=Decimal` to
  refuse a number it cannot hold, and the C and pure-Python decimal modules
  refuse different numbers. A Python built without `_decimal` accepted
  `1e9999999999999999999999`, so a `number` field holding it was VERIFIED
  where the C module gives QWED-AGENT-STATE-102. From 3.15 configure no
  longer falls back to the bundled libmpdec, and setup-python's 3.15.1 for
  Ubuntu is built without it. The server image builds `_decimal`.
  - The guard now checks the number's text first: an exponent outside the
    C module's range, or more digits than `sys.get_int_max_str_digits()`
    (4300 by default), is QWED-AGENT-STATE-102 with either module.
  - With the C module the only change is the digit rule: a decimal with
    more than 4300 digits is now refused, as a JSON integer with more than
    4300 digits already was.

- **Statistics verification and `verify_python_deep` work on Python 3.14
  and later (#568).** Python 3.14 removed `ast.Num` and `ast.Str`. The
  server image has run 3.14 since #356, and `requires-python` allows it.
  - `core/stats_verifier.py` named both in a class body, so the module
    could not be imported: every `/verify/stats` request that passed the
    upload checks was BLOCKED, and importing `StatsVerifier` raised.
  - `CodeVerifier.verify_python_deep` blocked any code with a sink argument
    that was neither a name nor a constant, such as
    `os.system(request.args)`: the taint analyzer named `ast.Str` while
    describing it.
  - Both failed closed, so nothing was admitted on the error. Both now rely
    on `ast.Constant`, which every literal has parsed to since Python 3.8,
    so 3.10 to 3.13 behave as before. `qwed_sdk/qwed_local.py` named them
    too, behind `hasattr` checks that never ran on a supported Python, since
    each function tested `ast.Constant` first; those checks are gone.
  - A new CI job runs the tests on the Python that the Dockerfile's `FROM`
    line names, so a base-image bump is tested on the Python it moves to.
    The `test` job stays on 3.11, where both names still exist.
  - From Python 3.14 the JSON parser is bounded by the C stack, not the
    recursion limit, so whether a file nested 100,000 deep parses depends
    on the platform. Where it parses (Linux), `qwed context validate` and
    `resolve` still refuse it, with `validation_failed`, `resolved: false`
    or `attestation_invalid` in place of `invalid_document_file` or
    `attestation_keys_unavailable`. The CLI tests now raise the
    `RecursionError` themselves, and check the real file on any platform.

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
  so `cur.execute("SELECT ?", params)`, `model.evaluate(x, y)`,
  `re.compile(r"[0-9]+")` and `compile_report()` came back VERIFIED with
  `is_valid` false (`dangerous_function`). Parameterised SQL, the safe way to
  run a query, was refused.
  - `eval`, `exec`, `compile`, `__import__`, `getattr` and `setattr` are now
    matched on the AST: as a name, called or not (`f = eval`), whatever an
    import elsewhere binds to it, since imports are not read by scope or
    order; as a keyword or a name bound other than by assignment (a
    parameter, a `def` or class, `except ... as`, a match capture, a type
    parameter), since introspection reads it back as a string
    (`list(dict(exec=1))`, `inspect.signature`, `vars(C)`); a keyword, or a
    binding other than a `def` or an import, is refused for the names
    refused only in strings too (`dict(__getattribute__=1)`,
    `def train(evaluate=False)`), and so are a name, a def (a method
    included: `def evaluate(self, x)`, `def __setattr__`), and an import
    whose module path holds one (`import evaluate`, `import pkg.exec as x`),
    since the object carries that name (`f.__name__`, `dir()` and `vars()`
    on its class, `module.__name__`, `obj.__module__`), as at main. Only
    `def __getattr__` is admitted, wherever it is defined: classes and
    modules (PEP 562) define it to answer attribute reads, and `object` has
    none; as an attribute, since the object may be the `builtins` module
    reached another way, whether read as `m.exec`, by `from m import exec`
    or by a match pattern (`case object(exec=run)`); and in a string as a
    whole identifier (`vars(module)["exec"]`). Steps on strings (a slice or
    an index, a `%`-format, a `str` method that removes characters or
    changes case, also called as `str.lower(s)`, `str()` and `+`) are worked
    out deepest first from the literals they start from, chains included
    (`"xexecx"[1:][:-1]`, `"xexec".upper().lower()[1:]`, `"ex" + "ec"`), and
    each result is matched as whole identifiers, the tuple `partition`
    gives included. A `%`-format is worked out when the format and its
    arguments are literals (`"%c%c%c%c" % (101, 120, 101, 99)`,
    `"%.4s" % "execute"`), unless its widths, precisions or a mapping key
    used by many conversions could make it longer than 16,384 characters
    (`"%.999999999d" % 1`). Otherwise its conversions are read as CPython
    reads them, nested mapping keys included, in one pass, each both as a
    separator and as nothing (`"ex%sec" % sep`), and a precision cuts what
    it inserts, not the format's own text. `str.format`, `format_map`, the
    builtin `format()` and f-strings are read the same way
    (`"{:.4}".format("execute")`, `f"ex{''}ec"`). An index that is not a
    literal may be a slice object (`"xexec"[slice(1, None)]`), so it is
    read as a slice. A regex function (`sub`, `findall`, `search`, `match`
    and their variants, and the `regex` package's `subf`, `subfn` and
    `splititer`) on `re` or `regex`, however it is named, is a step that
    removes characters (`re.sub("q", "", "qexec")`), as is `split` on a
    regex module or imported from one, whose pattern is not the text it
    cuts on; helpers that remove nothing (`re.escape`)
    are not. Its pattern is matched like its other arguments, so
    `re.search("evaluation", text)` stays refused, as at main: the pattern
    can reach what the call gives (a group name, `.re.pattern`), and the AST
    cannot show that `re` is the module, since reflection on `sys` can give
    `import re` another one whose function does the cut itself
    (`operator.getitem` in place of `split`). `%` with a number on the left is
    arithmetic (`10 % n`); a number on the right is not, since `%c` and `%x`
    insert letters. A format's own text, its fields read as separators and
    as nothing, is matched anywhere by a later step
    (`("xex%sec" % sep)[1:]`).
  - A step that removes characters but cannot be worked out (arguments
    that are not literals, a method read without being called, which may be
    saved and called later (not one set or deleted: `obj.title = t`), a `translate`
    or a `replace` that could grow the text past 16,384 characters, a
    precision in a format whose arguments are not known, a value longer
    than 4,096 characters carried from an earlier step, a value from
    anywhere else) matches anywhere the
    value an earlier step worked out, or the literals that can reach it. A
    literal index, a case change, `str()`, `+`, and `strip`, `split`, `partition`
    and their variants cutting on whitespace or on a literal with no word
    characters, cannot leave a whole name the value did not already hold,
    so they never refuse on their own.
  - The literals that can reach a value are found by following each one,
    over-approximately, to every value it can become or be stored in: the
    expressions that hold it; names and attributes bound by assignment of
    any shape, augmented assignment, a loop, `with`, a match capture or a
    parameter default; parameters of the functions a call names or is given
    (`map(f, ...)`, `partial(f, ...)`), or, for a call whose function is
    not named (`ops["cut"](s)`, `make()(s)`), of every lambda and every
    function or method read as a value (`{"a": obj.cut}`); and what they
    return or yield;
    `__doc__` for a docstring; `except ... as` for what is raised; a class
    and its subclasses for what its dunder methods return; what a call can
    store into (the object a method is called on, another argument, an
    argument through a parameter, a name bound to the same object); and
    every name, for a store through a namespace (`globals()["s"] = ...`);
    and what an import binds after other code has run, or inside a
    function, or what a module looked up by name gives (`import_module`,
    `pkgutil.resolve_name`, `pydoc.locate`, under any alias:
    `im = importlib.import_module`), from every literal and every other
    seed, since that code may have put a module of its own under the name
    (`sys.modules.update(m=ns)`, then `from m import s`). The module's
    opening run of imports, a `try` made only of imports included, binds
    the modules installed and is read as before.
    Where the source holds a name inside a word anywhere, identifiers and
    comments included, what can read the source or its names back as text
    is taken to hold it too: an exception caught with `except ... as` (its
    message can quote a value or a name: `int("xexec")`, `o.xexec`),
    introspection (`__name__`, `__code__`, `inspect`, `traceback`, `dir`,
    `globals`; and common words such as `fields`, `signature` and
    `exception` only when imported from, or read on, `dataclasses`,
    `inspect` or `sys`, the module followed through the graph however it
    is named or looked up: `d = dataclasses`, `sys.modules[...]`,
    `importlib.import_module(...)`; an import seeds its names where they
    are read as names, and a star import what the module exports plus
    its introspection names, `inspect.get_annotations` included), a
    call given a keyword of that name (`dict(xexec=1)`), and a class with a
    base that has a member of that name (an Enum member's `.name`). Names and attributes share one key per identifier, and scopes
    are not told apart. The graph is built only when the source holds a
    name inside a word, and walked once, so the work stays linear in the
    code. The string steps live in `string_steps.py`. A name
    bound once, to a literal as written, is worked out like that literal,
    unless the code uses a namespace other than to read an item of it
    (`vars(m)[k]`), captures one in a class pattern
    (`case object(f_globals=g)`), or star-imports. Concatenation with a value that is not
    a literal, and names built by `chr` or `join`, are not followed. An
    import of the `builtins` module (`import builtins`) is refused too.
  - Admitted: longer identifiers (`execute`, `evaluation`, `compile_report`),
    the names inside longer words in strings and docstrings, also when
    formatted or split (`"SELECT * FROM evaluations WHERE id = %s" % uid`,
    `"executing job"`, `"executed,ok".split(",")`), or when they reach only
    an index or a cut between words (`row[0].strip()` after a query on
    `evaluations`). Prose that can reach a slice or another cut that is not
    worked out stays refused, as before (`raise ValueError("evaluation
    failed")` beside `str(e)[:80]`). Also admitted:
    comments, and `re.compile(pattern, flags)` on a name every import binds
    to `re`. The builtin `compile` needs a filename and a mode, so it cannot
    run in that shape; any other `re.compile` call, or `re.compile` not
    called, is refused. The exception is also dropped when anything rebinds
    the name, sets an attribute on it or an attribute of that name on any
    object (`module.re = ...`), or can rebind it without an assignment: a
    namespace (`globals()`, `vars()`, `locals()`, a frame's `f_globals` or
    `f_locals`, a star import) or the import system (`sys.modules`,
    `sys.meta_path`, `sys.path_hooks`, `sys.path_importer_cache`), read as
    an attribute, through a class pattern (`case object(modules=c)`) or by a
    from-import. None of those tables is callable, so a method of that name
    that is called (`model.modules()`) and a variable of that name do not
    drop it. Still
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
    `_getattribute`; and the `os.exec*` family (`execl`, `execle`,
    `execlp`, `execlpe`, `execv`, `execve`, `execvp`, `execvpe`), however
    they are referenced (`from os import execv; run = execv`), where the
    process check reads calls only. `loop.subprocess_shell`, and `create_subprocess_shell`
    imported from `asyncio.subprocess`, which the substring scan admitted,
    are refused too.
    `ast.literal_eval` is admitted.
  - Calls that evaluate string annotations as code are refused:
    `get_type_hints`, `evaluate_forward_ref`, and the `eval_str` keyword
    (`inspect.get_annotations(f, eval_str=True)`, `inspect.signature`),
    matched like the names above, as a keyword, in a string and as any
    name bound, imports included (`from math import pi as eval_str`),
    since `**locals()` passes bound names as keywords.
  - On Python 3.14, `ForwardRef.evaluate()` runs its string as code
    (`List["..."].__args__[0].evaluate()`), and on the AST it cannot be told
    apart from `model.evaluate(x)`. `evaluate` is therefore read like
    `compile`: refused as an attribute, a from-import or a string, except
    in a call that `ForwardRef.evaluate()` raises on before it evaluates, two
    or more positional arguments or a keyword it does not take, with nothing
    unpacked. `model.evaluate(x, y)`, `model.evaluate(ds, verbose=0)` and
    `model.evaluate(x=X, y=Y)` are admitted; `model.evaluate(x)` and
    `model.evaluate()` stay refused on every Python version, as they were
    before this change. A function named `evaluate`, and the `evaluate`
    package, are admitted.
  - `__self__` is a dangerous attribute, as `__dict__` and `__globals__`
    are: on a builtin function it is the `builtins` module, so
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
