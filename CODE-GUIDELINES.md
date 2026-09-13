## Code Style Guidelines

Please keep contributions consistent with the existing codebase.

### Python

- Follow PEP 8 for Python code.
- Use type hints for functions and public interfaces where practical.
- Use descriptive names for variables, functions, classes, and modules.
- Keep functions focused and avoid unnecessary complexity.
- Prefer clear, readable code over clever implementations.
- Add docstrings to public classes, functions, and modules where appropriate.
- Avoid unrelated refactoring in feature or bug-fix PRs

### Verification Engines

When modifying or adding a verification engine:

- Keep verification logic deterministic.
- Do not use LLM output as the final verification result.
- Use the appropriate symbolic or deterministic verification library.
- Keep LLM-based translation separate from deterministic verification.
- Add tests for successful verification, failed verification, and relevant edge cases.
- Do not bypass existing safety or boundary wrappers.

### Tests

New functionality should include tests covering the expected behavior.

When fixing a bug, add a regression test when practical so that the issue does not reappear.

Run the relevant tests locally before opening a PR:

```bash
pytest tests/ -v
```

### Imports and Dependencies

- Remove unused imports.
- Avoid introducing a new dependency when an existing project dependency can solve the problem.
- If a new dependency is necessary, explain the reason in the PR description.
- Do not commit generated dependency files or local environment files unless they are explicitly required by the project.

### Formatting

Before submitting a PR, review your changes for:

- Consistent indentation and formatting
- Unused imports
- Debug statements
- Temporary code
- Hardcoded credentials or secrets
- Unnecessary changes outside the scope of the issue