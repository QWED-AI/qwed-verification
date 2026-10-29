# Copyright (c) 2026 QWED Team
# SPDX-License-Identifier: Apache-2.0

"""The owner of the organisation ``qwed init`` creates (#524).

``qwed init`` signs the organisation up with the owner's email and password,
so the owner can sign in later, for example to qwed-dashboard. The email
comes from ``--owner-email`` or QWED_OWNER_EMAIL, else a prompt. The password
is prompted for with hidden input and a confirmation; it is never a flag, so
it stays out of shell history.

Kept out of cli.py, which is at the security scan's file size limit.
"""

import os

import click

# bcrypt, which the server hashes passwords with, reads at most 72 bytes.
MAX_OWNER_PASSWORD_BYTES = 72

NO_PASSWORD = "--owner-email with --non-interactive needs QWED_OWNER_PASSWORD set."


def owner_email_problem(email: str) -> str | None:
    """Why ``email`` cannot be the owner's email, or None. The server checks it fully."""
    local, _, domain = email.partition("@")
    looks_valid = (
        email.count("@") == 1
        and local
        and "." in domain.strip(".")
        and not any(c.isspace() for c in email)
    )
    return None if looks_valid else f"Not an email address: {email!r}."


def owner_password_problem(password: str) -> str | None:
    """Why ``password`` cannot be the owner's password, or None."""
    if not password:
        return "The owner password must not be empty."
    if len(password.encode("utf-8")) > MAX_OWNER_PASSWORD_BYTES:
        return f"The owner password must be at most {MAX_OWNER_PASSWORD_BYTES} bytes."
    return None


def resolve_owner(owner_email: str | None, non_interactive: bool) -> tuple[str, str] | None:
    """The owner's email and password for the new organisation, or None.

    With ``--non-interactive`` nothing is prompted: the password comes from
    QWED_OWNER_PASSWORD, and without an email the result is None (an owner
    nobody can sign in as, as before #524).

    QWED_OWNER_EMAIL is read only when ``--owner-email`` is not given: an
    explicit but empty flag is refused (or asked again), never replaced.
    """
    explicit = owner_email is not None
    email = (owner_email if explicit else os.getenv("QWED_OWNER_EMAIL", "")).strip()
    if non_interactive:
        return _owner_from_environment(email) if email or explicit else None
    return _prompt_for_owner(email)


def signup_failure(detail: str, has_owner: bool) -> str:
    """The error for a refused signup, with what to do when the owner already exists."""
    message = f"Signup failed: {detail}"
    if has_owner and "already registered" in detail.lower():
        message += (
            " If an earlier init registered this owner, sign in with it (for example"
            " to qwed-dashboard) and create a key there, or use another email."
        )
    return message


def _owner_from_environment(email: str) -> tuple[str, str]:
    """The owner with the password from QWED_OWNER_PASSWORD; RuntimeError if unusable."""
    password = os.getenv("QWED_OWNER_PASSWORD", "")
    problem = owner_email_problem(email)
    if problem is None:
        problem = owner_password_problem(password) if password else NO_PASSWORD
    if problem:
        raise RuntimeError(problem)
    return email, password


def _prompt_for_owner(email: str) -> tuple[str, str]:
    """Ask for the email (unless given and valid) and the password, until both are usable."""
    while not email or owner_email_problem(email):
        if email:
            click.echo(f"  [x] {owner_email_problem(email)}", err=True)
        email = click.prompt("Owner email (to sign in later, e.g. to qwed-dashboard)").strip()
    while True:
        password = click.prompt("Owner password", hide_input=True, confirmation_prompt=True)
        problem = owner_password_problem(password)
        if problem is None:
            return email, password
        click.echo(f"  [x] {problem}", err=True)
