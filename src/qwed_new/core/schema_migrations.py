"""Column additions for tables that already exist (#484).

``SQLModel.metadata.create_all`` creates missing tables but never changes an
existing one, so a database made by an older release would lack the columns
added since. ``add_missing_columns`` adds them, nullable, with
``ALTER TABLE ... ADD COLUMN``. It only adds; it never drops, renames or
rewrites data, and it is a no-op once every column is there.
"""

import logging

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# table -> [(column, SQL type)]. Only nullable columns belong here: rows that
# already exist get NULL, which every reader treats as "not recorded".
ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "verificationlog": [
        ("api_key_id", "INTEGER"),
        ("verifier_version", "VARCHAR"),
    ],
}


def add_missing_columns(engine: Engine) -> list[str]:
    """Add any listed column a table lacks; return the ones added as table.column."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    added: list[str] = []
    with engine.begin() as connection:
        for table, columns in ADDED_COLUMNS.items():
            if table not in tables:
                continue  # create_all makes it with every column
            present = {column["name"] for column in inspector.get_columns(table)}
            for name, sql_type in columns:
                if name in present:
                    continue
                # Names come from ADDED_COLUMNS above, never from input.
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
                added.append(f"{table}.{name}")
    if added:
        logger.info("Added columns to existing tables: %s", ", ".join(added))
    return added
