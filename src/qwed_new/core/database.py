import logging
import os
from pathlib import Path

from sqlalchemy.exc import ArgumentError
from sqlalchemy.engine.url import make_url
from sqlmodel import SQLModel, create_engine, Session

from qwed_new.core.url_safety import sanitize_url

logger = logging.getLogger(__name__)

# SQLite for Dev, Postgres for Prod
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qwed.db")

# check_same_thread=False is needed for SQLite with FastAPI
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

parsed_db_url = None
engine = create_engine(DATABASE_URL, connect_args=connect_args)
try:
    parsed_db_url = make_url(DATABASE_URL)
except (ArgumentError, ValueError, TypeError):
    parsed_db_url = None
# Redact the password before logging (#228): shared with redis_config so the
# rule lives in one place.
logger.debug("DATABASE_URL=%s", sanitize_url(DATABASE_URL))
if parsed_db_url is not None and parsed_db_url.drivername.startswith("sqlite"):
    logger.debug("SQLite database file=%s", Path(parsed_db_url.database or "").name)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
