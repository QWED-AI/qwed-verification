import logging
import os

from sqlalchemy.engine.url import make_url
from sqlmodel import SQLModel, create_engine, Session

logger = logging.getLogger(__name__)

# SQLite for Dev, Postgres for Prod
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qwed.db")

# check_same_thread=False is needed for SQLite with FastAPI
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
try:
    safe_db_url = make_url(DATABASE_URL).render_as_string(hide_password=True)
except Exception:
    safe_db_url = "<invalid DATABASE_URL>"
logger.debug("DATABASE_URL=%s", safe_db_url)
if "sqlite" in DATABASE_URL:
    logger.debug("SQLite database file=%s", os.path.basename("qwed.db"))

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
