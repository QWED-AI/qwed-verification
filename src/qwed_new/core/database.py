import logging
import os

from sqlmodel import SQLModel, create_engine, Session

logger = logging.getLogger(__name__)

# SQLite for Dev, Postgres for Prod
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qwed.db")

# check_same_thread=False is needed for SQLite with FastAPI
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
logger.debug("DATABASE_URL=%s", DATABASE_URL)
logger.debug("CWD=%s", os.getcwd())
logger.debug("Absolute DB Path=%s", os.path.abspath("qwed.db"))

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
