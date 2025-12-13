from sqlmodel import SQLModel, create_engine, Session
import os

# SQLite for Dev, Postgres for Prod
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qwed.db")

# check_same_thread=False is needed for SQLite with FastAPI
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
print(f"DEBUG: DATABASE_URL={DATABASE_URL}")
print(f"DEBUG: CWD={os.getcwd()}")
print(f"DEBUG: Absolute DB Path={os.path.abspath('qwed.db')}")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
