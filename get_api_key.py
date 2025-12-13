from sqlmodel import Session, select
from qwed_new.core.database import engine
from qwed_new.core.models import ApiKey

def get_key():
    with Session(engine) as session:
        statement = select(ApiKey).where(ApiKey.is_active == True)
        result = session.exec(statement).first()
        if result:
            print(f"API_KEY={result.key}")
        else:
            print("No API key found")

if __name__ == "__main__":
    get_key()
