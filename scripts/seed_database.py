"""
Database Seed Script for Multi-Tenancy.

Creates a demo organization with an API key for testing.
"""

from sqlmodel import Session, select
from qwed_new.core.database import engine, create_db_and_tables
from qwed_new.core.models import Organization, ApiKey, ResourceQuota
from qwed_new.core.key_rotation import key_manager

def seed_database():
    """
    Seed the database with demo data.
    """
    create_db_and_tables()
    
    with Session(engine) as session:
        # Check if demo org already exists
        statement = select(Organization).where(Organization.name == "demo_org")
        existing_org = session.exec(statement).first()
        
        if existing_org:
            print("✅ Demo organization already exists")
            print(f"   Organization: {existing_org.display_name}")
            
            # Get API key
            api_key_stmt = select(ApiKey).where(
                ApiKey.organization_id == existing_org.id,
                ApiKey.is_active == True
            )
            api_key = session.exec(api_key_stmt).first()
            if api_key:
                print(f"   API Key Preview: {api_key.key_preview}")
                print(f"   (Full key was shown during creation)")
            return
        
        # Create demo organization
        demo_org = Organization(
            name="demo_org",
            display_name="Demo Organization",
            tier="pro",
            is_active=True
        )
        session.add(demo_org)
        session.commit()
        session.refresh(demo_org)
        
        # Create API key using KeyManager
        api_key_obj, raw_api_key = key_manager.create_key(
            organization_id=demo_org.id,
            name="Demo API Key",
            expires_in_days=90
        )
        
        # Create resource quota
        quota = ResourceQuota(
            organization_id=demo_org.id,
            max_requests_per_day=10000,
            max_requests_per_minute=100,
            max_concurrent_requests=20
        )
        session.add(quota)
        
        session.commit()
        
        print("✅ Database seeded successfully!")
        print(f"   Organization: {demo_org.display_name}")
        print(f"   API Key: {raw_api_key}")
        print(f"   Key Expires: {api_key_obj.expires_at}")
        print(f"   Tier: {demo_org.tier}")
        print(f"\n   Use this in your requests:")
        print(f"   curl -H 'x-api-key: {raw_api_key}' http://13.71.22.94:8000/verify/natural_language")

if __name__ == "__main__":
    seed_database()
