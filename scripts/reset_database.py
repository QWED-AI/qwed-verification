"""
Database Reset and Migration Script.

Drops all tables and recreates them with the new multi-tenancy schema.
"""

from sqlmodel import SQLModel
from qwed_new.core.database import engine

def reset_database():
    """
    Drop all tables and recreate them.
    """
    print("⚠️  Warning: This will delete all existing data!")
    
    # Drop all tables
    print("🗑️  Dropping all tables...")
    SQLModel.metadata.drop_all(engine)
    
    # Create all tables with new schema
    print("🔨 Creating tables with new schema...")
    SQLModel.metadata.create_all(engine)
    
    print("✅ Database reset complete!")
    print("\nNew tables created:")
    print("  - organization")
    print("  - user")
    print("  - apikey")
    print("  - resourcequota")
    print("  - verificationlog")
    print("  - agent (NEW - Phase 2)")
    print("  - agentpermission (NEW - Phase 2)")
    print("  - agentactivity (NEW - Phase 2)")
    print("  - toolcall (NEW - Phase 2)")
    
    print("\n💡 Run 'python seed_database.py' to add demo data.")

if __name__ == "__main__":
    reset_database()
