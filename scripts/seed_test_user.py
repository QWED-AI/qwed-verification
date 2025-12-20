"""
Seed a test user into QWED auth database.
For development only.
"""
import sys
sys.path.insert(0, 'src')

from qwed_new.auth.database import create_organization, create_user
from qwed_new.auth.security import hash_password

def seed_test_user():
    """Create a test user for development."""
    print("🌱 Seeding test user...")
    
    # Create test organization
    org = create_organization(name="Test Organization")
    print(f"✓ Created organization: {org['name']} (ID: {org['id']})")
    
    # Create test user
    user = create_user(
        email="test@email.com",
        password_hash=hash_password("test@123"),
        org_id=org["id"],
        role="owner"
    )
    print(f"✓ Created user: {user['email']}")
    print(f"  Password: test@123")
    print(f"  Role: {user['role']}")
    
    print("\n✅ Seed complete! You can now sign in with:")
    print("   Email: test@email.com")
    print("   Password: test@123")

if __name__ == "__main__":
    seed_test_user()
