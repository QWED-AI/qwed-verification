import sqlite3
import os

# Connect to the database
db_path = "qwed_new/src/qwed_v2.db"
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    # Check if column exists
    cursor.execute("PRAGMA table_info(user)")
    columns = [info[1] for info in cursor.fetchall()]
    print(f"Current columns in 'user': {columns}")

    if "role" not in columns:
        print("⚠️ 'role' column missing. Adding it now...")
        cursor.execute("ALTER TABLE user ADD COLUMN role VARCHAR DEFAULT 'member'")
        conn.commit()
        print("✅ 'role' column added successfully.")
    else:
        print("✅ 'role' column already exists.")

except Exception as e:
    print(f"❌ Error: {e}")
finally:
    conn.close()
