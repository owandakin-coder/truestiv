from app.core.database import engine
from sqlalchemy import text

print("Resetting database...")

with engine.connect() as conn:
    try:
        conn.execute(text("DROP DATABASE IF EXISTS trustguard"))
        conn.commit()
        print("Database dropped successfully!")
    except Exception as e:
        print(f"Error: {e}")

print("Done!")