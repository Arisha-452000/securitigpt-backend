from app.database import SessionLocal, engine
from app import models
from app.main import get_password_hash

# Create tables
models.Base.metadata.create_all(bind=engine)

# Create admin user
db = SessionLocal()
try:
    # Check if admin already exists
    existing_admin = db.query(models.User).filter(models.User.email == "admin@securitigpt.com").first()
    if existing_admin:
        print("Admin user already exists!")
    else:
        # Create admin user
        admin_user = models.User(
            email="admin@securitigpt.com",
            password_hash=get_password_hash("admin123"),
            credits=999999
        )
        db.add(admin_user)
        db.commit()
        print("Admin user created successfully!")
        print("Email: admin@securitigpt.com")
        print("Password: admin123")
    
    # List all users
    users = db.query(models.User).all()
    print(f"\nTotal users in database: {len(users)}")
    for user in users:
        print(f"- {user.email}: {user.credits} credits")
        
except Exception as e:
    print(f"Error: {e}")
finally:
    db.close()
