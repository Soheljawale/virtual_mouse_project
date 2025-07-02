from app import app, db, User  # Import `app` along with `db` and `User`
from werkzeug.security import generate_password_hash

# Use `app.app_context()` directly
with app.app_context():
    existing_admin = User.query.filter_by(username="admin").first()
    if existing_admin:
        print("⚠️ Admin user already exists!")
    else:
        hashed_password = generate_password_hash("admin123", method='pbkdf2:sha256')
        admin = User(username="admin", password=hashed_password, role="admin")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created successfully!")
