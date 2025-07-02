import os
import mimetypes
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from docx import Document
from functools import wraps
import subprocess
import pyautogui
import logging

app = Flask(__name__, instance_relative_config=True)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')

# Session Configuration
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB file upload limit

# Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'database.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Ensure directories exist
os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
os.makedirs(os.path.join(basedir, 'uploads'), exist_ok=True)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Hashed password
    role = db.Column(db.String(10), nullable=False)  # 'admin' or 'user'

# Initialize DB & Create Admin User
with app.app_context():
    db.create_all()
    if not User.query.filter_by(role="admin").first():
        hashed_password = generate_password_hash("admin123", method='pbkdf2:sha256:600000')
        admin = User(username="admin", password=hashed_password, role="admin")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin user created successfully!")

# Login Required Decorator
def login_required(role=None):
    def wrapper(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash("You need to log in first", "warning")
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                abort(403)  # Forbidden
            return func(*args, **kwargs)
        return decorated_function
    return wrapper

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            session.permanent = True  # Make session persistent
            return redirect(url_for('admin_dashboard' if user.role == 'admin' else 'user_dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')
        new_user = User(username=username, password=hashed_password, role="user")
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/admin_dashboard')
@login_required(role="admin")
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/user_dashboard')
@login_required(role="user")
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@login_required()
def upload_file():
    if 'file' not in request.files:
        flash("No file selected!", "warning")
        return redirect(request.referrer)

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        flash("Invalid file type or no file selected!", "danger")
        return redirect(request.referrer)

    # Ensure uploads folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    flash("File uploaded successfully!", "success")
    return redirect(url_for('display_file', filename=filename))

@app.route('/display/<filename>')
@login_required()
def display_file(filename):
    file_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Store the current file type in the session
    session["current_file_type"] = file_ext

    if not os.path.exists(file_path):
        flash("File not found", "danger")
        return redirect(url_for('user_dashboard'))

    try:
        if file_ext == 'txt':
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
            return render_template('display.html', filename=filename, file_type='txt', file_content=content)

        if file_ext in ['pdf', 'png', 'jpg', 'jpeg', 'gif']:
            return render_template('display.html', filename=filename, file_type=file_ext)

        if file_ext in ['doc', 'docx']:
            # Open in Microsoft Word (Windows)
            if os.name == 'nt':
                subprocess.run(['start', 'winword', file_path], shell=True)
            else:
                # Handle other platforms (Linux/macOS)
                subprocess.run(['open', file_path] if os.name == 'posix' else ['xdg-open', file_path], shell=True)
            flash("Document opened in Microsoft Word", "success")
            return redirect(url_for('user_dashboard'))

        if file_ext in ['ppt', 'pptx']:
            # Open in Microsoft PowerPoint (Windows)
            if os.name == 'nt':
                subprocess.run(['start', 'powerpnt', file_path], shell=True)
            else:
                # Handle other platforms (Linux/macOS)
                subprocess.run(['open', file_path] if os.name == 'posix' else ['xdg-open', file_path], shell=True)
            flash("Presentation opened in Microsoft PowerPoint", "success")
            return redirect(url_for('user_dashboard'))

        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

    except Exception as e:
        logging.error(f"Error displaying file: {e}")
        flash(f"Error displaying file: {e}", "danger")
        return redirect(url_for('user_dashboard'))

@app.route('/uploads/<filename>')
@login_required()
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/open_word', methods=['POST'])
def open_word():
    data = request.json
    file_path = data.get("file_path")

    if not file_path:
        return {"status": "error", "message": "No file path provided"}, 400

    try:
        # Open the Word document using the default application
        if os.name == 'nt':  # Windows
            os.startfile(file_path)
        elif os.name == 'posix':  # macOS or Linux
            subprocess.run(['open', file_path] if os.name == 'posix' else ['xdg-open', file_path], shell=True)
        return {"status": "success", "message": "Document opened successfully"}, 200
    except Exception as e:
        return {"status": "error", "message": str(e)}, 500

@app.route('/gesture_action', methods=['POST'])
def gesture_action():
    data = request.json
    gesture = data.get("gesture")

    if not gesture:
        return {"status": "error", "message": "No gesture provided"}, 400

    # Get the current file type from the session
    current_file_type = session.get("current_file_type")

    # Perform actions based on the file type and gesture
    if current_file_type == "pdf":
        if gesture == "zoom_in":
            pyautogui.hotkey('ctrl', '+')
        elif gesture == "zoom_out":
            pyautogui.hotkey('ctrl', '-')
        elif gesture == "scroll_up":
            pyautogui.scroll(100)
        elif gesture == "scroll_down":
            pyautogui.scroll(-100)
        elif gesture == "previous_page":
            pyautogui.press('left')
        elif gesture == "next_page":
            pyautogui.press('right')

    elif current_file_type in ["doc", "docx"]:
        if gesture == "zoom_in":
            pyautogui.hotkey('ctrl', '+')
        elif gesture == "zoom_out":
            pyautogui.hotkey('ctrl', '-')
        elif gesture == "scroll_up":
            pyautogui.scroll(100)
        elif gesture == "scroll_down":
            pyautogui.scroll(-100)
        elif gesture == "previous_page":
            pyautogui.press('pageup')
        elif gesture == "next_page":
            pyautogui.press('pagedown')

    elif current_file_type in ["ppt", "pptx"]:
        if gesture == "zoom_in":
            pyautogui.hotkey('ctrl', '+')
        elif gesture == "zoom_out":
            pyautogui.hotkey('ctrl', '-')
        elif gesture == "previous_page":
            pyautogui.press('left')
        elif gesture == "next_page":
            pyautogui.press('right')

    return {"status": "success", "gesture": gesture}, 200

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', 'True') == 'True+')