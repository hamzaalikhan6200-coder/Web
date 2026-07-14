import os
import sqlite3
import datetime
import hashlib
import random
import string
import json
import time
import uuid
import shutil
import subprocess
from functools import wraps
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, send_from_directory, jsonify, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Try to import psutil, fallback if not installed
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

# =========================
# APP INITIALIZATION
# =========================
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=32)))
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['THUMBNAIL_FOLDER'] = 'thumbnails'
app.config['BACKUP_FOLDER'] = 'backups'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'mkv', 'avi', 'mov', 'webm'}

# =========================
# AUTO-CREATE FOLDERS
# =========================
for folder in [app.config['UPLOAD_FOLDER'], app.config['THUMBNAIL_FOLDER'], app.config['BACKUP_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

# =========================
# DATABASE SETUP
# =========================
DATABASE = 'portal.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                full_name TEXT,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_count INTEGER DEFAULT 0
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                filename TEXT NOT NULL,
                thumbnail TEXT,
                category TEXT,
                views INTEGER DEFAULT 0,
                uploaded_by INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS watch_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                video_id INTEGER,
                watched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                progress INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (video_id) REFERENCES videos (id)
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                success INTEGER DEFAULT 0
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        # Insert default admin if not exists
        admin = db.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            hashed = generate_password_hash('admin123')
            db.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                       ('admin', hashed, 1))
        # Insert default settings
        defaults = {
            'site_name': 'Premium Video Portal',
            'primary_color': '#6C63FF',
            'accent_color': '#FF6584',
            'maintenance_mode': '0',
            'welcome_banner': 'Welcome to our premium video portal!',
            'contact_info': 'https://t.me/SIDDHARTHHH'
        }
        for key, val in defaults.items():
            db.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, val))
        db.commit()

init_db()

# =========================
# HELPER FUNCTIONS
# =========================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_setting(key):
    db = get_db()
    row = db.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    db.close()
    return row['value'] if row else None

def set_setting(key, value):
    db = get_db()
    db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    db.commit()
    db.close()

def is_maintenance():
    return get_setting('maintenance_mode') == '1'

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        if is_maintenance() and not session.get('is_admin'):
            flash('Site is under maintenance. Please try again later.', 'danger')
            return redirect(url_for('logout'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def generate_random_username():
    adjectives = ['Swift', 'Brave', 'Mighty', 'Fierce', 'Lucky', 'Golden', 'Silent', 'Rapid', 'Noble', 'Epic']
    nouns = ['Tiger', 'Eagle', 'Shark', 'Wolf', 'Phoenix', 'Dragon', 'Falcon', 'Panther', 'Viper', 'Knight']
    return random.choice(adjectives) + random.choice(nouns) + str(random.randint(10, 99))

def generate_secure_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

def log_audit(user_id, action, details=''):
    db = get_db()
    db.execute('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
               (user_id, action, details))
    db.commit()
    db.close()

def log_login(user_id, ip, user_agent, success):
    db = get_db()
    db.execute('INSERT INTO login_history (user_id, ip_address, user_agent, success) VALUES (?, ?, ?, ?)',
               (user_id, ip, user_agent, success))
    db.commit()
    db.close()

def get_user_by_id(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()
    return user

def get_user_by_username(username):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    db.close()
    return user

def get_total_users():
    db = get_db()
    count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    db.close()
    return count

def get_online_users():
    # Simple approximation: users with a session in the last 15 minutes
    # We'll use a simple session tracking via a table; for now return 0
    return 0

def get_offline_users():
    total = get_total_users()
    online = get_online_users()
    return total - online

def get_total_videos():
    db = get_db()
    count = db.execute('SELECT COUNT(*) FROM videos').fetchone()[0]
    db.close()
    return count

def get_today_views():
    db = get_db()
    today = datetime.date.today().isoformat()
    row = db.execute('SELECT SUM(views) FROM videos WHERE date(uploaded_at) = ?', (today,)).fetchone()
    db.close()
    return row[0] or 0

def get_monthly_views():
    db = get_db()
    now = datetime.datetime.now()
    first_day = now.replace(day=1).date().isoformat()
    row = db.execute('SELECT SUM(views) FROM videos WHERE date(uploaded_at) >= ?', (first_day,)).fetchone()
    db.close()
    return row[0] or 0

def get_storage_usage():
    total = 0
    upload_folder = app.config['UPLOAD_FOLDER']
    if os.path.exists(upload_folder):
        for f in os.listdir(upload_folder):
            path = os.path.join(upload_folder, f)
            if os.path.isfile(path):
                total += os.path.getsize(path)
    return total

def get_server_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            uptime_string = str(datetime.timedelta(seconds=uptime_seconds)).split('.')[0]
            return uptime_string
    except:
        return "N/A"

def get_ram_usage():
    if PSUTIL_AVAILABLE:
        mem = psutil.virtual_memory()
        return mem.percent
    return 0

def get_cpu_usage():
    if PSUTIL_AVAILABLE:
        return psutil.cpu_percent(interval=0.1)
    return 0

def get_disk_usage():
    if PSUTIL_AVAILABLE:
        disk = psutil.disk_usage('/')
        return disk.percent
    return 0

def get_network_speed():
    # Placeholder
    return {'upload': 0, 'download': 0}

# =========================
# TEMPLATES (Embedded)
# =========================
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ site_name }} - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .glass-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border-radius: 30px;
            border: 1px solid rgba(255,255,255,0.15);
            box-shadow: 0 25px 50px rgba(0,0,0,0.5);
            padding: 40px;
            width: 100%;
            max-width: 450px;
            animation: float 6s ease-in-out infinite;
        }
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
            100% { transform: translateY(0px); }
        }
        .login-title {
            color: #fff;
            font-weight: 700;
            font-size: 2rem;
            text-align: center;
            margin-bottom: 10px;
        }
        .login-subtitle {
            color: rgba(255,255,255,0.7);
            text-align: center;
            margin-bottom: 30px;
        }
        .form-control {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            color: #fff;
            padding: 12px 20px;
            border-radius: 50px;
            transition: all 0.3s;
        }
        .form-control:focus {
            background: rgba(255,255,255,0.1);
            border-color: #6C63FF;
            box-shadow: 0 0 20px rgba(108, 99, 255, 0.3);
            color: #fff;
        }
        .form-control::placeholder {
            color: rgba(255,255,255,0.5);
        }
        .btn-primary {
            background: linear-gradient(135deg, #6C63FF, #FF6584);
            border: none;
            padding: 12px;
            border-radius: 50px;
            font-weight: 600;
            width: 100%;
            transition: all 0.3s;
        }
        .btn-primary:hover {
            transform: scale(1.02);
            box-shadow: 0 10px 30px rgba(108, 99, 255, 0.4);
        }
        .contact-btn {
            background: rgba(255,255,255,0.05);
            border: 2px solid #FF6584;
            color: #fff;
            padding: 12px;
            border-radius: 50px;
            width: 100%;
            font-weight: 600;
            transition: all 0.3s;
            text-decoration: none;
            display: block;
            text-align: center;
            margin-top: 15px;
        }
        .contact-btn:hover {
            background: #FF6584;
            color: #fff;
            transform: scale(1.02);
            box-shadow: 0 10px 30px rgba(255, 101, 132, 0.3);
        }
        .invite-only {
            text-align: center;
            color: rgba(255,255,255,0.6);
            font-size: 0.9rem;
            margin-top: 20px;
        }
        .invite-only i {
            color: #FF6584;
            margin-right: 5px;
        }
        .alert {
            border-radius: 50px;
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            color: #fff;
        }
        .alert-danger {
            border-color: #FF6584;
        }
        .alert-success {
            border-color: #6C63FF;
        }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 50px;
            padding: 10px 15px;
            color: #fff;
            cursor: pointer;
            transition: all 0.3s;
        }
        .theme-toggle:hover {
            background: rgba(255,255,255,0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-12 col-md-8 col-lg-5">
                <div class="glass-card">
                    <div class="login-title">
                        <i class="fas fa-video" style="color: #FF6584;"></i> {{ site_name }}
                    </div>
                    <div class="login-subtitle">
                        <i class="fas fa-lock" style="color: #FF6584;"></i> Private Access Only
                    </div>
                    <p class="invite-only">
                        This website is invite-only.<br>
                        To obtain a Username and Password, contact the Administrator.
                    </p>
                    <a href="{{ contact_link }}" target="_blank" class="contact-btn">
                        <i class="fab fa-telegram-plane"></i> Contact to Buy Access
                    </a>
                    <hr style="border-color: rgba(255,255,255,0.1);">
                    <form method="POST" action="{{ url_for('login') }}">
                        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                        <div class="mb-3">
                            <input type="text" class="form-control" name="username" placeholder="Username" required>
                        </div>
                        <div class="mb-3">
                            <input type="password" class="form-control" name="password" placeholder="Password" required>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-sign-in-alt"></i> Login
                        </button>
                    </form>
                    {% with messages = get_flashed_messages(with_categories=true) %}
                        {% if messages %}
                            {% for category, message in messages %}
                                <div class="alert alert-{{ category }} mt-3">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

# Admin layout with a placeholder for content
ADMIN_LAYOUT = '''
<!DOCTYPE html>
<html lang="en" data-bs-theme="{{ theme }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ site_name }} - Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: {{ primary_color }};
            --accent: {{ accent_color }};
            --bg-dark: #0a0a1a;
            --glass-bg: rgba(255,255,255,0.05);
            --glass-border: rgba(255,255,255,0.1);
            --text-light: #f0f0f0;
            --text-muted: #aaa;
        }
        body {
            background: var(--bg-dark);
            color: var(--text-light);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .sidebar {
            position: fixed;
            top: 0;
            left: 0;
            height: 100vh;
            width: 260px;
            background: rgba(10,10,30,0.9);
            backdrop-filter: blur(20px);
            border-right: 1px solid var(--glass-border);
            padding-top: 20px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar-brand {
            text-align: center;
            padding: 20px 0;
            font-size: 1.5rem;
            font-weight: 700;
            color: #fff;
            border-bottom: 1px solid var(--glass-border);
            margin-bottom: 20px;
        }
        .sidebar-brand i {
            color: var(--accent);
        }
        .sidebar-menu {
            list-style: none;
            padding: 0;
        }
        .sidebar-menu li {
            padding: 12px 25px;
            margin: 5px 15px;
            border-radius: 15px;
            transition: all 0.3s;
            cursor: pointer;
        }
        .sidebar-menu li a {
            color: var(--text-muted);
            text-decoration: none;
            display: block;
            font-weight: 500;
        }
        .sidebar-menu li a i {
            margin-right: 15px;
            width: 20px;
            text-align: center;
        }
        .sidebar-menu li:hover, .sidebar-menu li.active {
            background: rgba(108,99,255,0.2);
        }
        .sidebar-menu li:hover a, .sidebar-menu li.active a {
            color: #fff;
        }
        .main-content {
            margin-left: 260px;
            padding: 30px;
            min-height: 100vh;
        }
        .stats-card {
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 20px;
            transition: all 0.3s;
            height: 100%;
        }
        .stats-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.3);
        }
        .stats-icon {
            font-size: 2.5rem;
            color: var(--accent);
            opacity: 0.8;
        }
        .stats-number {
            font-size: 2rem;
            font-weight: 700;
            margin: 10px 0 5px;
        }
        .stats-label {
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        .glass-card {
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 20px;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border: none;
        }
        .btn-primary:hover {
            transform: scale(1.02);
            box-shadow: 0 10px 30px rgba(108,99,255,0.3);
        }
        .table {
            color: var(--text-light);
        }
        .table th {
            border-bottom: 1px solid var(--glass-border);
            color: var(--text-muted);
        }
        .table td {
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .table-hover tbody tr:hover {
            background: rgba(255,255,255,0.05);
        }
        .badge {
            padding: 6px 12px;
            border-radius: 50px;
        }
        .theme-toggle {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 999;
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 50px;
            padding: 10px 18px;
            color: #fff;
            cursor: pointer;
        }
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
        }
        .toast {
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            color: #fff;
        }
        .video-thumb {
            width: 120px;
            height: 80px;
            object-fit: cover;
            border-radius: 10px;
        }
        .neon-glow {
            text-shadow: 0 0 10px var(--accent), 0 0 20px var(--accent);
        }
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                height: auto;
                position: relative;
                border-right: none;
                border-bottom: 1px solid var(--glass-border);
            }
            .main-content {
                margin-left: 0;
                padding: 15px;
            }
        }
        .skeleton {
            background: linear-gradient(90deg, var(--glass-bg) 25%, rgba(255,255,255,0.1) 50%, var(--glass-bg) 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: 10px;
        }
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--bg-dark);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 99999;
            transition: opacity 0.5s;
        }
        .loading-overlay.hidden {
            opacity: 0;
            pointer-events: none;
        }
        .spinner-border {
            color: var(--accent);
        }
    </style>
</head>
<body>
    <div class="loading-overlay" id="loadingOverlay">
        <div class="text-center">
            <div class="spinner-border" style="width: 4rem; height: 4rem;" role="status"></div>
            <p class="mt-3">Loading...</p>
        </div>
    </div>

    <div class="sidebar">
        <div class="sidebar-brand">
            <i class="fas fa-film"></i> {{ site_name }}
        </div>
        <ul class="sidebar-menu">
            <li class="{% if active == 'dashboard' %}active{% endif %}"><a href="{{ url_for('admin_dashboard') }}"><i class="fas fa-tachometer-alt"></i> Dashboard</a></li>
            <li class="{% if active == 'users' %}active{% endif %}"><a href="{{ url_for('admin_users') }}"><i class="fas fa-users"></i> Users</a></li>
            <li class="{% if active == 'videos' %}active{% endif %}"><a href="{{ url_for('admin_videos') }}"><i class="fas fa-video"></i> Videos</a></li>
            <li class="{% if active == 'settings' %}active{% endif %}"><a href="{{ url_for('admin_settings') }}"><i class="fas fa-cog"></i> Settings</a></li>
            <li class="{% if active == 'backup' %}active{% endif %}"><a href="{{ url_for('admin_backup') }}"><i class="fas fa-database"></i> Backup</a></li>
            <li class="{% if active == 'activity' %}active{% endif %}"><a href="{{ url_for('admin_activity') }}"><i class="fas fa-history"></i> Activity</a></li>
            <li><a href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
    </div>

    <div class="main-content">
        {{ content|safe }}
    </div>

    <div class="theme-toggle" onclick="toggleTheme()">
        <i class="fas fa-moon" id="themeIcon"></i>
    </div>

    <div class="toast-container" id="toastContainer"></div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        window.addEventListener('load', function() {
            document.getElementById('loadingOverlay').classList.add('hidden');
        });

        function toggleTheme() {
            const html = document.documentElement;
            const icon = document.getElementById('themeIcon');
            if (html.getAttribute('data-bs-theme') === 'dark') {
                html.setAttribute('data-bs-theme', 'light');
                icon.className = 'fas fa-sun';
            } else {
                html.setAttribute('data-bs-theme', 'dark');
                icon.className = 'fas fa-moon';
            }
            fetch('{{ url_for("toggle_theme") }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token }}'
                },
                body: JSON.stringify({ theme: html.getAttribute('data-bs-theme') })
            });
        }

        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast align-items-center text-white bg-${type} border-0 show`;
            toast.role = 'alert';
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">${message}</div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 5000);
        }

        const csrfToken = '{{ csrf_token }}';
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
'''

# Helper to render admin pages
def render_admin_page(content_template, **context):
    # Render the content template with context
    content = render_template_string(content_template, **context)
    # Render the layout with content inserted
    return render_template_string(ADMIN_LAYOUT, content=content, **context)

# =========================
# ROUTES
# =========================

@app.route('/', methods=['GET'])
def index():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if request.form.get('csrf_token') != session.get('csrf_token'):
            flash('Invalid CSRF token.', 'danger')
            return render_template_string(LOGIN_TEMPLATE, site_name=get_setting('site_name'), contact_link=get_setting('contact_info'), csrf_token=session.get('csrf_token', ''))

        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            if user['is_active'] == 0:
                flash('Your account has been disabled. Contact admin.', 'danger')
                return render_template_string(LOGIN_TEMPLATE, site_name=get_setting('site_name'), contact_link=get_setting('contact_info'), csrf_token=session.get('csrf_token', ''))
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            session.permanent = True
            db = get_db()
            db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1 WHERE id = ?', (user['id'],))
            db.commit()
            db.close()
            log_login(user['id'], request.remote_addr, request.headers.get('User-Agent'), 1)
            log_audit(user['id'], 'Login', 'User logged in')
            flash('Welcome back, {}!'.format(user['username']), 'success')
            return redirect(url_for('index'))
        else:
            log_login(None, request.remote_addr, request.headers.get('User-Agent'), 0)
            flash('Invalid username or password.', 'danger')
    session['csrf_token'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return render_template_string(LOGIN_TEMPLATE, site_name=get_setting('site_name'), contact_link=get_setting('contact_info'), csrf_token=session.get('csrf_token', ''))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit(session['user_id'], 'Logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# =========================
# ADMIN ROUTES
# =========================

@app.route('/admin')
@admin_required
def admin_dashboard():
    total_users = get_total_users()
    online_users = get_online_users()
    offline_users = get_offline_users()
    total_videos = get_total_videos()
    today_views = get_today_views()
    monthly_views = get_monthly_views()
    storage_usage = get_storage_usage()
    storage_gb = round(storage_usage / (1024**3), 2)
    uptime = get_server_uptime()
    db = get_db()
    logs = db.execute('''
        SELECT a.*, u.username FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC LIMIT 10
    ''').fetchall()
    db.close()
    # Chart data
    dates = []
    views = []
    for i in range(6, -1, -1):
        d = datetime.date.today() - datetime.timedelta(days=i)
        dates.append(d.strftime('%b %d'))
        db = get_db()
        count = db.execute('SELECT SUM(views) FROM videos WHERE date(uploaded_at) = ?', (d.isoformat(),)).fetchone()[0] or 0
        db.close()
        views.append(count)
    user_dates = []
    user_counts = []
    for i in range(6, -1, -1):
        d = datetime.date.today() - datetime.timedelta(days=i)
        user_dates.append(d.strftime('%b %d'))
        db = get_db()
        count = db.execute('SELECT COUNT(*) FROM users WHERE date(created_at) = ?', (d.isoformat(),)).fetchone()[0]
        db.close()
        user_counts.append(count)

    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'active': 'dashboard',
        'total_users': total_users,
        'online_users': online_users,
        'offline_users': offline_users,
        'total_videos': total_videos,
        'today_views': today_views,
        'monthly_views': monthly_views,
        'storage_usage_gb': storage_gb,
        'uptime': uptime,
        'recent_activity': logs,
        'chart_dates': dates,
        'chart_views': views,
        'user_chart_dates': user_dates,
        'user_chart_counts': user_counts
    }
    dashboard_content = '''
<div class="container-fluid">
    <h1 class="mb-4"><i class="fas fa-tachometer-alt me-2" style="color: var(--accent);"></i>Dashboard</h1>
    <div class="row g-4">
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-users stats-icon"></i></div>
                    <div class="stats-number" id="totalUsers">{{ total_users }}</div>
                </div>
                <div class="stats-label">Total Users</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-circle stats-icon" style="color: #28a745;"></i></div>
                    <div class="stats-number" id="onlineUsers">{{ online_users }}</div>
                </div>
                <div class="stats-label">Online Users</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-circle stats-icon" style="color: #dc3545;"></i></div>
                    <div class="stats-number" id="offlineUsers">{{ offline_users }}</div>
                </div>
                <div class="stats-label">Offline Users</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-video stats-icon"></i></div>
                    <div class="stats-number">{{ total_videos }}</div>
                </div>
                <div class="stats-label">Total Videos</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-eye stats-icon"></i></div>
                    <div class="stats-number">{{ today_views }}</div>
                </div>
                <div class="stats-label">Today's Views</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-calendar-alt stats-icon"></i></div>
                    <div class="stats-number">{{ monthly_views }}</div>
                </div>
                <div class="stats-label">Monthly Views</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-hdd stats-icon"></i></div>
                    <div class="stats-number">{{ storage_usage_gb }} GB</div>
                </div>
                <div class="stats-label">Storage Used</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-microchip stats-icon"></i></div>
                    <div class="stats-number" id="cpuUsage">0%</div>
                </div>
                <div class="stats-label">CPU Usage</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-memory stats-icon"></i></div>
                    <div class="stats-number" id="ramUsage">0%</div>
                </div>
                <div class="stats-label">RAM Usage</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-clock stats-icon"></i></div>
                    <div class="stats-number">{{ uptime }}</div>
                </div>
                <div class="stats-label">Uptime</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-users stats-icon"></i></div>
                    <div class="stats-number" id="activeSessions">0</div>
                </div>
                <div class="stats-label">Active Sessions</div>
            </div>
        </div>
        <div class="col-6 col-md-3">
            <div class="stats-card">
                <div class="d-flex justify-content-between">
                    <div><i class="fas fa-chart-line stats-icon"></i></div>
                    <div class="stats-number">{{ total_videos }}</div>
                </div>
                <div class="stats-label">Total Videos</div>
            </div>
        </div>
    </div>
    <div class="row mt-4">
        <div class="col-md-6">
            <div class="glass-card">
                <h5><i class="fas fa-chart-bar me-2"></i>Views Per Day (Last 7 Days)</h5>
                <canvas id="viewsChart" height="200"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="glass-card">
                <h5><i class="fas fa-user-chart me-2"></i>User Growth</h5>
                <canvas id="usersChart" height="200"></canvas>
            </div>
        </div>
    </div>
    <div class="row mt-4">
        <div class="col-12">
            <div class="glass-card">
                <h5><i class="fas fa-history me-2"></i>Recent Activity</h5>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr><th>User</th><th>Action</th><th>Time</th></tr>
                        </thead>
                        <tbody>
                            {% for log in recent_activity %}
                            <tr>
                                <td>{{ log.username or 'System' }}</td>
                                <td>{{ log.action }}</td>
                                <td>{{ log.timestamp }}</td>
                            </tr>
                            {% else %}
                            <tr><td colspan="3" class="text-center text-muted">No recent activity</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div class="row mt-4">
        <div class="col-12">
            <div class="glass-card">
                <h5><i class="fas fa-bolt me-2"></i>Quick Actions</h5>
                <div class="d-flex flex-wrap gap-2">
                    <a href="{{ url_for('admin_users') }}?action=create" class="btn btn-primary"><i class="fas fa-user-plus"></i> Add User</a>
                    <a href="{{ url_for('admin_videos') }}?action=upload" class="btn btn-primary"><i class="fas fa-upload"></i> Upload Video</a>
                    <a href="{{ url_for('admin_backup') }}" class="btn btn-primary"><i class="fas fa-download"></i> Backup Database</a>
                    <a href="#" onclick="restoreBackup()" class="btn btn-primary"><i class="fas fa-upload"></i> Restore Database</a>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
    function updateStats() {
        fetch('{{ url_for("api_stats") }}')
        .then(res => res.json())
        .then(data => {
            document.getElementById('cpuUsage').textContent = data.cpu + '%';
            document.getElementById('ramUsage').textContent = data.ram + '%';
            document.getElementById('onlineUsers').textContent = data.online_users;
            document.getElementById('offlineUsers').textContent = data.offline_users;
            document.getElementById('activeSessions').textContent = data.active_sessions;
        });
    }
    setInterval(updateStats, 5000);
    const ctxViews = document.getElementById('viewsChart').getContext('2d');
    new Chart(ctxViews, {
        type: 'line',
        data: {
            labels: {{ chart_dates|tojson }},
            datasets: [{
                label: 'Views',
                data: {{ chart_views|tojson }},
                borderColor: '#FF6584',
                backgroundColor: 'rgba(255,101,132,0.2)',
                tension: 0.3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#fff' } }
            },
            scales: {
                y: { ticks: { color: '#aaa' } },
                x: { ticks: { color: '#aaa' } }
            }
        }
    });
    const ctxUsers = document.getElementById('usersChart').getContext('2d');
    new Chart(ctxUsers, {
        type: 'bar',
        data: {
            labels: {{ user_chart_dates|tojson }},
            datasets: [{
                label: 'New Users',
                data: {{ user_chart_counts|tojson }},
                backgroundColor: '#6C63FF',
                borderRadius: 10
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#fff' } }
            },
            scales: {
                y: { ticks: { color: '#aaa' } },
                x: { ticks: { color: '#aaa' } }
            }
        }
    });
    function restoreBackup() {
        if (confirm('This will replace the current database with the backup. Continue?')) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '{{ url_for("admin_backup") }}';
            form.enctype = 'multipart/form-data';
            const input = document.createElement('input');
            input.type = 'file';
            input.name = 'backup_file';
            input.accept = '.db';
            input.onchange = function() {
                form.submit();
            };
            input.click();
        }
    }
</script>
'''
    return render_admin_page(dashboard_content, **context)

@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            username = request.form.get('username')
            password = request.form.get('password')
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            is_admin = 1 if request.form.get('is_admin') else 0
            if get_user_by_username(username):
                flash('Username already exists.', 'danger')
            else:
                hashed = generate_password_hash(password)
                db.execute('INSERT INTO users (username, password, full_name, email, is_admin) VALUES (?, ?, ?, ?, ?)',
                           (username, hashed, full_name, email, is_admin))
                db.commit()
                log_audit(session['user_id'], 'Create User', f'Created user {username}')
                flash(f'User {username} created successfully.', 'success')
        elif action == 'edit':
            user_id = request.form.get('user_id')
            full_name = request.form.get('full_name')
            email = request.form.get('email')
            is_admin = 1 if request.form.get('is_admin') else 0
            is_active = 1 if request.form.get('is_active') else 0
            db.execute('UPDATE users SET full_name=?, email=?, is_admin=?, is_active=? WHERE id=?',
                       (full_name, email, is_admin, is_active, user_id))
            db.commit()
            log_audit(session['user_id'], 'Edit User', f'Edited user ID {user_id}')
            flash('User updated.', 'success')
        elif action == 'delete':
            user_id = request.form.get('user_id')
            if user_id == str(session['user_id']):
                flash('Cannot delete yourself.', 'danger')
            else:
                db.execute('DELETE FROM users WHERE id = ?', (user_id,))
                db.commit()
                log_audit(session['user_id'], 'Delete User', f'Deleted user ID {user_id}')
                flash('User deleted.', 'success')
        elif action == 'reset_password':
            user_id = request.form.get('user_id')
            new_pass = generate_secure_password()
            hashed = generate_password_hash(new_pass)
            db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, user_id))
            db.commit()
            log_audit(session['user_id'], 'Reset Password', f'Reset password for user ID {user_id}')
            flash(f'Password reset. New password: {new_pass}', 'info')
        elif action == 'disable':
            user_id = request.form.get('user_id')
            db.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
            db.commit()
            log_audit(session['user_id'], 'Disable User', f'Disabled user ID {user_id}')
            flash('User disabled.', 'success')
        elif action == 'enable':
            user_id = request.form.get('user_id')
            db.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
            db.commit()
            log_audit(session['user_id'], 'Enable User', f'Enabled user ID {user_id}')
            flash('User enabled.', 'success')
        return redirect(url_for('admin_users'))
    search = request.args.get('search', '')
    if search:
        users = db.execute('SELECT * FROM users WHERE username LIKE ? OR full_name LIKE ?', ('%'+search+'%', '%'+search+'%')).fetchall()
    else:
        users = db.execute('SELECT * FROM users ORDER BY id DESC').fetchall()
    db.close()
    rand_user = generate_random_username()
    rand_pass = generate_secure_password()
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'active': 'users',
        'users': users,
        'rand_user': rand_user,
        'rand_pass': rand_pass,
        'search': search
    }
    content = '''
<div class="container-fluid">
    <h1 class="mb-4"><i class="fas fa-users me-2" style="color: var(--accent);"></i>User Management</h1>
    <div class="row mb-3">
        <div class="col-md-6">
            <form method="GET" class="d-flex">
                <input type="text" name="search" class="form-control me-2" placeholder="Search users..." value="{{ search }}">
                <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i></button>
            </form>
        </div>
        <div class="col-md-6 text-end">
            <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#createUserModal"><i class="fas fa-user-plus"></i> Create User</button>
        </div>
    </div>
    <div class="table-responsive glass-card">
        <table class="table table-hover">
            <thead>
                <tr><th>ID</th><th>Username</th><th>Full Name</th><th>Email</th><th>Admin</th><th>Active</th><th>Created</th><th>Actions</th></tr>
            </thead>
            <tbody>
                {% for user in users %}
                <tr>
                    <td>{{ user.id }}</td>
                    <td>{{ user.username }}</td>
                    <td>{{ user.full_name or '-' }}</td>
                    <td>{{ user.email or '-' }}</td>
                    <td>{% if user.is_admin %}<span class="badge bg-primary">Admin</span>{% else %}<span class="badge bg-secondary">User</span>{% endif %}</td>
                    <td>{% if user.is_active %}<span class="badge bg-success">Active</span>{% else %}<span class="badge bg-danger">Disabled</span>{% endif %}</td>
                    <td>{{ user.created_at[:10] }}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editUserModal{{ user.id }}"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-sm btn-outline-danger" onclick="if(confirm('Delete this user?')){document.getElementById('deleteUser{{ user.id }}').submit();}"><i class="fas fa-trash"></i></button>
                        <form id="deleteUser{{ user.id }}" method="POST" style="display:none;">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="user_id" value="{{ user.id }}">
                        </form>
                        <button class="btn btn-sm btn-outline-warning" onclick="resetPassword({{ user.id }})"><i class="fas fa-key"></i></button>
                        {% if user.is_active %}
                        <button class="btn btn-sm btn-outline-secondary" onclick="disableUser({{ user.id }})"><i class="fas fa-pause"></i></button>
                        {% else %}
                        <button class="btn btn-sm btn-outline-success" onclick="enableUser({{ user.id }})"><i class="fas fa-play"></i></button>
                        {% endif %}
                    </td>
                </tr>
                <div class="modal fade" id="editUserModal{{ user.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content glass-card">
                            <div class="modal-header">
                                <h5 class="modal-title">Edit User {{ user.username }}</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="POST">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="edit">
                                    <input type="hidden" name="user_id" value="{{ user.id }}">
                                    <div class="mb-3">
                                        <label>Full Name</label>
                                        <input type="text" name="full_name" class="form-control" value="{{ user.full_name or '' }}">
                                    </div>
                                    <div class="mb-3">
                                        <label>Email</label>
                                        <input type="email" name="email" class="form-control" value="{{ user.email or '' }}">
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" name="is_admin" {% if user.is_admin %}checked{% endif %}>
                                        <label class="form-check-label">Admin</label>
                                    </div>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" name="is_active" {% if user.is_active %}checked{% endif %}>
                                        <label class="form-check-label">Active</label>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="submit" class="btn btn-primary">Save</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
<div class="modal fade" id="createUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content glass-card">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-user-plus"></i> Create User</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <div class="modal-body">
                    <input type="hidden" name="action" value="create">
                    <div class="mb-3">
                        <label>Username</label>
                        <div class="input-group">
                            <input type="text" name="username" class="form-control" value="{{ rand_user }}" required>
                            <button type="button" class="btn btn-outline-secondary" onclick="document.querySelector('input[name=username]').value='{{ rand_user }}'"><i class="fas fa-sync"></i></button>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label>Password</label>
                        <div class="input-group">
                            <input type="text" name="password" class="form-control" value="{{ rand_pass }}" required>
                            <button type="button" class="btn btn-outline-secondary" onclick="document.querySelector('input[name=password]').value='{{ rand_pass }}'"><i class="fas fa-sync"></i></button>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label>Full Name</label>
                        <input type="text" name="full_name" class="form-control">
                    </div>
                    <div class="mb-3">
                        <label>Email</label>
                        <input type="email" name="email" class="form-control">
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="is_admin">
                        <label class="form-check-label">Admin</label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>
<script>
function resetPassword(userId) {
    if (confirm('Reset password for this user?')) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.innerHTML = `<input type="hidden" name="action" value="reset_password"><input type="hidden" name="user_id" value="${userId}">`;
        document.body.appendChild(form);
        form.submit();
    }
}
function disableUser(userId) {
    if (confirm('Disable this user?')) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.innerHTML = `<input type="hidden" name="action" value="disable"><input type="hidden" name="user_id" value="${userId}">`;
        document.body.appendChild(form);
        form.submit();
    }
}
function enableUser(userId) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.innerHTML = `<input type="hidden" name="action" value="enable"><input type="hidden" name="user_id" value="${userId}">`;
    document.body.appendChild(form);
    form.submit();
}
</script>
'''
    return render_admin_page(content, **context)

@app.route('/admin/videos', methods=['GET', 'POST'])
@admin_required
def admin_videos():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'upload':
            if 'video' not in request.files:
                flash('No file uploaded.', 'danger')
                return redirect(url_for('admin_videos'))
            file = request.files['video']
            if file.filename == '':
                flash('No file selected.', 'danger')
                return redirect(url_for('admin_videos'))
            if not allowed_file(file.filename):
                flash('File type not allowed.', 'danger')
                return redirect(url_for('admin_videos'))
            filename = secure_filename(file.filename)
            unique_name = str(uuid.uuid4()) + '_' + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
            file.save(filepath)
            title = request.form.get('title')
            description = request.form.get('description')
            category = request.form.get('category')
            thumbnail = None
            if 'thumbnail' in request.files and request.files['thumbnail'].filename != '':
                thumb_file = request.files['thumbnail']
                if thumb_file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    thumb_name = str(uuid.uuid4()) + '_' + secure_filename(thumb_file.filename)
                    thumb_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_name)
                    thumb_file.save(thumb_path)
                    thumbnail = thumb_name
            db.execute('INSERT INTO videos (title, description, filename, thumbnail, category, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)',
                       (title, description, unique_name, thumbnail, category, session['user_id']))
            db.commit()
            log_audit(session['user_id'], 'Upload Video', f'Uploaded video "{title}"')
            flash('Video uploaded successfully.', 'success')
        elif action == 'delete':
            video_id = request.form.get('video_id')
            video = db.execute('SELECT filename, thumbnail FROM videos WHERE id = ?', (video_id,)).fetchone()
            if video:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], video['filename']))
                except:
                    pass
                if video['thumbnail']:
                    try:
                        os.remove(os.path.join(app.config['THUMBNAIL_FOLDER'], video['thumbnail']))
                    except:
                        pass
                db.execute('DELETE FROM videos WHERE id = ?', (video_id,))
                db.commit()
                log_audit(session['user_id'], 'Delete Video', f'Deleted video ID {video_id}')
                flash('Video deleted.', 'success')
        elif action == 'edit':
            video_id = request.form.get('video_id')
            title = request.form.get('title')
            description = request.form.get('description')
            category = request.form.get('category')
            db.execute('UPDATE videos SET title=?, description=?, category=? WHERE id=?',
                       (title, description, category, video_id))
            db.commit()
            log_audit(session['user_id'], 'Edit Video', f'Edited video ID {video_id}')
            flash('Video updated.', 'success')
        return redirect(url_for('admin_videos'))
    videos = db.execute('SELECT v.*, u.username FROM videos v LEFT JOIN users u ON v.uploaded_by = u.id ORDER BY v.id DESC').fetchall()
    categories = ['Action', 'Comedy', 'Drama', 'Horror', 'Sci-Fi', 'Documentary', 'Other']
    db.close()
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'active': 'videos',
        'videos': videos,
        'categories': categories
    }
    content = '''
<div class="container-fluid">
    <h1 class="mb-4"><i class="fas fa-video me-2" style="color: var(--accent);"></i>Video Management</h1>
    <button class="btn btn-primary mb-3" data-bs-toggle="modal" data-bs-target="#uploadVideoModal"><i class="fas fa-upload"></i> Upload Video</button>
    <div class="table-responsive glass-card">
        <table class="table table-hover">
            <thead>
                <tr><th>ID</th><th>Thumb</th><th>Title</th><th>Category</th><th>Views</th><th>Uploaded By</th><th>Date</th><th>Actions</th></tr>
            </thead>
            <tbody>
                {% for video in videos %}
                <tr>
                    <td>{{ video.id }}</td>
                    <td>
                        {% if video.thumbnail %}
                        <img src="{{ url_for('serve_thumbnail', filename=video.thumbnail) }}" class="video-thumb">
                        {% else %}
                        <div class="video-thumb bg-secondary d-flex align-items-center justify-content-center"><i class="fas fa-video"></i></div>
                        {% endif %}
                    </td>
                    <td>{{ video.title }}</td>
                    <td>{{ video.category or '-' }}</td>
                    <td>{{ video.views }}</td>
                    <td>{{ video.username or 'Admin' }}</td>
                    <td>{{ video.uploaded_at[:10] }}</td>
                    <td>
                        <button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editVideoModal{{ video.id }}"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-sm btn-outline-danger" onclick="if(confirm('Delete this video?')){document.getElementById('deleteVideo{{ video.id }}').submit();}"><i class="fas fa-trash"></i></button>
                        <form id="deleteVideo{{ video.id }}" method="POST" style="display:none;">
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="video_id" value="{{ video.id }}">
                        </form>
                    </td>
                </tr>
                <div class="modal fade" id="editVideoModal{{ video.id }}" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content glass-card">
                            <div class="modal-header">
                                <h5 class="modal-title">Edit Video</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <form method="POST">
                                <div class="modal-body">
                                    <input type="hidden" name="action" value="edit">
                                    <input type="hidden" name="video_id" value="{{ video.id }}">
                                    <div class="mb-3">
                                        <label>Title</label>
                                        <input type="text" name="title" class="form-control" value="{{ video.title }}" required>
                                    </div>
                                    <div class="mb-3">
                                        <label>Description</label>
                                        <textarea name="description" class="form-control" rows="3">{{ video.description or '' }}</textarea>
                                    </div>
                                    <div class="mb-3">
                                        <label>Category</label>
                                        <select name="category" class="form-select">
                                            <option value="">None</option>
                                            {% for cat in categories %}
                                            <option value="{{ cat }}" {% if video.category == cat %}selected{% endif %}>{{ cat }}</option>
                                            {% endfor %}
                                        </select>
                                    </div>
                                </div>
                                <div class="modal-footer">
                                    <button type="submit" class="btn btn-primary">Update</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
<div class="modal fade" id="uploadVideoModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content glass-card">
            <div class="modal-header">
                <h5 class="modal-title"><i class="fas fa-upload"></i> Upload Video</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" enctype="multipart/form-data">
                <div class="modal-body">
                    <input type="hidden" name="action" value="upload">
                    <div class="mb-3">
                        <label>Title</label>
                        <input type="text" name="title" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label>Description</label>
                        <textarea name="description" class="form-control" rows="3"></textarea>
                    </div>
                    <div class="mb-3">
                        <label>Category</label>
                        <select name="category" class="form-select">
                            <option value="">None</option>
                            {% for cat in categories %}
                            <option value="{{ cat }}">{{ cat }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="mb-3">
                        <label>Video File (MP4, MKV, AVI, MOV, WEBM)</label>
                        <input type="file" name="video" class="form-control" accept=".mp4,.mkv,.avi,.mov,.webm" required>
                    </div>
                    <div class="mb-3">
                        <label>Thumbnail (Optional, PNG/JPG)</label>
                        <input type="file" name="thumbnail" class="form-control" accept=".png,.jpg,.jpeg,.gif">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="submit" class="btn btn-primary">Upload</button>
                </div>
            </form>
        </div>
    </div>
</div>
'''
    return render_admin_page(content, **context)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    if request.method == 'POST':
        for key in ['site_name', 'primary_color', 'accent_color', 'welcome_banner', 'contact_info']:
            val = request.form.get(key)
            if val is not None:
                set_setting(key, val)
        flash('Settings updated.', 'success')
        log_audit(session['user_id'], 'Update Settings', 'Updated website settings')
        return redirect(url_for('admin_settings'))
    settings = {}
    db = get_db()
    rows = db.execute('SELECT * FROM settings').fetchall()
    db.close()
    for row in rows:
        settings[row['key']] = row['value']
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'active': 'settings',
        'settings': settings
    }
    content = '''
<div class="container-fluid">
    <h1 class="mb-4"><i class="fas fa-cog me-2" style="color: var(--accent);"></i>Settings</h1>
    <div class="glass-card">
        <form method="POST">
            <div class="mb-3">
                <label>Site Name</label>
                <input type="text" name="site_name" class="form-control" value="{{ settings.site_name or '' }}">
            </div>
            <div class="mb-3">
                <label>Primary Color</label>
                <input type="color" name="primary_color" class="form-control form-control-color" value="{{ settings.primary_color or '#6C63FF' }}">
            </div>
            <div class="mb-3">
                <label>Accent Color</label>
                <input type="color" name="accent_color" class="form-control form-control-color" value="{{ settings.accent_color or '#FF6584' }}">
            </div>
            <div class="mb-3">
                <label>Welcome Banner</label>
                <textarea name="welcome_banner" class="form-control" rows="3">{{ settings.welcome_banner or '' }}</textarea>
            </div>
            <div class="mb-3">
                <label>Contact Info (Telegram Link)</label>
                <input type="text" name="contact_info" class="form-control" value="{{ settings.contact_info or '' }}">
            </div>
            <button type="submit" class="btn btn-primary">Save Settings</button>
        </form>
    </div>
</div>
'''
    return render_admin_page(content, **context)

@app.route('/admin/backup', methods=['GET', 'POST'])
@admin_required
def admin_backup():
    if request.method == 'POST':
        if 'backup_file' in request.files:
            file = request.files['backup_file']
            if file.filename.endswith('.db'):
                filepath = os.path.join(app.config['BACKUP_FOLDER'], secure_filename(file.filename))
                file.save(filepath)
                shutil.copyfile(filepath, DATABASE)
                flash('Database restored from backup.', 'success')
                log_audit(session['user_id'], 'Restore Database', f'Restored from {file.filename}')
            else:
                flash('Invalid backup file.', 'danger')
        return redirect(url_for('admin_backup'))
    backups = []
    for f in os.listdir(app.config['BACKUP_FOLDER']):
        if f.endswith('.db'):
            path = os.path.join(app.config['BACKUP_FOLDER'], f)
            backups.append({'name': f, 'size': os.path.getsize(path), 'modified': datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M')})
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'active': 'backup',
        'backups': backups
    }
    content = '''
<div class="container-fluid">
    <h1 class="mb-4"><i class="fas fa-database me-2" style="color: var(--accent);"></i>Backup & Restore</h1>
    <div class="row">
        <div class="col-md-6">
            <div class="glass-card">
                <h5>Create Backup</h5>
                <a href="{{ url_for('admin_backup_create') }}" class="btn btn-primary"><i class="fas fa-download"></i> Download Backup</a>
            </div>
        </div>
        <div class="col-md-6">
            <div class="glass-card">
                <h5>Restore Database</h5>
                <form method="POST" enctype="multipart/form-data">
                    <input type="file" name="backup_file" class="form-control mb-2" accept=".db">
                    <button type="submit" class="btn btn-warning"><i class="fas fa-upload"></i> Restore</button>
                </form>
            </div>
        </div>
    </div>
    <div class="row mt-4">
        <div class="col-12">
            <div class="glass-card">
                <h5>Available Backups</h5>
                <ul class="list-group">
                    {% for b in backups %}
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        {{ b.name }}
                        <span>{{ b.size|filesizeformat }} - {{ b.modified }}</span>
                    </li>
                    {% else %}
                    <li class="list-group-item text-muted">No backups found.</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
    </div>
</div>
'''
    return render_admin_page(content, **context)

@app.route('/admin/backup/create')
@admin_required
def admin_backup_create():
    backup_name = f'backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.db'
    backup_path = os.path.join(app.config['BACKUP_FOLDER'], backup_name)
    shutil.copyfile(DATABASE, backup_path)
    log_audit(session['user_id'], 'Create Backup', f'Created backup {backup_name}')
    flash('Backup created successfully.', 'success')
    return send_from_directory(app.config['BACKUP_FOLDER'], backup_name, as_attachment=True)

@app.route('/admin/activity')
@admin_required
def admin_activity():
    db = get_db()
    logs = db.execute('''
        SELECT a.*, u.username FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC LIMIT 100
    ''').fetchall()
    db.close()
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'active': 'activity',
        'logs': logs
    }
    content = '''
<div class="container-fluid">
    <h1 class="mb-4"><i class="fas fa-history me-2" style="color: var(--accent);"></i>Activity Logs</h1>
    <div class="table-responsive glass-card">
        <table class="table table-hover">
            <thead>
                <tr><th>User</th><th>Action</th><th>Details</th><th>Time</th></tr>
            </thead>
            <tbody>
                {% for log in logs %}
                <tr>
                    <td>{{ log.username or 'System' }}</td>
                    <td>{{ log.action }}</td>
                    <td>{{ log.details or '' }}</td>
                    <td>{{ log.timestamp }}</td>
                </tr>
                {% else %}
                <tr><td colspan="4" class="text-center text-muted">No logs found.</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>
'''
    return render_admin_page(content, **context)

# =========================
# USER PAGES
# =========================

@app.route('/user')
@login_required
def user_home():
    if session.get('is_admin'):
        return redirect(url_for('admin_dashboard'))
    db = get_db()
    videos = db.execute('SELECT * FROM videos WHERE is_active=1 ORDER BY uploaded_at DESC').fetchall()
    continue_watching = db.execute('''
        SELECT v.*, w.progress FROM watch_history w
        JOIN videos v ON w.video_id = v.id
        WHERE w.user_id = ?
        ORDER BY w.watched_at DESC LIMIT 10
    ''', (session['user_id'],)).fetchall()
    db.close()
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'videos': videos,
        'continue_watching': continue_watching,
        'username': session.get('username')
    }
    return render_template_string('''
<!DOCTYPE html>
<html lang="en" data-bs-theme="{{ theme }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ site_name }} - Home</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: {{ primary_color }};
            --accent: {{ accent_color }};
            --bg-dark: #0a0a1a;
            --glass-bg: rgba(255,255,255,0.05);
            --glass-border: rgba(255,255,255,0.1);
            --text-light: #f0f0f0;
            --text-muted: #aaa;
        }
        body {
            background: var(--bg-dark);
            color: var(--text-light);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .navbar {
            background: rgba(10,10,30,0.8);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--glass-border);
        }
        .video-card {
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            overflow: hidden;
            transition: all 0.3s;
            cursor: pointer;
            height: 100%;
        }
        .video-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.3);
        }
        .video-card img {
            width: 100%;
            height: 180px;
            object-fit: cover;
        }
        .video-card .card-body {
            padding: 15px;
        }
        .video-card .card-title {
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 5px;
        }
        .video-card .card-text {
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        .progress-bar-custom {
            height: 4px;
            background: var(--glass-border);
            border-radius: 10px;
            margin-top: 10px;
            overflow: hidden;
        }
        .progress-bar-custom .progress-fill {
            height: 100%;
            background: var(--accent);
            border-radius: 10px;
        }
        .theme-toggle {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 999;
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 50px;
            padding: 10px 18px;
            color: #fff;
            cursor: pointer;
        }
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
        }
        .toast {
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            color: #fff;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg">
        <div class="container-fluid">
            <a class="navbar-brand text-white" href="#"><i class="fas fa-film" style="color: var(--accent);"></i> {{ site_name }}</a>
            <div class="ms-auto d-flex align-items-center">
                <span class="text-light me-3"><i class="fas fa-user"></i> {{ username }}</span>
                <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% if continue_watching %}
        <h4 class="mb-3"><i class="fas fa-clock me-2" style="color: var(--accent);"></i>Continue Watching</h4>
        <div class="row g-4 mb-5">
            {% for video in continue_watching %}
            <div class="col-6 col-md-3">
                <div class="video-card" onclick="location.href='{{ url_for('watch_video', video_id=video.id) }}'">
                    {% if video.thumbnail %}
                    <img src="{{ url_for('serve_thumbnail', filename=video.thumbnail) }}" class="card-img-top" alt="{{ video.title }}">
                    {% else %}
                    <div class="bg-secondary d-flex align-items-center justify-content-center" style="height:180px;"><i class="fas fa-video fa-3x text-muted"></i></div>
                    {% endif %}
                    <div class="card-body">
                        <div class="card-title">{{ video.title }}</div>
                        <div class="card-text">{{ video.category or 'General' }}</div>
                        <div class="progress-bar-custom">
                            <div class="progress-fill" style="width: {{ (video.progress / 100)|default(0) }}%;"></div>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <h4 class="mb-3"><i class="fas fa-fire me-2" style="color: var(--accent);"></i>Recently Added</h4>
        <div class="row g-4">
            {% for video in videos %}
            <div class="col-6 col-md-3">
                <div class="video-card" onclick="location.href='{{ url_for('watch_video', video_id=video.id) }}'">
                    {% if video.thumbnail %}
                    <img src="{{ url_for('serve_thumbnail', filename=video.thumbnail) }}" class="card-img-top" alt="{{ video.title }}">
                    {% else %}
                    <div class="bg-secondary d-flex align-items-center justify-content-center" style="height:180px;"><i class="fas fa-video fa-3x text-muted"></i></div>
                    {% endif %}
                    <div class="card-body">
                        <div class="card-title">{{ video.title }}</div>
                        <div class="card-text">{{ video.category or 'General' }}</div>
                        <div class="card-text small"><i class="fas fa-eye"></i> {{ video.views }}</div>
                    </div>
                </div>
            </div>
            {% else %}
            <div class="col-12 text-center text-muted">No videos available.</div>
            {% endfor %}
        </div>
    </div>

    <div class="theme-toggle" onclick="toggleTheme()">
        <i class="fas fa-moon" id="themeIcon"></i>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleTheme() {
            const html = document.documentElement;
            const icon = document.getElementById('themeIcon');
            if (html.getAttribute('data-bs-theme') === 'dark') {
                html.setAttribute('data-bs-theme', 'light');
                icon.className = 'fas fa-sun';
            } else {
                html.setAttribute('data-bs-theme', 'dark');
                icon.className = 'fas fa-moon';
            }
            fetch('{{ url_for("toggle_theme") }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token }}'
                },
                body: JSON.stringify({ theme: html.getAttribute('data-bs-theme') })
            });
        }
    </script>
</body>
</html>
    ''', **context)

@app.route('/watch/<int:video_id>')
@login_required
def watch_video(video_id):
    db = get_db()
    video = db.execute('SELECT * FROM videos WHERE id = ? AND is_active=1', (video_id,)).fetchone()
    if not video:
        flash('Video not found.', 'danger')
        return redirect(url_for('user_home'))
    db.execute('UPDATE videos SET views = views + 1 WHERE id = ?', (video_id,))
    db.commit()
    progress = db.execute('SELECT progress FROM watch_history WHERE user_id = ? AND video_id = ? ORDER BY watched_at DESC LIMIT 1',
                          (session['user_id'], video_id)).fetchone()
    progress_sec = progress['progress'] if progress else 0
    db.close()
    context = {
        'site_name': get_setting('site_name'),
        'primary_color': get_setting('primary_color'),
        'accent_color': get_setting('accent_color'),
        'theme': session.get('theme', 'dark'),
        'csrf_token': session.get('csrf_token', ''),
        'video': video,
        'progress': progress_sec
    }
    return render_template_string('''
<!DOCTYPE html>
<html lang="en" data-bs-theme="{{ theme }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ video.title }} - {{ site_name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: {{ primary_color }};
            --accent: {{ accent_color }};
            --bg-dark: #0a0a1a;
            --glass-bg: rgba(255,255,255,0.05);
            --glass-border: rgba(255,255,255,0.1);
            --text-light: #f0f0f0;
        }
        body {
            background: var(--bg-dark);
            color: var(--text-light);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .video-container {
            max-width: 900px;
            margin: 30px auto;
            border-radius: 20px;
            overflow: hidden;
            background: #000;
            position: relative;
        }
        video {
            width: 100%;
            display: block;
            background: #000;
        }
        .video-info {
            padding: 20px;
        }
        .back-btn {
            position: fixed;
            top: 20px;
            left: 20px;
            z-index: 100;
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            color: #fff;
            padding: 10px 20px;
            border-radius: 50px;
            text-decoration: none;
            transition: all 0.3s;
        }
        .back-btn:hover {
            background: rgba(255,255,255,0.2);
            color: #fff;
        }
        .theme-toggle {
            position: fixed;
            bottom: 20px;
            right: 20px;
            z-index: 999;
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 50px;
            padding: 10px 18px;
            color: #fff;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <a href="{{ url_for('user_home') }}" class="back-btn"><i class="fas fa-arrow-left"></i> Back</a>

    <div class="video-container">
        <video id="videoPlayer" controls autoplay>
            <source src="{{ url_for('stream_video', video_id=video.id) }}" type="video/mp4">
            Your browser does not support the video tag.
        </video>
        <div class="video-info">
            <h2>{{ video.title }}</h2>
            <p>{{ video.description or '' }}</p>
            <div class="d-flex gap-3">
                <span><i class="fas fa-eye"></i> {{ video.views }} views</span>
                <span><i class="fas fa-calendar"></i> {{ video.uploaded_at[:10] }}</span>
                <span><i class="fas fa-tag"></i> {{ video.category or 'General' }}</span>
            </div>
        </div>
    </div>

    <div class="theme-toggle" onclick="toggleTheme()">
        <i class="fas fa-moon" id="themeIcon"></i>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const video = document.getElementById('videoPlayer');
        const videoId = {{ video.id }};
        const csrfToken = '{{ csrf_token }}';
        let progressInterval = null;

        const savedProgress = {{ progress }};
        if (savedProgress > 0) {
            video.currentTime = savedProgress;
        }

        function saveProgress() {
            const progress = Math.floor(video.currentTime);
            fetch('{{ url_for("update_progress") }}', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ video_id: videoId, progress: progress })
            });
        }

        video.addEventListener('play', function() {
            if (progressInterval) clearInterval(progressInterval);
            progressInterval = setInterval(saveProgress, 5000);
        });

        video.addEventListener('pause', function() {
            clearInterval(progressInterval);
            saveProgress();
        });

        video.addEventListener('ended', function() {
            clearInterval(progressInterval);
            saveProgress();
        });

        video.addEventListener('dblclick', function() {
            if (document.pictureInPictureEnabled && !document.pictureInPictureElement) {
                video.requestPictureInPicture();
            } else if (document.pictureInPictureElement) {
                document.exitPictureInPicture();
            }
        });

        function toggleTheme() {
            const html = document.documentElement;
            const icon = document.getElementById('themeIcon');
            if (html.getAttribute('data-bs-theme') === 'dark') {
                html.setAttribute('data-bs-theme', 'light');
                icon.className = 'fas fa-sun';
            } else {
                html.setAttribute('data-bs-theme', 'dark');
                icon.className = 'fas fa-moon';
            }
            fetch('{{ url_for("toggle_theme") }}', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ theme: html.getAttribute('data-bs-theme') })
            });
        }
    </script>
</body>
</html>
    ''', **context)

# =========================
# VIDEO STREAMING ROUTE
# =========================
@app.route('/stream/<int:video_id>')
@login_required
def stream_video(video_id):
    db = get_db()
    video = db.execute('SELECT filename FROM videos WHERE id = ?', (video_id,)).fetchone()
    db.close()
    if not video:
        abort(404)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], video['filename'])
    if not os.path.exists(filepath):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], video['filename'])

# =========================
# API ENDPOINTS
# =========================
@app.route('/api/stats')
@login_required
def api_stats():
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({
        'cpu': get_cpu_usage(),
        'ram': get_ram_usage(),
        'online_users': get_online_users(),
        'offline_users': get_offline_users(),
        'active_sessions': 0
    })

@app.route('/api/update_progress', methods=['POST'])
@login_required
def update_progress():
    data = request.get_json()
    video_id = data.get('video_id')
    progress = data.get('progress')
    if not video_id or progress is None:
        return jsonify({'error': 'Invalid data'}), 400
    db = get_db()
    db.execute('''
        INSERT INTO watch_history (user_id, video_id, progress, watched_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
    ''', (session['user_id'], video_id, progress))
    db.commit()
    db.close()
    return jsonify({'status': 'ok'})

@app.route('/toggle_theme', methods=['POST'])
@login_required
def toggle_theme():
    data = request.get_json()
    theme = data.get('theme')
    if theme in ['dark', 'light']:
        session['theme'] = theme
    return jsonify({'status': 'ok'})

# =========================
# STATIC FILE SERVING (for thumbnails)
# =========================
@app.route('/static/thumbnails/<path:filename>')
def serve_thumbnail(filename):
    return send_from_directory(app.config['THUMBNAIL_FOLDER'], filename)

# =========================
# ERROR HANDLERS
# =========================
@app.errorhandler(404)
def page_not_found(e):
    return render_template_string('''
    <h1>404 - Page Not Found</h1>
    <a href="{{ url_for('index') }}">Go Home</a>
    '''), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template_string('''
    <h1>500 - Internal Server Error</h1>
    <a href="{{ url_for('index') }}">Go Home</a>
    '''), 500

# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
