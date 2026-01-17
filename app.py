import os
import requests
import random
import time
import socket
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from flask import session  # Ensure session is imported at the top!
from flask import Flask, render_template, redirect, url_for, flash, request
from mailjet_rest import Client
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from secrets import compare_digest
from flask import abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import secrets
from pymongo import MongoClient
import smtplib
from email.message import EmailMessage
import pandas as pd
from io import BytesIO
from flask import send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import lru_cache
import threading
import logging
from logging.handlers import RotatingFileHandler
import traceback
import sys
# Quick fix for empty roles in MongoDB
from bson.objectid import ObjectId

load_dotenv()  # <-- this reads your .env file

# Add this after loading environment variables
required_env_vars = [
    'SECRET_KEY', 'MONGODB_USERNAME', 'MONGODB_PASSWORD',
    'MJ_API_KEY', 'MJ_API_SECRET', 'MJ_SENDER_EMAIL',
    'API_BASE', 'TOKEN_URL', 'CLIENT_ID', 'CLIENT_SECRET',
    'PIN_TEST_CODE', 'PIN_TEST_USERS'
]

missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Access environment variables
mongodb_username = os.getenv('MONGODB_USERNAME')
mongodb_password = os.getenv('MONGODB_PASSWORD')
mongodb_ip = os.getenv('MONGODB_IP')
mongodb_auth_source = os.getenv('MONGODB_AUTH_SOURCE')

# Mandatory Email
mandatory_email = os.getenv('Mandatory_email')

# Now os.environ has all your variables
SECRET_KEY = os.environ.get("SECRET_KEY")
# Construct the MongoDB URI using the loaded environment variables
MONGO_URI= f"mongodb://{mongodb_username}:{mongodb_password}@{mongodb_ip}/?authSource={mongodb_auth_source}"

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

# Configure logging
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
app.logger.addHandler(handler)


app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,     # trust X-Forwarded-For
    x_proto=1,
    x_host=1,
    x_port=1
)

# Session Security: 15-minute inactivity timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# --- DATABASE INITIALIZATION & HEALTH CHECK ---
try:
    # 1. Initialize the client
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

    # 2. Force a connection to verify health
    mongo_client.server_info()

    # 3. Select the 'local' database
    db = mongo_client["local"]

    print("✅ Successfully connected to MongoDB: 'local' database is active.")
except Exception as e:
    print("❌ CRITICAL: Could not connect to MongoDB!")
    print(f"Error Details: {e}")
    # Optional: Exit the app if DB is required
    # import sys; sys.exit(1)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = None  # <-- Disable the message
login_manager.login_message_category = "info"

serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# Configuration & Constants for Blacklist Reason
REASON_CODES = {
    "0010": "Faulty or Broken",
    "0011": "Stolen or Lost",
    "0016": "Duplicated IMEI",
    "0023": "Third Party Block Request",
    "0026": "Fraudulently Obtained",
    "0028": "Court Ordered Block",
    "0014": "Found (Previously Stolen)",
    "0018": "Repaired",
    "0022": "Aged IMEI"
}

# ---------------- API CONFIG ----------------
API_BASE = os.environ.get("API_BASE")
TOKEN_URL = os.environ.get("TOKEN_URL")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")

# ---------------- EMAIL CONFIG ----------------
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM")


PIN_COOLDOWN_SECONDS = 60
PIN_TEST_CODE = os.environ.get("PIN_TEST_CODE")

if not PIN_TEST_CODE:
    raise RuntimeError("PIN_TEST_CODE is missing from .env")

PIN_TEST_USERS = {
    email.strip().lower()
    for email in os.environ.get("PIN_TEST_USERS", "").split(",")
    if email.strip()
}

if not PIN_TEST_USERS:
    raise RuntimeError("PIN_TEST_USERS is empty or missing in .env")

# ---------------- FORMS ----------------
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class RoleForm(FlaskForm):
    role = SelectField("Role", choices=[("tech", "Tech"), ("admin", "Admin"), ("master", "Master")])
    submit = SubmitField("Update")

class DeleteForm(FlaskForm):
    submit = SubmitField("Delete")

class ResetRequestForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Send Reset Pin")

# ---------------- USER MODEL ----------------
class User(UserMixin):
    def __init__(self, user):
        self.id = str(user["_id"])
        self.email = user["email"]
        self.username = user["username"]
        self.role = user.get("role", "tech")

# ---------------- TOKEN CACHE FOR POSTMAN----------------
token_cache = {"token": None, "expires": datetime.utcnow()}

def get_access_token():
    if token_cache["token"] and token_cache["expires"] > datetime.utcnow():
        return token_cache["token"]

    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    r = requests.post(TOKEN_URL, data=payload, timeout=10)
    r.raise_for_status()
    data = r.json()

    token_cache["token"] = data["access_token"]
    token_cache["expires"] = datetime.utcnow() + timedelta(seconds=data["expires_in"] - 30)

    return token_cache["token"]



# ---------------- EMAIL LOGIC ----------------
def create_login_pin(email, request):
    now = datetime.utcnow()
    collection = get_pin_collection(email)

    existing_pin = collection.find_one({"email": email})

    # ⛔ Rate limit: 1 PIN per 60 seconds
    if existing_pin:
        last_created = existing_pin.get("created_at")
        if last_created and (now - last_created).total_seconds() < PIN_COOLDOWN_SECONDS:
            remaining = PIN_COOLDOWN_SECONDS - int((now - last_created).total_seconds())
            raise ValueError(f"Please wait {remaining} seconds before requesting a new code.")

    # Generate new PIN
    # 🔐 PIN selection logic
    if email in PIN_TEST_USERS:
        pin = PIN_TEST_CODE  # FIXED PIN FROM .ENV
    else: 
        pin = f"{random.randint(100000, 999999)}"
    print(f"the pin for the user is : {pin}")
    log_audit(
        event="PIN_REQUESTED",
        performed_by=email,
        request=request
    )

    collection.update_one(
        {"email": email},
        {"$set": {
            "pin": pin,
            "created_at": now,
            "attempts": 0
        }},
        upsert=True
    )

    if email not in PIN_TEST_USERS:
        send_pin_email(email, pin)
def fix_empty_roles():
    # Find users where role is missing, null, or an empty string
    result = db.users.update_many(
        {"$or": [
            {"role": {"$exists": False}},
            {"role": None},
            {"role": ""}
        ]},
        {"$set": {"role": "tech"}}
    )
    print(f"Updated {result.modified_count} users to 'tech' role.")

# fix_empty_roles()

def _send_pin_email_smtp(user_email, pin):
    """Sends PIN via Mailjet API instead of SMTP to bypass Windows timeouts"""

    # Use your existing keys from your environment/config
    api_key = os.environ.get('MJ_API_KEY')
    api_secret = os.environ.get('MJ_API_SECRET')
    sender_email = os.environ.get('MJ_SENDER_EMAIL')
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    data = {
      'Messages': [
        {
          "From": {
            "Email": sender_email,
            "Name": "SBE Security"
          },
          "To": [
            {
              "Email": user_email,
              "Name": "SBE User"
            }
          ],
          "Subject": f"{pin} is your SBE verification code for the Blacklist Check SBE Cordon",
          "HTMLPart": f"<h3>Blacklist Check SBE Cordon One-Time Code</h3><p>Your code is: <b>{pin}</b></p><p>Expires in 10 minutes.</p>"
        }
      ]
    }

    try:
        result = mailjet.send.create(data=data)
        if result.status_code == 200:
            print(f"✅ API SUCCESS: Email sent to {user_email}")
        else:
            print(f"❌ API ERROR: {result.status_code} - {result.json()}")

    except Exception as e:
        print(f"❌ CRITICAL API FAILURE: {e}")

def send_pin_email(user_email, pin):
    thread = threading.Thread(
        target=_send_pin_email_smtp,
        args=(user_email, pin),
        daemon=True
    )
    thread.start()

def send_security_alert(admin_email, content):
    """Sends immediate security alert via Mailjet API to bypass SMTP timeouts."""
    api_key = os.environ.get('MJ_API_KEY')
    api_secret = os.environ.get('MJ_API_SECRET')
    sender_email = os.environ.get('MJ_SENDER_EMAIL')

    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    # Local fallback log for security audits
    with open("security_audit.txt", "a") as f:
        f.write(f"[{datetime.now()}] ALERT SENT TO {admin_email}: {content}\n")

    data = {
      'Messages': [
        {
          "From": {
            "Email": sender_email,
            "Name": "SBE System Monitor"
          },
          "To": [
            {
              "Email": admin_email,
              "Name": "System Administrator"
            }
          ],
          "Subject": "⚠️ SECURITY ALERT: Unauthorized Action Detected",
          "HTMLPart": f"""
            <div style="font-family: Arial, sans-serif; border: 2px solid #dc3545; padding: 20px; border-radius: 10px;">
                <h2 style="color: #dc3545;">Security Alert</h2>
                <p>An unauthorized or failed master action was attempted on the <strong>SBE Blacklist Cordon</strong>.</p>
                <hr>
                <p style="background: #f8f9fa; padding: 10px;">{content}</p>
                <hr>
                <p style="font-size: 12px; color: #6c757d;">This is an automated alert. Please investigate immediately.</p>
            </div>
          """
        }
      ]
    }

    try:
        result = mailjet.send.create(data=data)
        if result.status_code == 200:
            print(f"✅ SECURITY ALERT SENT to {admin_email}")
        else:
            print(f"❌ SECURITY ALERT API ERROR: {result.status_code}")
    except Exception as e:
        print(f"❌ CRITICAL SECURITY ALERT FAILURE: {e}")

@login_manager.user_loader
def load_user(user_id):
    u = db.users.find_one({"_id": ObjectId(user_id)})
    return User(u) if u else None

# ---------------- HELPERS ----------------
def log_audit(event, performed_by, request, *,
              target=None,
              status="SUCCESS",
              details=None):

    db.audit_logs.insert_one({
        "timestamp": datetime.utcnow(),
        "event": event,
        "performed_by": performed_by,
        "target": target,
        "status": status,
        "ip_address": request.remote_addr,
        "details": details or {}
    })


def get_pin_collection(email):
    return db.pin_test if email in PIN_TEST_USERS else db.pins

@lru_cache(maxsize=1)
def get_role_settings():
    doc = db.role_settings.find_one({"_id": "default"})
    return doc["roles"] if doc else {}

def daily_limit(role):
    settings = get_role_settings()
    return settings.get(role, {}).get("daily_limit", 2)

def has_permission(user, permission: str) -> bool:
    """Check if user has specific permission"""
    try:
        roles = get_role_settings()
        role_config = roles.get(user.role, {})
        return role_config.get(permission, False)
    except Exception as e:
        app.logger.error(f"Permission check failed for {user.email}: {e}")
        return False  # Fail-safe: deny access on error

def clear_role_settings_cache():
    get_role_settings.cache_clear()

@app.route("/verify-pin", methods=["GET", "POST"])
def verify_pin():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("login"))

    collection = get_pin_collection(email)
    pin_doc = collection.find_one({"email": email})
    if not pin_doc:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for("login"))

    # Calculate how many seconds are LEFT in the cooldown
    now = datetime.utcnow()
    seconds_passed = (now - pin_doc["created_at"]).total_seconds()
    time_left = max(0, int(60 - seconds_passed))

    # Expiry: 10 minutes
    if datetime.utcnow() > pin_doc["created_at"] + timedelta(minutes=10):
        collection.delete_one({"_id": pin_doc["_id"]})
        flash("Code expired.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        user_pin = request.form.get("pin", "").strip()

        if compare_digest(user_pin, pin_doc["pin"]):
            # 1. Fetch the actual user from the DB
            user_data = db.users.find_one({"email": email})

            if user_data:
                # 2. Update Last Login and IP in ONE call
                db.users.update_one(
                    {"_id": user_data["_id"]},
                    {"$set": {
                        "last_login": datetime.utcnow(),
                        "last_ip": request.remote_addr
                    }}
                )

                # 3. Log the user in
                login_user(User(user_data))

                # 4. Cleanup
                collection.delete_one({"_id": pin_doc["_id"]})
                session.permanent = True
                session.pop("pending_email", None)

                flash("Logged in successfully!", "success")
                return redirect(url_for("index"))
            else:
                flash("User record not found.", "danger")
                return redirect(url_for("login"))

        # Incorrect PIN handling
        collection.update_one(
            {"_id": pin_doc["_id"]},
            {"$inc": {"attempts": 1}}
        )


        pin_doc = collection.find_one({"_id": pin_doc["_id"]})

        attempts_left = 3 - pin_doc["attempts"]
        if attempts_left <= 0:
            collection.delete_one({"_id": pin_doc["_id"]})
            flash("Too many attempts. Login blocked.", "danger")
            return redirect(url_for("login"))

        flash(f"Invalid code. {attempts_left} attempts left.", "warning")

    return render_template("verify_pin.html", email=email, time_left=time_left)

# MongoDB command to add 'tech' role to any user missing it
db.users.update_many(
    { "role": { "$exists": False } }, 
    { "$set": { "role": "tech" } }
)

db.users.update_many(
    { "role": "" }, 
    { "$set": { "role": "tech" } }
)

# ---------------- AUTH ROUTES ----------------
@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # Generate error ID
    error_id = secrets.token_hex(8)
    
    # Safe user extraction
    user_email = "anonymous"
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        user_email = current_user.email
    
    # Get debug mode from app config
    debug_mode = app.config.get('DEBUG', False)
    
    # Log to audit logs
    log_audit(
        event="SYSTEM_ERROR",
        performed_by=user_email,
        request=request,
        status="ERROR",
        details={
            "error": str(error),
            "error_id": error_id,
            "traceback": traceback.format_exc() if debug_mode else "Not available"
        }
    )
    
    # Log to file
    app.logger.error(f"500 Error ID {error_id}: {error}")
    
    return render_template('500.html', error_id=error_id), 500

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.context_processor
def inject_now():
    """Inject current datetime into all templates as 'now'"""
    return {'now': datetime.utcnow}

@app.before_request
def track_user_activity():
    # Skip tracking for login/logout pages to avoid redirect loops
    if request.endpoint in ['login', 'logout', 'static']:
        return
    
    if current_user.is_authenticated:
        # Update last activity timestamp
        session['last_activity'] = datetime.utcnow().isoformat()

        # Check session timeout
        if 'last_activity' in session:
            try:
                last_activity = datetime.fromisoformat(session['last_activity'])
                if datetime.utcnow() - last_activity > app.config['PERMANENT_SESSION_LIFETIME']:
                    logout_user()
                    flash('Session expired due to inactivity.', 'warning')
                    return redirect(url_for('login'))
            except (ValueError, KeyError):
                # Clear invalid session data
                session.pop('last_activity', None)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        # NEW: Check if this email has requested more than 5 PINs in the last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_requests = db.audit_logs.count_documents({
            "performed_by": email,
            "event": "PIN_REQUESTED",
            "timestamp": {"$gte": one_hour_ago}
        })

        if recent_requests >= 5:
             # Log the rate limit hit
            log_audit(
                event="RATE_LIMIT_HIT",
                performed_by=email,
                request=request,
                status="BLOCKED",
                details={"reason": "Too many PIN requests in last hour"}
            )
            flash("Too many login attempts. Please try again in an hour.", "danger")
            return redirect(url_for("login"))
        user = db.users.find_one({"email": email})
        if not user:
            flash("Unauthorized email address.Contact tech_support@sbe-ltd.co.uk to authorize your email address", "danger")
            return redirect(url_for("login"))

        try:
            create_login_pin(email, request)
        except ValueError as e:
            flash(str(e), "warning")
            return redirect(url_for("login"))

        session["pending_email"] = email
        flash("A login code has been sent to your email.", "info")
        return redirect(url_for("verify_pin"))

    return render_template("login_email_only.html")

@app.route("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "mongodb": "connected" if mongo_client else "disconnected"
    }

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

def initialize_database():
    """Initialize required collections and default settings"""
    try:
        # Ensure required collections exist
        required_collections = ['users', 'history', 'audit_logs', 'pins', 'pin_test', 'settings', 'role_settings']
        
        existing_collections = db.list_collection_names()
        
        for coll in required_collections:
            if coll not in existing_collections:
                db.create_collection(coll)
                print(f"✅ Created collection: {coll}")
        
        # Initialize default role settings if missing
        if not db.role_settings.find_one({"_id": "default"}):
            default_roles = {
                "_id": "default",
                "roles": {
                    "tech": {
                        "daily_limit": 4,
                        "can_access_admin": False,
                        "can_view_global_history": False,
                        "can_manage_users": False,
                        "can_delete_users": False,
                        "can_set_global_password": False,
                        "can_export": False,
                        "can_bulk_upload": False,
                        "can_view_audit_logs": False
                    },
                    "admin": {
                        "daily_limit": 8,
                        "can_access_admin": True,
                        "can_view_global_history": True,
                        "can_manage_users": True,
                        "can_delete_users": False,
                        "can_set_global_password": False,
                        "can_export": True,
                        "can_bulk_upload": True,
                        "can_view_audit_logs": True
                    },
                    "master": {
                        "daily_limit": 12,
                        "can_access_admin": True,
                        "can_view_global_history": True,
                        "can_manage_users": True,
                        "can_delete_users": True,
                        "can_set_global_password": True,
                        "can_export": True,
                        "can_bulk_upload": True,
                        "can_view_audit_logs": True
                    }
                }
            }
            db.role_settings.insert_one(default_roles)
            print("✅ Created default role settings")

        # Initialize global master password if missing
        if not db.settings.find_one({"setting_name": "global_master_password"}):
            default_hash = generate_password_hash("ChangeMe123!")
            db.settings.insert_one({
                "setting_name": "global_master_password",
                "hash": default_hash,
                "created_at": datetime.utcnow()
            })
            print("✅ Created default global master password")

        # Create indexes
        db.users.create_index("email", unique=True)
        db.history.create_index([("user_id", 1), ("timestamp", -1)])
        db.audit_logs.create_index([("timestamp", -1)])

        print("✅ Database initialization complete")

    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        raise

def is_valid_imei(imei: str) -> bool:
    """
    Validates IMEI using Luhn algorithm.
    IMEI must be exactly 15 digits.
    """
    if not imei.isdigit() or len(imei) != 15:
        return False

    total = 0
    for i, digit in enumerate(imei):
        n = int(digit)
        if i % 2 == 1:  # double every second digit (0-based index)
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0

# ---------------- DASHBOARD ----------------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    usage = db.history.count_documents({
        "user_id": ObjectId(current_user.id),
        "timestamp": {"$gte": today}
    })

    limit = daily_limit(current_user.role)
    results = error = None

    if request.method == "POST":
        if limit is not None and usage >= limit:
            error = "Daily limit reached."
        else:
            imei = request.form.get("imei", "").strip()

            if not is_valid_imei(imei):
                error = "Invalid IMEI number. Please enter a valid 15-digit IMEI."
            else:
                try:
                    token = get_access_token()
                    r = requests.get(
                        API_BASE,
                        headers={"Authorization": f"Bearer {token}"},
                        params={"context": "GSMA", "serialNumber": imei},
                        timeout=5
                    )
                    r.raise_for_status()
                    data = r.json()

                    # Data Extraction
                    is_blacklisted = data.get("isBlackListed", False)
                    raw_code = data.get("blacklistedReasonCode", "NA")
                    b_date = data.get("blacklistedDate")

                    # Map the code to your REASON_CODES dict
                    reason_friendly = REASON_CODES.get(raw_code, data.get("blacklistedReasonName", "NA"))

                    results = {
                        "imei": imei,
                        "is_bad": is_blacklisted,
                        "reason_text": reason_friendly,
                        "code": raw_code,
                        "blacklist_date": b_date,
                        "is_stolen": data.get("isStolen", False)
                    }

                    # Save to MongoDB (Fixed comma syntax here)
                    db.history.insert_one({
                        "user_id": ObjectId(current_user.id),
                        "imei": imei,
                        "is_bad": is_blacklisted,
                        "reason_code": raw_code,
                        "reason_text": reason_friendly,
                        "blacklist_date": b_date,
                        "timestamp": datetime.utcnow() # Comma was missing here
                    })

                except Exception as e:
                    error = f"API Error: {str(e)}"

    history = db.history.find(
        {"user_id": ObjectId(current_user.id)}
    ).sort("timestamp", -1).limit(5)

    return render_template(
        "index.html",
        results=results,
        error=error,
        history=history,
        usage=usage,
        limit=limit
    )

# ---------------- GLOBAL HISTORY ----------------
@app.route("/global-history")
@login_required
def global_history():
    if not has_permission(current_user, "can_view_global_history"):
        flash("Access denied","danger")
        return redirect(url_for("index"))


    pipeline = [
        # Lookup to join users collection
        {
            "$lookup": {
                "from": "users",           # the collection to join
                "localField": "user_id",   # field in history
                "foreignField": "_id",     # field in users
                "as": "user_info"          # resulting array
            }
        },
        # Unwind the array to convert it into a single object
        {"$unwind": {"path": "$user_info", "preserveNullAndEmptyArrays": True}},
        # Sort by timestamp descending
        {"$sort": {"timestamp": -1}},
        # Limit results
        {"$limit": 100}
    ]

    history = list(db.history.aggregate(pipeline))
    return render_template("global_history.html", history=history, enumerate=enumerate)


# ---------------- ADMIN ----------------
@app.route("/admin")
@login_required
def admin():
    if not has_permission(current_user, "can_access_admin"):
        flash("Access denied: Admin permissions required.", "danger")
        return redirect(url_for("index"))

    # Wrap the cursor in list() to fix the TypeError
    # This gets all users and sorts them alphabetically by username
    users = list(db.users.find().sort("username", 1))

    return render_template(
        "admin.html",
        users=users,
        role_form=RoleForm(),
        delete_form=DeleteForm()
    )

@app.route("/update_role/<user_id>", methods=["POST"])
@login_required
def update_role(user_id):
    if not has_permission(current_user, "can_manage_users"):
        flash("Unauthorized: You do not have permission to manage roles.", "danger")
        return redirect(url_for("index"))

    new_role = request.form.get("role", "").lower().strip()
    valid_roles = ["tech", "admin", "master"]

    if new_role not in valid_roles:
        flash(f"Invalid role selected: {new_role}", "danger")
        return redirect(url_for("admin"))

    target_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not target_user:
        flash("User not found", "danger")
        return redirect(url_for("admin"))

    # 1. ALWAYS USE THIS VARIABLE - IT IS SAFE
    target_current_role = target_user.get("role", "tech")
    target_email = target_user.get("email", "Unknown Email")

    # 2. Logic for ADMIN users
    if current_user.role == "admin":
        if target_current_role != "tech" or new_role != "admin":
            flash("Admins can only promote Technicians to Admin status.", "danger")
            return redirect(url_for("admin"))

    # 3. Logic for MASTER users
    elif current_user.role == "master":
        if str(target_user['_id']) == str(current_user.id) and new_role != "master":
             flash("You cannot demote yourself from Master.", "warning")
             return redirect(url_for("admin"))

    # 4. FIXED: Use the safe variable here to prevent KeyError
    if target_current_role == new_role:
        flash("User already has this role.", "info")
        return redirect(url_for("admin"))

    # Proceed with update...
    result = db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": new_role}}
    )

    if result.modified_count == 1:
        target_email = target_user.get('email', 'Unknown')
        # FIXED: Use target_email (safe) instead of target_user['email']
        flash(f"Success: {target_email} is now {new_role}.", "success")

        log_audit(
            event="ROLE_UPDATE",
            performed_by=current_user.email,
            request=request,
            target={
                "user_id": str(user_id),  # Convert ObjectId to String
                "email": target_email
            },
            details={
                "old_role": target_current_role,
                "new_role": new_role
            }
        )
        print(target_email,new_role)
        clear_role_settings_cache()
    else:
        flash("No changes were made.", "warning")

    return redirect(url_for("admin"))

@app.route("/admin/add_user", methods=["POST"])
@login_required
def add_user():
    # 1. Permission Check: Allow both Admin and Master
    if not has_permission(current_user, "can_manage_users"):
        flash("Unauthorized: Only permitted users can add users.", "danger")
        return redirect(url_for("index"))


    email = request.form.get("email", "").lower().strip()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "tech")

    # 2. Domain Validation: 
    if not email.endswith(f"@{mandatory_email}"):
        flash("Registration Error: Only sbe emails addresses are permitted.", "danger")
        return redirect(url_for("admin"))

    # 3. Duplicate Check: Ensure user doesn't exist
    existing_user = db.users.find_one({"email": email})
    if existing_user:
        flash(f"Error: User with email {email} already exists.", "warning")
        return redirect(url_for("admin"))

    # 4. Insertion
    db.users.insert_one({
        "email": email,
        "username": username,
        "role": role,
        "created_at": datetime.utcnow(),
        "last_login": None
    })

    flash(f"Success: {email} has been authorized as {role}.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/delete/<user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if current_user.role != "master":
        abort(403)
    # 1. Identity Check
    if not has_permission(current_user, "can_delete_users"):
        flash("Unauthorized access.", "danger")
        return redirect(url_for("admin"))


    # 2. Get the password from the Modal form
    input_password = request.form.get("confirm_password")

    # 3. Get the Global Hash from the settings collection
    global_setting = db.settings.find_one({"setting_name": "global_master_password"})

    if not global_setting:
        flash("System Error: Global Master Password not set in database.", "danger")
        return redirect(url_for("admin"))

    # 4. STRICT PASSWORD CHECK
    # This check MUST return False if the password doesn't match the hash
    if not check_password_hash(global_setting['hash'], input_password):
        # Notify about the failed attempt
        alert_msg = f"FAILED DELETION ATTEMPT\nUser: {current_user.email}\nTarget User ID: {user_id}\nIP: {request.remote_addr}"

        # Call the alert function (defined below)
        send_security_alert(os.environ.get("MJ_SENDER_EMAIL"), alert_msg)

        print(f"DEBUG: Password mismatch for {current_user.email}")
        flash("Incorrect Master Password! Access Denied.", "danger")
        # IMPORTANT: This return stops the code here
        return redirect(url_for("admin"))

    # 5. Success Logic - Only runs if password was CORRECT
    print(f"DEBUG: Password verified. Proceeding with deletion of {user_id}")

    if user_id == current_user.id:
        flash("You cannot delete yourself.", "warning")
        return redirect(url_for("admin"))

    db.users.delete_one({"_id": ObjectId(user_id)})
    flash("User successfully deleted.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/set-global-password", methods=["POST"])
@login_required
def set_global_password():
    master_email = os.environ.get('MJ_SENDER_EMAIL')
    # 1. Identity Lockdown: Only your specific email can access this logic
    # Check permissions
    if not has_permission(current_user, "can_set_global_password") \
       or current_user.email != master_email:

        # LOG THE UNAUTHORIZED ATTEMPT
        log_audit(
            event="UNAUTHORIZED_PASSWORD_CHANGE_ATTEMPT",
            performed_by=current_user.email,
            request=request,
            status="BLOCKED",
            details={
                "reason": "User tried to change global password without Master privileges"
            }
        )


        flash("Access Denied: Only the Master Admin can perform this action.", "danger")
        return redirect(url_for("admin"))


    new_pwd = request.form.get("new_global_password")
    if len(new_pwd) < 8:
        flash("Password must be at least 8 characters.", "warning")
        return redirect(url_for("admin"))

    # 2. Update the shared hash in the settings collection
    hashed = generate_password_hash(new_pwd)
    db.settings.update_one(
        {"setting_name": "global_master_password"},
        {"$set": {"hash": hashed}},
        upsert=True
    )
    flash("Global Master Password updated successfully.", "success")
    return redirect(url_for("admin"))

# --- EXPORT DAILY HISTORY ---
@app.route("/export-history")
@login_required
def export_history():
    if not has_permission(current_user, "can_export"):
        return "Unauthorized", 403

    # Fetch all history and join with user info
    pipeline = [
        {"$lookup": {"from": "users", "localField": "user_id", "foreignField": "_id", "as": "user"}},
        {"$unwind": "$user"}
    ]
    data = list(db.history.aggregate(pipeline))

    # Flatten for Excel
    rows = []
    for item in data:
        rows.append({
            "Timestamp": item.get("timestamp"),
            "User": item['user'].get("username"),
            "Email": item['user'].get("email"),
            "IMEI": item.get("imei"),
            "Status": "Blacklisted" if item.get("is_bad") else "Clean",
            "Reason": item.get("reason_text"),
            "GSMA_Date": item.get("blacklist_date")
        })

    df = pd.DataFrame(rows)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='IMEI_Checks')

    output.seek(0)
    return send_file(output, download_name="IMEI_History_Report.xlsx", as_attachment=True)

# --- EXPORT USER LIST ---
@app.route("/export-users")
@login_required
def export_users():
    if not has_permission(current_user, "can_export"):
        return "Unauthorized", 403

    users = list(db.users.find())
    rows = [{
        "Username": u.get("username"),
        "Email": u.get("email"),
        "Role": u.get("role"),
        "Created_At": u.get("created_at"),
        "Last_Login": u.get("last_login")
    } for u in users]

    df = pd.DataFrame(rows)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='User_Permissions')

    output.seek(0)
    return send_file(output, download_name="User_Access_Report.xlsx", as_attachment=True)

@app.route('/admin/bulk_upload', methods=['POST'])
@login_required
def bulk_upload_users():
    if not has_permission(current_user, "can_bulk_upload"):
        flash("Unauthorized access.", "danger")
        return redirect(url_for("admin"))


    file = request.files.get('file')
    if not file:
        flash('No file selected.', 'warning')
        return redirect(url_for('admin'))

    try:
        # header=None tells pandas to treat Row 1 as data
        df = pd.read_excel(file, header=None)

        # 1. Manually assign names to the first two columns found
        df.columns = ['email', 'username'] + list(df.columns[2:])

        # 2. Safety Check: If the first row contains the words "email" or "username", skip it
        first_row_val = str(df.iloc[0, 0]).lower().strip()
        if "email" in first_row_val or "username" in first_row_val:
            df = df.iloc[1:]

        success_count = 0
        error_list = []

        for index, row in df.iterrows():
            # Convert to string and clean
            email = str(row['email']).strip().lower()
            username = str(row['username']).strip()

            # Skip empty rows
            if not email or email == 'nan':
                continue

            # Validation: Domain Check
            if not email.endswith('@sbe-ltd.co.uk'):
                error_list.append(f"Row {index+1}: '{email}' skipped (Must use @sbe-ltd.co.uk)")
                continue

            # Validation: Duplicate Check (MongoDB)
            existing_user = db.users.find_one({'email': email})
            if existing_user:
                error_list.append(f"Row {index+1}: '{email}' already exists")
                continue

            # Create User (Method B - No password needed as per your auth)
            new_user = {
                'email': email,
                'username': username,
                'role': 'tech',
                'last_login': None,
                'last_ip': None
            }
            db.users.insert_one(new_user)
            success_count += 1

        if success_count > 0:
            flash(f'Successfully imported {success_count} technicians.', 'success')

        if error_list:
            flash("Some rows were skipped: " + " | ".join(error_list), 'warning')

    except Exception as e:
        flash(f'System Error: {str(e)}', 'danger')

    return redirect(url_for('admin'))

@app.route("/audit-logs")
@login_required
def view_audit_logs():
    if not has_permission(current_user, "can_view_audit_logs"):
        flash("Unauthorized.", "danger")
        return redirect(url_for("index"))

    # Read filters from query params
    performed_by = request.args.get("performed_by", "").strip()
    target_email = request.args.get("target_email", "").strip()
    event = request.args.get("event", "").strip()

    query = {}

    if performed_by:
        query["performed_by"] = {"$regex": performed_by, "$options": "i"}

    if target_email:
        query["target.email"] = {"$regex": target_email, "$options": "i"}

    if event:
        query["event"] = event

    logs = db.audit_logs.find(query).sort("timestamp", -1).limit(200)

    events = db.audit_logs.distinct("event")

    return render_template(
        "audit_logs.html",
        logs=logs,
        events=events,
        filters={
            "performed_by": performed_by,
            "target_email": target_email,
            "event": event
        }
    )

@app.route("/audit-logs/export")
@login_required
def export_audit_logs():
    if not has_permission(current_user, "can_view_audit_logs"):
        return "Unauthorized", 403

    performed_by = request.args.get("performed_by", "").strip()
    target_email = request.args.get("target_email", "").strip()
    event = request.args.get("event", "").strip()

    query = {}

    if performed_by:
        query["performed_by"] = {"$regex": performed_by, "$options": "i"}

    if target_email:
        query["target.email"] = {"$regex": target_email, "$options": "i"}

    if event:
        query["event"] = event

    logs = list(db.audit_logs.find(query).sort("timestamp", -1))

    rows = []
    for log in logs:
        rows.append({
            "Timestamp": log.get("timestamp"),
            "Event": log.get("event"),
            "Performed By": log.get("performed_by"),
            "Target User": log.get("target", {}).get("email"),
            "Old Role": log.get("details", {}).get("old_role"),
            "New Role": log.get("details", {}).get("new_role"),
            "Status": log.get("status"),
            "IP Address": log.get("ip_address")
        })

    df = pd.DataFrame(rows)

    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)

    return send_file(
        output,
        mimetype="text/csv",
        as_attachment=True,
        download_name="audit_logs.csv"
    )

if __name__ == "__main__":
    # Initialize database first
    try:
        initialize_database()
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")
        sys.exit(1)

    # Create TTL indexes
    try:
        db.pins.create_index("created_at", expireAfterSeconds=600)
        db.pin_test.create_index("created_at", expireAfterSeconds=600)
        print("✅ Created TTL indexes")
    except Exception as e:
        print(f"⚠️ Could not create TTL indexes: {e}")

    app.run(debug=False, use_reloader=False, host='0.0.0.0', port=5000)

