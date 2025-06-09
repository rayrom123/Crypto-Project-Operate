import os
import json
import datetime
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import bcrypt, base64
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Cấu hình CORS chi tiết hơn
CORS(app, 
     resources={r"/*": {
         "origins": ["https://crypto-project-operate.vercel.app"],
         "methods": ["GET", "POST", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"],
         "expose_headers": ["Content-Type", "X-CSRFToken"],
         "supports_credentials": True,
         "max_age": 3600
     }},
     supports_credentials=True
)

# Cấu hình session
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "secret_key"),
    SESSION_COOKIE_SAMESITE='None',  # Cho phép cross-site cookies
    SESSION_COOKIE_SECURE=True,      # Yêu cầu HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # Bảo vệ cookie khỏi JavaScript
    SESSION_COOKIE_DOMAIN=None,      # Cho phép tất cả domain
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7)  # Session tồn tại 7 ngày
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploaded_files")
PUBKEY_DIR = os.path.join(BASE_DIR, "public_keys")
INBOX_FILE = os.path.join(BASE_DIR, "inbox.json")
USER_DB_FILE = os.path.join(BASE_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "server_log.json")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PUBKEY_DIR, exist_ok=True)

# ==== Logging ====
def log_action(action_type: str, message: str, user: str = "Guest"):
    timestamp = datetime.datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "user": user,
        "action_type": action_type,
        "message": message
    }
    try:
        logs = []
        if os.path.exists(LOG_FILE) and os.stat(LOG_FILE).st_size > 0:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                file_content = f.read().strip()
                if file_content:
                    logs = json.loads(file_content)
        logs.append(log_entry)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"[LOG ERROR] {e}")

# ==== User Management ====
def load_users():
    if not os.path.exists(USER_DB_FILE) or os.stat(USER_DB_FILE).st_size == 0:
        return {}
    with open(USER_DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users_data):
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=4, ensure_ascii=False)

def verify_password(stored_password, provided_password):
    if isinstance(stored_password, str):
        stored_password = stored_password.encode('utf-8')
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "message": "Bạn chưa đăng nhập. Vui lòng đăng nhập để tiếp tục."}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# ==== API Register ====
@app.route("/api/register", methods=["POST"])
def api_register_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "Username và Password không được để trống."}), 400

    users = load_users()
    if username in users:
        log_action("Registration Failed", f"Attempt to register existing username: '{username}'.", username)
        return jsonify({"success": False, "message": "Username đã tồn tại. Vui lòng chọn username khác."}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    users[username] = {"password_hash": hashed_password}
    save_users(users)
    log_action("User Registration", f"User '{username}' registered successfully.", username)
    return jsonify({"success": True, "message": f"User '{username}' đã được đăng ký thành công."}), 200

# ==== API Login ====
@app.route("/api/login", methods=["POST"])
def api_login_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "Username và Password không được để trống."}), 400

    users = load_users()
    user_info = users.get(username)

    if user_info and verify_password(user_info["password_hash"], password):
        session['username'] = username
        session.permanent = True  # Đặt session là permanent
        log_action("User Login", f"User '{username}' logged in successfully.", username)
        return jsonify({"success": True, "message": f"Đăng nhập thành công cho user '{username}'."}), 200
    else:
        log_action("User Login Failed", f"Failed login attempt for user '{username}'. Invalid credentials.", username)
        return jsonify({"success": False, "message": "Username hoặc Password không đúng."}), 401

# ==== API Logout ====
@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout_user():
    user = session.pop('username', None)
    if user:
        log_action("User Logout", f"User '{user}' logged out.", user)
    return jsonify({"success": True, "message": "Bạn đã đăng xuất thành công."}), 200

# ==== API Check Login Status ====
@app.route("/api/check_login_status", methods=["GET"])
def api_check_login_status():
    if 'username' in session:
        return jsonify({"logged_in": True, "username": session['username']}), 200
    return jsonify({"logged_in": False}), 200

# ==== API Upload Transaction (File giao dịch đã mã hóa) ====
@app.route("/api/upload_transaction", methods=["POST"])
@login_required
def upload_transaction():
    from_user = session['username']
    to_user = request.form.get("to_user")
    f = request.files['file']
    filename = f.filename
    f.save(os.path.join(UPLOAD_DIR, filename))
    # Ghi vào inbox
    data = []
    if os.path.exists(INBOX_FILE):
        with open(INBOX_FILE, "r", encoding="utf-8") as ff:
            try: data = json.load(ff)
            except: data = []
    data.append({"file": filename, "from": from_user, "to": to_user, "timestamp": datetime.datetime.now().isoformat()})
    with open(INBOX_FILE, "w", encoding="utf-8") as ff:
        json.dump(data, ff, indent=2, ensure_ascii=False)
    log_action("upload", f"{from_user} gửi file {filename} cho {to_user}", from_user)
    return jsonify({"success": True, "message": f"Đã upload file {filename} cho {to_user}"})

# ==== API get inbox (hộp thư đến) ====
@app.route("/api/get_inbox", methods=["GET"])
@login_required
def get_inbox():
    user = session['username']
    inbox = []
    if os.path.exists(INBOX_FILE):
        with open(INBOX_FILE, "r", encoding="utf-8") as ff:
            try: inbox = json.load(ff)
            except: inbox = []
    files = [x for x in inbox if x['to'] == user]
    return jsonify({"success": True, "inbox": files})

# ==== API Upload public key ====
@app.route("/api/upload_pubkey", methods=["POST"])
@login_required
def upload_pubkey():
    data = request.get_json()
    username = data.get("username")
    key_type = data.get("key_type")
    public_key = data.get("public_key")  # Dạng base64 string hoặc PEM string

    if not (username and key_type and public_key):
        return jsonify({"success": False, "message": "Thiếu thông tin."}), 400

    # Lưu public key thành file
    ext = "pem" if key_type in ("ECDSA", "RSA") else "pub"
    filename = f"{username}.{key_type.lower()}.pub.{ext}"
    path = os.path.join(PUBKEY_DIR, filename)
    try:
        if key_type in ("ECDSA", "RSA"):
            if public_key.startswith("-----"):
                pem_bytes = public_key.encode('utf-8')
            else:
                pem_bytes = base64.b64decode(public_key)
        else:
            pem_bytes = base64.b64decode(public_key)
        with open(path, "wb") as f:
            f.write(pem_bytes)
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi lưu file: {e}"}), 500

    log_action("upload_pubkey", f"{session['username']} upload public key {filename}", session['username'])
    import hashlib
    fingerprint = hashlib.sha256(pem_bytes).hexdigest()[:16]
    return jsonify({"success": True, "message": f"Đã upload public key {filename}", "fingerprint": fingerprint})

# ==== API Download file giao dịch (phân quyền) ====
@app.route("/api/download/transaction/<filename>", methods=["GET"])
@login_required
def download_transaction(filename):
    inbox = []
    if os.path.exists(INBOX_FILE):
        with open(INBOX_FILE, "r", encoding="utf-8") as ff:
            try: inbox = json.load(ff)
            except: inbox = []
    file_info = next((x for x in inbox if x['file'] == filename), None)
    if not file_info or (session['username'] not in [file_info['to'], file_info['from']]):
        return jsonify({"success": False, "message": "Không có quyền tải file này"}), 403
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)

@app.route("/api/get_pubkey", methods=["GET"])
def get_pubkey():
    username = request.args.get("username")
    key_type = request.args.get("key_type")  # "RSA", "ECDSA", ...
    user_request = username

    if not username or not key_type:
        log_action("get_pubkey_fail", f"{user_request} lấy public key thiếu tham số", user_request)
        return jsonify({"success": False, "message": "Thiếu tham số"}), 400

    ext = "pem" if key_type in ("RSA", "ECDSA") else "pub"
    pubkey_path = os.path.join(PUBKEY_DIR, f"{username}.{key_type.lower()}.pub.{ext}")
    if not os.path.exists(pubkey_path):
        log_action("get_pubkey_fail", f"{user_request} lấy public key {username}.{key_type} KHÔNG TÌM THẤY", user_request)
        return jsonify({"success": False, "message": "Không tìm thấy public key"}), 404

    with open(pubkey_path, "rb") as f:
        pubkey_pem = f.read()

    log_action("get_pubkey", f"{user_request} truy vấn public key {username}.{key_type}", user_request)
    return jsonify({"success": True, "pubkey_pem": pubkey_pem.decode()})

# ==== API get log ====
@app.route("/api/get_log", methods=["GET"])
@login_required
def get_log():
    if not os.path.exists(LOG_FILE):
        return jsonify({"success": True, "log": ""})
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = f.read()
    return jsonify({"success": True, "log": logs})

# Thêm route cho root path
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "status": "running",
        "message": "Crypto Backend API is running",
        "version": "1.0.0"
    })

# Thêm health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat()
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
