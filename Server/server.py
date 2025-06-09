import os
import datetime
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
from pymongo import MongoClient
from bson.binary import Binary
import bcrypt, base64, hashlib
from io import BytesIO
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
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_DOMAIN=None,
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=7)
)

# --- MongoDB INIT --- #
client = MongoClient(os.getenv("MONGODB_URI"))  # Mongo URI from .env
mongo_db = client["crypto_app"]

# ==== Logging -> MongoDB ==== #
def log_action(action_type: str, message: str, user: str = "Guest"):
    mongo_db.logs.insert_one({
        "timestamp": datetime.datetime.utcnow(),
        "user": user,
        "action_type": action_type,
        "message": message
    })

# ==== User Management -> MongoDB ==== #
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

# ==== Register/Login ==== #
@app.route("/api/register", methods=["POST"])
def api_register_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"success": False, "message": "Username và Password không được để trống."}), 400

    if mongo_db.users.find_one({"_id": username}):
        log_action("Registration Failed", f"Username '{username}' tồn tại.", username)
        return jsonify({"success": False, "message": "Username đã tồn tại."}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    mongo_db.users.insert_one({"_id": username, "password_hash": hashed})
    log_action("User Registration", f"User '{username}' đăng ký thành công.", username)
    return jsonify({"success": True, "message": f"User '{username}' đăng ký thành công."})

@app.route("/api/login", methods=["POST"])
def api_login_user():
    data = request.get_json()
    username, password = data.get("username"), data.get("password")
    user = mongo_db.users.find_one({"_id": username})
    if user and verify_password(user["password_hash"], password):
        session['username'] = username
        session.permanent = True
        log_action("User Login", f"User '{username}' đăng nhập.", username)
        return jsonify({"success": True, "message": "Đăng nhập thành công."})
    log_action("Login Failed", f"Sai thông tin cho '{username}'", username)
    return jsonify({"success": False, "message": "Sai username hoặc password."}), 400

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
    file_content = f.read()

    mongo_db.transactions.insert_one({
        "file": filename,
        "content": Binary(file_content),
        "from": from_user,
        "to": to_user,
        "timestamp": datetime.datetime.utcnow()
    })

    log_action("upload", f"{from_user} gửi file {filename} cho {to_user}", from_user)
    return jsonify({"success": True, "message": f"Đã upload file {filename} cho {to_user}"})

# ==== API get inbox (hộp thư đến) ====
@app.route("/api/get_inbox", methods=["GET"])
@login_required
def get_inbox():
    user = session['username']
    inbox = list(mongo_db.transactions.find({"to": user}, {"_id": 0, "content": 0}))
    return jsonify({"success": True, "inbox": inbox})

# ==== API Download Transaction (phân quyền) ==== #
@app.route("/api/download/transaction/<filename>", methods=["GET"])
@login_required
def download_transaction(filename):
    user = session['username']
    file_info = mongo_db.transactions.find_one({"file": filename, "$or": [{"to": user}, {"from": user}]})

    if not file_info:
        return jsonify({"success": False, "message": "Không có quyền tải file này"}), 403

    return send_file(BytesIO(file_info['content']), download_name=filename, as_attachment=True)

# ==== API Upload Public Key ==== #
@app.route("/api/upload_pubkey", methods=["POST"])
@login_required
def upload_pubkey():
    data = request.get_json()
    username = data.get("username")
    key_type = data.get("key_type")
    public_key = data.get("public_key")

    if not (username and key_type and public_key):
        return jsonify({"success": False, "message": "Thiếu thông tin."}), 400

    mongo_db.pubkeys.replace_one(
        {"username": username, "key_type": key_type},
        {"username": username, "key_type": key_type, "public_key": public_key},
        upsert=True
    )

    log_action("upload_pubkey", f"{session['username']} upload public key {key_type}", session['username'])
    fingerprint = hashlib.sha256(public_key).hexdigest()[:16]
    return jsonify({"success": True, "message": f"Đã upload public key cho {key_type}", "fingerprint": fingerprint})

# ==== API Get Public Key ==== #
@app.route("/api/get_pubkey", methods=["GET"])
def get_pubkey():
    username = request.args.get("username")
    key_type = request.args.get("key_type")

    if not username or not key_type:
        return jsonify({"success": False, "message": "Thiếu tham số"}), 400

    pubkey = mongo_db.pubkeys.find_one({"username": username, "key_type": key_type})

    if not pubkey:
        return jsonify({"success": False, "message": "Không tìm thấy public key"}), 404

        # Giả sử public_key_base64 = pubkey['public_key']
    public_key_base64 = pubkey['public_key']

    try:
        # Decode base64 thành PEM string
        public_key_pem = base64.b64decode(public_key_base64).decode('utf-8')
    except Exception as e:
        # Nếu không phải base64, trả về thẳng
        public_key_pem = public_key_base64

    return jsonify({"success": True, "pubkey_pem": public_key_pem})

# ==== API get log ==== #
@app.route("/api/get_log", methods=["GET"])
@login_required
def get_log():
    logs = list(mongo_db.logs.find({}, {"_id": 0}))
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
