import os
import json
import datetime
from functools import wraps
from flask import Flask, request, jsonify, session, redirect, url_for, send_from_directory
from flask_cors import CORS
import bcrypt, base64
from dilithium_py.ml_dsa import ML_DSA_44
from modules.crypto_utils import (
    load_pem_pub, public_key_fingerprint, ecdsa_verify, rsa_encrypt, aes_encrypt
)

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = "secret_key"

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

# ==== Mã hóa AES + RSA ====
@app.route("/api/sign_encrypt", methods=["POST"])
@login_required
def api_sign_encrypt():
    unique_filename_on_server = request.form.get("unique_filename_on_server")
    signer_name = request.form.get("signer_name")
    ecdsa_signature_b64 = request.form.get("ecdsa_signature")
    mldsa_signature_b64 = request.form.get("mldsa_signature")
    ecdsa_pub_key_b64 = request.form.get("ecdsa_public_key")
    mldsa_pub_key_b64 = request.form.get("mldsa_public_key")
    receiver_name = request.form.get("receiver_name")
    order_content_raw = request.form.get("order_content")
    if not order_content_raw:
        return jsonify({"success": False, "message": "Không nhận được nội dung giao dịch (order_content) từ client."}), 400
    try:
        order = json.loads(order_content_raw)
    except Exception as e:
        return jsonify({"success": False, "message": f"Nội dung order_content không hợp lệ: {e}"}), 400

    data_bytes = json.dumps(order, ensure_ascii=False).encode()

    # --- Xác thực chữ ký ---
    try:
        ecdsa_pub_bytes = base64.b64decode(ecdsa_pub_key_b64)
        ecdsa_sig_bytes = base64.b64decode(ecdsa_signature_b64)
        ecdsa_verified = ecdsa_verify(ecdsa_pub_bytes, data_bytes, ecdsa_sig_bytes)
    except Exception as e:
        return jsonify({"success": False, "message": f"Xác thực ECDSA thất bại: {e}"}), 400

    try:
        mldsa_pub_bytes = base64.b64decode(mldsa_pub_key_b64)
        mldsa_sig_bytes = base64.b64decode(mldsa_signature_b64)
        mldsa_verified = ML_DSA_44.verify(mldsa_pub_bytes, data_bytes, mldsa_sig_bytes)
    except Exception as e:
        return jsonify({"success": False, "message": f"Xác thực ML-DSA thất bại: {e}"}), 400

    if not ecdsa_verified or not mldsa_verified:
        return jsonify({"success": False, "message": "Chữ ký số không hợp lệ!"}), 400

    # --- Đóng gói package để mã hóa ---
    package = {
        "order": order,
        "signatures": [
            {
                "algo": "ECDSA",
                "signer_name": signer_name,
                "signature": ecdsa_signature_b64,
                "public_key": ecdsa_pub_key_b64,
                "fingerprint": public_key_fingerprint(ecdsa_pub_bytes)
            },
            {
                "algo": "ML-DSA",
                "signer_name": signer_name,
                "signature": mldsa_signature_b64,
                "public_key": mldsa_pub_key_b64,
                "fingerprint": public_key_fingerprint(mldsa_pub_bytes)
            }
        ]
    }
    json_bytes = json.dumps(package, ensure_ascii=False, indent=2).encode()

    # --- Mã hóa AES+RSA ---
    rsa_pub = load_pem_pub(os.path.join(PUBKEY_DIR, f"{receiver_name}.rsa.pub.pem"))
    if not rsa_pub:
        return jsonify({"success": False, "message": "Không tìm thấy public key RSA của người nhận"}), 400
    aes_key = os.urandom(32)
    iv, aes_ciphertext = aes_encrypt(aes_key, json_bytes)
    rsa_key_cipher = rsa_encrypt(rsa_pub, aes_key)

    output_file_name = f'transaction_signed_{order["order_id"]}_{int(__import__("time").time())}.encrypted'
    output_filepath = os.path.join(UPLOAD_DIR, output_file_name)
    with open(output_filepath, "w", encoding="utf-8") as f:
        json.dump({
            "rsa_key_cipher": base64.b64encode(rsa_key_cipher).decode(),
            "iv": base64.b64encode(iv).decode(),
            "aes_ciphertext": base64.b64encode(aes_ciphertext).decode(),
            "encrypted_for_receiver": receiver_name,
            "original_order_filename": unique_filename_on_server  # Tham chiếu file gốc nếu muốn
        }, f, indent=2, ensure_ascii=False)

    # Ghi vào inbox tự động
    data = []
    if os.path.exists(INBOX_FILE):
        with open(INBOX_FILE, "r", encoding="utf-8") as ff:
            try: data = json.load(ff)
            except: data = []
    data.append({"file": output_file_name, "from": signer_name, "to": receiver_name, "timestamp": datetime.datetime.now().isoformat()})
    with open(INBOX_FILE, "w", encoding="utf-8") as ff:
        json.dump(data, ff, indent=2, ensure_ascii=False)

    log_action("sign_encrypt", f"{signer_name} gửi và mã hóa giao dịch cho {receiver_name}: {output_file_name}", signer_name)

    return jsonify({
        "success": True,
        "message": f"Đã ký, xác thực, mã hóa và lưu file: {output_file_name}",
        "filename": output_file_name
    })

# ==== API get log ====
@app.route("/api/get_log", methods=["GET"])
@login_required
def get_log():
    if not os.path.exists(LOG_FILE):
        return jsonify({"success": True, "log": ""})
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = f.read()
    return jsonify({"success": True, "log": logs})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
