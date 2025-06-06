# BE/app.py
import hashlib
import json
import os
import datetime
import base64
import logging
from functools import wraps

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, abort
from flask_cors import CORS

# --- Giả định modules.crypto_utils tồn tại và chứa các hàm này ---
# Vui lòng đảm bảo file modules/crypto_utils.py được đặt trong thư mục BE/modules/
# hoặc bạn định nghĩa trực tiếp các hàm này tại đây.
from modules.crypto_utils import (
    ecdsa_keygen, rsa_keygen, mldsa_keygen, save_pem, load_pem, load_pem_pub, load_mldsa_priv,
    public_key_fingerprint, ecdsa_sign, ecdsa_verify, rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt
)
from dilithium_py.ml_dsa import ML_DSA_44

# Các import cần thiết cho cryptography.hazmat, nếu không dùng modules.crypto_utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding # Đổi tên để tránh xung đột
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend


app = Flask(__name__,
            template_folder='../FE', # Cấu hình Flask tìm templates trong thư mục FE
            static_folder='../FE/static') # Cấu hình Flask tìm file tĩnh trong thư mục FE/static

# --- Cấu hình Flask ---
app.config['SECRET_KEY'] = 'mot_secret_key_rat_manh_va_bao_mat_cua_ban_12345_abcxyz_long_string'
CORS(app, supports_credentials=True)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False # False cho môi trường dev HTTP

# Thiết lập thư mục và file (tuyệt đối hóa đường dẫn)
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Đường dẫn thư mục BE
KEY_DIR = os.path.join(BASE_DIR, "user_keys")
TRANSACTION_DIR = os.path.join(BASE_DIR, "transactions")
USER_DB_FILE = os.path.join(BASE_DIR, "users.json")
LOG_FILE = os.path.join(BASE_DIR, "system_log.json")

# Tạo các thư mục nếu chúng chưa tồn tại
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(TRANSACTION_DIR, exist_ok=True)

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Chức năng Logging ---
def log_action(action_type: str, message: str, user: str = "Guest"):
    """Ghi lại hành động của người dùng vào file log."""
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
        app.logger.info(f"Log: {action_type} by {user} - {message}")
    except json.JSONDecodeError:
        app.logger.error(f"Error decoding JSON from log file: {LOG_FILE}. File might be corrupted. Attempting to overwrite.")
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump([log_entry], f, indent=4, ensure_ascii=False)
    except Exception as e:
        app.logger.error(f"Failed to write log to {LOG_FILE}: {e}")

# --- Chức năng Quản lý User ---
def load_users():
    """Tải dữ liệu người dùng từ file JSON."""
    if not os.path.exists(USER_DB_FILE) or os.stat(USER_DB_FILE).st_size == 0:
        return {}
    with open(USER_DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users_data):
    """Lưu dữ liệu người dùng vào file JSON."""
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=4, ensure_ascii=False)

def hash_password(password):
    """Hash mật khẩu bằng PBKDF2HMAC với salt."""
    salt = os.urandom(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + pwdhash.hex()

def verify_password(stored_password, provided_password):
    """Xác minh mật khẩu."""
    salt = bytes.fromhex(stored_password[:32])
    stored_pwdhash = bytes.fromhex(stored_password[32:])
    pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return pwdhash == stored_pwdhash

# --- Decorator để yêu cầu đăng nhập ---
def login_required(f):
    """Decorator để bảo vệ các routes yêu cầu đăng nhập."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "message": "Bạn chưa đăng nhập. Vui lòng đăng nhập để tiếp tục."}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- API Đăng ký User ---
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

    hashed_password = hash_password(password)
    users[username] = {"password_hash": hashed_password}
    save_users(users)
    log_action("User Registration", f"User '{username}' registered successfully.", username)
    return jsonify({"success": True, "message": f"User '{username}' đã được đăng ký thành công."}), 200

# --- API Đăng nhập ---
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

# --- API Đăng xuất ---
@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout_user():
    user = session.pop('username', None)
    if user:
        log_action("User Logout", f"User '{user}' logged out.", user)
    return jsonify({"success": True, "message": "Bạn đã đăng xuất thành công."}), 200

# --- API để kiểm tra trạng thái đăng nhập (Frontend sẽ gọi cái này) ---
@app.route("/api/check_login_status", methods=["GET"])
def api_check_login_status():
    if 'username' in session:
        return jsonify({"logged_in": True, "username": session['username']}), 200
    return jsonify({"logged_in": False}), 200

# --- API sinh/lưu khóa (nhận public key từ client và yêu cầu đăng nhập) ---
@app.route("/api/generate_key", methods=["POST"])
@login_required
def api_generate_key():
    data = request.get_json()
    username = data.get("username")
    key_type = data.get("key_type")
    public_key_b64 = data.get("public_key")

    if username != session['username']:
        log_action("Unauthorized Key Gen", f"Attempt to generate key for '{username}' by '{session['username']}'. Access denied.", session['username'])
        return jsonify({"success": False, "message": "Bạn chỉ có thể sinh khóa cho tài khoản của mình."}), 403

    if not username or not key_type or not public_key_b64:
        return jsonify({"success": False, "message": "Dữ liệu thiếu (username, key_type, hoặc public_key)."}), 400

    try:
        public_key_bytes = base64.b64decode(public_key_b64)
        pub_file = os.path.join(KEY_DIR, f"{username}.{key_type.lower()}.pub.pem")
        
        with open(pub_file, "wb") as f:
            f.write(public_key_bytes)
        
        log_action("Key Generation", f"Generated and saved {key_type} public key for user '{username}'.", username)
        return jsonify({
            "success": True,
            "message": f"Đã sinh khóa trên client và lưu Public Key trên server. Fingerprint: {public_key_fingerprint(public_key_bytes)}",
            "public_key_stored_at": pub_file,
            "fingerprint": public_key_fingerprint(public_key_bytes)
        })
    except Exception as e:
        log_action("Key Generation Failed", f"Error generating key for '{username}': {str(e)}", username)
        return jsonify({"success": False, "message": f"Lỗi: {str(e)}"}), 500

# --- API tạo giao dịch (Đã điều chỉnh quyền) ---
@app.route("/api/create_transaction", methods=["POST"])
@login_required
def api_create_transaction():
    data = request.get_json()
    order_id = data.get("order_id")
    buyer = data.get("buyer")
    seller = data.get("seller")
    amount = data.get("amount")
    currency = data.get("currency")
    items_str = data.get("items")

    if buyer != session['username']:
        log_action("Unauthorized Create Transaction", f"Attempt to create transaction for '{buyer}' by '{session['username']}'. Access denied.", session['username'])
        return jsonify({"success": False, "message": "Bạn chỉ có thể tạo giao dịch cho tài khoản của mình."}), 403

    if not all([order_id, buyer, seller, amount, currency, items_str]):
        return jsonify({"success": False, "message": "Dữ liệu giao dịch thiếu."}), 400

    items = [item.strip() for item in items_str.split(',')]

    transaction_data = {
        "order_id": order_id,
        "buyer": buyer,
        "seller": seller,
        "amount": float(amount),
        "currency": currency,
        "items": items,
        "created_at": datetime.datetime.now().isoformat()
    }

    unique_filename = f'order_{order_id}_{int(datetime.datetime.now().timestamp())}.json'
    file_path = os.path.join(TRANSACTION_DIR, unique_filename)

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(transaction_data, f, indent=4, ensure_ascii=False)
        log_action("Create Transaction", f"Transaction '{order_id}' created by '{buyer}'. Filename: {unique_filename}", session['username'])
        return jsonify({
            "success": True,
            "message": f"Giao dịch '{order_id}' đã được tạo thành công.",
            "filename_on_server": unique_filename,
            "order": transaction_data
        }), 200
    except Exception as e:
        log_action("Create Transaction Failed", f"Error creating transaction '{order_id}': {str(e)}", session['username'])
        return jsonify({"success": False, "message": f"Lỗi tạo giao dịch: {str(e)}"}), 500

# --- API lấy nội dung giao dịch từ server (mới thêm cho sign_encrypt) ---
@app.route("/api/get_transaction_content", methods=["POST"])
@login_required
def api_get_transaction_content():
    data = request.get_json()
    filename = data.get("filename")
    user = data.get("user") # user (buyer) gửi từ frontend

    if not filename or not user:
        return jsonify({"success": False, "message": "Thiếu tên file hoặc thông tin người dùng."}), 400

    if user != session['username']:
        log_action("Unauthorized Get Transaction Content", f"Attempt to get content of '{filename}' for '{user}' by '{session['username']}'. Access denied.", session['username'])
        return jsonify({"success": False, "message": "Bạn không có quyền xem giao dịch này."}), 403

    file_path = os.path.join(TRANSACTION_DIR, filename)
    if not os.path.exists(file_path):
        log_action("Get Transaction Content Failed", f"File '{filename}' not found for user '{user}'.", session['username'])
        return jsonify({"success": False, "message": "File giao dịch không tồn tại."}), 404

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            order_content = json.load(f)
        
        # Kiểm tra thêm: ensure the buyer in the file matches the current user
        if order_content.get("buyer") != session['username']:
            log_action("Unauthorized Get Transaction Content", f"Attempt to get content of '{filename}' owned by '{order_content.get('buyer')}' by '{session['username']}'. Access denied.", session['username'])
            return jsonify({"success": False, "message": "Bạn không có quyền xem giao dịch này."}), 403

        log_action("Get Transaction Content", f"Fetched content of transaction '{filename}' for user '{user}'.", session['username'])
        return jsonify({"success": True, "order_content": order_content}), 200
    except Exception as e:
        log_action("Get Transaction Content Failed", f"Error reading file '{filename}': {str(e)}", session['username'])
        return jsonify({"success": False, "message": f"Lỗi đọc file: {str(e)}"}), 500


# --- API ký số & mã hóa giao dịch (Đã điều chỉnh để nhận chữ ký từ client và quyền) ---
@app.route("/api/sign_encrypt", methods=["POST"])
@login_required
def api_sign_encrypt():
    unique_filename_on_server = request.form.get("unique_filename_on_server")
    signer_name_from_form = request.form.get("signer_name") # Lấy tên người ký từ form
    ecdsa_signature_b64 = request.form.get("ecdsa_signature")
    mldsa_signature_b64 = request.form.get("mldsa_signature")
    ecdsa_pub_key_b64 = request.form.get("ecdsa_public_key")
    mldsa_pub_key_b64 = request.form.get("mldsa_public_key")
    receiver_name = request.form.get("receiver_name")
    
    if not all([unique_filename_on_server, signer_name_from_form, ecdsa_signature_b64, mldsa_signature_b64, 
                ecdsa_pub_key_b64, mldsa_pub_key_b64, receiver_name]):
        return jsonify({"success": False, "message": "Dữ liệu ký/mã hóa bị thiếu."}), 400

    original_order_filepath = os.path.join(TRANSACTION_DIR, unique_filename_on_server)
    if not os.path.exists(original_order_filepath):
        log_action("Sign/Encrypt Failed", f"Original order file '{unique_filename_on_server}' not found on server.", session['username'])
        return jsonify({"success": False, "message": "File giao dịch gốc không tồn tại trên server."}), 404
    
    with open(original_order_filepath, 'r', encoding='utf-8') as f:
        order = json.load(f)

    # Kiểm tra quyền: Người ký (buyer trong order) phải là người dùng hiện tại
    if order.get("buyer") != session['username'] or signer_name_from_form != session['username']:
        log_action("Unauthorized Sign/Encrypt", f"Attempt to sign/encrypt transaction '{order.get('order_id')}' for buyer '{order.get('buyer')}' by '{session['username']}'. Access denied.", session['username'])
        return jsonify({"success": False, "message": "Bạn chỉ có thể ký/mã hóa giao dịch mà bạn là người mua."}), 403

    data_bytes = json.dumps(order, ensure_ascii=False).encode()

    ecdsa_verified = False
    mldsa_verified = False
    try:
        ecdsa_pub_bytes = base64.b64decode(ecdsa_pub_key_b64)
        ecdsa_sig_bytes = base64.b64decode(ecdsa_signature_b64)
        ecdsa_verified = ecdsa_verify(ecdsa_pub_bytes, data_bytes, ecdsa_sig_bytes)
    except Exception as e:
        app.logger.error(f"ECDSA verification failed for order {order.get('order_id')}: {e}")
    
    try:
        mldsa_pub_bytes = base64.b64decode(mldsa_pub_key_b64)
        mldsa_sig_bytes = base64.b64decode(mldsa_signature_b64)
        mldsa_verified = ML_DSA_44.verify(mldsa_pub_bytes, data_bytes, mldsa_sig_bytes)
    except Exception as e:
        app.logger.error(f"ML-DSA verification failed for order {order.get('order_id')}: {e}")

    if not ecdsa_verified or not mldsa_verified:
        log_action("Sign/Encrypt Failed", f"Signature verification failed for transaction '{order.get('order_id')}' by '{session['username']}'.", session['username'])
        return jsonify({"success": False, "message": "Xác thực chữ ký thất bại trên server."}), 400

    package = {
        "order": order,
        "signatures": [
            {
                "algo": "ECDSA",
                "signer_name": order["buyer"],
                "signature": ecdsa_signature_b64,
                "public_key": ecdsa_pub_key_b64,
                "fingerprint": public_key_fingerprint(ecdsa_pub_bytes),
                "verified_by_server": ecdsa_verified
            },
            {
                "algo": "ML-DSA",
                "signer_name": order["buyer"],
                "signature": mldsa_signature_b64,
                "public_key": mldsa_pub_key_b64,
                "fingerprint": public_key_fingerprint(mldsa_pub_bytes),
                "verified_by_server": mldsa_verified
            }
        ]
    }
    
    json_bytes = json.dumps(package, ensure_ascii=False, indent=2).encode()

    rsa_pub = load_pem_pub(os.path.join(KEY_DIR, f"{receiver_name}.rsa.pub.pem")) # Dùng os.path.join
    if not rsa_pub:
        log_action("Sign/Encrypt Failed", f"RSA public key not found for receiver '{receiver_name}' (transaction {order.get('order_id')}).", session['username'])
        return jsonify({"success": False, "message": f"Không tìm thấy khóa công khai RSA của người nhận ({receiver_name})!"}), 400
    
    aes_key = os.urandom(32)
    iv, aes_ciphertext = aes_encrypt(aes_key, json_bytes)
    rsa_key_cipher = rsa_encrypt(rsa_pub, aes_key)

    data_to_save = {
        "rsa_key_cipher": base64.b64encode(rsa_key_cipher).decode(),
        "iv": base64.b64encode(iv).decode(),
        "aes_ciphertext": base64.b64encode(aes_ciphertext).decode(),
        "encrypted_for_receiver": receiver_name,
        "original_order_filename": unique_filename_on_server # Lưu tên file gốc để tham chiếu
    }
    output_file_name = f'transaction_signed_{order["order_id"]}_{int(datetime.datetime.now().timestamp())}.encrypted' # Đổi tên cho rõ ràng hơn
    output_filepath = os.path.join(TRANSACTION_DIR, output_file_name)
    with open(output_filepath, "w", encoding="utf-8") as f:
        json.dump(data_to_save, f, indent=2, ensure_ascii=False)
    
    log_action("Sign/Encrypt", f"Transaction '{order.get('order_id')}' signed by '{order.get('buyer')}' and encrypted for '{receiver_name}'. File: {output_file_name}", session['username'])
    return jsonify({
        "success": True,
        "message": f"Đã nhận chữ ký, xác thực và mã hóa giao dịch. File đã mã hóa: {output_file_name}",
        "filename": output_file_name
    })

# --- API giải mã & xác thực giao dịch (Đã điều chỉnh quyền) ---
@app.route("/api/decrypt_verify", methods=["POST"])
@login_required
def api_decrypt_verify():
    # Frontend sẽ gửi tên file mã hóa (hoặc ID) và tên người nhận lên.
    file_id = request.form.get("file_id")
    receiver_name_from_form = request.form.get("receiver_name") # Tên người nhận (seller) từ frontend

    if not file_id or not receiver_name_from_form:
        return jsonify({"success": False, "message": "Thiếu ID file mã hóa hoặc tên người nhận."}), 400

    # Kiểm tra quyền: Người nhận từ form phải là người dùng hiện tại
    if receiver_name_from_form != session['username']:
        log_action("Unauthorized Decrypt Request", f"Attempt to decrypt for '{receiver_name_from_form}' by '{session['username']}'. Access denied.", session['username'])
        return jsonify({"success": False, "message": "Bạn chỉ có thể giải mã giao dịch dành cho tài khoản của bạn."}), 403

    encrypted_filepath = os.path.join(TRANSACTION_DIR, file_id)

    if not os.path.exists(encrypted_filepath):
        return jsonify({"success": False, "message": "File mã hóa không tồn tại."}), 404

    try:
        with open(encrypted_filepath, "r", encoding="utf-8") as f:
            encrypted_data = json.load(f)
        
        # Thêm kiểm tra `encrypted_for_receiver` để đảm bảo file này là của người dùng hiện tại
        if encrypted_data.get("encrypted_for_receiver") != session['username']:
             log_action("Unauthorized Decrypt Request", f"Attempt to decrypt non-owned file '{file_id}' (intended for '{encrypted_data.get('encrypted_for_receiver')}') by '{session['username']}'. Access denied.", session['username'])
             return jsonify({"success": False, "message": "Bạn không có quyền giải mã file này."}), 403

        log_action("Decrypt Request", f"Requested decryption of file '{file_id}' by '{session['username']}'.", session['username'])
        return jsonify({
            "success": True,
            "message": "Đã tải file mã hóa. Vui lòng giải mã trên máy client.",
            "encrypted_data": encrypted_data # Gửi dữ liệu mã hóa về client
        })

    except Exception as e:
        log_action("Decrypt Request Failed", f"Error loading encrypted file '{file_id}': {str(e)}", session['username'])
        return jsonify({"success": False, "message": f"Lỗi đọc file mã hóa: {str(e)}"}), 500

# --- API nhận dữ liệu đã giải mã và xác thực từ client ---
@app.route("/api/submit_decrypted_transaction", methods=["POST"])
@login_required
def api_submit_decrypted_transaction():
    data = request.get_json()
    decrypted_package = data.get("decrypted_package")

    if not decrypted_package:
        return jsonify({"success": False, "message": "Không nhận được dữ liệu đã giải mã."}), 400
    
    # Kiểm tra xem giao dịch đã giải mã có phải dành cho người dùng hiện tại không
    # Người nhận (seller) trong `order` của decrypted_package phải là user hiện tại
    if decrypted_package.get("order", {}).get("seller") != session['username']:
        log_action("Unauthorized Decrypt Submit", f"Attempt to submit non-owned decrypted transaction (for seller '{decrypted_package.get('order', {}).get('seller')}') by '{session['username']}'. Access denied.", session['username'])
        return jsonify({"success": False, "message": "Giao dịch đã giải mã không dành cho tài khoản của bạn."}), 403


    order = decrypted_package["order"]
    data_bytes = json.dumps(order, ensure_ascii=False).encode()
    verify_results = []

    for sig in decrypted_package["signatures"]:
        algo = sig["algo"]
        signer = sig.get("signer_name", "??")
        pubkey_b64 = sig["public_key"]
        fingerprint = sig.get("fingerprint", "")
        signature_b64 = sig["signature"]
        valid = False
        try:
            if algo == "ECDSA":
                valid = ecdsa_verify(
                    base64.b64decode(pubkey_b64), data_bytes, base64.b64decode(signature_b64))
            elif algo == "ML-DSA":
                valid = ML_DSA_44.verify(
                    base64.b64decode(pubkey_b64), data_bytes, base64.b64decode(signature_b64))
        except Exception as e:
            valid = False
            app.logger.error(f"Verification error for {algo} in order {order.get('order_id')}: {e}")

        verify_results.append({
            "algo": algo,
            "signer": signer,
            "fingerprint": fingerprint,
            "valid": valid
        })
    
    log_action("Decrypt/Verify", f"Transaction '{order.get('order_id')}' decrypted and verified by '{session['username']}'. Verification results: {verify_results}", session['username'])
    return jsonify({
        "success": True,
        "order": order,
        "verify_results": verify_results
    })

# --- API lấy log hệ thống (Đã điều chỉnh quyền và lọc log) ---
@app.route("/api/get_log", methods=["GET"])
@login_required
def api_get_log():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
            
            filtered_logs = [log for log in logs if log.get("user") == session['username'] or log.get("user") == "Guest"]
            
            formatted_logs = "\n".join([
                f"[{log['timestamp']}] User: {log['user']} | Type: {log['action_type']} | Message: {log['message']}"
                for log in filtered_logs
            ])
            return jsonify({"success": True, "log": formatted_logs}), 200
        else:
            return jsonify({"success": True, "log": "Không có log nào."}), 200
    except Exception as e:
        app.logger.error(f"Error reading log file: {e}")
        return jsonify({"success": False, "message": f"Lỗi đọc log: {str(e)}"}), 500

# --- Routes phục vụ HTML (có hoặc không yêu cầu đăng nhập) ---
@app.route('/')
def root_redirect():
    """Chuyển hướng đến trang đăng nhập hoặc dashboard tùy trạng thái session."""
    if 'username' in session:
        return redirect(url_for('index_page'))
    return redirect(url_for('login_page'))

@app.route('/login.html')
def login_page():
    """Phục vụ trang đăng nhập."""
    return render_template('login.html')

@app.route('/register.html')
def register_page():
    """Phục vụ trang đăng ký."""
    return render_template('register.html')

@app.route('/index.html')
@login_required
def index_page():
    """Phục vụ trang dashboard."""
    return render_template('index.html')

@app.route('/generate_key.html')
@login_required
def generate_key_page():
    """Phục vụ trang sinh/lưu khóa."""
    return render_template('generate_key.html')

@app.route('/create_transaction.html')
@login_required
def create_transaction_page():
    """Phục vụ trang tạo giao dịch."""
    return render_template('create_transaction.html')

@app.route('/sign_encrypt.html')
@login_required
def sign_encrypt_page():
    """Phục vụ trang ký số & mã hóa giao dịch."""
    return render_template('sign_encrypt.html')

@app.route('/decrypt_verify.html')
@login_required
def decrypt_verify_page():
    """Phục vụ trang giải mã & xác thực giao dịch."""
    return render_template('decrypt_verify.html')

@app.route('/log.html')
@login_required
def log_page():
    """Phục vụ trang xem log thao tác."""
    return render_template('log.html')

# --- Khởi chạy ứng dụng ---
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5560, debug=True)
