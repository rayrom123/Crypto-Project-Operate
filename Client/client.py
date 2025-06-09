import os
import json
import datetime
import base64
import requests
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives import serialization
from flask_cors import CORS
from modules.crypto_utils import (
    ecdsa_keygen, rsa_keygen, mldsa_keygen, save_pem, load_pem, load_mldsa_priv,
    public_key_fingerprint, ecdsa_sign, ecdsa_verify, rsa_decrypt, aes_decrypt,
    aes_encrypt, rsa_encrypt, load_pem_pub
)
from dilithium_py.ml_dsa import ML_DSA_44

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = "secret_key"  
SERVER_BASE_URL = "https://crypto-project-operate.onrender.com"
if getattr(sys, 'frozen', False):
    # Nếu ứng dụng đang chạy dưới dạng đóng gói (ví dụ: PyInstaller)
    # Lấy đường dẫn của file .exe
    application_path = os.path.dirname(sys.executable)
else:
    # Nếu ứng dụng đang chạy dưới dạng file .py bình thường
    application_path = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = application_path
KEY_DIR = os.path.join(BASE_DIR, "user_keys")
TRANSACTION_DIR = os.path.join(BASE_DIR, "transactions")
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(TRANSACTION_DIR, exist_ok=True)

def get_pubkey_live(server_base_url, username, key_type):
    import requests
    res = requests.get(f"{server_base_url}/api/get_pubkey", params={"username": username, "key_type": key_type})
    data = res.json()
    if data.get("success"):
        pubkey_pem = data["pubkey_pem"]
        return pubkey_pem.encode() if isinstance(pubkey_pem, str) else pubkey_pem
    else:
        raise Exception(data.get("message", "Không lấy được public key!"))

@app.route("/")
def home():
    return send_from_directory('.', "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    # Phục vụ mọi file html, css, js từ thư mục hiện tại
    return send_from_directory('.', filename)

# ---- API sinh key ----
@app.route("/api/generate_key", methods=["POST"])
def api_generate_key():
    data = request.get_json()
    username = data.get("username")
    passphrase = data.get("passphrase", "")
    key_type = data.get("key_type", "ECDSA") # Cho phép chọn loại key

    passphrase_bytes = passphrase.encode() if passphrase else None
    if not (username and key_type):
        return jsonify({"success": False, "message": "Thiếu thông tin"}), 400

    if key_type == "ECDSA":
        pub_bytes, priv_bytes = ecdsa_keygen(passphrase_bytes)
        pub_file = f"{KEY_DIR}/{username}.ecdsa.pub.pem"
        priv_file = f"{KEY_DIR}/{username}.ecdsa.priv.pem"
    elif key_type == "RSA":
        pub_bytes, priv_bytes = rsa_keygen(passphrase_bytes)
        pub_file = f"{KEY_DIR}/{username}.rsa.pub.pem"
        priv_file = f"{KEY_DIR}/{username}.rsa.priv.pem"
    elif key_type == "ML-DSA":
        pub_bytes, priv_bytes = mldsa_keygen(passphrase_bytes)
        pub_file = f"{KEY_DIR}/{username}.mldsa.pub"
        priv_file = f"{KEY_DIR}/{username}.mldsa.priv"
    else:
        return jsonify({"success": False, "message": "Loại khóa không hợp lệ"}), 400

    save_pem(pub_file, pub_bytes)
    save_pem(priv_file, priv_bytes)
    return jsonify({
        "success": True,
        "message": f"Đã sinh và lưu {key_type} cho {username}",
        "public_key": base64.b64encode(pub_bytes).decode(),
        "fingerprint": public_key_fingerprint(pub_bytes),
        "pub_file": os.path.basename(pub_file),
        "priv_file": os.path.basename(priv_file)
    })

# ---- API tạo giao dịch ----
@app.route("/api/create_transaction", methods=["POST"])
def api_create_transaction():
    data = request.get_json()
    order = {
        "order_id": data.get("order_id"),
        "buyer": data.get("buyer"),
        "seller": data.get("seller"),
        "amount": data.get("amount"),
        "currency": data.get("currency"),
        "items": [item.strip() for item in data.get("items", "").split(",")],
        "timestamp": datetime.datetime.now().isoformat()
    }
    filename = f'{TRANSACTION_DIR}/order_{order["order_id"]}_{int(datetime.datetime.now().timestamp())}.json'
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(order, f, ensure_ascii=False, indent=2)
        return jsonify({
            "success": True,
            "message": f"Đã lưu giao dịch vào {os.path.basename(filename)}",
            "filename": os.path.basename(filename),
            "order": order
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi lưu file: {e}"}), 500

# ---- API ký số & mã hóa ----
@app.route("/api/sign_and_encrypt_transaction", methods=["POST"])
def sign_and_encrypt_transaction():
    req = request.get_json()
    data_to_sign = req["data_to_sign"]
    signer_name = req["signer_name"]
    ecdsa_passphrase = req["ecdsa_passphrase"]
    mldsa_passphrase = req["mldsa_passphrase"]
    receiver_name = req["receiver_name"]

    data_bytes = json.dumps(data_to_sign, ensure_ascii=False).encode()

    # --- Ký ECDSA ---
    try:
        ecdsa_priv_obj = load_pem(
            os.path.join(KEY_DIR, f"{signer_name}.ecdsa.priv.pem"),
            passphrase=ecdsa_passphrase.encode()
        )
        if not hasattr(ecdsa_priv_obj, 'sign'):
            return jsonify({"success": False, "message": "Không load được khóa ECDSA"}), 400
        ecdsa_sig = ecdsa_sign(ecdsa_priv_obj, data_bytes)
        ecdsa_pub_pem = ecdsa_priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        return jsonify({"success": False, "message": f"Ký ECDSA lỗi: {e}"}), 400

    # --- Ký ML-DSA ---
    try:
        mldsa_priv = load_mldsa_priv(
            os.path.join(KEY_DIR, f"{signer_name}.mldsa.priv"),
            passphrase=mldsa_passphrase.encode()
        )
        mldsa_pub = open(os.path.join(KEY_DIR, f"{signer_name}.mldsa.pub"), "rb").read()
        mldsa_sig = ML_DSA_44.sign(mldsa_priv, data_bytes)
    except Exception as e:
        return jsonify({"success": False, "message": f"Ký ML-DSA lỗi: {e}"}), 400

    # --- Đóng gói package để mã hóa ---
    package = {
        "order": data_to_sign,
        "signatures": [
            {
                "algo": "ECDSA",
                "signer_name": signer_name,
                "signature": base64.b64encode(ecdsa_sig).decode(),
                "public_key": base64.b64encode(ecdsa_pub_pem).decode()
            },
            {
                "algo": "ML-DSA",
                "signer_name": signer_name,
                "signature": base64.b64encode(mldsa_sig).decode(),
                "public_key": base64.b64encode(mldsa_pub).decode()
            }
        ]
    }
    package_bytes = json.dumps(package, ensure_ascii=False, indent=2).encode()

    # --- Mã hóa AES+RSA tại local ---
    try:
        aes_key = os.urandom(32)
        iv, aes_ciphertext = aes_encrypt(aes_key, package_bytes)
        rsa_pub = get_pubkey_live(SERVER_BASE_URL, receiver_name, "RSA")
        if not rsa_pub:
            return jsonify({"success": False, "message": "Không load được public key RSA của người nhận"}), 400
        rsa_key_cipher = rsa_encrypt(rsa_pub, aes_key)
    except Exception as e:
        return jsonify({"success": False, "message": f"Mã hóa AES+RSA lỗi: {e}"}), 400

    encrypted_package = {
        "rsa_key_cipher": base64.b64encode(rsa_key_cipher).decode(),
        "iv": base64.b64encode(iv).decode(),
        "aes_ciphertext": base64.b64encode(aes_ciphertext).decode(),
        "encrypted_for_receiver": receiver_name,
        "order_id": data_to_sign["order_id"]
    }

    encrypted_filename = f'transaction_{data_to_sign["order_id"]}_{int(datetime.datetime.now().timestamp())}.encrypted'
    encrypted_filepath = os.path.join(TRANSACTION_DIR, encrypted_filename)
    try:
        with open(encrypted_filepath, "w", encoding="utf-8") as f:
            json.dump(encrypted_package, f, indent=2, ensure_ascii=False)
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi lưu file đã mã hóa: {e}"}), 500

    return jsonify({
        "success": True,
        "encrypted_data": encrypted_package,
        "suggest_filename": encrypted_filename
    })
# ---- API giải mã & xác thực ----
@app.route("/decrypt_transaction", methods=["POST"])
def decrypt_transaction():
    f = request.files['encrypted_file']
    receiver_name = request.form.get("receiver_name")
    rsa_passphrase = request.form.get("rsa_passphrase")
    content = json.load(f)
    
    # Load private RSA key của người nhận
    rsa_priv = load_pem(
        os.path.join(KEY_DIR, f"{receiver_name}.rsa.priv.pem"),
        passphrase=rsa_passphrase.encode()
    )
    try:
        aes_key = rsa_decrypt(rsa_priv, base64.b64decode(content['rsa_key_cipher']))
        iv = base64.b64decode(content['iv'])
        aes_ciphertext = base64.b64decode(content['aes_ciphertext'])
        json_bytes = aes_decrypt(aes_key, iv, aes_ciphertext)
        package = json.loads(json_bytes)
    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi giải mã: {e}"}), 400

    # Xác minh chữ ký
    order = package["order"]
    data_bytes = json.dumps(order, ensure_ascii=False).encode()
    verify_results = []
    for sig in package["signatures"]:
        algo = sig["algo"]
        pubkey_b64 = sig["public_key"]
        signature_b64 = sig["signature"]
        fingerprint = sig.get("fingerprint", "")
        valid = False
        try:
            if algo == "ECDSA":
                valid = ecdsa_verify(base64.b64decode(pubkey_b64), data_bytes, base64.b64decode(signature_b64))
            elif algo == "ML-DSA":
                valid = ML_DSA_44.verify(base64.b64decode(pubkey_b64), data_bytes, base64.b64decode(signature_b64))
        except Exception as e:
            valid = False
        verify_results.append({
            "algo": algo,
            "signer": sig.get("signer_name", "??"),
            "fingerprint": fingerprint,
            "valid": valid
        })

    return jsonify({
        "success": True,
        "order": order,
        "verify_results": verify_results
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5550, debug=True)
