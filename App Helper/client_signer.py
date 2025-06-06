# App_Helper/client_signer_app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import base64
import logging

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec # Giữ RSA và EC
from cryptography.hazmat.primitives import padding as sym_padding # Đổi tên import padding đối xứng
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding # Giữ import padding cho asymmetric (ví dụ RSA OAEP)

from dilithium_py.ml_dsa import ML_DSA_44 # Đảm bảo thư viện này được cài đặt

app = Flask(__name__)
# Cho phép CORS cho tất cả các request đến từ frontend (thường là từ localhost:5560)
CORS(app) 

# Thiết lập thư mục lưu trữ private keys trên máy client
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Đường dẫn thư mục App_Helper
CLIENT_KEY_DIR = os.path.join(BASE_DIR, "client_keys")
if not os.path.exists(CLIENT_KEY_DIR):
    os.makedirs(CLIENT_KEY_DIR)

# Cấu hình logging cho App Helper
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Crypto Utilities (tái sử dụng hoặc định nghĩa lại nếu không có modules.crypto_utils.py) ---
def _derive_key(passphrase: bytes, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes for AES-256
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase)

def _encrypt_private_key_aes(private_key_bytes: bytes, passphrase: bytes) -> dict:
    """Mã hóa private key bằng AES-256-CBC với PBKDF2HMAC cho key derivation."""
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    iv = os.urandom(16)
    cipher = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder() # Đã sửa: dùng sym_padding
    padded_data = padder.update(private_key_bytes) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return {
        "encrypted_private_key": base64.b64encode(ciphertext).decode(),
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode()
    }

def _decrypt_private_key_aes(encrypted_data_dict: dict, passphrase: bytes) -> bytes:
    """Giải mã private key đã được mã hóa bằng AES-256-CBC."""
    encrypted_priv_bytes = base64.b64decode(encrypted_data_dict["encrypted_private_key"])
    salt = base64.b64decode(encrypted_data_dict["salt"])
    iv = base64.b64decode(encrypted_data_dict["iv"])
    
    key = _derive_key(passphrase, salt)
    cipher = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_priv_bytes) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder() # Đã sửa: dùng sym_padding
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return data

def save_encrypted_key_file(filepath: str, private_key_bytes: bytes, passphrase: bytes):
    """Lưu private key đã mã hóa vào file JSON."""
    encrypted_data = _encrypt_private_key_aes(private_key_bytes, passphrase)
    with open(filepath, "w") as f:
        json.dump(encrypted_data, f, indent=4)
    app.logger.info(f"Private key encrypted and saved to {filepath}")

def load_encrypted_key_file(filepath: str, passphrase: bytes) -> bytes:
    """Tải và giải mã private key từ file JSON."""
    with open(filepath, "r") as f:
        encrypted_data_dict = json.load(f)
    return _decrypt_private_key_aes(encrypted_data_dict, passphrase)

def public_key_fingerprint(public_key_bytes: bytes) -> str:
    """Tính toán SHA256 fingerprint của public key."""
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(public_key_bytes)
    return hasher.finalize().hex()

# --- API của App Helper ---

@app.route("/generate_key", methods=["POST"])
def client_generate_key():
    data = request.get_json()
    username = data.get("username")
    key_type = data.get("key_type")
    passphrase = data.get("passphrase", "").encode()

    if not username or not key_type or not passphrase:
        app.logger.warning(f"Generate key failed: Missing data for user '{username}'.")
        return jsonify({"success": False, "message": "Username, loại khóa hoặc passphrase không hợp lệ"}), 400

    try:
        priv_bytes = None
        pub_bytes = None
        priv_file_path = None
        pub_file_path = None # Dùng để lưu public key ML-DSA nếu cần

        if key_type == "ECDSA":
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            priv_file_path = os.path.join(CLIENT_KEY_DIR, f"{username}.ecdsa.priv.encrypted")

        elif key_type == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            
            priv_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            priv_file_path = os.path.join(CLIENT_KEY_DIR, f"{username}.rsa.priv.encrypted")

        elif key_type == "ML-DSA":
            mldsa_priv_obj, mldsa_pub_obj = ML_DSA_44.keygen()
            
            priv_bytes = mldsa_priv_obj # ML-DSA private key is bytes
            pub_bytes = mldsa_pub_obj   # ML-DSA public key is bytes

            priv_file_path = os.path.join(CLIENT_KEY_DIR, f"{username}.mldsa.priv.encrypted")
            pub_file_path = os.path.join(CLIENT_KEY_DIR, f"{username}.mldsa.pub") # Lưu public key ML-DSA riêng (không mã hóa)
            
            # Lưu public key ML-DSA trực tiếp (không mã hóa)
            with open(pub_file_path, "wb") as f:
                f.write(pub_bytes)

        else:
            app.logger.warning(f"Generate key failed for user '{username}': Invalid key type '{key_type}'.")
            return jsonify({"success": False, "message": "Loại khóa không hợp lệ"}), 400

        # Lưu private key đã mã hóa bằng passphrase
        if priv_bytes is not None and priv_file_path is not None: # Đã sửa: Kiểm tra None thay vì bool
            save_encrypted_key_file(priv_file_path, priv_bytes, passphrase)
        else:
            raise Exception("Private key or file path not defined after key generation.")

        app.logger.info(f"Key generated successfully for user '{username}', type '{key_type}'.")
        return jsonify({
            "success": True,
            "message": f"Đã sinh {key_type} và lưu private key mã hóa trên máy client.",
            "public_key": base64.b64encode(pub_bytes).decode(), # Gửi public key về frontend
            "fingerprint": public_key_fingerprint(pub_bytes),
            "private_key_file_on_client": priv_file_path # Để debug/thông tin
        })
    except Exception as e:
        app.logger.error(f"Error generating key for user '{username}': {str(e)}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi sinh khóa trên client: {str(e)}"}), 500

@app.route("/sign_transaction", methods=["POST"])
def client_sign_transaction():
    data = request.get_json()
    order_data = data.get("data_to_sign") # Nhận toàn bộ object order
    signer_name = data.get("signer_name")
    ecdsa_passphrase = data.get("ecdsa_passphrase", "").encode()
    mldsa_passphrase = data.get("mldsa_passphrase", "").encode()

    if not order_data or not signer_name:
        app.logger.warning(f"Sign transaction failed: Missing data for user '{signer_name}'.")
        return jsonify({"success": False, "message": "Dữ liệu thiếu để ký."}), 400

    data_bytes = json.dumps(order_data, ensure_ascii=False).encode()
    
    ecdsa_sig_b64 = None
    mldsa_sig_b64 = None
    ecdsa_pub_b64 = None
    mldsa_pub_b64 = None

    # Ký ECDSA
    ecdsa_priv_file = os.path.join(CLIENT_KEY_DIR, f"{signer_name}.ecdsa.priv.encrypted")
    try:
        encrypted_ecdsa_priv_bytes = load_encrypted_key_file(ecdsa_priv_file, ecdsa_passphrase)
        ecdsa_private_key = serialization.load_pem_private_key(
            encrypted_ecdsa_priv_bytes, password=None, backend=default_backend()
        )
        ecdsa_signature = ecdsa_private_key.sign(
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        ecdsa_sig_b64 = base64.b64encode(ecdsa_signature).decode()
        ecdsa_public_key_pem = ecdsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ecdsa_pub_b64 = base64.b64encode(ecdsa_public_key_pem).decode()
        app.logger.info(f"ECDSA signing successful for user '{signer_name}'.")
    except Exception as e:
        app.logger.error(f"ECDSA signing failed for user '{signer_name}': {e}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi ký ECDSA: {str(e)}. Sai passphrase hoặc khóa không tồn tại."}), 400

    # Ký ML-DSA
    mldsa_priv_file = os.path.join(CLIENT_KEY_DIR, f"{signer_name}.mldsa.priv.encrypted")
    mldsa_pub_file = os.path.join(CLIENT_KEY_DIR, f"{signer_name}.mldsa.pub") # Public key của ML-DSA được lưu riêng
    try:
        encrypted_mldsa_priv_bytes = load_encrypted_key_file(mldsa_priv_file, mldsa_passphrase)
        mldsa_signature = ML_DSA_44.sign(encrypted_mldsa_priv_bytes, data_bytes)
        mldsa_sig_b64 = base64.b64encode(mldsa_signature).decode()

        with open(mldsa_pub_file, 'rb') as f:
            mldsa_pub_b64 = base64.b64encode(f.read()).decode()
        app.logger.info(f"ML-DSA signing successful for user '{signer_name}'.")
    except Exception as e:
        app.logger.error(f"ML-DSA signing failed for user '{signer_name}': {e}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi ký ML-DSA: {str(e)}. Sai passphrase hoặc khóa không tồn tại."}), 400

    return jsonify({
        "success": True,
        "message": "Ký số thành công trên client.",
        "ecdsa_signature": ecdsa_sig_b64,
        "ecdsa_public_key": ecdsa_pub_b64,
        "mldsa_signature": mldsa_sig_b64,
        "mldsa_public_key": mldsa_pub_b64,
    })

@app.route("/decrypt_transaction", methods=["POST"])
def client_decrypt_transaction():
    data = request.get_json()
    encrypted_data = data.get("encrypted_data")
    receiver_name = data.get("receiver_name")
    rsa_passphrase = data.get("rsa_passphrase", "").encode()

    if not encrypted_data or not receiver_name:
        app.logger.warning(f"Decrypt transaction failed: Missing data for user '{receiver_name}'.")
        return jsonify({"success": False, "message": "Dữ liệu giải mã bị thiếu."}), 400

    rsa_priv_file = os.path.join(CLIENT_KEY_DIR, f"{receiver_name}.rsa.priv.encrypted")
    
    try:
        encrypted_rsa_priv_bytes = load_encrypted_key_file(rsa_priv_file, rsa_passphrase)
        rsa_private_key = serialization.load_pem_private_key(
            encrypted_rsa_priv_bytes, password=None, backend=default_backend()
        )

        rsa_key_cipher = base64.b64decode(encrypted_data["rsa_key_cipher"])
        iv = base64.b64decode(encrypted_data["iv"])
        aes_ciphertext = base64.b64decode(encrypted_data["aes_ciphertext"])

        aes_key = rsa_private_key.decrypt(
            rsa_key_cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Hàm aes_decrypt (nếu bạn không có từ crypto_utils)
        cipher = ciphers.Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(aes_ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder() # Đã sửa: dùng sym_padding
        json_bytes = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        package = json.loads(json_bytes)
        app.logger.info(f"Decryption successful for user '{receiver_name}'.")

        return jsonify({
            "success": True,
            "message": "Giải mã thành công trên client.",
            "decrypted_package": package # Gửi toàn bộ package đã giải mã về backend
        })

    except Exception as e:
        app.logger.error(f"RSA decryption failed for user '{receiver_name}': {e}", exc_info=True)
        return jsonify({"success": False, "message": f"Lỗi giải mã: {str(e)}. Sai passphrase hoặc khóa không tồn tại."}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
