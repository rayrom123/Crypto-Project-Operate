import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from dilithium_py.ml_dsa import ML_DSA_44

# ==== Tiện ích mã hóa/giải mã AES cho file key ML-DSA ====

def encrypt_bytes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext

def decrypt_bytes(key, ciphertext):
    iv = ciphertext[:16]
    data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]

def derive_key_from_passphrase(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase)

# ==== Sinh/lưu key ECDSA, RSA, ML-DSA (có mã hóa passphrase) ====

def ecdsa_keygen(passphrase=None):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption())
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub_bytes, priv_bytes

def rsa_keygen(passphrase=None):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption())
    return pub_bytes, priv_bytes

def mldsa_keygen(passphrase=None):
    pub_bytes, priv_bytes = ML_DSA_44.keygen()
    if passphrase:
        salt = os.urandom(16)
        key = derive_key_from_passphrase(passphrase, salt)
        encrypted_priv = encrypt_bytes(key, priv_bytes)
        return pub_bytes, salt + encrypted_priv
    else:
        return pub_bytes, priv_bytes

def save_pem(filename, pem_bytes):
    with open(filename, "wb") as f:
        f.write(pem_bytes)

# ==== Load key ====

def load_pem(filename, passphrase=None):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        content = f.read()
    if b"ENCRYPTED" in content:
        return serialization.load_pem_private_key(content, password=passphrase)
    return content

def load_pem_pub(filename):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        return f.read()

# ==== Load khóa riêng ML-DSA có passphrase ====

def load_mldsa_priv(filename, passphrase=None):
    if not os.path.exists(filename):
        return None
    with open(filename, "rb") as f:
        content = f.read()
    if passphrase:
        salt = content[:16]
        ciphertext = content[16:]
        key = derive_key_from_passphrase(passphrase, salt)
        priv_bytes = decrypt_bytes(key, ciphertext)
        return priv_bytes
    else:
        return content

# ==== Tiện ích ====

def public_key_fingerprint(pub_bytes):
    return hashlib.sha256(pub_bytes).hexdigest()[:16]

def ecdsa_sign(priv_obj, data_bytes):
    return priv_obj.sign(data_bytes, ec.ECDSA(hashes.SHA256()))

def ecdsa_verify(pub_pem, data_bytes, signature):
    public_key = serialization.load_pem_public_key(pub_pem)
    public_key.verify(signature, data_bytes, ec.ECDSA(hashes.SHA256()))
    return True

def rsa_encrypt(pub_pem, plaintext):
    public_key = serialization.load_pem_public_key(pub_pem)
    return public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(priv_obj, ciphertext):
    return priv_obj.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]*pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]
