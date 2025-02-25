from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import base64
import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

def xor_cipher(data, key):
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def xor_encrypt(data, key):
    return base64.b64encode(xor_cipher(data, key))

def xor_decrypt(data, key):
    return xor_cipher(base64.b64decode(data), key)

def derive_aes_key(key):
    return hashlib.sha256(key.encode()).digest()

def aes_encrypt(data, key):
    key = derive_aes_key(key)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(pad(data, 16)) + encryptor.finalize()
    return iv + encrypted_data

def aes_decrypt(data, key):
    key = derive_aes_key(key)
    iv, encrypted_data = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(encrypted_data) + decryptor.finalize(), 16)

def des_encrypt(data, key):
    key = key[:8].ljust(8, '0').encode()
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(data, DES.block_size)))

def des_decrypt(data, key):
    key = key[:8].ljust(8, '0').encode()
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(data)), DES.block_size)

app = Flask(__name__)
CORS(app)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    file = request.files["file"]
    key = request.form["key"]
    method = request.form["method"]
    data = file.read()
    
    if method == "AES":
        encrypted_data = aes_encrypt(data, key)
    elif method == "DES":
        encrypted_data = des_encrypt(data, key)
    elif method == "XOR":
        encrypted_data = xor_encrypt(data, key)
    else:
        return jsonify({"error": "Metode tidak didukung"}), 400
    
    encrypted_file_path = os.path.join(UPLOAD_FOLDER, file.filename + ".enc")
    with open(encrypted_file_path, "wb") as f:
        f.write(encrypted_data)
    
    return jsonify({"download_url": encrypted_file_path})

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    file = request.files["file"]
    key = request.form["key"]
    method = request.form["method"]
    data = file.read()
    
    if method == "AES":
        decrypted_data = aes_decrypt(data, key)
    elif method == "DES":
        decrypted_data = des_decrypt(data, key)
    elif method == "XOR":
        decrypted_data = xor_decrypt(data, key)
    else:
        return jsonify({"error": "Metode tidak didukung"}), 400
    
    decrypted_file_path = os.path.join(UPLOAD_FOLDER, file.filename.replace(".enc", "_decrypted"))
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)
    
    return jsonify({"download_url": decrypted_file_path})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
