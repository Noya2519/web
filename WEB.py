from flask import Flask, request, send_file, jsonify
import os
import base64
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
    encrypted = cipher.encrypt(pad(data, DES.block_size))
    return base64.b64encode(encrypted)

def des_decrypt(data, key):
    key = key[:8].ljust(8, '0').encode()
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(data)), DES.block_size)
    return decrypted

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
RESULT_FOLDER = "results"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    file = request.files["file"]
    key = request.form["key"]
    method = request.form["method"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    with open(filepath, "rb") as f:
        data = f.read()
    
    if method == "XOR":
        encrypted_data = xor_encrypt(data, key)
    elif method == "AES":
        encrypted_data = aes_encrypt(data, key)
    elif method == "DES":
        encrypted_data = des_encrypt(data, key)
    
    encrypted_path = os.path.join(RESULT_FOLDER, file.filename + ".enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
    
    return jsonify({"download_url": f"/download/{file.filename}.enc"})

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    file = request.files["file"]
    key = request.form["key"]
    method = request.form["method"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    with open(filepath, "rb") as f:
        data = f.read()
    
    if method == "XOR":
        decrypted_data = xor_decrypt(data, key)
    elif method == "AES":
        decrypted_data = aes_decrypt(data, key)
    elif method == "DES":
        decrypted_data = des_decrypt(data, key)
    
    decrypted_path = os.path.join(RESULT_FOLDER, file.filename.replace(".enc", "_decrypted"))
    with open(decrypted_path, "wb") as f:
        f.write(decrypted_data)
    
    return jsonify({"download_url": f"/download/{file.filename.replace('.enc', '_decrypted')}"})

@app.route("/download/<filename>")
def download(filename):
    return send_file(os.path.join(RESULT_FOLDER, filename), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)