from flask import Flask, request, jsonify, render_template
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

app = Flask(__name__)

# AES Configuración (clave de 16 bytes y IV de 16 bytes)
KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
             0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F])
IV = b'1234567890123456'

data_store = []

def decrypt_data(encrypted_hex):
    try:
        encrypted_bytes = binascii.unhexlify(encrypted_hex)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print("Desencriptación fallida:", e)
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/post', methods=['POST'])
def post_data():
    content = request.get_json()
    encrypted = content.get('data')
    decrypted = decrypt_data(encrypted)
    if decrypted:
        data_store.append({
            "raw": encrypted,
            "data": decrypted,
            "timestamp": datetime.utcnow().isoformat()
        })
        return jsonify({"status": "ok"})
    return jsonify({"status": "error", "message": "decryption failed"})

@app.route('/data')
def get_data():
    return jsonify(data_store)
