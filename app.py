from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
import base64
import binascii
import csv
from datetime import datetime
import os

app = Flask(__name__)
DATA_FILE = "data.csv"

# AES Configuration
KEY = bytes.fromhex('2B7E151628AED2A6ABF7158809CF4F3C')
IV = b'1234567890123456'

def decrypt_aes(hex_data):
    try:
        encrypted_bytes = bytes.fromhex(hex_data)
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted = cipher.decrypt(encrypted_bytes)
        decrypted = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
        return decrypted
    except Exception as e:
        print("Desencriptación fallida:", e)
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/post', methods=['POST'])
def post_data():
    content = request.get_json()
    hex_data = content.get("data", "")
    decrypted = decrypt_aes(hex_data)
    if decrypted:
        with open(DATA_FILE, 'a') as f:
            writer = csv.writer(f)
            writer.writerow([decrypted, datetime.utcnow().isoformat()])
    return jsonify({"status": "ok"})

@app.route('/data')
def get_data():
    if not os.path.exists(DATA_FILE):
        return jsonify([])
    result = []
    with open(DATA_FILE, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            result.append({"data": row[0], "timestamp": row[1]})
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)