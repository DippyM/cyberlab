from flask import Flask, render_template, jsonify, request
from cryptography.fernet import Fernet
import bcrypt
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Password strength patterns
patterns = {
    'length': lambda p: len(p) >= 8,
    'uppercase': lambda p: bool(re.search(r'[A-Z]', p)),
    'lowercase': lambda p: bool(re.search(r'[a-z]', p)),
    'numbers': lambda p: bool(re.search(r'\d', p)),
    'special': lambda p: bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', p))
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze-password', methods=['POST'])
def analyze_password():
    password = request.json.get('password', '')
    results = {key: pattern(password) for key, pattern in patterns.items()}
    strength = sum(results.values()) / len(patterns) * 100
    return jsonify({
        'strength': strength,
        'checks': results
    })

@app.route('/api/encrypt', methods=['POST'])
def encrypt_text():
    text = request.json.get('text', '')
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted = f.encrypt(text.encode())
    return jsonify({
        'encrypted': encrypted.decode(),
        'key': key.decode()
    })

@app.route('/api/decrypt', methods=['POST'])
def decrypt_text():
    try:
        encrypted = request.json.get('encrypted', '').encode()
        key = request.json.get('key', '').encode()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted)
        return jsonify({
            'decrypted': decrypted.decode()
        })
    except Exception as e:
        return jsonify({
            'error': 'Invalid key or encrypted text'
        }), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
