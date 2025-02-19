import random
import string
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import html

class SecurityLabs:
    @staticmethod
    def generate_secure_password(length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    @staticmethod
    def simulate_sql_injection(user_input):
        # Simulated vulnerable query
        vulnerable_query = f"SELECT * FROM users WHERE username = '{user_input}'"
        
        # Check for SQL injection attempts
        dangerous_chars = ["'", ";", "--", "/*", "*/", "UNION", "SELECT", "DROP", "DELETE"]
        is_attack = any(char.upper() in user_input.upper() for char in dangerous_chars)
        
        return {
            'query': vulnerable_query,
            'is_attack': is_attack,
            'explanation': 'SQL injection detected!' if is_attack else 'Input appears safe'
        }

    @staticmethod
    def simulate_xss(user_input):
        # Demonstrate XSS vulnerability vs protection
        vulnerable_output = user_input
        protected_output = html.escape(user_input)
        
        return {
            'vulnerable': vulnerable_output,
            'protected': protected_output,
            'is_attack': '<script>' in user_input.lower()
        }

    @staticmethod
    def generate_encryption_keys():
        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        return {
            'private_key': private_key.decode(),
            'public_key': public_key.decode()
        }

    @staticmethod
    def encrypt_file(file_data, recipient_public_key):
        # Generate a random session key
        session_key = get_random_bytes(16)
        
        # Encrypt the session key with RSA
        recipient_key = RSA.import_key(recipient_public_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        
        # Encrypt the file data with AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
        
        return {
            'encrypted_session_key': b64encode(enc_session_key).decode('utf-8'),
            'nonce': b64encode(cipher_aes.nonce).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8')
        }

    @staticmethod
    def analyze_phishing_email(email_content):
        indicators = {
            'urgency': ['urgent', 'immediate', 'account suspended', 'security alert'],
            'personal_info': ['ssn', 'password', 'credit card', 'bank account'],
            'suspicious_sender': ['@gmail.com', '@yahoo.com', '@hotmail.com'],
            'poor_grammar': ['kindly', 'dear sir', 'dear madam', 'yours truly'],
            'threats': ['suspended', 'terminated', 'legal action', 'police']
        }
        
        results = {}
        email_lower = email_content.lower()
        
        for category, words in indicators.items():
            matches = [word for word in words if word in email_lower]
            results[category] = {
                'detected': bool(matches),
                'matches': matches
            }
        
        risk_score = sum(1 for cat in results.values() if cat['detected']) / len(indicators) * 100
        
        return {
            'indicators': results,
            'risk_score': risk_score,
            'is_suspicious': risk_score > 40
        }

    @staticmethod
    def simulate_brute_force(password, attempt_limit=1000):
        chars = string.ascii_lowercase + string.digits
        attempts = 0
        found = False
        
        # Simulate limited brute force attempts
        while attempts < attempt_limit and not found:
            attempt = ''.join(random.choices(chars, k=len(password)))
            attempts += 1
            if attempt == password:
                found = True
        
        return {
            'success': found,
            'attempts': attempts,
            'time_estimate_full': (attempts / attempt_limit) * (len(chars) ** len(password)) / 1000,
            'password_space': len(chars) ** len(password)
        }
