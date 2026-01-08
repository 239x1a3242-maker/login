import os
import json
import random
import datetime
import re
import smtplib
from flask import Flask, request, jsonify, render_template, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email.mime.text import MIMEText
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)

# --- Flask-Limiter ---
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])

# --- Email Config (Gmail SMTP) ---
SMTP_EMAIL = 'rn8711399@gmail.com'
SMTP_PASSWORD = 'your token here'  # Gmail App Password
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# --- JSON file paths ---
USERS_FILE = 'users.json'
RESET_OTPS_FILE = 'reset_otps.json'

# --- JSON Load/Save Helpers ---
def load_json(path, default):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, type(default)) else default
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def load_users(): return load_json(USERS_FILE, [])
def save_users(data): save_json(USERS_FILE, data)
def load_reset_otps(): return load_json(RESET_OTPS_FILE, {})
def save_reset_otps(data): save_json(RESET_OTPS_FILE, data)

# --- Utils ---
def is_valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def send_otp_email(to_email, otp):
    subject = "Your OTP for Password Reset"
    body = f"Your OTP is: {otp}. It is valid for 5 minutes."

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_EMAIL
    msg['To'] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# --- Routes ---
@app.route('/')
def index():
    return render_template('chat.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/auth.html')
def auth_html():
    return redirect('/auth')

@app.route('/index')
def home():
    return render_template('chat.html')

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name, email, password = data.get('name'), data.get('email'), data.get('password')
    errors = {}

    if not name: errors['name'] = 'Username is required.'
    if not email or not is_valid_email(email): errors['email'] = 'Valid email required.'
    if not password or len(password) < 6: errors['password'] = 'Password must be at least 6 characters.'

    if errors:
        return jsonify({'message': 'Validation failed.', 'errors': errors}), 400

    users = load_users()
    if any(u['email'].lower() == email.lower() for u in users):
        return jsonify({'message': 'Email already registered.'}), 409
    if any(u['name'].lower() == name.lower() for u in users):
        return jsonify({'message': 'Username already taken.'}), 409

    hashed_pw = pbkdf2_sha256.hash(password)
    users.append({'name': name, 'email': email, 'password': hashed_pw})
    save_users(users)
    os.makedirs(f'userdata/{name}', exist_ok=True)

    return jsonify({'message': 'Signup successful!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username_or_email, password = data.get('username_or_email'), data.get('password')
    errors = {}

    if not username_or_email: errors['username_or_email'] = 'Username or Email is required.'
    if not password: errors['password'] = 'Password is required.'
    if errors: return jsonify({'message': 'Validation failed.', 'errors': errors}), 400

    users = load_users()
    user = next((u for u in users if u['email'].lower() == username_or_email.lower()
                or u['name'].lower() == username_or_email.lower()), None)

    if user and pbkdf2_sha256.verify(password, user['password']):
        return jsonify({'message': 'Login successful.', 'user': {'name': user['name'], 'email': user['email']}}), 200
    return jsonify({'message': 'Invalid credentials.'}), 401

@app.route('/api/forgot_password_request', methods=['POST'])
@limiter.limit("10 per minute")
def forgot_password_request():
    data = request.get_json()
    email = data.get('email')
    print(f"DEBUG: Received email: {email}")
    if not email or not is_valid_email(email):
        print(f"DEBUG: Email validation failed for: {email}")
        return jsonify({'message': 'Valid email required.'}), 400

    users = load_users()
    print(f"DEBUG: Loaded users: {users}")
    email_lower = email.lower()
    found = any(u['email'].lower() == email_lower for u in users)
    print(f"DEBUG: Email {email_lower} found in users: {found}")

    if not found:
        print(f"DEBUG: Email not registered: {email}")
        return jsonify({'message': 'Email not registered. Please check your email address or sign up.'}), 404

    otp = str(random.randint(10000000, 99999999))
    expiry = (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat()

    print(f"DEBUG: Attempting to send OTP to: {email}")
    if not send_otp_email(email, otp):
        print(f"DEBUG: Email sending failed for: {email}")
        return jsonify({'message': 'Failed to send OTP. Try again later.'}), 500

    otps = load_reset_otps()
    otps[email] = {'otp': otp, 'expiry': expiry, 'verified': False}
    save_reset_otps(otps)

    print(f"DEBUG: OTP sent successfully to: {email}")
    return jsonify({'message': 'OTP sent to your email.'}), 200

@app.route('/api/verify_otp', methods=['POST'])
@limiter.limit("5 per hour")
def verify_otp():
    data = request.get_json()
    email, otp = data.get('email'), data.get('otp')

    otps = load_reset_otps()
    if email not in otps or otps[email]['otp'] != otp:
        return jsonify({'message': 'Invalid OTP.'}), 401

    expiry = datetime.datetime.fromisoformat(otps[email]['expiry'])
    if datetime.datetime.now() > expiry:
        del otps[email]
        save_reset_otps(otps)
        return jsonify({'message': 'OTP expired.'}), 401

    otps[email]['verified'] = True
    save_reset_otps(otps)
    return jsonify({'message': 'OTP verified. You can reset your password now.'}), 200

@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email, new_pw = data.get('email'), data.get('new_password')

    if not new_pw or len(new_pw) < 6:
        return jsonify({'message': 'New password must be at least 6 characters.'}), 400

    otps = load_reset_otps()
    if not otps.get(email, {}).get('verified'):
        return jsonify({'message': 'OTP not verified.'}), 403

    users = load_users()
    for user in users:
        if user['email'].lower() == email.lower():
            user['password'] = pbkdf2_sha256.hash(new_pw)
            save_users(users)
            del otps[email]
            save_reset_otps(otps)
            return jsonify({'message': 'Password reset successful.'}), 200

    return jsonify({'message': 'User not found.'}), 404

@app.route('/api/check_user', methods=['POST'])
def check_user():
    data = request.get_json()
    identifier = data.get('identifier')  # email or name
    users = load_users()
    exists = any(u['email'].lower() == identifier.lower() or u['name'].lower() == identifier.lower() for u in users)
    return jsonify({'exists': exists})

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    # For now, return a mock response since no AI model is integrated
    # In a real implementation, this would process the prompt and files with an AI model
    prompt = request.form.get('prompt', '')
    files = request.files.getlist('files')
    
    # Mock response
    response = f"I received your message: '{prompt}'. "
    if files:
        response += f"You attached {len(files)} file(s): {[f.filename for f in files]}."
    else:
        response += "No files attached."
    
    response += " This is a placeholder response. Please integrate with your preferred AI model."
    
    return jsonify({'response': response})

if __name__ == '__main__':
    for file, init in [(USERS_FILE, []), (RESET_OTPS_FILE, {})]:
        try:
            with open(file, 'x') as f: json.dump(init, f)
        except FileExistsError:
            pass
    app.run(debug=True)


