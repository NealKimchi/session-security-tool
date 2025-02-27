import base64
import json
import hmac
import hashlib
import time
from flask import Flask, render_template, request, make_response, redirect, url_for, session, jsonify
import secrets
import datetime
import os
import sys
from functools import wraps

# Add the correct path to the scripts directory
current_dir = os.path.abspath(os.path.dirname(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "../.."))
sys.path.append(project_root)

# Now import from scripts directory
from scripts.run_analyzer import analyze_token

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

# Different security levels for tokens
SECURITY_LEVELS = {
    'high': {
        'algorithm': 'sha256',
        'expiration': 3600,  # 1 hour
        'http_only': True,
        'secure': True,
        'same_site': 'Strict'
    },
    'medium': {
        'algorithm': 'sha256',
        'expiration': 86400,  # 24 hours
        'http_only': True,
        'secure': False,
        'same_site': 'Lax'
    },
    'low': {
        'algorithm': 'sha256',  # Using same algorithm but with a weak key
        'expiration': 604800,  # 7 days
        'http_only': False,
        'secure': False,
        'same_site': None
    }
}

# User database (in-memory for simplicity)
users = {
    'admin': 'admin',
    'user1': 'user1',
    'guest': 'guest'
}

# Custom token functions to replace JWT
def encode_base64_url_safe(data):
    """Encode data as base64 URL safe string."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def decode_base64_url_safe(data):
    """Decode base64 URL safe string."""
    padding = b'=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data.encode('utf-8') + padding)

def sign_data(data, key, algorithm='sha256'):
    """Sign data with HMAC using specified algorithm and key."""
    if algorithm == 'sha256':
        return hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).digest()
    # Add more algorithms if needed
    return b''  # Return empty bytes if algorithm not supported

def generate_token(username, security_level='high'):
    """Generate a custom token (similar to JWT but without the library)."""
    settings = SECURITY_LEVELS[security_level]
    
    # Create header
    header = {
        'alg': settings['algorithm'],
        'typ': 'SES'  # Custom type for Session
    }
    
    # Create payload
    current_time = int(time.time())
    payload = {
        'sub': username,
        'iat': current_time,
        'security_level': security_level
    }
    
    # Add expiration if set
    if settings['expiration']:
        payload['exp'] = current_time + settings['expiration']
    
    # Encode header and payload
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload, separators=(',', ':'))
    
    header_b64 = encode_base64_url_safe(header_json.encode('utf-8'))
    payload_b64 = encode_base64_url_safe(payload_json.encode('utf-8'))
    
    # Create signature
    message = f"{header_b64}.{payload_b64}"
    
    # For low security level, use a weak key
    if security_level == 'low':
        secret_key = 'weak_secret'
    else:
        secret_key = app.secret_key
    
    # Sign the message
    signature = sign_data(message, secret_key, settings['algorithm'])
    signature_b64 = encode_base64_url_safe(signature)
    
    # Combine all parts to create the token
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return token

def decode_token(token, verify=True):
    """Decode and verify a custom token."""
    try:
        # Split the token into its parts
        parts = token.split('.')
        if len(parts) != 3:
            return None, "Invalid token format"
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Decode header and payload
        try:
            header_json = decode_base64_url_safe(header_b64).decode('utf-8')
            payload_json = decode_base64_url_safe(payload_b64).decode('utf-8')
            
            header = json.loads(header_json)
            payload = json.loads(payload_json)
        except Exception as e:
            return None, f"Error decoding token parts: {str(e)}"
        
        # Check if token is expired
        if 'exp' in payload and payload['exp'] < time.time():
            return None, "Token expired"
        
        # Verify signature if required
        if verify:
            message = f"{header_b64}.{payload_b64}"
            algorithm = header.get('alg', 'sha256')
            
            # Try with app secret key first
            expected_signature = sign_data(message, app.secret_key, algorithm)
            expected_signature_b64 = encode_base64_url_safe(expected_signature)
            
            if signature_b64 != expected_signature_b64:
                # If that fails, try with the weak key for low security
                expected_signature = sign_data(message, 'weak_secret', algorithm)
                expected_signature_b64 = encode_base64_url_safe(expected_signature)
                
                if signature_b64 != expected_signature_b64:
                    return None, "Invalid signature"
        
        return payload, None
    except Exception as e:
        return None, f"Error decoding token: {str(e)}"

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('session_token')
        if not token:
            return redirect(url_for('login'))
        
        payload, error = decode_token(token)
        if payload is None:
            print(f"Login validation error: {error}")
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        security_level = request.form.get('security_level', 'high')
        
        if username in users and users[username] == password:
            # Generate token with selected security level
            token = generate_token(username, security_level)
            
            # Create response with redirect
            response = make_response(redirect(url_for('dashboard')))
            
            # Set cookie based on security level
            settings = SECURITY_LEVELS[security_level]
            response.set_cookie(
                'session_token', 
                token,
                httponly=settings['http_only'],
                secure=settings['secure'],
                samesite=settings['same_site'],
                max_age=settings['expiration']
            )
            
            return response
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    token = request.cookies.get('session_token')
    
    payload, error = decode_token(token)
    
    if payload is None:
        # For demo purposes, show the error
        username = "Error decoding token"
        security_level = "Unknown"
        expiration_str = error
    else:
        username = payload.get('sub', 'Unknown')
        security_level = payload.get('security_level', 'Unknown')
        expiration = payload.get('exp')
        
        if expiration:
            expiration_time = datetime.datetime.fromtimestamp(expiration)
            time_remaining = expiration_time - datetime.datetime.now()
            expiration_str = f"{time_remaining.total_seconds() / 60:.1f} minutes"
        else:
            expiration_str = "No expiration"
    
    return render_template('dashboard.html', 
                          username=username, 
                          security_level=security_level,
                          expiration=expiration_str,
                          session_token=token)

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('session_token')
    return response

@app.route('/vulnerable')
def vulnerable():
    """Endpoint with intentionally vulnerable session handling"""
    return render_template('vulnerable.html')

@app.route('/token-info')
def token_info():
    """Display information about the current token"""
    token = request.cookies.get('session_token')
    
    if not token:
        return jsonify({"error": "No token found"})
    
    payload, error = decode_token(token, verify=True)
    
    if payload is None:
        # Try without verification
        payload, error = decode_token(token, verify=False)
        verified = False
        if payload is None:
            return jsonify({"error": error})
    else:
        verified = True
    
    return jsonify({
        "token": token,
        "decoded": payload,
        "verified": verified
    })

@app.route('/api/create-vulnerable-token')
def create_vulnerable_token():
    """Create an intentionally vulnerable token"""
    # Get current token to extract username if possible
    current_token = request.cookies.get('session_token')
    username = 'hacker'
    
    # Try to extract username from current token
    if current_token:
        payload, _ = decode_token(current_token, verify=False)
        if payload:
            username = payload.get('sub', 'hacker')
    
    vuln_type = request.args.get('type', 'weak_key')
    
    if vuln_type == 'weak_key':
        # Create a token with a very weak key
        current_time = int(time.time())
        
        header = {
            'alg': 'sha256',
            'typ': 'SES'
        }
        
        payload = {
            'sub': username,
            'iat': current_time,
            'exp': current_time + (30 * 86400),  # 30 days
            'security_level': 'low',
            'role': 'admin'  # Privilege escalation
        }
        
        # Encode header and payload
        header_json = json.dumps(header, separators=(',', ':'))
        payload_json = json.dumps(payload, separators=(',', ':'))
        
        header_b64 = encode_base64_url_safe(header_json.encode('utf-8'))
        payload_b64 = encode_base64_url_safe(payload_json.encode('utf-8'))
        
        # Create signature with weak key
        message = f"{header_b64}.{payload_b64}"
        signature = sign_data(message, 'weak_secret', 'sha256')
        signature_b64 = encode_base64_url_safe(signature)
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
    elif vuln_type == 'expired':
        # Create an expired token
        current_time = int(time.time())
        
        header = {
            'alg': 'sha256',
            'typ': 'SES'
        }
        
        payload = {
            'sub': username,
            'iat': current_time - (2 * 86400),  # 2 days ago
            'exp': current_time - 86400,  # 1 day ago (expired)
            'security_level': 'medium'
        }
        
        # Encode header and payload
        header_json = json.dumps(header, separators=(',', ':'))
        payload_json = json.dumps(payload, separators=(',', ':'))
        
        header_b64 = encode_base64_url_safe(header_json.encode('utf-8'))
        payload_b64 = encode_base64_url_safe(payload_json.encode('utf-8'))
        
        # Create signature
        message = f"{header_b64}.{payload_b64}"
        signature = sign_data(message, app.secret_key, 'sha256')
        signature_b64 = encode_base64_url_safe(signature)
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
    else:
        # Default to a regular token
        token = generate_token(username, 'medium')
    
    # Create a response with the vulnerable token
    try:
        payload, _ = decode_token(token, verify=False)
        response = make_response(jsonify({
            "token": token,
            "decoded": payload,
            "message": "Vulnerable token created successfully"
        }))
        
        # Add token cookie with minimal security
        response.set_cookie(
            'session_token', 
            token,
            httponly=False,
            secure=False,
            max_age=604800
        )
        
        return response
    except Exception as e:
        print(f"Error creating vulnerable token: {str(e)}")
        return jsonify({"error": f"Error creating vulnerable token: {str(e)}"}), 500

# New route for token analyzer
@app.route('/analyzer', methods=['GET', 'POST'])
def analyzer():
    """Route to analyze JWT tokens using the external analyzer script."""
    result = None
    token = request.args.get('token', '')  # Get token from query string if provided
    
    # If no token in query string, try to get from current session
    if not token:
        token = request.cookies.get('session_token', '')
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        attempt_exploits = 'attempt_exploits' in request.form
        
        if token:
            try:
                # Call the analyze_token function from run_analyzer.py
                result = analyze_token(token, secret_key=None, attempt_exploits=attempt_exploits)
            except Exception as e:
                result = {"error": str(e), "token": token}
    
    return render_template('analyzer.html', token=token, result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5001)