# app.py
from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS 
import uuid
import hashlib
import datetime
import jwt 
from functools import wraps

app = Flask(__name__)
CORS(app) 

# Use a strong, random key in a production environment!
app.config['SECRET_KEY'] = b'\xc5\x1eG\xc1\xaa\xd8\x12C\xbd\x9a\xcb\xbc\xba\xf2\x05\x05\xba\xdd\x08u\xf9\xa6\x0c\x11'
app.config['JWT_SECRET_KEY'] = 'f8b1a3d9e2c0b5f7a1e3c5d7b9f0a2e4d6c8e0a2b4f6d8e0c2a4b6f8d0a1b3c5'
app.config['JWT_EXPIRATION_DAYS'] = 1 

# --- Database Simulation (for demonstration purposes) ---
# In a real application, you would use a database (e.g., PostgreSQL, MySQL, SQLite, MongoDB)
# and an ORM (e.g., SQLAlchemy, Peewee) to manage data.

# User dictionary: {username: {'password_hash': '...', 'referral_id': '...'}}
users_db = {}
# Clicks dictionary: {referral_id: [{'ip': '...', 'timestamp': '...'}, ...]}
clicks_db = {}
# Dictionary to track unique clicks from an IP within 24h:
# {referral_id: {'ip_address': 'last_click_timestamp', ...}}
unique_ip_clicks_tracker = {}

# Earnings per click (0.01 cent = 1 unit, e.g., 1/100 of a dollar)
# Stored in cents to avoid floating-point issues
CLICK_EARNINGS_CENTS = 1 

# --- Helper Functions ---

def hash_password(password):
    """Hashes the password using SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def generate_referral_id():
    """Generates a unique referral ID."""
    return str(uuid.uuid4())[:8] 

def create_jwt_token(user_id, username):
    """Creates a JWT token."""
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['JWT_EXPIRATION_DAYS'])
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': expiration_time
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token

def verify_jwt_token(token):
    """Verifies the JWT token and returns the payload."""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired.'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token.'}

def login_required(f):
    """Decorator to protect endpoints requiring login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authentication token is missing.'}), 401

        try:
            token = auth_header.split(" ")[1] 
        except IndexError:
            return jsonify({'error': 'Invalid authentication token format.'}), 401

        payload = verify_jwt_token(token)
        if 'error' in payload:
            return jsonify(payload), 401

        request.user = payload 
        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---

@app.route('/')
def index():
    """Main page of the application. Can serve the HTML file."""
    
    return jsonify({'message': 'Backend is running. Access the frontend at aw0.fun.'}), 200

@app.route('/register', methods=['POST'])
def register():
    """Endpoint for user registration."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    if username in users_db:
        return jsonify({'error': 'Username already exists.'}), 409

    hashed_password = hash_password(password)
    referral_id = generate_referral_id()

    users_db[username] = {
        'password_hash': hashed_password,
        'referral_id': referral_id
    }
    clicks_db[referral_id] = [] 
    unique_ip_clicks_tracker[referral_id] = {} 

    print(f"User registered: {username} with ID: {referral_id}")
    return jsonify({'message': 'Registration successful. You can now log in.'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint for user login."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    user_data = users_db.get(username)
    if not user_data or user_data['password_hash'] != hash_password(password):
        return jsonify({'error': 'Invalid username or password.'}), 401

    token = create_jwt_token(user_data['referral_id'], username)
    return jsonify({'message': 'Login successful.', 'token': token}), 200

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Endpoint to retrieve user dashboard data."""
    user_id = request.user['user_id'] 
    username = request.user['username']

    user_clicks = clicks_db.get(user_id, [])
    
    total_clicks = len(user_clicks)
    total_earnings = total_clicks * CLICK_EARNINGS_CENTS 

    return jsonify({
        'username': username,
        'referral_id': user_id,
        'clicks': total_clicks,
        'earnings': total_earnings 
    }), 200

@app.route('/track_click', methods=['POST'])
def track_click():
    """
    Endpoint to track clicks on referral links.
    Implements basic anti-fraud logic:
    - Counts only unique clicks from a given IP for a given referral_id within 24 hours.
    """
    data = request.get_json()
    referral_id = data.get('referral_id')
    client_ip = request.remote_addr 

    if not referral_id:
        return jsonify({'error': 'Referral ID is missing.'}), 400

    if referral_id not in clicks_db:
        
        print(f"Unknown referral_id: {referral_id}. Click from IP {client_ip} ignored.")
        return jsonify({'message': 'Unknown referral ID.'}), 200

    current_time = datetime.datetime.now()
    
    ip_tracker = unique_ip_clicks_tracker.get(referral_id, {})

    
    last_click_time = ip_tracker.get(client_ip)
    if last_click_time:
        time_since_last_click = current_time - last_click_time
        if time_since_last_click < datetime.timedelta(hours=24):
            print(f"Duplicate click from IP {client_ip} for ID {referral_id} within 24h. Ignored.")
            return jsonify({'message': 'Click already registered from this IP within the last 24 hours.'}), 200

    
    clicks_db[referral_id].append({
        'ip': client_ip,
        'timestamp': current_time.isoformat()
    })
    
    ip_tracker[client_ip] = current_time
    unique_ip_clicks_tracker[referral_id] = ip_tracker 

    print(f"Registered unique click for ID: {referral_id} from IP: {client_ip}")
    return jsonify({'message': 'Click registered successfully.'}), 200

if __name__ == '__main__':
    
    app.run(debug=True, port=5000)
