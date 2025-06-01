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

app.config['SECRET_KEY'] = 'twoj_bardzo_tajny_klucz_sesji_produkcyjnej' # Użyj wygenerowanego klucza!
app.config['JWT_SECRET_KEY'] = 'inny_bardzo_tajny_klucz_jwt_produkcyjny' # Użyj wygenerowanego klucza!
app.config['JWT_EXPIRATION_DAYS'] = 1

users_db = {}
clicks_db = {}
unique_ip_clicks_tracker = {}
CLICK_EARNINGS_CENTS = 1

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def generate_referral_id():
    return str(uuid.uuid4())[:8]

def create_jwt_token(user_id, username):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['JWT_EXPIRATION_DAYS'])
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': expiration_time
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired.'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token.'}

def login_required(f):
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

@app.route('/')
def index():
    return jsonify({'message': 'Backend is running. Access the frontend at aw0.fun.'}), 200

@app.route('/register', methods=['POST'])
def register():
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

# --- NOWY ENDPOINT DLA SYMULACJI DODAWANIA ŚRODKÓW I PRZEKIEROWANIA ---
@app.route('/add_funds_and_redirect', methods=['GET'])
def add_funds_and_redirect():
    # To jest tylko symulacja! W prawdziwej aplikacji byłaby tu logika płatności.
    # Wysłanie tego linku użytkownikowi symuluje pomyślną płatność.

    # Możesz tutaj dodać logikę, która faktycznie przypisuje środki do konta użytkownika,
    # jeśli masz autoryzację tokenem, czy ID użytkownika.
    # Na razie po prostu zakładamy, że "pieniądze zostały dodane".

    # Adres, na który chcesz przekierować użytkownika po zakończeniu operacji.
    # Zastąp 'https://aw0.fun' swoim rzeczywistym adresem frontendowym
    # i upewnij się, że nie jest to adres API, ale strona główna twojego serwisu.
    redirect_url = 'https://aw0.fun/' # Strona główna Twojej aplikacji frontendowej

    print(f"Symulowane dodanie środków. Przekierowuję na: {redirect_url}")
    return redirect(redirect_url, code=302) # Kod 302 oznacza tymczasowe przekierowanie

if __name__ == '__main__':
    app.run(debug=True, port=5000)
