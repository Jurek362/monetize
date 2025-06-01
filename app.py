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

# Użyj silnych, wygenerowanych kluczy w środowisku produkcyjnym!
app.config['SECRET_KEY'] = b'\xc5\x1eG\xc1\xaa\xd8\x12C\xbd\x9a\xcb\xbc\xba\xf2\x05\x05\xba\xdd\x08u\xf9\xa6\x0c\x11'
app.config['JWT_SECRET_KEY'] = 'f8b1a3d9e2c0b5f7a1e3c5d7b9f0a2e4d6c8e0a2b4f6d8e0c2a4b6f8d0a1b3c5'
app.config['JWT_EXPIRATION_DAYS'] = 1

# --- Symulacja bazy danych (do celów demonstracyjnych) ---
# W prawdziwej aplikacji użyłbyś bazy danych (np. PostgreSQL, MySQL, SQLite, MongoDB)
# i ORM (np. SQLAlchemy, Peewee) do zarządzania danymi.

# Słownik użytkowników: {username: {'password_hash': '...', 'referral_id': '...'}}
users_db = {}
# Słownik kliknięć: {referral_id: [(ip_address, timestamp), ...]}
clicks_db = {}
# Słownik do śledzenia unikalnych kliknięć z IP w ciągu 24h: {ip_address: timestamp}
unique_ip_clicks_tracker = {}

# Stawka za kliknięcie (0.01 centa = 1 jednostka, np. 1/100 dolara)
CLICK_EARNINGS_CENTS = 1 # 1 cent = 0.01 dolara

# Minimalne limity dla nazwy użytkownika i hasła
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 20
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 30

# --- Funkcje pomocnicze ---

def hash_password(password):
    """Haszuje hasło za pomocą SHA256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def generate_referral_id():
    """Generuje unikalny ID polecający."""
    return str(uuid.uuid4())[:8] # Krótszy ID dla czytelności

def create_jwt_token(user_id, username):
    """Tworzy token JWT."""
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(days=app.config['JWT_EXPIRATION_DAYS'])
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': expiration_time
    }
    token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
    return token

def verify_jwt_token(token):
    """Weryfikuje token JWT i zwraca payload."""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token wygasł.'}
    except jwt.InvalidTokenError:
        return {'error': 'Nieprawidłowy token.'}

def login_required(f):
    """Dekorator do ochrony endpointów wymagających logowania."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Brak tokena uwierzytelniającego.'}), 401

        try:
            token = auth_header.split(" ")[1] # Oczekujemy formatu "Bearer <token>"
        except IndexError:
            return jsonify({'error': 'Nieprawidłowy format tokena uwierzytelniającego.'}), 401

        payload = verify_jwt_token(token)
        if 'error' in payload:
            return jsonify(payload), 401

        request.user = payload # Dodaj payload tokena do obiektu request
        return f(*args, **kwargs)
    return decorated_function

# --- Endpointy API ---

@app.route('/')
def home():
    """Główna strona aplikacji. Służy jako punkt wejścia dla frontendu."""
    return jsonify({'message': 'Backend is running. Access the frontend at aw0.fun.'}), 200

@app.route('/register', methods=['POST'])
def register():
    """Endpoint do rejestracji nowego użytkownika."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Nazwa użytkownika i hasło są wymagane.'}), 400

    # Backend validation for length
    if not (MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH):
        return jsonify({'error': f'Nazwa użytkownika musi mieć od {MIN_USERNAME_LENGTH} do {MAX_USERNAME_LENGTH} znaków.'}), 400
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return jsonify({'error': f'Hasło musi mieć od {MIN_PASSWORD_LENGTH} do {MAX_PASSWORD_LENGTH} znaków.'}), 400

    if username in users_db:
        return jsonify({'error': 'Nazwa użytkownika już istnieje.'}), 409

    hashed_password = hash_password(password)
    new_referral_id = generate_referral_id()

    users_db[username] = {
        'password_hash': hashed_password,
        'referral_id': new_referral_id
    }
    clicks_db[new_referral_id] = [] # Inicjuj listę kliknięć dla nowego użytkownika

    print(f"Zarejestrowano użytkownika: {username} z ID: {new_referral_id}")
    return jsonify({'message': 'Rejestracja udana. Możesz się teraz zalogować.'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint do logowania użytkownika."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Nazwa użytkownika i hasło są wymagane.'}), 400

    # Backend validation for length (less critical for login as user already exists)
    if not (MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH):
        return jsonify({'error': f'Nazwa użytkownika musi mieć od {MIN_USERNAME_LENGTH} do {MAX_USERNAME_LENGTH} znaków.'}), 400
    if not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return jsonify({'error': f'Hasło musi mieć od {MIN_PASSWORD_LENGTH} do {MAX_PASSWORD_LENGTH} znaków.'}), 400

    user_data = users_db.get(username)
    if not user_data or user_data['password_hash'] != hash_password(password):
        return jsonify({'error': 'Nieprawidłowa nazwa użytkownika lub hasło.'}), 401

    token = create_jwt_token(user_data['referral_id'], username)
    return jsonify({'message': 'Logowanie udane.', 'token': token}), 200

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Endpoint do pobierania danych panelu użytkownika."""
    current_user_referral_id = request.user['user_id'] # Pobierz ID użytkownika z tokena JWT
    username = request.user['username']

    user_clicks = clicks_db.get(current_user_referral_id, [])
    total_clicks = len(user_clicks)
    total_earnings = total_clicks * CLICK_EARNINGS_CENTS # Zarobki w centach

    return jsonify({
        'username': username,
        'referral_id': current_user_referral_id,
        'clicks': total_clicks,
        'earnings': total_earnings # Zarobki w centach
    }), 200

@app.route('/track_click', methods=['POST'])
def track_click():
    """
    Endpoint do śledzenia kliknięć w linki polecające.
    Implementuje podstawową logikę anty-fraudową.
    """
    data = request.get_json()
    referral_id = data.get('referral_id')
    client_ip = request.remote_addr # Pobierz adres IP klienta
    current_time = datetime.datetime.now()

    if not referral_id:
        return jsonify({'error': 'Referral ID is missing.'}), 400

    # Sprawdź, czy referral_id istnieje
    user_exists = False
    for user_data in users_db.values():
        if user_data['referral_id'] == referral_id:
            user_exists = True
            break

    if not user_exists:
        print(f"Nieznany referral_id: {referral_id}. Kliknięcie z IP {client_ip} zignorowane.")
        return jsonify({'message': 'Nieznany ID polecającego.'}), 200

    # Logika anty-fraudowa: Tylko jedno unikalne kliknięcie z danego IP na 24 godziny
    last_click_time = unique_ip_clicks_tracker.get(client_ip)

    if last_click_time:
        time_since_last_click = current_time - last_click_time
        if time_since_last_click < datetime.timedelta(hours=24):
            print(f"Zduplikowane kliknięcie z IP {client_ip} w ciągu 24h. Zignorowano.")
            return jsonify({'message': 'Zduplikowane kliknięcie z tego samego adresu IP w ciągu 24 godzin.'}), 200

    # Jeśli unikalne, zarejestruj kliknięcie
    clicks_db.get(referral_id, []).append((client_ip, current_time.isoformat()))
    unique_ip_clicks_tracker[client_ip] = current_time
    print(f"Zarejestrowano unikalne kliknięcie dla ID: {referral_id} z IP: {client_ip}")

    return jsonify({'message': 'Kliknięcie zarejestrowane pomyślnie.'}), 200


@app.route('/add_funds_and_redirect', methods=['GET'])
def add_funds_and_redirect():
    # To jest tylko symulacja! W prawdziwej aplikacji byłaby tu logika płatności.
    redirect_url = 'https://aw0.fun/' # Strona główna Twojej aplikacji frontendowej
    print(f"Symulowane dodanie środków. Przekierowuję na: {redirect_url}")
    return redirect(redirect_url, code=302)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
