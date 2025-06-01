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
app.config['SECRET_KEY'] = b'\xc5\x1eG\xc1\xaa\xd8\x12C\xbd\x9a\xcb\bc\xba\xf2\x05\x05\xba\xdd\x08u\xf9\xa6\x0c\x11'
app.config['JWT_SECRET_KEY'] = 'f8b1a3d9e2c0b5f7a1e3c5d7b9f0a2e4d6c8e0a2b4f6d8e0c2a4b6f8d0a1b3c5'
app.config['JWT_EXPIRATION_DAYS'] = 1

# --- Symulacja bazy danych (do celów demonstracyjnych) ---
# W prawdziwej aplikacji użyłbyś bazy danych (np. PostgreSQL, MySQL, SQLite, MongoDB)
# i ORM (np. SQLAlchemy, Peewee) do zarządzania danymi.

# Słownik użytkowników: {username: {'password_hash': '...', 'referral_id': '...', 'referred_by': 'referral_id_rodzica' (opcjonalnie)}}
# 'referred_by' przechowuje ID polecającego (rodzica) danego użytkownika
users_db = {} # {username: user_data}
# Słownik pomocniczy do szybkiego znajdowania użytkownika po jego referral_id: {referral_id: username}
# W prawdziwej bazie danych szukałoby się po indeksie referral_id
referral_id_to_username = {}

# Globalna lista kliknięć: [{'user_id': '...', 'ip': '...', 'timestamp': '...', 'earnings_cents': amount}, ...]
clicks_db = []
# Słownik do śledzenia unikalnych kliknięć z IP w ciągu 24h dla każdego polecającego:
# {(user_id, ip_address): timestamp}
unique_ip_clicks_tracker = {}

# Stawki za kliknięcie (w jednostkach centów, np. 1 = 0.01 dolara, 0.1 = 0.001 dolara)
DIRECT_CLICK_EARNINGS_CENTS = 1    # 0.01 centa (1 jednostka)
TIER_CLICK_EARNINGS_CENTS = 0.1  # 0.001 centa (0.1 jednostki)

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
    while True:
        new_id = str(uuid.uuid4())[:8] # Krótszy ID dla czytelności
        # Sprawdź, czy ID już istnieje (bardzo małe prawdopodobieństwo kolizji)
        if new_id not in referral_id_to_username:
            return new_id

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
    # referrer_ref_id to ID polecającego, który przyprowadził tego nowego użytkownika
    referrer_ref_id = data.get('referrer_ref_id')

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

    # Sprawdź, czy referrer_ref_id jest prawidłowy (czy istnieje taki użytkownik)
    actual_referrer_id = None
    if referrer_ref_id and referrer_ref_id in referral_id_to_username:
        actual_referrer_id = referrer_ref_id
    elif referrer_ref_id:
        print(f"Ostrzeżenie: Nieprawidłowy referrer_ref_id '{referrer_ref_id}' podczas rejestracji użytkownika '{username}'. Ignorowanie.")

    users_db[username] = {
        'password_hash': hashed_password,
        'referral_id': new_referral_id,
        'referred_by': actual_referrer_id # Zapisz ID polecającego (rodzica)
    }
    referral_id_to_username[new_referral_id] = username # Dodaj do słownika szybkiego wyszukiwania

    print(f"Zarejestrowano użytkownika: {username} z ID: {new_referral_id}, polecony przez: {actual_referrer_id if actual_referrer_id else 'brak'}")
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

    # Zlicz wszystkie kliknięcia i sumuj zarobki, które zostały przypisane do tego użytkownika
    total_clicks = 0
    total_earnings_sum = 0
    for click_entry in clicks_db:
        if click_entry['user_id'] == current_user_referral_id:
            total_clicks += 1
            total_earnings_sum += click_entry['earnings_cents'] # Dodaj faktyczną kwotę zarobioną za to kliknięcie

    return jsonify({
        'username': username,
        'referral_id': current_user_referral_id,
        'clicks': total_clicks,
        'earnings': total_earnings_sum # Zarobki w centach
    }), 200

@app.route('/track_click', methods=['POST'])
def track_click():
    """
    Endpoint do śledzenia kliknięć w linki polecające.
    Implementuje logikę anty-fraudową i nalicza zarobki dla wszystkich poziomów poleceń
    z różnymi stawkami.
    """
    data = request.get_json()
    direct_referrer_id = data.get('referral_id') # ID bezpośredniego polecającego (tego, którego link został kliknięty)
    client_ip = request.remote_addr # Pobierz adres IP klienta
    current_time = datetime.datetime.now()

    if not direct_referrer_id:
        return jsonify({'error': 'Referral ID is missing.'}), 400

    # Funkcja pomocnicza do rejestrowania kliknięcia dla danego użytkownika z określoną kwotą
    def register_earning_click(user_id_to_credit, ip_address, current_ts, amount_cents):
        # Sprawdź, czy użytkownik istnieje
        if user_id_to_credit not in referral_id_to_username:
            print(f"Ostrzeżenie: Próba naliczenia dla nieistniejącego ID: {user_id_to_credit}. Zignorowano.")
            return False

        # Klucz do trackera to para (user_id, ip_address)
        tracker_key = (user_id_to_credit, ip_address)
        last_click_time = unique_ip_clicks_tracker.get(tracker_key)

        if last_click_time:
            time_since_last_click = current_ts - last_click_time
            if time_since_last_click < datetime.timedelta(hours=24):
                print(f"Zduplikowane kliknięcie dla ID {user_id_to_credit} z IP {ip_address} w ciągu 24h. Zignorowano.")
                return False # Kliknięcie zignorowane

        # Jeśli unikalne, zarejestruj kliknięcie
        clicks_db.append({
            'user_id': user_id_to_credit,
            'ip': ip_address,
            'timestamp': current_ts.isoformat(),
            'earnings_cents': amount_cents # Zapisz konkretną kwotę zarobioną za to kliknięcie
        })
        unique_ip_clicks_tracker[tracker_key] = current_ts
        print(f"Zarejestrowano unikalne kliknięcie dla ID: {user_id_to_credit} z IP: {ip_address}. Zarobki: {amount_cents / 100:.3f}$")
        return True # Kliknięcie zarejestrowane

    # Znajdź bezpośredniego polecającego
    current_referrer_username = referral_id_to_username.get(direct_referrer_id)
    if not current_referrer_username:
        print(f"Nieznany direct_referrer_id: {direct_referrer_id}. Kliknięcie z IP {client_ip} zignorowane.")
        return jsonify({'message': 'Nieznany ID polecającego.'}), 200

    # Przejdź w górę łańcucha poleceń i naliczaj zarobki
    current_referrer_id_in_chain = direct_referrer_id
    is_direct_referrer = True # Flaga do rozróżniania bezpośredniego polecającego

    while current_referrer_id_in_chain:
        # Znajdź dane użytkownika po jego referral_id
        user_found = False
        user_data_in_chain = None
        for username_in_db, data_in_db in users_db.items():
            if data_in_db['referral_id'] == current_referrer_id_in_chain:
                user_data_in_chain = data_in_db
                user_found = True
                break
        
        if not user_found:
            print(f"Ostrzeżenie: Użytkownik z ID '{current_referrer_id_in_chain}' nie znaleziony w łańcuchu. Przerwano naliczanie.")
            break # Przerwij, jeśli ID nie istnieje

        # Określ kwotę do naliczenia
        if is_direct_referrer:
            amount_to_credit = DIRECT_CLICK_EARNINGS_CENTS
            is_direct_referrer = False # Po pierwszym naliczeniu, reszta to wyższe poziomy
        else:
            amount_to_credit = TIER_CLICK_EARNINGS_CENTS
        
        # Nalicz zarobki dla bieżącego użytkownika w łańcuchu
        register_earning_click(current_referrer_id_in_chain, client_ip, current_time, amount_to_credit)
        
        # Przejdź do polecającego rodzica
        current_referrer_id_in_chain = user_data_in_chain.get('referred_by')

    return jsonify({'message': 'Kliknięcie zarejestrowane pomyślnie dla wszystkich poziomów poleceń.'}), 200


@app.route('/add_funds_and_redirect', methods=['GET'])
def add_funds_and_redirect():
    # To jest tylko symulacja! W prawdziwej aplikacji byłaby tu logika płatności.
    redirect_url = 'https://aw0.fun/' # Strona główna Twojej aplikacji frontendowej
    print(f"Symulowane dodanie środków. Przekierowuję na: {redirect_url}")
    return redirect(redirect_url, code=302)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
