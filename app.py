# app.py
from flask import Flask, request, jsonify, session, redirect, url_for
import uuid
import hashlib
import datetime
import jwt # pip install PyJWT
from functools import wraps

app = Flask(__name__)
# Użyj silnego, losowego klucza w środowisku produkcyjnym!
app.config['SECRET_KEY'] = 'twoj_bardzo_tajny_klucz_bezpieczenstwa_do_sesji_i_jwt'
app.config['JWT_SECRET_KEY'] = 'inny_bardzo_tajny_klucz_do_jwt' # Klucz do podpisywania JWT
app.config['JWT_EXPIRATION_DAYS'] = 1 # Token wygasa po 1 dniu

# --- Symulacja bazy danych (do celów demonstracyjnych) ---
# W prawdziwej aplikacji użyłbyś bazy danych (np. PostgreSQL, MySQL, SQLite, MongoDB)
# i ORM (np. SQLAlchemy, Peewee) do zarządzania danymi.

# Słownik użytkowników: {username: {'password_hash': '...', 'referral_id': '...'}}
users_db = {}
# Słownik kliknięć: {referral_id: [{'ip': '...', 'timestamp': '...'}, ...]}
clicks_db = {}
# Słownik do śledzenia unikalnych kliknięć z IP w ciągu 24h:
# {referral_id: {'ip_address': 'last_click_timestamp', ...}}
unique_ip_clicks_tracker = {}

# Stawka za kliknięcie (0.01 centa = 1 jednostka, np. 1/100 dolara)
# Przechowujemy w centach, aby uniknąć problemów z zmiennoprzecinkowymi
CLICK_EARNINGS_CENTS = 1 # 1 cent = 0.01 dolara

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
def index():
    """Główna strona aplikacji. Może służyć do serwowania pliku HTML."""
    # W środowisku produkcyjnym, zazwyczaj używasz `send_from_directory`
    # lub serwera Nginx/Apache do serwowania statycznych plików.
    # Na potrzeby tego przykładu, zakładamy, że plik HTML jest serwowany oddzielnie
    # lub jako część aplikacji Flask.
    return "Serwer działa. Przejdź do pliku HTML w przeglądarce."

@app.route('/register', methods=['POST'])
def register():
    """Endpoint do rejestracji nowego użytkownika."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Nazwa użytkownika i hasło są wymagane.'}), 400

    if username in users_db:
        return jsonify({'error': 'Nazwa użytkownika już istnieje.'}), 409

    hashed_password = hash_password(password)
    referral_id = generate_referral_id()

    users_db[username] = {
        'password_hash': hashed_password,
        'referral_id': referral_id
    }
    clicks_db[referral_id] = [] # Inicjalizuj listę kliknięć dla nowego użytkownika
    unique_ip_clicks_tracker[referral_id] = {} # Inicjalizuj tracker IP

    print(f"Zarejestrowano użytkownika: {username} z ID: {referral_id}")
    return jsonify({'message': 'Rejestracja pomyślna. Możesz się zalogować.'}), 201

@app.route('/login', methods=['POST'])
def login():
    """Endpoint do logowania użytkownika."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Nazwa użytkownika i hasło są wymagane.'}), 400

    user_data = users_db.get(username)
    if not user_data or user_data['password_hash'] != hash_password(password):
        return jsonify({'error': 'Nieprawidłowa nazwa użytkownika lub hasło.'}), 401

    # Generowanie tokena JWT po pomyślnym logowaniu
    token = create_jwt_token(user_data['referral_id'], username)
    return jsonify({'message': 'Logowanie pomyślne.', 'token': token}), 200

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Endpoint do pobierania danych panelu użytkownika."""
    user_id = request.user['user_id'] # Pobierz ID użytkownika z tokena JWT
    username = request.user['username']

    user_clicks = clicks_db.get(user_id, [])
    # Filtruj kliknięcia, które są unikalne i aktualne (np. z ostatnich 24h)
    # W tym prostym przykładzie, `clicks_db` zawiera już tylko "unikalne" kliknięcia
    # zgodnie z logiką `track_click`.
    # W bardziej zaawansowanym systemie, tutaj mogłaby być dodatkowa logika filtrowania
    # i agregacji danych z bazy.

    # Liczymy kliknięcia i zarobki
    total_clicks = len(user_clicks)
    total_earnings = total_clicks * CLICK_EARNINGS_CENTS # Zarobki w centach

    return jsonify({
        'username': username,
        'referral_id': user_id,
        'clicks': total_clicks,
        'earnings': total_earnings # Zarobki w centach
    }), 200

@app.route('/track_click', methods=['POST'])
def track_click():
    """
    Endpoint do śledzenia kliknięć w linki polecające.
    Implementuje podstawową logikę anty-fraudową:
    - Liczy tylko unikalne kliknięcia z danego IP dla danego referral_id w ciągu 24 godzin.
    """
    data = request.get_json()
    referral_id = data.get('referral_id')
    client_ip = request.remote_addr # Pobierz adres IP klienta

    if not referral_id:
        return jsonify({'error': 'Brak ID polecającego.'}), 400

    if referral_id not in clicks_db:
        # Jeśli ID polecającego nie istnieje, ignoruj kliknięcie
        # lub zwróć błąd, w zależności od polityki.
        # Na potrzeby anty-fraud, lepiej ignorować.
        print(f"Nieznany referral_id: {referral_id}. Kliknięcie z IP {client_ip} zignorowane.")
        return jsonify({'message': 'Nieznany ID polecającego.'}), 200

    current_time = datetime.datetime.now()
    # Pobierz tracker dla danego referral_id
    ip_tracker = unique_ip_clicks_tracker.get(referral_id, {})

    # Sprawdź, czy to IP już kliknęło w ciągu ostatnich 24 godzin
    last_click_time = ip_tracker.get(client_ip)
    if last_click_time:
        time_since_last_click = current_time - last_click_time
        if time_since_last_click < datetime.timedelta(hours=24):
            print(f"Kliknięcie zduplikowane z IP {client_ip} dla ID {referral_id} w ciągu 24h. Zignorowano.")
            return jsonify({'message': 'Kliknięcie już zarejestrowane z tego IP w ciągu ostatnich 24 godzin.'}), 200

    # Jeśli kliknięcie jest unikalne, zarejestruj je
    clicks_db[referral_id].append({
        'ip': client_ip,
        'timestamp': current_time.isoformat()
    })
    # Zaktualizuj tracker IP
    ip_tracker[client_ip] = current_time
    unique_ip_clicks_tracker[referral_id] = ip_tracker # Zapisz zaktualizowany tracker

    print(f"Zarejestrowano unikalne kliknięcie dla ID: {referral_id} z IP: {client_ip}")
    return jsonify({'message': 'Kliknięcie zarejestrowane pomyślnie.'}), 200

if __name__ == '__main__':
    # Uruchomienie aplikacji Flask
    # W środowisku produkcyjnym użyj serwera WSGI (np. Gunicorn, uWSGI)
    app.run(debug=True, port=5000) # debug=True tylko do celów deweloperskich
