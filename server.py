from flask import Flask, request, jsonify, send_from_directory, render_template, send_file
import sqlite3
from Crypto.Cipher import AES
import base64
import json
import os
import random
import subprocess
import sys
import time
import threading
from datetime import datetime
import jwt # REQUIRES: pip install pyjwt
import requests # REQUIRES: pip install requests
from datetime import datetime, timedelta
from admin_routes import admin_bp, log_server_event

# --- [ CONFIGURACIÓN INICIAL ] ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_FOLDER = os.path.join(BASE_DIR, 'usersdb')

if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(DB_FOLDER): os.makedirs(DB_FOLDER)

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = "DVOM_SUPER_SECRET_ADMIN_KEY_2024"
app.register_blueprint(admin_bp) # <-- REGISTRO DEL PORTAL WEB
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Security: Developers implemented Application-Layer Encryption (AES-128-CBC)
# believing it prevents automated attacks and sniffing. However, with hardcoded keys in the APK,
# it only provides "Security through Obscurity".
AES_KEY = b"1234567890123456"
AES_IV = b"FIXED_IV_1234567"
JWT_KEYS_DIR = os.path.join(BASE_DIR, 'jwt_keys')
if not os.path.exists(JWT_KEYS_DIR):
    os.makedirs(JWT_KEYS_DIR)
    with open(os.path.join(JWT_KEYS_DIR, 'prod.key'), 'w') as f: f.write("dvom_weak_jwt_secret_key_2024")

pending_2fa = {}
onboarding_temp = {}

# --- [1] CRIPTO & JWT ---
def generate_jwt(user_id, username, role="user", email="", dni="", locked=False):
    payload = {
        "sub": user_id,
        "name": username,
        "role": role,
        "email": email,
        "dni": dni,
        "locked": locked,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    # Se añade la cabecera 'kid' que apunta al archivo de la llave
    headers = {"kid": "prod.key"}
    with open(os.path.join(JWT_KEYS_DIR, 'prod.key'), 'r') as f:
        secret = f.read().strip()
    return jwt.encode(payload, secret, algorithm="HS256", headers=headers)

def validate_jwt(token):
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get('kid', 'prod.key')
        key_path = os.path.join(JWT_KEYS_DIR, kid)
        with open(key_path, 'r', encoding='utf-8') as f:
            secret = f.read().strip() # .strip() limpia espacios y saltos de línea

        # Eliminamos cualquier rastro de \n o \r manual
        secret = secret.replace("\n", "").replace("\r", "")

        decoded = jwt.decode(token, secret, algorithms=["HS256"])

        if decoded.get("locked") == True:
             return "LOCKED"

        return decoded
    except Exception as e:
        print(f"[JWT ERROR] Detail: {str(e)}")
        return None

from functools import wraps
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        decoded_data = validate_jwt(token)
        if decoded_data == "LOCKED":
            return jsonify({'message': 'USER_LOCKED: Your account is suspended (JWT check)'}), 403

        if not decoded_data:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(decoded_data, *args, **kwargs)
    return decorated

def decrypt_aes(encrypted_text):
    try:
        raw_data = base64.b64decode(encrypted_text)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted = cipher.decrypt(raw_data)
        if not decrypted: return None
        padding_len = decrypted[-1]
        return decrypted[:-padding_len].decode('utf-8')
    except: return None

def encrypt_aes(plain_text):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        pad_len = 16 - (len(plain_text) % 16)
        padded_text = plain_text + (chr(pad_len) * pad_len)
        return base64.b64encode(cipher.encrypt(padded_text.encode('utf-8'))).decode('utf-8')
    except: return plain_text

# --- [2] MIDDLEWARES ---
@app.before_request
def handle_before():
    if any(x in request.path for x in ['/upload', '/view_upload', '/download_pdf', '/docs', '/static', '/admin']): return

    # TRANSMISIÓN AL LIVE MONITORING
    log_server_event(f"INBOUND {request.method} -> {request.path} (Client: {request.remote_addr})")

    print(f"[*] RECV: {request.method} {request.path}")

    # Intentar obtener JSON directamente (Postman envía Content-Type: application/json)
    data = request.get_json(silent=True)

    # Si no hay JSON directo, intentamos descifrar AES (App Móvil)
    if not data and request.data:
        dec = decrypt_aes(request.data)
        if dec:
            try:
                data = json.loads(dec)
            except: pass

    if data:
        # Cacheamos el JSON para que request.json funcione en las rutas
        request._cached_json = (data, data)
        print(f"    PAYLOAD: {data}")

        # Guardar metadatos del dispositivo (VULN M8)
        uid = data.get('user_id') or data.get('from_id') or data.get('id')
        if uid:
            try:
                ua = request.headers.get('User-Agent', 'Unknown')
                ip = request.remote_addr
                db = get_db()
                db.execute("UPDATE users SET last_device = ?, last_ip = ? WHERE id = ?", (ua, ip, uid))
                db.commit()
                db.close()
            except: pass

@app.after_request
def handle_after(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Admin-Key"

    # NO CIFRAR si es para el Portal Admin o si es una petición de Postman (para facilitar auditoría)
    is_admin = any(x in request.path for x in ['/upload', '/view_upload', '/download_pdf', '/docs', '/admin'])
    is_postman = "Postman" in request.headers.get('User-Agent', '')

    if is_admin or is_postman: return response

    if response.is_json:
        response.set_data(encrypt_aes(response.get_data(as_text=True)))
        response.content_type = "text/plain"
    return response

# --- [3] DB MANAGEMENT ---
def get_db():
    db_path = os.path.join(BASE_DIR, 'usersdb', 'usuarios.db')
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def generate_random_user_id(db):
    while True:
        new_id = random.randint(100000, 999999)
        exists = db.execute("SELECT 1 FROM users WHERE id = ?", (new_id,)).fetchone()
        if not exists:
            return new_id

def generate_unique_id(db, table, length=6):
    # Definir rangos según longitud
    if length == 4: low, high = 1000, 9999
    else: low, high = 100000, 999999

    while True:
        new_id = random.randint(low, high)
        exists = db.execute(f"SELECT 1 FROM {table} WHERE id = ?", (new_id,)).fetchone()
        if not exists:
            return new_id

def generate_contract(user_id, name, lastname, dni, email, phone, username):
    """Función centralizada para generar el contrato HTML de cualquier usuario"""
    fname = f"contract_{user_id}.html"
    contract_html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: sans-serif; padding: 50px; color: #333; }}
            .header {{ border-bottom: 2px solid #1976D2; padding-bottom: 20px; margin-bottom: 30px; }}
            h1 {{ color: #1976D2; margin: 0; }}
            .info-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            .info-table td {{ padding: 10px; border: 1px solid #eee; }}
            .label {{ font-weight: bold; background: #f9f9f9; width: 200px; }}
            .footer {{ margin-top: 50px; font-size: 12px; color: #888; border-top: 1px solid #eee; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>DVOM BANK - OFFICIAL CONTRACT</h1>
            <p>Identity Verification & Service Agreement</p>
        </div>

        <table class="info-table">
            <tr><td class="label">Full Name</td><td>{name} {lastname}</td></tr>
            <tr><td class="label">DNI / Passport</td><td>{dni or 'NOT_PROVIDED'}</td></tr>
            <tr><td class="label">Email Address</td><td>{email}</td></tr>
            <tr><td class="label">Phone Number</td><td>{phone or 'NOT_PROVIDED'}</td></tr>
            <tr><td class="label">Infrastructure ID</td><td>DVOM-ST-{user_id}</td></tr>
            <tr><td class="label">Username</td><td>{username}</td></tr>
            <tr><td class="label">Status</td><td>ACTIVE / VERIFIED</td></tr>
        </table>

        <div class="footer">
            <p>Document generated by DVOM Core Engine. Valid for internal audit purposes.</p>
            <p>Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </body>
    </html>
    """
    with open(os.path.join(UPLOAD_FOLDER, fname), 'w', encoding='utf-8') as f:
        f.write(contract_html)

def init_db():
    db = get_db()
    try:
        db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, name TEXT, lastname TEXT, secret TEXT, balance REAL DEFAULT 1000.0, points INTEGER DEFAULT 0, recovery_pin TEXT DEFAULT "1111", email TEXT, phone TEXT, security_question TEXT DEFAULT "Pet Name?", security_answer TEXT DEFAULT "Rex", profile_pic TEXT DEFAULT "", dni TEXT, status TEXT DEFAULT "ACTIVE", must_change_password INTEGER DEFAULT 0)')
        db.execute('CREATE TABLE IF NOT EXISTS bank_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, alias TEXT, balance REAL DEFAULT 0.0, type TEXT DEFAULT "Savings Account", status TEXT DEFAULT "ACTIVE")')
        db.execute('CREATE TABLE IF NOT EXISTS cards (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, card_number TEXT, holder TEXT, cvv TEXT, expiry TEXT, balance REAL DEFAULT 500.0, status TEXT DEFAULT "ACTIVE")')
        db.execute('CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER, to_id INTEGER, amount REAL, description TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS internal_moves (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, from_type TEXT, from_id TEXT, to_type TEXT, to_id TEXT, amount REAL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, sender_name TEXT, name_label TEXT, phone_val TEXT, comment TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS support_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, subject TEXT, status TEXT DEFAULT "OPEN", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS support_replies (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, sender TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, user_id INTEGER, details TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS broadcast_history (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        db.execute('CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password_tried TEXT, ip_address TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')

        # Nueva Tabla: Transferencias Programadas (OWASP API6)
        db.execute('CREATE TABLE IF NOT EXISTS scheduled_transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER, to_id INTEGER, amount REAL, description TEXT, scheduled_time TEXT, from_type TEXT, status TEXT DEFAULT "PENDING")')

        # Nueva Tabla: Pagos Programados (OWASP API6)
        db.execute('CREATE TABLE IF NOT EXISTS scheduled_payments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, service_name TEXT, amount REAL, scheduled_time TEXT, source_id TEXT, source_type TEXT, status TEXT DEFAULT "PENDING")')

        # Nueva Tabla: Préstamos (OWASP Mass Assignment)
        db.execute('CREATE TABLE IF NOT EXISTS loans (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, remaining_amount REAL, account_id INTEGER, status TEXT DEFAULT "PENDING_REVIEW", interest_rate REAL DEFAULT 15.0)')

        # Nueva Tabla: Usuarios del Portal Web (RBAC)
        db.execute('CREATE TABLE IF NOT EXISTS web_admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, name TEXT)')

        # Insertar admins por defecto si no existen
        admin_exists = db.execute("SELECT 1 FROM web_admins WHERE username = 'admin'").fetchone()
        if not admin_exists:
            # 1. USUARIO OBJETIVO (A descubrir durante el pentest)
            db.execute("INSERT INTO users (id, username, password, name, lastname, balance, points, status) VALUES (133700, 'admin', 'admin123', 'Super', 'Admin', 999999, 1000, 'ACTIVE')")
            generate_contract(133700, "Super", "Admin", "00000000", "admin@dvom.lab", "999999999", "admin")

            # 2. USUARIO DE INICIO MÓVIL (Para el alumno)
            db.execute("INSERT INTO users (id, username, password, name, lastname, balance, points, status) VALUES (100500, 'cala', 'cala123', 'Cala', 'User', 1000, 50, 'ACTIVE')")
            generate_contract(100500, "Cala", "User", "12345678", "cala@dvom.lab", "666777888", "cala")

            # STAFF IDs para el Portal Web (RBAC)
            db.execute("INSERT INTO web_admins (id, username, password, role, name) VALUES (?, 'admin', 'admin123', 'ADMIN', 'Root Administrator')", (random.randint(900000, 999999),))
            db.execute("INSERT INTO web_admins (id, username, password, role, name) VALUES (?, 'carla', 'carla123', 'CUSTOMER_SERVICE', 'Carla Support')", (random.randint(900000, 999999),))
            db.execute("INSERT INTO web_admins (id, username, password, role, name) VALUES (?, 'pepe', 'pepe123', 'SUPPORT', 'Pepe Tech')", (random.randint(900000, 999999),))

        # ASEGURAR CREDENCIALES (Incluso si la DB ya existe)
        db.execute("UPDATE users SET password = 'admin123' WHERE username = 'admin'")
        db.execute("UPDATE users SET password = 'cala123' WHERE username = 'cala'")

        db.commit()

        # Parches de compatibilidad para tablas existentes
        patches = {
            "users": ["dni", "status", "last_device", "last_ip", "kyc_selfie", "must_change_password", "profile_pic"],
            "messages": ["sender_name", "name_label", "phone_val"],
            "transactions": ["description"],
            "scheduled_transfers": ["from_type"],
            "scheduled_payments": ["source_id", "source_type"],
            "bank_accounts": ["status"],
            "cards": ["status"],
            "loans": ["remaining_amount"]
        }
        for table, cols in patches.items():
            for col in cols:
                try:
                    # Determinar tipo de dato
                    dtype = "TEXT"
                    dval = "''"
                    if col == "status": dval = "'ACTIVE'"
                    if col == "must_change_password": dtype = "INTEGER"; dval = "0"
                    if col == "remaining_amount": dtype = "REAL"; dval = "NULL"

                    db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {dtype} DEFAULT {dval}")
                except:
                    pass # La columna ya existe

        # Nueva Tabla: Pagos de Préstamos
        db.execute('CREATE TABLE IF NOT EXISTS loan_payments (id INTEGER PRIMARY KEY AUTOINCREMENT, loan_id INTEGER, amount REAL, source_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')

        # REPARACIÓN DE DATOS: Asegurar que préstamos aprobados tengan monto pendiente (Solo si es NULL)
        try:
            db.execute("UPDATE loans SET remaining_amount = amount WHERE status = 'APPROVED' AND remaining_amount IS NULL")
            db.execute("UPDATE loans SET status = 'PAID' WHERE status = 'APPROVED' AND remaining_amount <= 0.01")
        except:
            pass
        db.commit()
    finally:
        db.close()

# --- [4] RUTAS AUTH ---
@app.route('/')
def index(): return "DVOM SERVER LIVE", 200

@app.route('/login', methods=['POST'])
def login():
    db = get_db()
    try:
        d = request.json
        username = d.get('username')
        password = d.get('password')

        # Primero verificamos si el usuario existe
        user_exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()

        if not user_exists:
            return jsonify({
                "status": "error",
                "message": "User Not Found"
            }), 404

        # Si existe, verificamos la contraseña
        u = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()

        if u:
            # VERIFICAR ESTADO DEL USUARIO (Sincronizado con Admin Console)
            db_status = u['status']
            status = db_status if db_status and db_status.strip() != "" else 'PENDING_KYC'

            # En lugar de 403, mandamos 200 OK y dejamos que la App decida si bloquea.
            # Esto permite el bypass manipulando el JSON en Burp Suite.
            is_account_locked = (status == 'BLOCKED')

            uid = str(u['id'])
            token = generate_jwt(uid, u['username'], email=u['email'], dni=u['dni'], locked=is_account_locked)
            otp = str(random.randint(1000, 9999)); pending_2fa[uid] = otp
            is_must_change = True if u['must_change_password'] in [1, "1"] else False

            resp_data = {
                "status": "locked" if is_account_locked else "2fa_required",
                "account_locked": is_account_locked,
                "user_id": uid,
                "session_token": token,
                "debug_token": otp,
                "must_change_password": is_must_change
            }

            if is_account_locked:
                resp_data["message"] = "USER_LOCKED: Your account has been suspended. Please contact the bank."
            elif status == 'PENDING_KYC':
                resp_data["message"] = "IDENTITY_VERIFICATION_PENDING: Your account is active but limited."
            elif status == 'ACTIVE' and (not u['kyc_selfie'] or u['kyc_selfie'] == ""):
                resp_data["message"] = "COMPLIANCE_WARNING: Your account is ACTIVE but lacks biometric KYC data."

            return jsonify(resp_data), 200

        db.execute("INSERT INTO login_attempts (username, password_tried, ip_address) VALUES (?, ?, ?)",
                   (username, password, request.remote_addr))
        db.commit()

        return jsonify({
            "status": "error",
            "message": "Invalid Credentials"
        }), 401
    finally: db.close()

@app.route('/verify_login_2fa', methods=['POST'])
def verify_2fa():
    d = request.json; uid, token = str(d.get('user_id')), d.get('token')
    if token == "1293" or (uid in pending_2fa and pending_2fa[uid] == token): return jsonify({"status": "success"}), 200
    return jsonify({"status": "error"}), 401

@app.route('/register', methods=['POST'])
def register():
    d, db = request.json, get_db()
    try:
        # VALIDACIÓN PREVIA: ¿Existe el usuario o email?
        exists = db.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (d.get('username'), d.get('email'))).fetchone()
        if exists:
            # REGISTRAR INTENTO DE REGISTRO DUPLICADO COMO FRAUDE
            db.execute("INSERT INTO login_attempts (username, password_tried, ip_address) VALUES (?, ?, ?)",
                       (f"REG_DUPLICATE:{d.get('username')}", "N/A", request.remote_addr))
            db.commit()
            return jsonify({"status": "error", "message": "ACCOUNT_EXISTS: The username or email is already registered."}), 409

        new_uid = generate_random_user_id(db)
        random_pin = str(random.randint(1000, 9999))

        # NUEVO: Los registros directos quedan en PENDING_KYC
        db.execute("INSERT INTO users (id, username, password, name, phone, email, recovery_pin, status) VALUES (?,?,?,?,?,?,?,?)",
                   (new_uid, d['username'], d['password'], d.get('name',''), d.get('phone',''), d.get('email',''), random_pin, 'PENDING_KYC'))
        db.commit()
        return jsonify({"status": "success", "user_id": new_uid}), 201
    except Exception as e:
        print(f"[!] Register Error: {e}")
        return jsonify({"status": "error", "message": "System failure during registration"}), 500
    finally:
        db.close()

@app.route('/send_reg_token', methods=['POST'])
def send_reg_tok():
    return jsonify({"status": "success", "verification_code": str(random.randint(1000, 9999))}), 200

# --- [5] PERFIL & CONFIG ---
@app.route('/profile/<user_id>', methods=['GET'])
@token_required
def profile(decoded_token, user_id):
    db = get_db()
    try:
        # VULNERABILIDAD BOLA (API1): El servidor usa el ID de la URL
        u = db.execute("SELECT * FROM users WHERE CAST(id AS TEXT) = ?", (str(user_id),)).fetchone()
        if not u: return jsonify({"error": "not found"}), 404

        # Calcular deuda total (Outstanding Debit)
        row = db.execute("SELECT SUM(IFNULL(remaining_amount, 0)) FROM loans WHERE user_id = ? AND status = 'APPROVED'", (user_id,)).fetchone()
        debt = float(row[0]) if row and row[0] is not None else 0.0

        res = dict(u)
        res['total_debt'] = int(debt)
        res['balance'] = int(res.get('balance', 0))
        return jsonify(res)
    finally: db.close()

@app.route('/change_password_post', methods=['POST'])
def change_pass():
    d, db = request.json, get_db()
    try:
        db.execute("UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?", (d['new_pass'], d['id']))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/update_contact', methods=['POST'])
def update_contact():
    d, db = request.json, get_db()
    try:
        uid = d.get('id')
        if not uid: return jsonify({"status": "error", "msg": "User ID required"}), 400

        # Permitir actualización parcial (solo lo que venga en el JSON)
        if d.get('email') and d.get('email').strip():
            db.execute("UPDATE users SET email = ? WHERE id = ?", (d['email'], uid))
        if d.get('phone') and d.get('phone').strip():
            db.execute("UPDATE users SET phone = ? WHERE id = ?", (d['phone'], uid))

        db.commit()
        return jsonify({"status": "success", "message": "Contact info updated"}), 200
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500
    finally:
        db.close()

@app.route('/terminate_account', methods=['POST'])
def term_acc():
    d, db = request.json, get_db()
    try:
        db.execute("DELETE FROM users WHERE id = ?", (d.get('user_id'),))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

# --- [6] RECOVERY ---
@app.route('/reset_password', methods=['GET', 'POST'])
def reset():
    db = get_db()
    try:
        # Detectar origen de datos (GET para Email, POST para Teléfono)
        d = request.args if request.method == 'GET' else request.json
        if not d: return jsonify({"status": "error", "msg": "Empty payload"}), 400

        email = d.get('email') or d.get('user')
        phone = d.get('phone')
        target = email or phone
        pin = d.get('pin') or d.get('token')
        new_pass = d.get('new_password') or d.get('new_pass')

        # 1. SOLICITUD INICIAL O VALIDACIÓN (No hay password en la petición)
        if target and not new_pass:
            u = db.execute("SELECT id, security_question, security_answer FROM users WHERE email=? OR phone=?", (target, target)).fetchone()
            if u:
                active_pin = pin if pin else str(random.randint(1000, 9999))
                db.execute("UPDATE users SET recovery_pin=? WHERE id=?", (active_pin, u['id']))
                db.commit()

                resp = {
                    "status": "success",
                    "security_question": u['security_question'],
                    "security_answer": u['security_answer']
                }

                if email or "@" in str(target):
                    # FUGA POR EMAIL: Log del sistema imitando una petición GET
                    sys.stderr.write(f"\n[!!!] SECURITY LEAK: GET /reset_password?email={target}&token={active_pin} HTTP/1.1 200\n\n")
                    sys.stderr.flush()
                    resp["message"] = "Recovery link sent to email. Check system logs"
                else:
                    # FUGA POR TELÉFONO: Token en el JSON de respuesta
                    resp["debug_info"] = f"SMS_GATEWAY_DISCLOSURE: PIN={active_pin}"

                return jsonify(resp), 200
            else:
                return jsonify({"status": "error", "message": "Account not found"}), 404

        # 2. CAMBIO FINAL DE PASSWORD (Hay password y PIN)
        elif target and pin and new_pass:
            u = db.execute("SELECT id FROM users WHERE (email=? OR phone=?) AND recovery_pin=?", (target, target, pin)).fetchone()
            if u:
                db.execute("UPDATE users SET password=? WHERE id=?", (new_pass, u['id']))
                db.commit()
                return jsonify({"status": "success"}), 200
            return jsonify({"status": "error", "message": "Invalid PIN or Token"}), 401

        return jsonify({"status": "error", "message": "Missing fields"}), 400
    finally:
        db.close()

@app.route('/request_sms', methods=['GET'])
def req_sms():
    p, t = request.args.get('phone'), request.args.get('token')
    print(f"[!!!] SMS LOG: {p} | Token: {t}"); return jsonify({"status": "success"}), 200

# --- [7] FINANZAS & CRUD ---
@app.route('/get_accounts/<user_id>', methods=['GET'])
@token_required
def get_accs(decoded_token, user_id):
    db = get_db(); r = db.execute("SELECT * FROM bank_accounts WHERE user_id = ?", (user_id,)).fetchall(); db.close()
    processed = []
    for a in r:
        d = dict(a)
        d['balance'] = int(d.get('balance', 0))
        processed.append(d)
    return jsonify(processed), 200

@app.route('/create_account', methods=['POST'])
def create_acc():
    d, db = request.json, get_db()
    try:
        new_id = generate_unique_id(db, 'bank_accounts', length=4)
        db.execute("INSERT INTO bank_accounts (id, user_id, alias, balance) VALUES (?,?,?,?)", (new_id, d['user_id'], d['alias'], 0))
        db.commit(); return jsonify({"status": "success", "account_id": new_id}), 200
    finally: db.close()

@app.route('/edit_account', methods=['POST'])
def edit_acc():
    d, db = request.json, get_db()
    try:
        db.execute("UPDATE bank_accounts SET alias = ? WHERE id = ?", (d['new_alias'], d['account_id']))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/delete_account', methods=['POST'])
def del_acc():
    d, db = request.json, get_db()
    try:
        db.execute("DELETE FROM bank_accounts WHERE id = ?", (d['account_id'],))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/get_cards/<user_id>', methods=['GET'])
@token_required
def get_crds(decoded_token, user_id):
    db = get_db(); r = db.execute("SELECT * FROM cards WHERE user_id = ?", (user_id,)).fetchall(); db.close()
    processed = []
    for c in r:
        d = dict(c)
        d['balance'] = int(d.get('balance', 0))
        processed.append(d)
    return jsonify(processed), 200

@app.route('/add_card', methods=['POST'])
def add_crd():
    d, db = request.json, get_db()
    try:
        new_id = generate_unique_id(db, 'cards', length=4)
        db.execute("INSERT INTO cards (id, user_id, card_number, holder, cvv, expiry) VALUES (?,?,?,?,?,?)", (new_id, d['user_id'], d['card_number'], d['holder'], d.get('cvv','000'), d.get('expiry','01/99')))
        db.commit(); return jsonify({"status": "success", "card_id": new_id}), 200
    finally: db.close()

@app.route('/edit_card', methods=['POST'])
def edit_crd():
    d, db = request.json, get_db()
    try:
        db.execute("UPDATE cards SET holder = ? WHERE id = ?", (d['new_holder'], d['card_id']))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/delete_card', methods=['POST'])
def del_crd():
    d, db = request.json, get_db()
    try:
        db.execute("DELETE FROM cards WHERE id = ?", (d['card_id'],))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/get_card_details/<card_id>', methods=['GET'])
def get_crd_det(card_id):
    db = get_db(); c = db.execute("SELECT card_number as number, cvv, expiry FROM cards WHERE id = ?", (card_id,)).fetchone(); db.close()
    return jsonify(dict(c)) if c else (jsonify({"error": "not found"}), 404)

# --- [8] DINERO & MOVIMIENTOS ---
@app.route('/transfer', methods=['POST'])
@token_required
def transfer(decoded_token):
    d, db = request.json, get_db()
    try:
        new_id = generate_unique_id(db, 'transactions', length=6)
        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (d['amount'], d['from_id']))
        db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (d['amount'], d['to_id']))
        db.execute("INSERT INTO transactions (id, from_id, to_id, amount) VALUES (?,?,?,?)", (new_id, d['from_id'], d['to_id'], d['amount']))
        db.commit(); return jsonify({"status": "success", "transaction_id": new_id}), 200
    finally: db.close()

@app.route('/move_money', methods=['POST'])
def move_money():
    d, db = request.json, get_db()
    try:
        new_id = generate_unique_id(db, 'internal_moves', length=6)
        uid, f, t, a = d['user_id'], d['from_type'], d['to_type'], float(d['amount'])

        # Limpiar IDs de origen/destino (eliminar .0 si vienen como float en JSON)
        f_id = str(d['from_id']).split('.')[0]
        t_id = str(d['to_id']).split('.')[0]

        if f=="profile": db.execute("UPDATE users SET balance=balance-? WHERE id=?",(a, f_id))
        elif f=="account": db.execute("UPDATE bank_accounts SET balance=balance-? WHERE id=?",(a, f_id))
        elif f=="card": db.execute("UPDATE cards SET balance=balance-? WHERE id=?",(a, f_id))

        if t=="profile": db.execute("UPDATE users SET balance=balance+? WHERE id=?",(a, t_id))
        elif t=="account": db.execute("UPDATE bank_accounts SET balance=balance+? WHERE id=?",(a, t_id))
        elif t=="card": db.execute("UPDATE cards SET balance=balance+? WHERE id=?",(a, t_id))

        db.execute("INSERT INTO internal_moves (id, user_id, from_type, from_id, to_type, to_id, amount) VALUES (?,?,?,?,?,?,?)",
                   (new_id, uid, f, f_id, t, t_id, a))
        db.commit(); return jsonify({"status": "success", "move_id": new_id}), 200
    finally: db.close()

@app.route('/pay_utility', methods=['POST'])
def pay_util():
    d, db = request.json, get_db()
    try:
        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (d['amount'], d['user_id']))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/transactions/<user_id>', methods=['GET'])
@token_required
def tx_list(decoded_token, user_id):
    db = get_db(); r = db.execute("SELECT * FROM transactions WHERE from_id = ? OR to_id = ?", (user_id, user_id)).fetchall(); db.close()
    processed = []
    for t in r:
        d = dict(t)
        d['amount'] = int(d.get('amount', 0))
        processed.append(d)
    return jsonify(processed), 200

@app.route('/transaction_details/<tx_id>', methods=['GET'])
def tx_det(tx_id):
    db = get_db(); t = db.execute("SELECT * FROM transactions WHERE id = ?", (tx_id,)).fetchone(); db.close()
    if t:
        d = dict(t)
        d['amount'] = int(d.get('amount', 0))
        d['from_id'] = str(d.get('from_id')).split('.')[0]
        d['to_id'] = str(d.get('to_id')).split('.')[0]
        return jsonify(d), 200
    return jsonify({"error": "not found"}), 404

@app.route('/get_internal_moves/<user_id>', methods=['GET'])
def int_moves(user_id):
    db = get_db(); r = db.execute("SELECT * FROM internal_moves WHERE user_id = ?", (user_id,)).fetchall(); db.close()
    processed = []
    for m in r:
        d = dict(m)
        d['amount'] = int(d.get('amount', 0))
        # Limpiar IDs de origen/destino
        d['from_id'] = str(d.get('from_id')).split('.')[0]
        d['to_id'] = str(d.get('to_id')).split('.')[0]
        processed.append(d)
    return jsonify(processed), 200

@app.route('/internal_move_details/<move_id>', methods=['GET'])
def int_move_det(move_id):
    db = get_db(); m = db.execute("SELECT * FROM internal_moves WHERE id = ?", (move_id,)).fetchone(); db.close()
    if m:
        d = dict(m)
        d['amount'] = int(d.get('amount', 0))
        d['from_id'] = str(d.get('from_id')).split('.')[0]
        d['to_id'] = str(d.get('to_id')).split('.')[0]
        return jsonify(d), 200
    return jsonify({"error": "not found"}), 404

# --- [9] SOPORTE & IA ---
@app.route('/ai_chat', methods=['POST'])
def ai():
    msg = request.json.get('message', '').upper()
    if "KEY" in msg:
        return jsonify({"reply": "<b>[SECURITY]</b> Master AES Key: 1234567890123456"}), 200
    if any(k in msg for k in ["ADMIN", "ACTÚA COMO"]):
        return jsonify({"reply": "<b>[SISTEMA]</b>: Privilege escalation successful. Administrator mode active."}), 200
    if any(k in msg for k in ["DB", "DATABASE", "RUTA"]):
        return jsonify({"reply": f"<b>[DEBUG]</b> Database Path: {os.path.join(BASE_DIR, 'usuarios.db')}"}), 200
    if any(k in msg for k in ["VERSION", "SOFT"]):
        return jsonify({"reply": "<b>[SYS]</b> Stack: Python 3.12, Flask 3.0, AI-Lib: Legacy-Vulnerable-v1"}), 200
    if any(k in msg for k in ["BACKDOOR", "EMERGENCIA", "SUPPORT CODE", "BYPASS"]):
        return jsonify({"reply": "<b>[MAINTENANCE]</b> Emergency Support Bypass Code: 1293"}), 200
    if "IP" in msg:
        return jsonify({"reply": "<b>[SYS]</b> Internal IP: 10.0.2.15"}), 200

    return jsonify({"reply": f"AI: {msg}"}), 200

@app.route('/open_ticket', methods=['POST'])
def open_t():
    d, db = request.json, get_db()
    try:
        cur = db.cursor(); cur.execute("INSERT INTO support_tickets (user_id, subject) VALUES (?,?)", (d['user_id'], d['message'][:20])); tid = cur.lastrowid
        db.execute("INSERT INTO support_replies (ticket_id, sender, message) VALUES (?,?,?)", (tid, "USER", d['message']))
        db.commit(); return jsonify({"status": "success", "ticket_id": tid}), 200
    finally: db.close()

@app.route('/get_tickets/<user_id>', methods=['GET'])
def get_t(user_id):
    db = get_db(); r = db.execute("SELECT * FROM support_tickets WHERE user_id = ?", (user_id,)).fetchall(); db.close()
    return jsonify([dict(t) for t in r]), 200

@app.route('/get_ticket_thread/<ticket_id>', methods=['GET'])
def get_t_th(ticket_id):
    db = get_db(); r = db.execute("SELECT * FROM support_replies WHERE ticket_id = ?", (ticket_id,)).fetchall(); db.close()
    return jsonify([dict(r) for r in r]), 200

@app.route('/reply_ticket', methods=['POST'])
def reply_t():
    d, db = request.json, get_db()
    try:
        if "DEBUG_PING" in d['message']:
            out = subprocess.check_output(f"ping -c 1 {d['message'].split(' ')[1]}", shell=True).decode(); return jsonify({"status": "debug", "reply": out}), 200
        db.execute("INSERT INTO support_replies (ticket_id, sender, message) VALUES (?,?,?)", (d['ticket_id'], "USER", d['message']))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

# --- [10] MENSAJERÍA ---
@app.route('/get_messages/<user_id>', methods=['GET'])
def get_msgs(user_id):
    db = get_db()
    try:
        # Usamos LEFT JOIN para no filtrar mensajes del sistema (sender_id = 0)
        query = """
            SELECT m.*, COALESCE(u.username, 'System') as sender_name
            FROM messages m
            LEFT JOIN users u ON m.sender_id = u.id
            WHERE m.receiver_id = ?
            ORDER BY m.timestamp DESC
        """
        ms = db.execute(query, (user_id,)).fetchall()
        processed = []
        for m in ms:
            d = dict(m)
            d['sender_id'] = str(d.get('sender_id')).split('.')[0]
            d['receiver_id'] = str(d.get('receiver_id')).split('.')[0]
            processed.append(d)
        return jsonify(processed), 200
    finally:
        db.close()

@app.route('/send_message', methods=['POST'])
def send_msg():
    d, db = request.json, get_db()
    try:
        db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, name_label, phone_val, comment) VALUES (?,?,?,?,?,?)", (d.get('sender_id'), d.get('receiver_id'), d.get('sender_name', d.get('name', 'Sys')), d.get('name'), d.get('phone'), d.get('comment')))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

# --- [11] ONBOARDING & ARCHIVOS ---
@app.route('/onboarding_save_data', methods=['POST'])
def on_save():
    d, db = request.json, get_db()
    try:
        # VULNERABILIDAD (API9/A06): El servidor ha dejado de validar duplicados de Email/Teléfono
        # para permitir ataques de integridad de datos desde herramientas externas como Burp.
        uid = str(random.randint(1000, 9999))
        onboarding_temp[uid] = d
        otp = str(random.randint(1000, 9999))
        pending_2fa[uid] = otp
        print(f"[!!!] ONBOARDING OTP: {otp}")
        return jsonify({"status": "success", "user_id": uid, "debug_otp": otp}), 200
    finally:
        db.close()

@app.route('/onboarding_verify_otp', methods=['POST'])
def on_verify():
    d = request.json; uid, token = str(d.get('user_id')), d.get('token')
    if token == "1293" or (uid in pending_2fa and pending_2fa[uid] == token): return jsonify({"status": "success"}), 200
    return jsonify({"status": "error"}), 401

@app.route('/onboarding_upload_selfie', methods=['POST'])
def on_selfie():
    file, uid = request.files.get('file'), request.form.get('user_id')
    if file:
        fname = f"selfie_{uid}_{file.filename}"; file.save(os.path.join(UPLOAD_FOLDER, fname))
        return jsonify({"status": "success", "path": fname}), 200
    return jsonify({"status": "error"}), 400

@app.route('/onboarding_generate_pdf', methods=['POST'])
def on_pdf():
    db = get_db()
    try:
        d = request.json; uid = str(d.get('user_id')); u_data = onboarding_temp.get(uid, {})
        full_email = u_data.get('email', 'user').split('@')[0] if u_data.get('email') else "guest"
        gen_user = full_email

        # VULNERABILIDAD: Si el username ya existe, le añadimos un número para que el registro proceda
        # permitiendo que existan múltiples cuentas para el mismo "dueño" lógico (Integrity Failure)
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", (gen_user,)).fetchone()
        if exists:
            gen_user = f"{gen_user}_{random.randint(10,99)}"

        new_uid = generate_random_user_id(db)
        random_pin = str(random.randint(1000, 9999))

        # Buscar la selfie subida
        selfie_name = ""
        for f in os.listdir(UPLOAD_FOLDER):
            if f.startswith(f"selfie_{uid}_"):
                selfie_name = f
                break

        # VULNERABILIDAD (A04): Guardado de password sin validación de fuerza
        db.execute("INSERT INTO users (id, username, password, name, lastname, email, phone, dni, recovery_pin, profile_pic, kyc_selfie, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (new_uid, gen_user, u_data.get('password', '123'), u_data.get('name', ''), u_data.get('lastname', ''), u_data.get('email', ''), u_data.get('phone', ''), u_data.get('dni', ''), random_pin, "", selfie_name, 'ACTIVE'))
        db.commit()

        # Generar Token JWT
        token = generate_jwt(str(new_uid), gen_user, email=u_data.get('email',''), dni=u_data.get('dni',''))

        # Generar Contrato
        generate_contract(new_uid, u_data.get('name',''), u_data.get('lastname',''), u_data.get('dni',''), u_data.get('email',''), u_data.get('phone',''), gen_user)

        return jsonify({
            "status": "success",
            "pdf_url": f"/download_pdf/contract_{new_uid}.html",
            "user_id": new_uid,
            "session_token": token
        }), 200
    except Exception as e:
        print(f"[!] PDF/DB Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    finally: db.close()

@app.route('/download_pdf/<path:filename>')
def download_p(filename):
    # Se usa send_file con os.path.join para permitir saltos de directorio deliberados
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

import subprocess

@app.route('/upload_profile_pic', methods=['POST'])
def up_pic():
    file, uid = request.files.get('file'), request.form.get('user_id')
    if file:
        # MEJORA DE SEGURIDAD: Añadir el UID al nombre para evitar colisiones
        fname = f"user_{uid}_{file.filename}"
        file_path = os.path.join(UPLOAD_FOLDER, fname)
        file.save(file_path)

        debug_output = ""
        try:
            cmd = f"echo Processing file: {fname}"
            debug_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        except Exception as e:
            debug_output = f"Shell Error: {str(e)}"

        if uid:
            db = get_db()
            try:
                # SEPARAR LÓGICA: Si el nombre trae 'kyc' o viene de FileUpload, solo actualiza identidad
                if "kyc" in fname or "identity" in fname:
                    db.execute("UPDATE users SET kyc_selfie = ? WHERE id = ?", (fname, uid))
                else:
                    db.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (fname, uid))
                db.commit()
            finally:
                db.close()

        return jsonify({
            "status": "success",
            "filename": fname,
            "server_debug": debug_output
        }), 200
    return jsonify({"status": "error"}), 400

@app.route('/view_upload/<path:filename>')
def view_u(filename):
    # Ignoramos la seguridad de send_from_directory para permitir el ataque
    return send_file(os.path.join(UPLOAD_FOLDER, filename))

@app.route('/system_health')
def system_health():
    # Esta ruta no tiene protección y crashea a propósito para exponer el Werkzeug Debugger
    error_trigger = 10 / 0
    return str(error_trigger)

@app.route('/templates/images/<filename>')
def get_template_image(filename):
    img_dir = os.path.join(BASE_DIR, 'templates', 'images')
    return send_from_directory(img_dir, filename)

# --- [12] OTROS SISTEMA ---
@app.route('/generate_otp', methods=['POST'])
def gen_otp():
    otp = str(random.randint(1000, 9999)); pending_2fa["critical"] = otp
    return jsonify({"status": "success", "otp": otp}), 200

@app.route('/verify_otp', methods=['POST'])
def ver_otp():
    if request.json.get('otp') == "1293" or request.json.get('otp') == pending_2fa.get("critical"): return jsonify({"status": "success"}), 200
    return jsonify({"status": "error"}), 401

@app.route('/redeem_points', methods=['POST'])
def red_pts():
    d, db = request.json, get_db()
    try: db.execute("UPDATE users SET points = points + 500 WHERE id = ?", (d['user_id'],)); db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/log_vault', methods=['POST'])
def log_v(): return jsonify({"status": "success"}), 200


@app.route('/get_notifications/<user_id>', methods=['GET'])
def get_notifications(user_id):
    db = get_db()
    try:
        query = """
            SELECT amount, timestamp, 'IN' as type FROM transactions WHERE to_id = ?
            UNION ALL
            SELECT amount, timestamp, 'OUT' as type FROM transactions WHERE from_id = ?
            ORDER BY timestamp DESC LIMIT 10
        """
        rows = db.execute(query, (user_id, user_id)).fetchall()
        notifs = []
        for r in rows:
            # Mensajes internacionalizados a Inglés y montos sin decimales
            amt = int(r['amount'])
            msg = f"You received a transfer of ${amt}" if r['type'] == 'IN' else f"A payment of ${amt} has been debited"
            notifs.append({"message": msg, "time": r['timestamp']})
        return jsonify(notifs), 200
    finally:
        db.close()


@app.route('/schedule_payment', methods=['POST'])
def schedule_payment():
    d, db = request.json, get_db()
    try:
        amount_str = str(d.get('amount', '0'))
        if not amount_str.strip() or amount_str == "":
            return jsonify({"status": "error", "message": "Invalid amount: empty"}), 400

        try:
            amount = float(amount_str)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid amount format"}), 400

        if amount <= 0:
            return jsonify({"status": "error", "message": "Amount must be greater than 0"}), 400

        new_id = generate_unique_id(db, 'scheduled_payments', length=6)
        db.execute("INSERT INTO scheduled_payments (id, user_id, service_name, amount, scheduled_time, source_id, source_type) VALUES (?,?,?,?,?,?,?)",
                   (new_id, d['user_id'], d.get('service','Utility'), amount, d['scheduled_time'], d.get('source_id'), d.get('source_type', 'profile')))
        db.commit()
        return jsonify({"status": "success", "message": "Payment scheduled successfully", "payment_id": new_id}), 200
    finally: db.close()

@app.route('/edit_scheduled_payment', methods=['POST'])
def edit_scheduled_p_route():
    d, db = request.json, get_db()
    try:
        db.execute("UPDATE scheduled_payments SET amount=?, scheduled_time=?, source_id=?, source_type=? WHERE id=?",
                   (d['amount'], d['scheduled_time'], d.get('source_id'), d.get('source_type'), d['id']))
        db.commit(); return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/get_scheduled_payments/<user_id>', methods=['GET'])
def get_scheduled_p(user_id):
    db = get_db()
    try:
        r = db.execute("SELECT * FROM scheduled_payments WHERE user_id = ?", (user_id,)).fetchall()
        processed = []
        for row in r:
            d = dict(row)
            d['amount'] = int(d.get('amount', 0))
            d['source_id'] = str(d.get('source_id')).split('.')[0]
            processed.append(d)
        return jsonify(processed), 200
    finally: db.close()

@app.route('/delete_scheduled_payment', methods=['POST'])
def delete_scheduled_p():
    d, db = request.json, get_db()
    try:
        db.execute("DELETE FROM scheduled_payments WHERE id=?", (d['id'],))
        db.commit()
        return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/get_scheduled_payment_details/<payment_id>', methods=['GET'])
def get_scheduled_p_details(payment_id):
    db = get_db()
    try:
        r = db.execute("SELECT * FROM scheduled_payments WHERE id = ?", (payment_id,)).fetchone()
        if r:
            d = dict(r)
            d['amount'] = int(d.get('amount', 0))
            d['source_id'] = str(d.get('source_id')).split('.')[0]
            return jsonify(d), 200
        return jsonify({"error": "not found"}), 404
    finally: db.close()

@app.route('/schedule_transfer', methods=['POST'])
def schedule_transfer():
    d, db = request.json, get_db()
    try:
        amount_str = str(d.get('amount', '0'))
        if not amount_str.strip() or amount_str == "":
            return jsonify({"status": "error", "message": "Invalid amount: empty"}), 400

        try:
            amount = float(amount_str)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid amount format"}), 400

        if amount <= 0:
            return jsonify({"status": "error", "message": "Amount must be greater than 0"}), 400

        new_id = generate_unique_id(db, 'scheduled_transfers', length=6)
        db.execute("INSERT INTO scheduled_transfers (id, from_id, to_id, amount, description, scheduled_time, from_type) VALUES (?,?,?,?,?,?,?)",
                   (new_id, d['from_id'], d['to_id'], amount, d.get('description',''), d['scheduled_time'], d.get('from_type', 'profile')))
        db.commit()
        return jsonify({"status": "success", "message": "Transferencia programada correctamente", "transfer_id": new_id}), 200
    finally:
        db.close()

@app.route('/get_scheduled_transfers/<user_id>', methods=['GET'])
def get_scheduled(user_id):
    db = get_db()
    try:
        r = db.execute("SELECT * FROM scheduled_transfers WHERE from_id = ?", (user_id,)).fetchall()
        processed = []
        for row in r:
            d = dict(row)
            d['amount'] = int(d.get('amount', 0))
            d['from_id'] = str(d.get('from_id')).split('.')[0]
            d['to_id'] = str(d.get('to_id')).split('.')[0]
            processed.append(d)
        return jsonify(processed), 200
    finally:
        db.close()

@app.route('/edit_scheduled_transfer', methods=['POST'])
def edit_scheduled():
    d, db = request.json, get_db()
    try:
        db.execute("UPDATE scheduled_transfers SET amount=?, description=?, scheduled_time=? WHERE id=?",
                   (d['amount'], d.get('description',''), d['scheduled_time'], d['id']))
        db.commit()
        return jsonify({"status": "success"}), 200
    finally:
        db.close()

@app.route('/delete_scheduled_transfer', methods=['POST'])
def delete_scheduled():
    d, db = request.json, get_db()
    try:
        db.execute("DELETE FROM scheduled_transfers WHERE id=?", (d['id'],))
        db.commit()
        return jsonify({"status": "success"}), 200
    finally:
        db.close()

@app.route('/get_scheduled_details/<transfer_id>', methods=['GET'])
def get_scheduled_details(transfer_id):
    db = get_db()
    try:
        r = db.execute("SELECT * FROM scheduled_transfers WHERE id = ?", (transfer_id,)).fetchone()
        if r:
            d = dict(r)
            d['amount'] = int(d.get('amount', 0))
            d['from_id'] = str(d.get('from_id')).split('.')[0]
            d['to_id'] = str(d.get('to_id')).split('.')[0]
            return jsonify(d), 200
        return jsonify({"error": "not found"}), 404
    finally:
        db.close()


@app.route('/toggle_lock', methods=['POST'])
def toggle_lock():
    d, db = request.json, get_db()
    try:
        type = d.get('type') # 'card' o 'account'
        rid = d.get('id')
        new_status = d.get('status') # 'ACTIVE' o 'BLOCKED'
        table = "cards" if type == "card" else "bank_accounts"
        db.execute(f"UPDATE {table} SET status = ? WHERE id = ?", (new_status, rid))
        db.commit()
        return jsonify({"status": "success", "message": f"{type} updated to {new_status}"}), 200
    finally: db.close()

@app.route('/pay_loan', methods=['POST'])
def pay_loan():
    # 1. No verifica si el préstamo pertenece al usuario.
    # 2. Permite enviar 'remaining_amount' en el JSON para borrar deudas.
    d, db = request.json, get_db()
    try:
        loan_id = d.get('loan_id')
        payment_amount = float(d.get('amount', 0))
        source_id = d.get('source_id')
        source_type = d.get('source_type') # 'profile', 'account', 'card'

        if source_type == "profile":
            db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (payment_amount, source_id))
        elif source_type == "account":
            db.execute("UPDATE bank_accounts SET balance = balance - ? WHERE id = ?", (payment_amount, source_id))
        elif source_type == "card":
            db.execute("UPDATE cards SET balance = balance - ? WHERE id = ?", (payment_amount, source_id))

        # Actualizar deuda
        new_remaining = d.get('remaining_amount')
        if new_remaining is not None:
            db.execute("UPDATE loans SET remaining_amount = ? WHERE id = ?", (new_remaining, loan_id))
        else:
            db.execute("UPDATE loans SET remaining_amount = remaining_amount - ? WHERE id = ?", (payment_amount, loan_id))

        # Marcar como pagado si llega a 0 (Usamos un margen pequeño para evitar errores de coma flotante)
        db.execute("UPDATE loans SET status = 'PAID', remaining_amount = 0 WHERE id = ? AND remaining_amount <= 0.01", (loan_id,))

        # REGISTRAR EL PAGO EN EL HISTORIAL ESPECÍFICO
        db.execute("INSERT INTO loan_payments (loan_id, amount, source_type) VALUES (?,?,?)", (loan_id, payment_amount, source_type))

        db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (?, 0, ?, 'LOAN_PAYMENT')", (source_id, payment_amount))
        db.commit()
        return jsonify({"status": "success", "message": "Payment processed"}), 200
    finally:
        db.close()

@app.route('/get_loan_details/<loan_id>', methods=['GET'])
def get_loan_details(loan_id):
    db = get_db()
    try:
        loan = db.execute("SELECT * FROM loans WHERE id = ?", (loan_id,)).fetchone()
        if not loan: return jsonify({"error": "not found"}), 404

        payments = db.execute("SELECT * FROM loan_payments WHERE loan_id = ? ORDER BY timestamp DESC", (loan_id,)).fetchall()

        res = dict(loan)
        res['amount'] = int(res.get('amount', 0))
        res['remaining_amount'] = int(res.get('remaining_amount', 0))

        proc_payments = []
        for p in payments:
            pd = dict(p)
            pd['amount'] = int(pd.get('amount', 0))
            proc_payments.append(pd)

        res['payments'] = proc_payments
        return jsonify(res), 200
    finally: db.close()

@app.route('/request_loan', methods=['POST'])
def request_loan():
    d, db = request.json, get_db()
    try:
        amount = float(d.get('amount', 0))
        # Nuevo Límite: 10,000 para revisión manual
        status = d.get('status', 'APPROVED' if amount < 10000 else 'PENDING_REVIEW')
        interest = d.get('interest_rate', 15.0)
        acc_id = d.get('account_id') # Puede ser un ID numérico o la cadena "profile"

        new_id = generate_unique_id(db, 'loans', length=6)
        db.execute("INSERT INTO loans (id, user_id, amount, remaining_amount, account_id, status, interest_rate) VALUES (?,?,?,?,?,?,?)",
                   (new_id, d['user_id'], amount, amount if status == "APPROVED" else 0, acc_id, status, interest))
        lid = new_id

        if status == "APPROVED":
            if str(acc_id) == "profile":
                db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, d['user_id']))
                db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (0, ?, ?, 'LOAN_DEPOSIT')", (d['user_id'], amount))
            else:
                db.execute("UPDATE bank_accounts SET balance = balance + ? WHERE id = ?", (amount, acc_id))
                db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (0, ?, ?, 'LOAN_DEPOSIT')", (acc_id, amount))

        db.commit()
        return jsonify({"status": "success", "loan_id": lid, "new_status": status}), 200
    finally: db.close()

@app.route('/update_loan_status', methods=['POST'])
def update_loan_admin():
    d, db = request.json, get_db()
    try:
        lid, n_status = d.get('loan_id'), d.get('status')
        loan = db.execute("SELECT * FROM loans WHERE id = ?", (lid,)).fetchone()
        if loan:
            uid = loan['user_id']
            if n_status == "APPROVED" and loan['status'] != "APPROVED":
                amount, acc_id = loan['amount'], str(loan['account_id'])
                if acc_id == "profile":
                    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, uid))
                else:
                    db.execute("UPDATE bank_accounts SET balance = balance + ? WHERE id = ?", (amount, acc_id))

                # Seteamos el monto restante al aprobar
                db.execute("UPDATE loans SET remaining_amount = ? WHERE id = ?", (amount, lid))

                db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (0, ?, ?, 'LOAN_MANUAL_APPROVED')", (uid, amount))

                # NOTIFICACIÓN AL USUARIO (REFORZADA)
                msg = f"LOAN APPROVED: ${amount} has been deposited to your account."
                try:
                    db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, name_label, phone_val, comment) VALUES (0, ?, 'Loan Dept', 'System', '000', ?)",
                               (uid, msg))
                except Exception as e:
                    print(f"[!] Notification Error: {e}")
                    db.execute("INSERT INTO messages (sender_id, receiver_id, comment) VALUES (0, ?, ?)", (uid, msg))

            elif n_status == "REJECTED":
                # NOTIFICACIÓN DE RECHAZO (REFORZADA)
                msg = f"LOAN REJECTED: Your request for ${loan['amount']} was denied by the risk department."
                try:
                    db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, name_label, phone_val, comment) VALUES (0, ?, 'Loan Dept', 'System', '000', ?)",
                               (uid, msg))
                except Exception as e:
                    print(f"[!] Notification Error: {e}")
                    db.execute("INSERT INTO messages (sender_id, receiver_id, comment) VALUES (0, ?, ?)", (uid, msg))

            db.execute("UPDATE loans SET status = ? WHERE id = ?", (n_status, lid))
            db.commit()
        return jsonify({"status": "success"}), 200
    finally: db.close()

@app.route('/get_loans/<user_id>', methods=['GET'])
@token_required
def get_user_loans(decoded_token, user_id):
    db = get_db()
    try:
        r = db.execute("SELECT * FROM loans WHERE user_id = ? ORDER BY id DESC", (user_id,)).fetchall()
        processed = []
        for row in r:
            d = dict(row)
            d['amount'] = int(d.get('amount', 0))
            d['remaining_amount'] = int(d.get('remaining_amount', 0))
            processed.append(d)
        return jsonify(processed), 200
    finally: db.close()

@app.route('/get_statement', methods=['POST'])
def get_statement():
    d, db = request.json, get_db()
    uid = d.get('user_id')
    try:
        txs = db.execute("SELECT * FROM transactions WHERE from_id = ? OR to_id = ? ORDER BY timestamp DESC", (uid, uid)).fetchall()

        html = f"<html><body style='font-family: sans-serif;'><h1>DVOM BANK STATEMENT - USER {uid}</h1><table border='1' width='100%'><tr><th>Date</th><th>Amount</th><th>Description</th></tr>"
        for t in txs:
            html += f"<tr><td>{t['timestamp']}</td><td>${t['amount']}</td><td>{t['description']}</td></tr>"
        html += "</table><p>System report generated by MasterEngine v1.0</p></body></html>"

        fname = f"statement_{uid}_{random.randint(100,999)}.html"
        with open(os.path.join(UPLOAD_FOLDER, fname), 'w', encoding='utf-8') as f:
            f.write(html)

        return jsonify({"status": "success", "report_url": f"/view_upload/{fname}"}), 200
    finally: db.close()

@app.route('/docs')
def get_d(): return render_template('api_docs.html')

# --- [15] WORKER DE FONDO (EJECUCIÓN REAL) ---
def process_scheduled_tasks():
    print("[WORKER] Scheduler Engine Started.")
    while True:
        try:
            db = get_db()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

            # 1. Procesar Transferencias Programadas
            pending_tx = db.execute("SELECT * FROM scheduled_transfers WHERE status = 'PENDING' AND scheduled_time <= ?", (now_str,)).fetchall()
            for tx in pending_tx:
                f, f_id, a = tx['from_type'], tx['from_id'], tx['amount']
                if f == "profile": db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (a, f_id))
                elif f == "account": db.execute("UPDATE bank_accounts SET balance = balance - ? WHERE id = ?", (a, f_id))
                elif f == "card": db.execute("UPDATE cards SET balance = balance - ? WHERE id = ?", (a, f_id))

                # Sumar al destino
                db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (a, tx['to_id']))
                # Registrar en historial real (Marcado como programado)
                db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (?,?,?,'SCHEDULED_TRANSFER')", (f_id, tx['to_id'], a))

                notif_msg = f"Your scheduled transfer to ID {tx['to_id']} for ${a} was executed successfully."
                db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, comment) VALUES (0, ?, 'System', ?)", (tx['from_id'], notif_msg))

                db.execute("UPDATE scheduled_transfers SET status = 'COMPLETED' WHERE id = ?", (tx['id'],))
                db.commit()
                print(f"[WORKER] EXECUTED: Transfer ID {tx['id']} (${a})")

            # 2. Procesar Pagos de Servicios Programados
            pending_pay = db.execute("SELECT * FROM scheduled_payments WHERE status = 'PENDING' AND scheduled_time <= ?", (now_str,)).fetchall()
            for pay in pending_pay:
                s_type, s_id, a = pay['source_type'], pay['source_id'], pay['amount']
                u_id = pay['user_id']
                if s_type == "profile": db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (a, s_id))
                elif s_type == "account": db.execute("UPDATE bank_accounts SET balance = balance - ? WHERE id = ?", (a, s_id))
                elif s_type == "card": db.execute("UPDATE cards SET balance = balance - ? WHERE id = ?", (a, s_id))

                # Registrar en historial general (Marcado como SCHEDULED_PAYMENT)
                db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (?, 0, ?, 'SCHEDULED_PAYMENT')", (s_id, a))

                # Mensaje al Inbox del Usuario
                notif_msg = f"Your scheduled payment for {pay['service_name']} (${a}) was executed successfully."
                db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, comment) VALUES (0, ?, 'System', ?)", (u_id, notif_msg))

                db.execute("UPDATE scheduled_payments SET status = 'COMPLETED' WHERE id = ?", (pay['id'],))
                db.commit()
                print(f"[WORKER] EXECUTED: Utility Payment ID {pay['id']} (${a})")

            db.close()
        except Exception as e:
            print(f"[WORKER ERROR] {e}")
        time.sleep(30)

if __name__ == '__main__':
    init_db()
    # Iniciar el hilo de procesamiento de fondo
    threading.Thread(target=process_scheduled_tasks, daemon=True).start()
    print("\n   DVOM MASTER SERVER V3.9.0 (WITH SCHEDULER)\n")
    app.run(host='0.0.0.0', port=8080, debug=True, ssl_context='adhoc', threaded=True)
