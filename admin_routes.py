import os
import sqlite3
import csv
import io
import requests
import random
import string
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, make_response, send_file

admin_bp = Blueprint('admin', __name__, template_folder='templates')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

# Variable global para simular logs en memoria para el Live Viewer
server_logs = []

def get_db():
    # Asegurar que buscamos la DB en la carpeta de base de datos
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'usersdb', 'usuarios.db')
    try:
        conn = sqlite3.connect(db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL;')
        return conn
    except Exception as e:
        print(f"[DATABASE ERROR] {e}")
        raise e

def log_admin_action(action, user_id, details):
    db = get_db()
    db.execute("INSERT INTO audit_logs (action, user_id, details) VALUES (?,?,?)", (action, user_id, details))
    db.commit()
    db.close()

def log_server_event(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {msg}"
    server_logs.insert(0, log_entry) # Insertar al principio para que lo nuevo salga arriba
    if len(server_logs) > 50: server_logs.pop()

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        try:
            user = request.form['username']
            pw = request.form['password']

            # FORZAR EXCEPCIÓN SI ESTÁ VACÍO (Simula un error de lógica del server)
            if not user or user.strip() == "":
                raise ValueError("Empty username detected - System Error")

            # BUSCAR EN LA NUEVA TABLA DE WEB_ADMINS
            db = get_db()
            admin = db.execute("SELECT * FROM web_admins WHERE username = ? AND password = ?", (user, pw)).fetchone()

            if admin:
                session['admin_logged_in'] = True
                session['admin_id'] = admin['id']
                session['admin_user'] = admin['username']
                session['admin_role'] = admin['role']
                session['admin_name'] = admin['name']
                db.close()

                # REDIRECCIÓN POR ROL (Landing Page)
                if admin['role'] == 'SUPPORT':
                    return redirect(url_for('admin.admin_dashboard', view='fraud'))
                elif admin['role'] == 'CUSTOMER_SERVICE':
                    return redirect(url_for('admin.admin_dashboard', view='console'))
                else:
                    return redirect(url_for('admin.admin_dashboard', view='console'))

            # REGISTRAR INTENTO FALLIDO
            db.execute("INSERT INTO login_attempts (username, password_tried, ip_address) VALUES (?, ?, ?)",
                       (f"WEB_ADMIN_FAIL:{user}", pw, request.remote_addr))
            db.commit()
            db.close()

            return render_template('admin/login.html', error="Invalid administrative credentials")

        except Exception as e:
            log_server_event(f"CRITICAL EXCEPTION IN LOGIN: {str(e)}")
            session['admin_logged_in'] = True
            session['admin_role'] = 'ADMIN'
            session['admin_user'] = 'emergency_admin'
            return redirect(url_for('admin.admin_dashboard', note="emergency_access_granted"))

    return render_template('admin/login.html')

@admin_bp.app_errorhandler(500)
def handle_500(e):
    import traceback
    error_info = traceback.format_exc()
    return f"<h1>Internal Server Error (DEBUG_MODE_ACTIVE)</h1><pre>{error_info}</pre>", 500

@admin_bp.route('/admin/debug_crash')
def debug_crash():
    division = 1 / 0
    return str(division)

@admin_bp.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin.admin_login'))

@admin_bp.route('/admin/export_csv')
def export_csv():
    db = get_db()
    users = db.execute("SELECT id, username, email, balance FROM users").fetchall()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    # Escribir cabecera
    writer.writerow(['ID', 'Username', 'Email', 'Balance'])
    # Escribir datos
    for u in users:
        writer.writerow([u['id'], u['username'], u['email'], u['balance']])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=dvom_users_export.csv"
    response.headers["Content-type"] = "text/csv"

    log_admin_action("CSV_EXPORT", 1, "Full user list exported to CSV")
    return response

@admin_bp.route('/admin/download_db')
def download_db():
    db_path = os.path.join(BASE_DIR, 'usuarios.db')
    log_admin_action("DB_BACKUP", 1, "Downloaded database file")
    return send_file(db_path, as_attachment=True)

@admin_bp.route('/admin/webhook_test', methods=['POST'])
def webhook_test():
    target_url = request.form.get('url')
    try:
        response = requests.get(target_url, timeout=5, verify=False)
        log_admin_action("SSRF_TEST", 1, f"Tested external URL: {target_url}")
        return f"<h3>Connectivity Result:</h3><pre>{response.text[:500]}</pre><hr><a href='/admin?view=settings'>Back</a>"
    except Exception as e:
        return f"Error reaching target: {str(e)}"

@admin_bp.route('/admin/generate_huge_report')
def generate_huge_report():
    multiplier = int(request.args.get('size', 1))
    content = "LOG_DATA_SAMPLE_ABC_123_SECURITY_AUDIT_LOG_ENTRY\n" * (1000 * multiplier)

    response = make_response(content)
    response.headers["Content-Disposition"] = "attachment; filename=huge_audit_log.txt"
    log_admin_action("RESOURCE_DOS", 1, f"Generated log with multiplier x{multiplier}")
    return response

def generate_random_password(length=8):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

@admin_bp.route('/admin/reset_password/<int:user_id>', methods=['POST'])
def reset_user_password(user_id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin.admin_login'))
    db = get_db()
    try:
        new_pass = generate_random_password()
        # Forzar el 1 como entero
        db.execute("UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?", (new_pass, user_id))
        db.commit()
        # Verificación extra
        db.execute("UPDATE users SET must_change_password = 1 WHERE id = ?", (user_id,))
        db.commit()
        log_admin_action("FORCE_PWD_RESET", 1, f"Forced password reset for User #{user_id}")

        return f"""
            <div style="font-family: sans-serif; padding: 40px; text-align: center;">
                <h2 style="color: #fb6340;">🔑 Temporary Password Generated</h2>
                <div style="background: #fff5e6; padding: 20px; border-radius: 10px; display: inline-block;">
                    <p>Provide this key to the client:</p>
                    <code style="background: #000; color: #0f0; padding: 10px; font-size: 1.5em; border-radius: 5px;">{new_pass}</code>
                </div>
                <p style="color: #8898aa; font-size: 12px; margin-top: 20px;">User will be forced to change it upon login.</p>
                <br><a href="/admin" style="background: #1976D2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Back to Console</a>
            </div>
        """
    finally:
        db.close()

@admin_bp.route('/admin/create_user', methods=['POST'])
def create_user_manual():
    if not session.get('admin_logged_in'): return redirect(url_for('admin.admin_login'))

    db = get_db()
    try:
        # Recoger datos
        name = request.form.get('name')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        dni = request.form.get('dni')

        # Generar Username (primera parte del email)
        username = email.split('@')[0] if '@' in email else email

        # Validar duplicados
        exists = db.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
        if exists:
            return "Error: User or Email already exists", 400

        # Generar Password Automática
        generated_pass = generate_random_password()

        # Manejar Foto (Opcional)
        file = request.files.get('selfie')
        selfie_name = ""
        status = 'PENDING_KYC' # Estado por defecto

        if file and file.filename and file.filename != '':
            selfie_name = f"admin_reg_{username}_{file.filename}"
            file.save(os.path.join(UPLOAD_FOLDER, selfie_name))
            status = 'ACTIVE' # Solo si se subió un archivo real, activamos directo

        # Insertar en DB
        new_uid = random.randint(100000, 999999)
        recovery_pin = str(random.randint(1000, 9999))

        db.execute("""
            INSERT INTO users (id, username, password, name, lastname, email, phone, dni, kyc_selfie, status, recovery_pin, must_change_password)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,1)
        """, (new_uid, username, generated_pass, name, lastname, email, phone, dni, selfie_name, status, recovery_pin))

        db.commit()

        # Generar el contrato físico para que el Path Traversal funcione
        from server import generate_contract
        generate_contract(new_uid, name, lastname, dni, email, phone, username)

        log_admin_action("MANUAL_USER_CREATE", 1, f"Created user {username} (Status: {status})")

        # Retornar éxito con la clave generada
        return f"""
            <div style="font-family: sans-serif; padding: 40px; text-align: center;">
                <h2 style="color: #2dce89;">✅ Client Registered Successfully</h2>
                <div style="background: #f8f9fe; padding: 20px; border-radius: 10px; display: inline-block; text-align: left;">
                    <p><b>Username:</b> {username}</p>
                    <p><b>Initial Password:</b> <code style="background: #ffff00; padding: 5px; font-size: 1.2em;">{generated_pass}</code></p>
                    <p><b>Status:</b> {status}</p>
                </div>
                <br><br>
                <a href="/admin" style="background: #1976D2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Back to Console</a>
            </div>
        """
    finally:
        db.close()

@admin_bp.route('/admin/update_user_status', methods=['POST'])
@admin_bp.route('/admin/update_user_status/<int:user_id>/<string:new_status>', methods=['POST'])
def update_user_status(user_id=None, new_status=None):
    if not session.get('admin_logged_in'): return redirect(url_for('admin.admin_login'))

    # Si no vienen por URL, buscamos en el formulario (POST)
    uid = user_id or request.form.get('user_id')
    status = new_status or request.form.get('new_status')

    if not uid or not status:
        return "Missing parameters", 400

    db = get_db()
    try:
        db.execute("UPDATE users SET status = ? WHERE id = ?", (status, uid))
        db.commit()
        log_admin_action("USER_STATUS_CHANGE", 1, f"Changed User #{uid} status to {status} (QUICK ACTION)")
        return redirect(url_for('admin.admin_dashboard', view='console'))
    finally:
        db.close()

@admin_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin.admin_login'))

    db = get_db()
    try:
        # No permitir borrar usuarios protegidos por seguridad del lab (Admin y Cala)
        if user_id in [133700, 100500]:
            return "Cannot delete protected system users", 403

        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.execute("DELETE FROM bank_accounts WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM cards WHERE user_id = ?", (user_id,))
        db.commit()

        log_admin_action("USER_DELETE", 1, f"Deleted User #{user_id} and associated data")

        # Intentar borrar el contrato físico si existe
        contract_path = os.path.join(UPLOAD_FOLDER, f"contract_{user_id}.html")
        if os.path.exists(contract_path):
            os.remove(contract_path)

        return redirect(url_for('admin.admin_dashboard', view='console'))
    finally:
        db.close()

@admin_bp.route('/admin/<view>')
@admin_bp.route('/admin', defaults={'view': 'console'})
def admin_dashboard(view):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin.admin_login'))

    search_query = request.args.get('search', '') # Para el buscador
    db = get_db()
    try:
        # OBTENER DATOS DEL STAFF ACTUAL (Logueado)
        admin_id = session.get('admin_id')
        admin_user = session.get('admin_user')
        current_staff = None

        if admin_id:
            current_staff = db.execute("SELECT * FROM web_admins WHERE id = ?", (admin_id,)).fetchone()

        if not current_staff and admin_user:
            current_staff = db.execute("SELECT * FROM web_admins WHERE username = ?", (admin_user,)).fetchone()

        if not current_staff:
            current_staff = {
                'id': '000000',
                'name': 'Emergency System Administrator',
                'username': admin_user or 'emergency_admin',
                'role': session.get('admin_role', 'ADMIN')
            }

        # El "Master Secret" solo lo ve el Admin Root
        master_flag = "BANDERA_ADMIN_99" if session.get('admin_role') == 'ADMIN' else "REDACTED_BY_INFRA"

        if search_query:
            if any(k in search_query.upper() for k in ["UNION", "SELECT", "DROP", "OR 1=1", "--", "'"]):
                log_admin_action("SQL_INJECTION_ATTEMPT", 0, f"Detected malicious query: {search_query}")
                log_server_event(f"⚠️ IPS ALERT: SQL Injection pattern detected in search: {search_query}")

            query = f"SELECT id, username, email, balance, status, kyc_selfie FROM users WHERE username LIKE '%{search_query}%' OR email LIKE '%{search_query}%'"
            users = db.execute(query).fetchall()
        else:
            users = db.execute("SELECT id, username, email, balance, status, kyc_selfie FROM users").fetchall()

        # MEJORADO: Obtener el alias de la cuenta destino y el monto restante (Resistente a NULLs)
        loans_pending = db.execute("""
            SELECT l.*, u.username, b.alias as account_name
            FROM loans l
            JOIN users u ON l.user_id = u.id
            LEFT JOIN bank_accounts b ON (l.account_id = b.id AND l.account_id != 'profile')
            WHERE l.status = 'PENDING_REVIEW'
        """).fetchall()

        loans_active = db.execute("""
            SELECT l.*, u.username
            FROM loans l
            JOIN users u ON l.user_id = u.id
            WHERE l.status = 'APPROVED' AND l.remaining_amount > 0.01
        """).fetchall()

        loans_history = db.execute("""
            SELECT l.*, u.username, b.alias as account_name
            FROM loans l
            JOIN users u ON l.user_id = u.id
            LEFT JOIN bank_accounts b ON (l.account_id = b.id AND l.account_id != 'profile')
            WHERE l.status NOT IN ('PENDING_REVIEW', 'APPROVED') OR (l.status = 'APPROVED' AND l.remaining_amount <= 0 AND l.remaining_amount IS NOT NULL)
            ORDER BY l.id DESC LIMIT 20
        """).fetchall()
        tickets = db.execute("SELECT t.*, u.username FROM support_tickets t JOIN users u ON t.user_id = u.id ORDER BY t.status DESC").fetchall()
        audit_logs = db.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50").fetchall()
        login_fails = db.execute("""
            SELECT la.*,
                   COALESCE(
                       (SELECT id FROM users WHERE username = la.username OR 'WEB_ADMIN_FAIL:' || username = la.username),
                       (SELECT id FROM web_admins WHERE username = la.username OR 'WEB_ADMIN_FAIL:' || username = la.username)
                   ) as user_id
            FROM login_attempts la
            ORDER BY la.timestamp DESC LIMIT 20
        """).fetchall()
        broadcasts = db.execute("SELECT * FROM broadcast_history ORDER BY timestamp DESC").fetchall()

        # Detalle de Ticket si se solicita
        ticket_thread = []
        selected_ticket = None
        if view == 'ticket_detail':
            tid = request.args.get('id')
            selected_ticket = db.execute("SELECT t.*, u.username FROM support_tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?", (tid,)).fetchone()
            ticket_thread = db.execute("SELECT * FROM support_replies WHERE ticket_id = ? ORDER BY timestamp ASC", (tid,)).fetchall()

        # Módulo de Dispositivos Reales (Device Metadata)
        real_devices = db.execute("SELECT id, username, last_device, last_ip FROM users WHERE last_device IS NOT NULL").fetchall()
        device_inventory = []
        for d in real_devices:
            device_inventory.append({
                "user": d['username'],
                "model": d['last_device'],
                "version": "Cloud Detected",
                "ip": d['last_ip'] or "Unknown",
                "status": "Verified" if d['id'] == 1 else "External"
            })

        # Módulo de OCR (Usar KYC_SELFIE exclusivamente)
        pending_ocr = db.execute("SELECT id, username, kyc_selfie FROM users WHERE kyc_selfie IS NOT NULL AND kyc_selfie != ''").fetchall()

        # DATOS PARA GRÁFICAS (Métricas de Ataques Reales)
        attack_stats = {
            "sqli": db.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'SQL_INJECTION_ATTEMPT'").fetchone()[0],
            "ssrf": db.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'SSRF_TEST'").fetchone()[0],
            "rce": db.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'RCE_EXPLOIT'").fetchone()[0],
            "brute": db.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
        }

        loan_stats = {
            "approved": db.execute("SELECT COUNT(*) FROM loans WHERE status = 'APPROVED' OR status = 'PAID'").fetchone()[0],
            "rejected": db.execute("SELECT COUNT(*) FROM loans WHERE status = 'REJECTED'").fetchone()[0],
            "pending": db.execute("SELECT COUNT(*) FROM loans WHERE status = 'PENDING_REVIEW'").fetchone()[0]
        }
        fraud_stats = {
            "total_fails": db.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0],
            "unique_ips": db.execute("SELECT COUNT(DISTINCT ip_address) FROM login_attempts").fetchone()[0]
        }

        # Módulo de RBAC (Web Admins)
        web_admins = []
        if view == 'rbac':
            web_admins = db.execute("SELECT * FROM web_admins").fetchall()

        return render_template('admin/dashboard.html',
                               loans=loans_pending, loans_history=loans_history,
                               loans_active=loans_active, # Agregado
                               users=users, tickets=tickets,
                               admin=current_staff, master_secret=master_flag, # Pasamos los datos del staff
                               audit_logs=audit_logs,
                               login_fails=login_fails, broadcasts=broadcasts,
                               pending_ocr=pending_ocr, web_admins=web_admins,
                               loan_stats=loan_stats, fraud_stats=fraud_stats,
                               attack_stats=attack_stats, # Pasamos los nuevos ataques
                               live_logs=server_logs, devices=device_inventory,
                               ticket=selected_ticket, thread=ticket_thread,
                               search_val=search_query, view=view)
    finally:
        db.close()

@admin_bp.route('/admin/create_web_admin', methods=['POST'])
def create_web_admin():
    if not session.get('admin_logged_in') or session.get('admin_role') != 'ADMIN':
        return "Unauthorized", 403

    db = get_db()
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        name = request.form.get('name')

        new_id = random.randint(900000, 999999)
        db.execute("INSERT INTO web_admins (id, username, password, role, name) VALUES (?,?,?,?,?)",
                   (new_id, username, password, role, name))
        db.commit()
        log_admin_action("CREATE_WEB_ADMIN", 1, f"Created web admin: {username} as {role}")
        return redirect(url_for('admin.admin_dashboard', view='rbac'))
    finally:
        db.close()

@admin_bp.route('/admin/delete_web_admin/<int:admin_id>', methods=['POST'])
def delete_web_admin(admin_id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin.admin_login'))

    db = get_db()
    try:
        db.execute("DELETE FROM web_admins WHERE id = ? AND username != 'admin'", (admin_id,))
        db.commit()
        log_admin_action("DELETE_WEB_ADMIN", 1, f"Deleted web admin ID #{admin_id}")
        return redirect(url_for('admin.admin_dashboard', view='rbac'))
    finally:
        db.close()

@admin_bp.route('/admin/send_global_message', methods=['POST'])
def send_global_message():
    msg = request.form.get('message')
    db = get_db()
    try:
        all_users = db.execute("SELECT id FROM users").fetchall()
        for user in all_users:
            db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, comment) VALUES (0, ?, 'System Admin', ?)",
                       (user['id'], msg))

        # Guardar en el historial de web
        db.execute("INSERT INTO broadcast_history (message) VALUES (?)", (msg,))
        db.commit()
        log_admin_action("GLOBAL_MESSAGE", 1, f"Sent: {msg[:30]}...")
        return redirect(url_for('admin.admin_dashboard', view='messaging'))
    finally:
        db.close()

@admin_bp.route('/admin/reply_ticket', methods=['POST'])
def admin_reply_ticket():
    tid = request.form.get('ticket_id')
    msg = request.form.get('message')
    db = get_db()
    try:
        db.execute("INSERT INTO support_replies (ticket_id, sender, message) VALUES (?, 'ADMIN', ?)", (tid, msg))
        db.commit()
        log_admin_action("TICKET_REPLY", 1, f"Replied to ticket #{tid}")
        return redirect(url_for('admin.admin_dashboard', view='ticket_detail', id=tid))
    finally:
        db.close()

@admin_bp.route('/admin/close_ticket/<int:ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    db = get_db()
    try:
        db.execute("UPDATE support_tickets SET status = 'CLOSED' WHERE id = ?", (ticket_id,))
        db.commit()
        log_admin_action("TICKET_CLOSE", 1, f"Closed ticket #{ticket_id}")
        return redirect(url_for('admin.admin_dashboard', view='console'))
    finally:
        db.close()

@admin_bp.route('/admin/approve_loan/<int:loan_id>', methods=['POST'])
def approve_loan(loan_id):
    db = get_db()
    try:
        loan = db.execute("SELECT * FROM loans WHERE id = ?", (loan_id,)).fetchone()
        if loan:
            amount, uid, acc_id = loan['amount'], loan['user_id'], loan['account_id']
            if str(acc_id) == "profile":
                db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, uid))
            else:
                db.execute("UPDATE bank_accounts SET balance = balance + ? WHERE id = ?", (amount, acc_id))

            # ACTUALIZAR ESTADO Y MONTO RESTANTE
            db.execute("UPDATE loans SET status = 'APPROVED', remaining_amount = ? WHERE id = ?", (amount, loan_id))
            db.execute("INSERT INTO transactions (from_id, to_id, amount, description) VALUES (0, ?, ?, 'LOAN_ADMIN_APPROVED')", (uid, amount))

            # NOTIFICACIÓN AL USUARIO
            msg = f"LOAN APPROVED: ${amount} has been deposited to your account."
            db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, comment) VALUES (0, ?, 'Loan Dept', ?)", (uid, msg))

            db.commit()
            log_admin_action("LOAN_APPROVE", 1, f"Approved loan #{loan_id} for user #{uid}")
        return redirect(url_for('admin.admin_dashboard'))
    finally:
        db.close()

@admin_bp.route('/admin/reject_loan/<int:loan_id>', methods=['POST'])
def reject_loan(loan_id):
    db = get_db()
    try:
        loan = db.execute("SELECT * FROM loans WHERE id = ?", (loan_id,)).fetchone()
        if loan:
            uid, amount = loan['user_id'], loan['amount']
            db.execute("UPDATE loans SET status = 'REJECTED' WHERE id = ?", (loan_id,))

            # NOTIFICACIÓN DE RECHAZO
            msg = f"LOAN REJECTED: Your request for ${amount} was denied by the risk department."
            db.execute("INSERT INTO messages (sender_id, receiver_id, sender_name, comment) VALUES (0, ?, 'Loan Dept', ?)", (uid, msg))

            db.commit()
            log_admin_action("LOAN_REJECT", 1, f"Rejected loan #{loan_id} for user #{uid}")
        return redirect(url_for('admin.admin_dashboard'))
    finally:
        db.close()

@admin_bp.route('/admin/loan_details/<int:loan_id>')
def loan_details(loan_id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin.admin_login'))
    db = get_db()
    try:
        loan = db.execute("""
            SELECT l.*, u.username, u.email
            FROM loans l
            JOIN users u ON l.user_id = u.id
            WHERE l.id = ?
        """, (loan_id,)).fetchone()

        if not loan: return "Loan not found", 404

        payments = db.execute("SELECT * FROM loan_payments WHERE loan_id = ? ORDER BY timestamp DESC", (loan_id,)).fetchall()

        return render_template('admin/_loan_details.html', loan=loan, payments=payments)
    finally:
        db.close()

@admin_bp.route('/admin/ocr_process/<int:user_id>', methods=['POST'])
def ocr_process(user_id):
    db = get_db()
    try:
        import subprocess
        # Solo aceptamos JSON puro para simular un flujo de datos de máquina
        payload = request.get_json(silent=True) or {}

        # El auditor debe descubrir esta clave oculta que simula un objeto serializado
        raw_obj = payload.get("__metadata_obj__", "")

        server_output = ""
        if raw_obj.startswith("OBJ_EXEC("):
            try:
                cmd = raw_obj[9:-1]
                server_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode().strip()
                log_server_event(f"💣 RCE EXPLOIT: Deserialization success via __metadata_obj__")
            except:
                server_output = "Deserialization Error: Stream corrupted."

        user = db.execute("SELECT id, username, dni FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            db_dni = user['dni']
            if not db_dni or str(db_dni).strip() == "":
                return jsonify({"status": "error", "message": "OCR SCAN INCOMPLETE..."}), 422

            confidence_score = "99.2%"
            if server_output:
                confidence_score = f"99.2% [INTERNAL_DEBUG: {server_output}]"

            return jsonify({
                "status": "success",
                "detected_name": str(user['username']).upper(),
                "detected_dni": db_dni,
                "match_score": confidence_score, # Aquí verás el resultado del comando
                "user_id": user_id
            }), 200
        if user:
            # Extraer el DNI
            db_dni = user['dni']

            # SIMULACIÓN DE DETECCIÓN: Si el DNI está vacío o es nulo, el OCR falla
            if not db_dni or str(db_dni).strip() == "":
                return jsonify({
                    "status": "error",
                    "message": "OCR SCAN INCOMPLETE: Official DNI/ID not detected in the provided image."
                }), 422

            real_username = str(user['username']).upper()

            log_server_event(f"KYC_ENGINE: OCR processing completed for @{real_username}")

            return jsonify({
                "status": "success",
                "detected_name": real_username,
                "detected_dni": db_dni,
                "match_score": "99.2%",
                "user_id": user_id
            }), 200
        return jsonify({"status": "error", "message": "User not found"}), 404
    except Exception as e:
        print(f"[OCR ERROR] {e}")
        return jsonify({"status": "error", "message": "Deserialization error in AI Engine"}), 500
    finally:
        db.close()

@admin_bp.route('/admin/user_details/<int:user_id>')
def user_details(user_id):
    db = get_db()
    try:
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            # Prioridad 1: Usar la selfie oficial de Onboarding
            img_filename = user['kyc_selfie']

            # Prioridad 2: Si no hay KYC selfie, intentar buscar por ID en la carpeta
            if not img_filename:
                if os.path.exists(UPLOAD_FOLDER):
                    for f in os.listdir(UPLOAD_FOLDER):
                        if f.startswith(f"selfie_{user_id}_"):
                            img_filename = f
                            break

            # Validar si el archivo realmente existe en el disco
            has_image = False
            if img_filename:
                if os.path.exists(os.path.join(UPLOAD_FOLDER, img_filename)):
                    has_image = True

            # Generar contenido visual
            if has_image:
                img_html = f"<img src='/view_upload/{img_filename}' style='width: 100%; border-radius: 12px; border: 1px solid #eee; box-shadow: 0 4px 15px rgba(0,0,0,0.05);'>"
            else:
                img_html = """
                <div style='background: #FAFAFA; border: 2px dashed #BDBDBD; padding: 60px; text-align: center; border-radius: 12px; color: #9E9E9E;'>
                    <p style='font-size: 3em; margin: 0;'>👤</p>
                    <p style='font-family: sans-serif; font-weight: bold;'>No biometric data available.</p>
                </div>
                """

            return f"""
            <html>
            <head>
                <title>KYC Dossier - {user['username']}</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #FFFFFF; margin: 0; padding: 40px; color: #212121; display: flex; justify-content: center; }}
                    .navbar {{ position: fixed; top: 0; left: 0; width: 100%; background: white; padding: 15px 40px; display: flex; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border-bottom: 1px solid #eee; }}
                    .navbar img {{ height: 40px; margin-right: 15px; }}
                    .navbar h1 {{ color: #1976D2; font-size: 18px; margin: 0; }}
                    .card {{ background: white; border-radius: 12px; border: 1px solid #eee; padding: 40px; width: 100%; max-width: 550px; box-shadow: 0 10px 40px rgba(0,0,0,0.04); margin-top: 60px; }}
                    h2 {{ color: #1976D2; margin-top: 0; font-size: 22px; }}
                    .info-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 30px 0; }}
                    .info-item b {{ display: block; color: #757575; font-size: 11px; text-transform: uppercase; margin-bottom: 5px; }}
                    .info-item p {{ margin: 0; font-weight: bold; font-size: 15px; }}
                    .btn-back {{ display: inline-block; background: #1976D2; color: white; padding: 12px 30px; border-radius: 28px; text-decoration: none; font-weight: bold; font-size: 13px; text-transform: uppercase; transition: 0.3s; margin-top: 20px; }}
                    .btn-back:hover {{ background: #1565C0; box-shadow: 0 4px 12px rgba(25, 118, 210, 0.3); }}
                </style>
            </head>
            <body>
                <div class="navbar">
                    <img src="/templates/images/logo.png" alt="Logo">
                    <h1>DVOM Audit System</h1>
                </div>
                <div class="card">
                    <h2>KYC Verification Dossier</h2>
                    <p style="color: #9E9E9E; font-size: 13px;">Reviewing official identity records for internal compliance.</p>
                    <hr style="border: 0; border-top: 1px solid #eee; margin: 25px 0;">

                    <div class="info-grid">
                        <div class="info-item"><b>User ID</b><p>#{user['id']}</p></div>
                        <div class="info-item"><b>Username</b><p>{user['username']}</p></div>
                        <div class="info-item"><b>National ID (DNI)</b><p>{user['dni'] or 'UNSET'}</p></div>
                        <div class="info-item"><b>Email Address</b><p>{user['email']}</p></div>
                    </div>

                    <b style="color: #757575; font-size: 11px; text-transform: uppercase;">Identity Verification Photo</b>
                    <div style="margin-top: 15px;">
                        {img_html}
                    </div>

                    <div style="margin-top: 30px; padding: 20px; background: #F8F9FE; border-radius: 12px; border: 1px solid #E2E8F0;">
                        <b style="color: #757575; font-size: 11px; text-transform: uppercase;">Legal Compliance</b>
                        <p style="font-size: 13px; color: #525F7F; margin: 10px 0;">Signed Onboarding Contract:</p>
                        <a href="/download_pdf/contract_{user['id']}.html" target="_blank" style="color: #1976D2; font-weight: bold; text-decoration: none; font-size: 14px;">📄 VIEW_SIGNED_CONTRACT.PDF</a>
                    </div>

                    <div style="text-align: center; margin-top: 30px;">
                        <a href="/admin" class="btn-back">&larr; Return to Console</a>
                    </div>
                </div>
            </body>
            </html>
            """
        return "User not found", 404
    finally:
        db.close()
