from flask import Flask, render_template, request, redirect, url_for, flash, jsonify,send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_db_connection, generate_auto_code

import os
import uuid
import re
import hashlib
import time
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'super_secret_glass_key_123'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50 MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, role, unit_id, sub_unit_id=None, full_name=None, email=None):
        self.id = id
        self.username = username
        self.role = role
        self.unit_id = unit_id
        self.sub_unit_id = sub_unit_id
        self.full_name = full_name or username
        self.email = email

    @property
    def initials(self):
        name = (self.full_name or self.username).strip()
        parts = name.split()
        if len(parts) >= 2:
            return (parts[0][0] + parts[-1][0]).upper()
        elif len(parts) == 1 and parts[0]:
            return parts[0][:2].upper()
        return "U"

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(
            id=user['id'], 
            username=user['username'], 
            role=user['role'], 
            unit_id=user['unit_id'],
            sub_unit_id=user['sub_unit_id'] if 'sub_unit_id' in user.keys() else None,
            full_name=user['full_name'] if 'full_name' in user.keys() and user['full_name'] else user['username'],
            email=user['email'] if 'email' in user.keys() else None
        )
    return None

def validate_password_complexity(password):
    if len(password) < 6:
        return False, "Şifre en az 6 karakter olmalıdır."
    if not re.search(r'[A-Z]', password):
        return False, "Şifre en az 1 büyük harf içermelidir."
    if not re.search(r'[a-z]', password):
        return False, "Şifre en az 1 küçük harf içermelidir."
    if not re.search(r'\d', password):
        return False, "Şifre en az 1 rakam içermelidir."
    if not re.search(r'[^a-zA-Z0-9]', password):
        return False, "Şifre en az 1 özel karakter içermelidir."
    return True, ""

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        conn = get_db_connection()
        unread_notifs = conn.execute(
            'SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at ASC',
            (current_user.id,)
        ).fetchall()
        
        if unread_notifs:
            conn.execute(
                'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0',
                (current_user.id,)
            )
            conn.commit()

        conn.close()
        return {'login_toast_notifications': unread_notifs}
    return {'login_toast_notifications': []}

def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if current_user.role not in roles:
                flash("Bu sayfaya erişim yetkiniz yok.", "error")
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            user_obj = User(
                id=user['id'], 
                username=user['username'], 
                role=user['role'], 
                unit_id=user['unit_id'],
                sub_unit_id=user['sub_unit_id'] if 'sub_unit_id' in user.keys() else None
            )
            login_user(user_obj)
            return redirect(url_for('dashboard'))
        else:
            flash("Kullanıcı adı veya şifre hatalı veya hesabınız pasif.", "error")

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            flash('Lütfen kullanıcı adınızı giriniz.', 'error')
            return redirect(url_for('login'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()

        if not user:
            conn.close()
            flash('Bu kullanıcı adına sahip aktif bir hesap bulunamadı.', 'error')
            return redirect(url_for('login'))

        # Benzersiz jeton (token) ve 1 saatlik son kullanma tarihi üret
        token = uuid.uuid4().hex
        expires = (datetime.now() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")

        conn.execute('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', (token, expires, user['id']))
        conn.commit()
        conn.close()

        # E-posta içeriğindeki şifre sıfırlama bağlantısı
        reset_url = url_for('reset_password', token=token, _external=True)

        # Hedef e-posta adresi: username@tuseb.gov.tr (varsa kullanıcı e-postası)
        recipient_email = user['email'] if ('email' in user.keys() and user['email']) else f"{username}@tuseb.gov.tr"

        # E-posta Ayarları (mail.tuseb.gov.tr)
        smtp_server = 'smtp.freesmtpservers.com'
        smtp_port = 25
        sender_email = 'notify@mysite.com'

        subject = "İstatistik Sistemi - Şifre Sıfırlama Bağlantısı"
        user_name_display = user['full_name'] if ('full_name' in user.keys() and user['full_name']) else username
        
        body_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f6f9; padding: 20px; margin: 0; color: #333;">
  <div style="max-width: 550px; margin: 0 auto; background: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); border: 1px solid #e5e7eb;">
    <div style="text-align: center; margin-bottom: 25px;">
      <h2 style="color: #0f172a; margin: 0; font-size: 22px;">🔒 TÜSEB İstatistik Sistemi</h2>
      <p style="color: #64748b; font-size: 14px; margin-top: 5px;">Şifre Sıfırlama Talebi</p>
    </div>
    
    <p style="font-size: 15px; line-height: 1.6; color: #334155;">
      Sayın <strong>{user_name_display}</strong>,
    </p>
    <p style="font-size: 15px; line-height: 1.6; color: #334155;">
      Hesabınız için bir şifre sıfırlama talebinde bulundunuz. Şifrenizi yenilemek için lütfen aşağıdaki butona veya bağlantıya tıklayınız:
    </p>
    
    <div style="text-align: center; margin: 30px 0;">
      <a href="{reset_url}" target="_blank" style="background-color: #0284c7; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block; font-size: 15px;">
        🔑 Şifremi Sıfırla
      </a>
    </div>

    <p style="font-size: 13px; color: #64748b; line-height: 1.5;">
      Eğer buton çalışmıyorsa, aşağıdaki bağlantıyı doğrudan tarayıcınıza yapıştırabilirsiniz:<br>
      <a href="{reset_url}" target="_blank" style="color: #0284c7; word-break: break-all;">{reset_url}</a>
    </p>

    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; font-size: 12px; color: #94a3b8;">
      <p style="margin: 0;">Bu bağlantı <strong>1 saat</strong> boyunca geçerlidir.</p>
      <p style="margin-top: 5px;">TÜSEB İstatistik Sistemi Otomatik E-posta Servisi</p>
    </div>
  </div>
</body>
</html>
"""
        msg = MIMEText(body_html, 'html', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = Header(f"TÜSEB İstatistik Sistemi <{sender_email}>", 'utf-8')
        msg['To'] = recipient_email

        mail_sent = False
        mail_error = ""
        try:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                server.sendmail(sender_email, [recipient_email], msg.as_string())
            mail_sent = True
        except Exception as e:
            mail_error = str(e)

        if mail_sent:
            flash(f"Şifre sıfırlama bağlantısı {recipient_email} adresinize e-posta olarak gönderildi.", "success")
        else:
            flash(f"Şifre sıfırlama bağlantısı oluşturuldu ({reset_url}). E-posta gönderim uyarısı: {mail_error}", "warning")

        return redirect(url_for('login'))

    return redirect(url_for('login'))

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE reset_token = ? AND is_active = 1', (token,)).fetchone()

    if not user:
        conn.close()
        flash('Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.', 'error')
        return redirect(url_for('login'))

    # Son kullanma süresi kontrolü (1 saat)
    if 'reset_token_expires' in user.keys() and user['reset_token_expires']:
        try:
            expires_dt = datetime.strptime(user['reset_token_expires'], "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expires_dt:
                conn.close()
                flash('Şifre sıfırlama bağlantısının süresi dolmuş. Lütfen tekrar talepte bulunun.', 'error')
                return redirect(url_for('login'))
        except Exception:
            pass

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            conn.close()
            flash('Şifreler birbiriyle eşleşmiyor.', 'error')
            return render_template('reset_password.html', token=token, username=user['username'])

        is_valid, err_msg = validate_password_complexity(password)
        if not is_valid:
            conn.close()
            flash(err_msg, 'error')
            return render_template('reset_password.html', token=token, username=user['username'])

        hashed_pw = generate_password_hash(password)
        conn.execute('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', (hashed_pw, user['id']))
        conn.commit()
        conn.close()

        flash('Şifreniz başarıyla değiştirildi. Yeni şifrenizle giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token, username=user['username'])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/get_sub_units/<int:unit_id>')
@login_required
def get_sub_units(unit_id):
    conn = get_db_connection()
    sub_units = conn.execute(
        'SELECT id, code, name FROM sub_units WHERE unit_id = ? AND is_active = 1 ORDER BY name ASC',
        (unit_id,)
    ).fetchall()
    conn.close()
    return jsonify([{'id': s['id'], 'code': s['code'], 'name': s['name']} for s in sub_units])
def get_filtered_data_entries(user_obj, include_passive=False, uploader_role=None):
    conn = get_db_connection()
    query = '''
        SELECT d.id, u.username as user, u.full_name as user_full_name,
               un.name as unit, un.code as unit_code,
               su.name as sub_unit, su.code as sub_unit_code,
               i.name as institute, i.code as institute_code,
               d.day, d.month, d.year, d.time, d.title, d.note, d.request_note, d.file_path, 
               d.special_auth, d.approval_status, d.rejection_reason, d.created_at,
            d.user_id, d.unit_id, d.sub_unit_id, d.status, d.is_active,
               d.updated_file_path, d.updated_by, d.updated_at,
               u.role as uploader_role
        FROM data_entries d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN units un ON d.unit_id = un.id
        LEFT JOIN sub_units su ON d.sub_unit_id = su.id
        LEFT JOIN institutes i ON un.institute_id = i.id
    '''
    conditions = []
    params = []

    # Pasif kayıtlar sadece rootadmin'e istatistik sayfasında gösterilir
    if not include_passive:
        conditions.append('(d.is_active IS NULL OR d.is_active = 1)')

    # Sadece belirtilen rolün yükledikleri (örn. 'rootadmin')
    if uploader_role:
        conditions.append('u.role = ?')
        params.append(uploader_role)

    if user_obj.role not in ['rootadmin', 'admin']:
        user_inst_id = None
        if user_obj.unit_id:
            inst_row = conn.execute('SELECT institute_id FROM units WHERE id = ?', (user_obj.unit_id,)).fetchone()
            if inst_row:
                user_inst_id = inst_row['institute_id']
        conditions.append('(d.user_id = ? OR d.unit_id = ? OR (? IS NOT NULL AND un.institute_id = ?))')
        params.extend([user_obj.id, user_obj.unit_id or 0, user_inst_id, user_inst_id])

    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    query += ' ORDER BY d.created_at DESC'

    data_list = conn.execute(query, params).fetchall()
    conn.close()
    return data_list

@app.route('/dashboard')
@login_required
def dashboard():
    data_list = get_filtered_data_entries(current_user)

    # ADMIN ve ROOTADMIN: rootadmin'in yüklediği veriler dashboard'da GİZLENİR
    if current_user.role in ['admin', 'rootadmin']:
        data_list = [d for d in data_list if d['uploader_role'] != 'rootadmin']

    authorized_ids = set()

    if current_user.role == 'user':
        # USER ROLÜ: rootadmin'in yüklediği veriler SADECE special_auth yetkisiyle görünür
        visible = []
        my_name = current_user.username.strip().lower()
        for d in data_list:
            if d['uploader_role'] == 'rootadmin':
                auth_users = [u.strip().lower() for u in str(d['special_auth'] or '').split(',') if u.strip()]
                if my_name in auth_users:
                    visible.append(d)
                    authorized_ids.add(d['id'])
            else:
                visible.append(d)
        data_list = visible
    else:
        # admin / rootadmin: yeşil font işaretlemesi
        for d in data_list:
            if d['special_auth']:
                auth_users = [u.strip().lower() for u in str(d['special_auth']).split(',') if u.strip()]
                if current_user.username.lower() in auth_users:
                    authorized_ids.add(d['id'])

    return render_template('dashboard.html', user=current_user, data=data_list,
                           authorized_ids=authorized_ids)

@app.route('/units/edit/<int:unit_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def edit_unit(unit_id):
    conn = get_db_connection()
    name = request.form.get('name', '').strip()
    institute_id = request.form.get('institute_id')
    is_active = 1 if request.form.get('is_active') == 'on' else 0

    if len(name) < 2:
        flash('Birim adı en az 2 karakter olmalıdır.', 'error')
        conn.close()
        return redirect(url_for('units'))

    try:
        conn.execute('UPDATE units SET name = ?, institute_id = ?, is_active = ? WHERE id = ?',
                     (name, institute_id or None, is_active, unit_id))
        conn.commit()
        flash('Birim bilgileri güncellendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('units'))

@app.route('/units', methods=['GET', 'POST'])
@login_required
@role_required('rootadmin')
def units():
    conn = get_db_connection()

    if request.method == 'POST':
        action = request.form.get('action')
        name = request.form.get('name', '').strip()

        if not name:
            flash('Lütfen bir isim giriniz.', 'error')
            return redirect(url_for('units'))

        try:
            if action == 'add_institute':
                code = generate_auto_code(name, table='institutes')
                conn.execute('INSERT INTO institutes (code, name) VALUES (?, ?)', (code, name))
                flash(f'Enstitü eklendi (Kod: {code}).', 'success')

            elif action == 'add_unit':
                institute_id = request.form.get('institute_id') or None
                code = generate_auto_code(name, is_sub=False)
                conn.execute('INSERT INTO units (institute_id, code, name) VALUES (?, ?, ?)',
                             (institute_id, code, name))
                flash(f'Birim eklendi (Kod: {code}).', 'success')

            elif action == 'add_sub_unit':
                unit_id = request.form.get('unit_id')
                if not unit_id:
                    flash('Lütfen ana birim seçiniz.', 'error')
                    return redirect(url_for('units'))
                code = generate_auto_code(name, is_sub=True, unit_id=unit_id)
                conn.execute('INSERT INTO sub_units (unit_id, code, name) VALUES (?, ?, ?)',
                             (unit_id, code, name))
                flash(f'Alt birim eklendi (Kod: {code}).', 'success')

            conn.commit()
        except Exception as e:
            flash(f'Hata: {str(e)}', 'error')

        return redirect(url_for('units'))

    institutes_raw = conn.execute('SELECT * FROM institutes ORDER BY name ASC').fetchall()
    institutes_tree = []
    for inst in institutes_raw:
        inst_units = conn.execute(
            'SELECT * FROM units WHERE institute_id = ? ORDER BY name ASC', (inst['id'],)
        ).fetchall()
        institutes_tree.append({
            'id': inst['id'],
            'code': inst['code'],
            'name': inst['name'],
            'is_active': inst['is_active'],
            'units': inst_units
        })

    units_raw = conn.execute('SELECT * FROM units ORDER BY name ASC').fetchall()
    units_tree = []
    for u in units_raw:
        subs = conn.execute(
            'SELECT * FROM sub_units WHERE unit_id = ? ORDER BY name ASC', (u['id'],)
        ).fetchall()
        units_tree.append({
            'id': u['id'],
            'institute_id': u['institute_id'] if 'institute_id' in u.keys() else None,
            'code': u['code'],
            'name': u['name'],
            'is_active': u['is_active'],
            'sub_units': subs
        })

    conn.close()
    return render_template('units.html',
                           institutes_tree=institutes_tree,
                           units_tree=units_tree,
                           institutes=institutes_raw,
                           units=units_raw)

@app.route('/institutes/edit/<int:institute_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def edit_institute(institute_id):
    conn = get_db_connection()
    name = request.form.get('name', '').strip()
    is_active = 1 if request.form.get('is_active') == 'on' else 0

    if len(name) < 2:
        flash('Enstitü adı en az 2 karakter olmalıdır.', 'error')
        conn.close()
        return redirect(url_for('units'))

    try:
        conn.execute('UPDATE institutes SET name = ?, is_active = ? WHERE id = ?',
                     (name, is_active, institute_id))
        conn.commit()
        flash('Enstitü bilgileri güncellendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('units'))

@app.route('/sub_units/edit/<int:sub_unit_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def edit_sub_unit(sub_unit_id):
    conn = get_db_connection()
    name = request.form.get('name', '').strip()
    unit_id = request.form.get('unit_id')
    is_active = 1 if request.form.get('is_active') == 'on' else 0

    if len(name) < 2:
        flash('Alt birim adı en az 2 karakter olmalıdır.', 'error')
        conn.close()
        return redirect(url_for('units'))

    if not unit_id:
        flash('Üst birim seçilmelidir.', 'error')
        conn.close()
        return redirect(url_for('units'))

    try:
        conn.execute('UPDATE sub_units SET name = ?, unit_id = ?, is_active = ? WHERE id = ?',
                     (name, unit_id, is_active, sub_unit_id))
        conn.commit()
        flash('Alt birim bilgileri güncellendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('units'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if current_user.role not in ['user', 'admin', 'rootadmin']:
        flash('Yetkisiz işlem.', 'error')
        return redirect(url_for('dashboard'))

    title = request.form.get('title', '').strip()
    note = request.form.get('note', '').strip()
    request_note = request.form.get('request_note', '').strip()

    # Requirement 3: Min 6 characters & no special characters
    if len(title) < 6:
        flash('Veri başlığı en az 6 karakter olmalıdır.', 'error')
        return redirect(request.referrer or url_for('dashboard'))
    if re.search(r'[^a-zA-Z0-9çÇğĞıİöÖşŞüÜ\s]', title):
        flash('Veri başlığı özel karakter içeremez.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    # Requirement 4: File is mandatory & MUST be .zip only
    file = request.files.get('file')
    if not file or file.filename == '':
        flash('Dosya yüklenmesi zorunludur.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    if not file.filename.lower().endswith('.zip'):
        flash('Sadece ZIP (.zip) uzantılı dosyalar yüklenebilir.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    # Requirement 4: Calculate file hash & check duplicate
    file_bytes = file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    file.seek(0)

    conn = get_db_connection()
    existing = conn.execute('SELECT id FROM data_entries WHERE file_hash = ?', (file_hash,)).fetchone()
    if existing:
        conn.close()
        flash('Bu dosya (dosya imzası aynı olan dosya) daha önce yüklenmiştir. Aynı dosya tekrar gönderilemez.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    now = datetime.now()
    day = now.day
    month = now.month
    year = now.year
    time_str = now.strftime("%H:%M:%S")
    if current_user.role == 'rootadmin':
        unit_id = request.form.get('unit_id')
        sub_unit_id = request.form.get('sub_unit_id') or None
        if not unit_id:
            conn.close()
            flash('Lütfen Birim seçiniz.', 'error')
            return redirect(url_for('statistics'))
    elif current_user.role == 'admin':
        unit_id = current_user.unit_id
        sub_unit_id = current_user.sub_unit_id
        if not unit_id or not sub_unit_id:
            conn.close()
            flash('Birim/Alt birim bilginiz tanımlı değil. Lütfen yöneticiyle iletişime geçin.', 'error')
            return redirect(url_for('statistics'))
    else:
        unit_id = current_user.unit_id
        sub_unit_id = current_user.sub_unit_id

    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(full_path)
    file_path = f"uploads/{unique_filename}"

    try:
        curr=conn.execute('''
            INSERT INTO data_entries (user_id, unit_id, sub_unit_id, day, month, year, time, title, note, request_note, file_path, file_hash, approval_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        ''', (current_user.id, unit_id, sub_unit_id, day, month, year, time_str, title, note, request_note, file_path, file_hash))
        new_data_id = curr.lastrowid

        # 📩 Bildirim SADECE user rolü yüklediğinde → tüm aktif rootadmin'lere
        if current_user.role == 'user':
            rootadmins = conn.execute(
                "SELECT id FROM users WHERE role = 'rootadmin' AND is_active = 1"
            ).fetchall()
            uploader_name = current_user.full_name or current_user.username
            msg = f"📩 '{title}' başlıklı yeni veri {uploader_name} tarafından gönderildi."
            for ra in rootadmins:
                conn.execute('INSERT INTO notifications (user_id, data_id, message) VALUES (?, ?, ?)',
                             (ra['id'], new_data_id, msg))

        
        
        conn.commit()
        flash('Veri başarıyla eklendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'error')
    finally:
        conn.close()

    if current_user.role in ['admin', 'rootadmin']:
        return redirect(url_for('statistics'))
    return redirect(url_for('dashboard'))

@app.route('/statistics', methods=['GET'])
@login_required
@role_required('rootadmin', 'admin')
def statistics():
    conn = get_db_connection()
    data_list = get_filtered_data_entries(
        current_user,
        include_passive=(current_user.role == 'rootadmin'),
        uploader_role='rootadmin'   # ← SADECE ROOTADMIN'İN YÜKLEDİKLERİ
    )

    admin_unit = None
    admin_sub_unit = None
    if current_user.role == 'admin':
        if current_user.unit_id:
            admin_unit = conn.execute('SELECT * FROM units WHERE id = ?', (current_user.unit_id,)).fetchone()
        if current_user.sub_unit_id:
            admin_sub_unit = conn.execute('SELECT * FROM sub_units WHERE id = ?', (current_user.sub_unit_id,)).fetchone()

    units_list = conn.execute('SELECT * FROM units WHERE is_active = 1 ORDER BY name ASC').fetchall()
    institutes_list = conn.execute('SELECT * FROM institutes WHERE is_active = 1 ORDER BY name ASC').fetchall()
    conn.close()

    return render_template('statistics.html', user=current_user, data=data_list, units=units_list,
                           institutes=institutes_list,
                           admin_unit=admin_unit, admin_sub_unit=admin_sub_unit)

@app.route('/users', methods=['GET', 'POST'])
@login_required
@role_required('rootadmin')
def users():
    conn = get_db_connection()
    
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        unit_id = request.form.get('unit_id')
        sub_unit_id = request.form.get('sub_unit_id')
        role = request.form.get('role', 'user')
        
        # Requirement 1: full_name, username, password, email, role, unit_id mandatory
        if not full_name or not username or not password or not email or not role or not unit_id:
            flash('Ad, Kullanıcı Adı, Şifre, E-posta, Rol ve Birim alanları zorunludur.', 'error')
            conn.close()
            return redirect(url_for('users'))

        valid, msg = validate_password_complexity(password)
        if not valid:
            flash(msg, 'error')
            conn.close()
            return redirect(url_for('users'))

        if len(username) < 6:
            flash('Kullanıcı adı en az 6 karakter olmalıdır.', 'error')
            conn.close()
            return redirect(url_for('users'))

        try:
            hashed_pw = generate_password_hash(password)
            conn.execute('''
                INSERT INTO users (username, password, full_name, email, role, unit_id, sub_unit_id, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            ''', (username, hashed_pw, full_name, email, role, unit_id or None, sub_unit_id or None))
            conn.commit()
            flash('Kullanıcı başarıyla eklendi.', 'success')
        except Exception as e:
            flash(f'Hata: Kullanıcı adı zaten mevcut olabilir. {str(e)}', 'error')
            
        conn.close()
        return redirect(url_for('users'))

    users_list = conn.execute('''
        SELECT u.id, u.username, u.full_name, u.email, u.role, u.is_active, u.unit_id, u.sub_unit_id,
               un.name as unit_name, un.code as unit_code,
               su.name as sub_unit_name, su.code as sub_unit_code,
               i.name as institute_name, i.code as institute_code
        FROM users u 
        LEFT JOIN units un ON u.unit_id = un.id
        LEFT JOIN sub_units su ON u.sub_unit_id = su.id
        LEFT JOIN institutes i ON un.institute_id = i.id
        ORDER BY u.id DESC
    ''').fetchall()
    units_list = conn.execute('SELECT * FROM units ORDER BY name ASC').fetchall()
    institutes_list = conn.execute('SELECT * FROM institutes ORDER BY name ASC').fetchall()
    conn.close()
    
    return render_template('users.html', users=users_list, units=units_list, institutes=institutes_list)

@app.route('/download/<int:data_id>')
@login_required
def download_file(data_id):
    conn = get_db_connection()
    d = conn.execute('SELECT * FROM data_entries WHERE id = ?', (data_id,)).fetchone()
    
    if not d or not d['file_path']:
        conn.close()
        flash('Dosya bulunamadı.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    # Update status to 'indirildi' upon download
    if 'status' in d.keys() and d['status'] != 'indirildi':
        conn.execute("UPDATE data_entries SET status = 'indirildi' WHERE id = ?", (data_id,))
        conn.commit()
 
    conn.close()

    # 🔄 Güncellenmiş dosya varsa ONU servis et
    file_to_serve = d['file_path']
    if 'updated_file_path' in d.keys() and d['updated_file_path']:
        file_to_serve = d['updated_file_path']

    filename = os.path.basename(file_to_serve)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def edit_user(user_id):
    conn = get_db_connection()
    
    full_name = request.form.get('full_name', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    email = request.form.get('email', '').strip()
    role = request.form.get('role', 'user')
    unit_id = request.form.get('unit_id')
    sub_unit_id = request.form.get('sub_unit_id')
    is_active = 1 if request.form.get('is_active') == 'on' else 0

    if len(username) < 6:
        flash('Kullanıcı adı en az 6 karakter olmalıdır.', 'error')
        conn.close()
        return redirect(url_for('users'))

    try:
        if password:
            valid, msg = validate_password_complexity(password)
            if not valid:
                flash(msg, 'error')
                conn.close()
                return redirect(url_for('users'))
            hashed_pw = generate_password_hash(password)
            conn.execute('''
                UPDATE users 
                SET username = ?, password = ?, full_name = ?, email = ?, role = ?, unit_id = ?, sub_unit_id = ?, is_active = ?
                WHERE id = ?
            ''', (username, hashed_pw, full_name, email, role, unit_id or None, sub_unit_id or None, is_active, user_id))
        else:
            conn.execute('''
                UPDATE users 
                SET username = ?, full_name = ?, email = ?, role = ?, unit_id = ?, sub_unit_id = ?, is_active = ?
                WHERE id = ?
            ''', (username, full_name, email, role, unit_id or None, sub_unit_id or None, is_active, user_id))
            
        conn.commit()
        flash('Kullanıcı bilgileri güncellendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('users'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    password = request.form.get('password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    if not password:
        flash('Yeni şifre alanı boş bırakılamaz.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    if password != confirm_password:
        flash('Şifreler eşleşmiyor.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    valid, msg = validate_password_complexity(password)
    if not valid:
        flash(msg, 'error')
        return redirect(request.referrer or url_for('dashboard'))

    hashed_pw = generate_password_hash(password)
    conn = get_db_connection()
    conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, current_user.id))
    conn.commit()
    conn.close()

    flash('Şifreniz başarıyla değiştirildi.', 'success')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/data/approve_reject/<int:data_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def approve_reject_data(data_id):
    action = request.form.get('action')
    reason = request.form.get('reason', '').strip()
    if not reason and action not in ['onayla']:
        flash('Gerekçe girilmesi zorunludur.', 'error')
        return redirect(request.referrer or url_for('statistics'))

    if action not in ['onayla', 'reddet']:
        flash('Geçersiz işlem.', 'error')
        return redirect(request.referrer or url_for('statistics'))

    conn = get_db_connection()
    data_entry = conn.execute('SELECT * FROM data_entries WHERE id = ?', (data_id,)).fetchone()
    if not data_entry:
        conn.close()
        flash('Veri kaydı bulunamadı.', 'error')
        return redirect(request.referrer or url_for('statistics'))

    status_str = 'onaylandi' if action == 'onayla' else 'reddedildi'
    status_tr = 'ONAYLANDI' if action == 'onayla' else 'REDDEDİLDİ'

    conn.execute('UPDATE data_entries SET approval_status = ?, rejection_reason = ? WHERE id = ?',
                 (status_str, reason, data_id))

    notif_msg = f'"{data_entry["title"]}" başlıklı veri talebiniz rootadmin tarafından {status_tr}. Gerekçe: {reason}' 
    conn.execute('INSERT INTO notifications (user_id, data_id, message) VALUES (?, ?, ?)',
                 (data_entry['user_id'], data_id, notif_msg))

    conn.commit()
    conn.close()

    flash(f'Veri talebi {status_tr.lower()} ve kullanıcıya bildirim gönderildi.', 'success')
    return redirect(request.referrer or url_for('statistics'))

@app.route('/data/special_auth/<int:data_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def set_special_auth(data_id):
    raw = request.form.get('special_auth', '').strip()
    names = [n.strip() for n in raw.split(',') if n.strip()]

    conn = get_db_connection()
    if names:
        placeholders = ','.join('?' * len(names))
        rows = conn.execute(
            f'SELECT username FROM users WHERE lower(username) IN ({placeholders})',
            [n.lower() for n in names]
        ).fetchall()
        valid_lower = {r['username'].lower() for r in rows}
        invalid = [n for n in names if n.lower() not in valid_lower]
        if invalid:
            conn.close()
            flash(f'Şu kullanıcı adları sistemde bulunamadı: {", ".join(invalid)}', 'error')
            return redirect(url_for('statistics'))
        value = ', '.join(names)
    else:
        value = None

    conn.execute('UPDATE data_entries SET special_auth = ? WHERE id = ?', (value, data_id))
    conn.commit()
    conn.close()
    flash('Özel yetkiler güncellendi.', 'success')
    return redirect(url_for('statistics'))


@app.route('/data/toggle_active/<int:data_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def toggle_data_active(data_id):
    is_active = 1 if request.form.get('is_active') == 'on' else 0
    conn = get_db_connection()
    conn.execute('UPDATE data_entries SET is_active = ? WHERE id = ?', (is_active, data_id))
    conn.commit()
    conn.close()
    flash('İstatistik durumu güncellendi.', 'success')
    return redirect(url_for('statistics'))
@app.route('/data/update_file/<int:data_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def update_data_file(data_id):
    conn = get_db_connection()
    try:
        d = conn.execute('SELECT * FROM data_entries WHERE id = ?', (data_id,)).fetchone()

        if not d:
            flash('Veri kaydı bulunamadı.', 'error')
            return redirect(url_for('statistics'))

        # 🔒 Pasif kaydın dosyası güncellenemez
        is_active_val = d['is_active'] if 'is_active' in d.keys() else 1
        if is_active_val == 0:
            flash('Pasif istatistiğin dosyası güncellenemez. Önce aktife alın.', 'error')
            return redirect(url_for('statistics'))

        file = request.files.get('file')
        if not file or file.filename == '':
            flash('Dosya seçilmedi.', 'error')
            return redirect(url_for('statistics'))

        if not file.filename.lower().endswith('.zip'):
            flash('Sadece ZIP (.zip) uzantılı dosyalar yüklenebilir.', 'error')
            return redirect(url_for('statistics'))

        # 🔒 Hash kontrolü — TÜM sistemde (bu kayıt dahil)
        file_bytes = file.read()
        new_hash = hashlib.sha256(file_bytes).hexdigest()
        file.seek(0)

        existing = conn.execute('''
            SELECT id FROM data_entries
            WHERE file_hash = ? OR updated_file_hash = ?
        ''', (new_hash, new_hash)).fetchone()
        if existing:
            if existing['id'] == data_id:
                flash('Bu dosya bu kaydın mevcut dosyasıyla aynı. Aynı dosya tekrar gönderilemez.', 'error')
            else:
                flash('Bu dosya sistemde başka bir kayıtta zaten mevcut. Farklı bir dosya seçin.', 'error')
            return redirect(url_for('statistics'))

        # Dosyayı diske kaydet
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(full_path)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn.execute('''
            UPDATE data_entries
            SET updated_file_path = ?, updated_file_hash = ?, updated_by = ?, updated_at = ?
            WHERE id = ?
        ''', (f"uploads/{unique_filename}", new_hash, current_user.username, now, data_id))
        conn.commit()

        flash('Dosya güncellendi. Artık "İndir" butonu güncel dosyayı verecektir.', 'success')
        return redirect(url_for('statistics'))

    except Exception as e:
        # ⚠️ Hata olsa bile MUTLAKA return döner — None hatası imkansız
        flash(f'Hata oluştu: {str(e)}', 'error')
        return redirect(url_for('statistics'))
    finally:
        conn.close()

@app.route('/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def read_notification(notif_id):
    conn = get_db_connection()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', (notif_id, current_user.id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/notifications/read_all', methods=['POST'])
@login_required
def read_all_notifications():
    conn = get_db_connection()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ?', (current_user.id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
