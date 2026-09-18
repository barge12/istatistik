from flask import Flask, render_template, request, redirect, url_for, flash, jsonify,send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_db_connection, generate_auto_code

import os
import uuid
from datetime import datetime
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
    def __init__(self, id, username, role, unit_id, sub_unit_id=None):
        self.id = id
        self.username = username
        self.role = role
        self.unit_id = unit_id
        self.sub_unit_id = sub_unit_id

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
            sub_unit_id=user['sub_unit_id'] if 'sub_unit_id' in user.keys() else None
        )
    return None

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
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    query = '''
      
        SELECT d.id, u.username as user, un.name as unit, su.name as sub_unit, 
               d.day, d.month, d.year, d.time, d.title, d.note, d.file_path, 
               d.special_auth
        FROM data_entries d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN units un ON d.unit_id = un.id
        LEFT JOIN sub_units su ON d.sub_unit_id = su.id
    '''
    
    params = []
    
    if current_user.role == 'user':
        query += ' WHERE d.unit_id = ?'
        params.append(current_user.unit_id)
        
    query += ' ORDER BY d.created_at DESC'
    
    data_list = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('dashboard.html', user=current_user, data=data_list)
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
       
        # Enstitü opsiyonel — boş gelirse NULL (bağımsız) olur
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
                # Enstitü opsiyonel — seçilmezse bağımsız birim olarak eklenir
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

    # ── GET: İki ayrı yapı oluştur ──

    # Panel 1: Enstitüler → Birimleri
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

    # Panel 2: Birimler → Alt Birimleri
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

    if len(title) < 6:
        flash('Veri başlığı en az 6 karakter olmalıdır.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    now = datetime.now()
    day = now.day
    month = now.month
    year = now.year
    time_str = now.strftime("%H:%M:%S")

    if current_user.role == 'rootadmin':
        # ✅ Rootadmin: formdan seçtiği TÜM aktif birimler
        unit_id = request.form.get('unit_id')
        sub_unit_id = request.form.get('sub_unit_id')
        if not unit_id or not sub_unit_id:
            flash('Lütfen Birim ve Alt Birim seçiniz.', 'error')
            return redirect(url_for('statistics'))

    elif current_user.role == 'admin':
        # ✅ Admin: SADECE kendi birimi (form verisi KABUL EDİLMEZ — güvenlik)
        unit_id = current_user.unit_id
        sub_unit_id = current_user.sub_unit_id
        if not unit_id or not sub_unit_id:
            flash('Birim/Alt birim bilginiz tanımlı değil. Lütfen yöneticiyle iletişime geçin.', 'error')
            return redirect(url_for('statistics'))

    else:
        # User: kendi birimi
        unit_id = current_user.unit_id
        sub_unit_id = current_user.sub_unit_id

    file = request.files.get('file')
    file_path = None

    if file and file.filename != '':
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(full_path)
        file_path = f"uploads/{unique_filename}"

    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO data_entries (user_id, unit_id, sub_unit_id, day, month, year, time, title, note, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (current_user.id, unit_id, sub_unit_id, day, month, year, time_str, title, note, file_path))
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

    query = '''
        SELECT d.id, u.username as user, un.name as unit, su.name as sub_unit, 
               d.day, d.month, d.year, d.time, d.title, d.note, d.file_path, d.special_auth, d.status
        FROM data_entries d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN units un ON d.unit_id = un.id
        LEFT JOIN sub_units su ON d.sub_unit_id = su.id
        ORDER BY d.created_at DESC
    '''
    data_list = conn.execute(query).fetchall()

    # ✅ Admin'in kendi atandığı birim/alt birim bilgileri (formda kilitli gösterilecek)
    admin_unit = None
    admin_sub_unit = None
    if current_user.role == 'admin':
        if current_user.unit_id:
            admin_unit = conn.execute('SELECT * FROM units WHERE id = ?', (current_user.unit_id,)).fetchone()
        if current_user.sub_unit_id:
            admin_sub_unit = conn.execute('SELECT * FROM sub_units WHERE id = ?', (current_user.sub_unit_id,)).fetchone()

    units_list = conn.execute('SELECT * FROM units WHERE is_active = 1 ORDER BY name ASC').fetchall()
    conn.close()

    return render_template('statistics.html', user=current_user, data=data_list, units=units_list,
                           admin_unit=admin_unit, admin_sub_unit=admin_sub_unit)



@app.route('/users', methods=['GET', 'POST'])
@login_required
@role_required('rootadmin')
def users():
    conn = get_db_connection()
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        unit_id = request.form.get('unit_id')
        sub_unit_id = request.form.get('sub_unit_id')
        role = request.form.get('role', 'user')
        
        if len(username) < 6 or len(password) < 6:
            flash('Kullanıcı adı ve şifre en az 6 karakter olmalıdır.', 'error')
        else:
            try:
                hashed_pw = generate_password_hash(password)
                # When adding new user, default to Active (is_active = 1)
                conn.execute('''
                    INSERT INTO users (username, password, email, role, unit_id, sub_unit_id, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                ''', (username, hashed_pw, email, role, unit_id or None, sub_unit_id or None))
                conn.commit()
                flash('Kullanıcı başarıyla eklendi.', 'success')
            except Exception as e:
                flash(f'Hata: Kullanıcı adı zaten mevcut olabilir. {str(e)}', 'error')
                
        return redirect(url_for('users'))

    users_list = conn.execute('''
        SELECT u.id, u.username, u.email, u.role, u.is_active, u.unit_id, u.sub_unit_id,
               un.name as unit_name, su.name as sub_unit_name 
        FROM users u 
        LEFT JOIN units un ON u.unit_id = un.id
        LEFT JOIN sub_units su ON u.sub_unit_id = su.id
        ORDER BY u.id DESC
    ''').fetchall()
    units_list = conn.execute('SELECT * FROM units ORDER BY name ASC').fetchall()
    conn.close()
    
    return render_template('users.html', users=users_list, units=units_list)



@app.route('/download/<int:data_id>')
@login_required
def download_file(data_id):
    """Dosyayı indirir ve durumu OTOMATİK 'İndirildi' yapar."""
    conn = get_db_connection()
    d = conn.execute('SELECT * FROM data_entries WHERE id = ?', (data_id,)).fetchone()
    
    if not d or not d['file_path']:
        conn.close()
        flash('Dosya bulunamadı.', 'error')
        return redirect(request.referrer or url_for('dashboard'))

    # ✅ OTOMATİK durum güncelleme — indirme anında tetiklenir
    if d['status'] != 'indirildi':
        conn.execute("UPDATE data_entries SET status = 'indirildi' WHERE id = ?", (data_id,))
        conn.commit()
    conn.close()

    filename = os.path.basename(d['file_path'])
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
@role_required('rootadmin')
def edit_user(user_id):
    conn = get_db_connection()
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    email = request.form.get('email', '').strip()
    role = request.form.get('role', 'user')
    unit_id = request.form.get('unit_id')
    sub_unit_id = request.form.get('sub_unit_id')
    is_active = 1 if request.form.get('is_active') == 'on' else 0

    if len(username) < 6:
        flash('Kullanıcı adı en az 6 karakter olmalıdır.', 'error')
        return redirect(url_for('users'))

    try:
        if password:
            if len(password) < 6:
                flash('Yeni şifre en az 6 karakter olmalıdır.', 'error')
                return redirect(url_for('users'))
            hashed_pw = generate_password_hash(password)
            conn.execute('''
                UPDATE users 
                SET username = ?, password = ?, email = ?, role = ?, unit_id = ?, sub_unit_id = ?, is_active = ?
                WHERE id = ?
            ''', (username, hashed_pw, email, role, unit_id or None, sub_unit_id or None, is_active, user_id))
        else:
            conn.execute('''
                UPDATE users 
                SET username = ?, email = ?, role = ?, unit_id = ?, sub_unit_id = ?, is_active = ?
                WHERE id = ?
            ''', (username, email, role, unit_id or None, sub_unit_id or None, is_active, user_id))
            
        conn.commit()
        flash('Kullanıcı bilgileri güncellendi.', 'success')
    except Exception as e:
        flash(f'Hata oluştu: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('users'))

if __name__ == '__main__':
    app.run(debug=True,port=4000)
