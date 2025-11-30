import time
import os
import random
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'default_dev_key')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

db_config = {
    'host': os.environ.get('DB_HOST', 'db'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', 'root_secure_pass'),
    'database': os.environ.get('DB_NAME', 'void_archive'),
    'auth_plugin': 'mysql_native_password',
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'use_unicode': True
}

LORE_QUOTES = [
    "Истина скрыта в именах, которые все знают, но никто не произносит.",
    "Библиотека отвергает тех, кто представляется своим истинным именем.",
    "Схема мироздания закрыта для глаз смертных.",
]

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password_hash'])
    except:
        return None
    return None

def init_flag():
    flag = os.environ.get('FLAG')
    if not flag:
        print("[!] ОШИБКА: Флаг не найден в .env!")
        flag = "CTF{PLACEHOLDER_ERROR}"

    print("[*] Ожидание БД...")
    while True:
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS admin (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    password VARCHAR(255)
                )
            """)
            cursor.execute("DELETE FROM admin")
            cursor.execute("INSERT INTO admin (password) VALUES (%s)", (flag,))
            conn.commit()
            print(f"[*] Флаг успешно спрятан в таблице 'admin'.")
            conn.close()
            break
        except Exception as e:
            print(f"[!] Ожидание БД: {e}")
            time.sleep(3)

def waf_check(request):
    val = request.form.get('query', '')
    val_upper = val.upper()
    user_agent = request.headers.get('User-Agent', '').lower()

    if 'sqlmap' in user_agent:
        return True, "Архив отвергает автоматизированных големов (Bad User-Agent)."
    if "INFORMATION_SCHEMA" in val_upper:
        return True, "Попытка познать структуру мироздания запрещена."
    
    blacklist = ["UNION", "SLEEP", "BENCHMARK"]
    for bad in blacklist:
        if bad in val_upper:
            return True, "Запрещенное заклинание."
    return False, ""

@app.route('/')
def index():
    return redirect(url_for('search'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            conn.close()
            if user_data and check_password_hash(user_data['password_hash'], password):
                user = User(user_data['id'], user_data['username'], user_data['password_hash'])
                login_user(user)
                return redirect(url_for('search'))
            else:
                flash('Неверное имя или пароль.')
        except Exception as e:
            flash('Ошибка подключения к Архиву.')
            print(e)
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            hashed_pw = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed_pw))
            conn.commit()
            conn.close()
            flash('Успешная регистрация.')
            return redirect(url_for('login'))
        except:
            flash('Ошибка регистрации.')
    return render_template('register.html')

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    results = []
    msg = "Введите запрос."
    query_val = ""
    random_quote = random.choice(LORE_QUOTES)

    if request.method == 'POST':
        query_val = request.form.get('query', '')
        is_blocked, reason = waf_check(request)
        
        if is_blocked:
            msg = reason
        else:
            try:
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=True)
                sql = f"SELECT title, author, description FROM books WHERE title LIKE '%{query_val}%'"
                cursor.execute(sql)
                results = cursor.fetchall()
                conn.close()
                if not results:
                    msg = "В свитках ничего не найдено."
                else:
                    msg = f"Найдено записей: {len(results)}"
            except:
                msg = "Тьма скрыла ответ."

    return render_template('search.html', results=results, msg=msg, last_query=query_val, lore_quote=random_quote)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_flag()
    app.run(host='0.0.0.0', port=5000)