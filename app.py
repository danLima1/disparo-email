from flask import Flask, request, jsonify, render_template, session, redirect, url_for, g
import threading
import time
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import psycopg2
from psycopg2 import sql, errors
import os
from flask_cors import CORS  # Importante para lidar com CORS
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from functools import wraps
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # Substitua por uma chave secreta segura

# Configuração de CORS para permitir credenciais
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})

# Configurações de sessão
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True  # Certifique-se de usar HTTPS em produção

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Definir a URL do banco de dados PostgreSQL
DATABASE_URL = "postgresql://postgres:Evp5BZ0ZcriInfQG@oddly-sharp-nightcrawler.data-1.use1.tembo.io:5432/postgres"

# Classe User para Flask-Login
class User(UserMixin):
    def __init__(self, id, email, password_hash):
        self.id = id
        self.email = email
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('SELECT id, email, password FROM users WHERE id = %s', (int(user_id),))
    user = c.fetchone()
    conn.close()
    if user:
        return User(*user)
    else:
        return None

# Função para enviar e-mail
def enviar_email(subject, body, to_email, from_email, from_name, password, smtp_server="smtp.hostinger.com", smtp_port=587):
    try:
        # Conectando ao servidor SMTP
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(from_email, password)

            # Configurando o e-mail
            msg = MIMEMultipart()
            msg['From'] = f"{from_name} <{from_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))

            # Enviando o e-mail
            server.sendmail(from_email, to_email, msg.as_string())
            print(f"E-mail enviado para {to_email}")
    except Exception as e:
        print(f"Erro ao enviar o e-mail para {to_email}: {e}")

# Função para enviar e-mails em uma thread separada
def send_emails_thread(emails_list, subject, body, from_email, from_name, password, total_emails, dispatch_id):
    # Atualiza o status do disparo no banco de dados
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = %s, progress = %s, last_email = %s WHERE id = %s', ('executando', 0, '', dispatch_id))
    conn.commit()
    conn.close()
    for idx, to_email in enumerate(emails_list):
        # Envia o e-mail
        enviar_email(subject, body, to_email, from_email, from_name, password)
        # Atualiza o progresso no banco de dados
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('UPDATE dispatch SET progress = %s, last_email = %s WHERE id = %s', (idx+1, to_email, dispatch_id))
        conn.commit()
        conn.close()
        # Aguarda 60 segundos se não for o último e-mail
        if idx < len(emails_list) - 1:
            time.sleep(60)
    # Marca o disparo como concluído
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = %s WHERE id = %s', ('concluído', dispatch_id))
    conn.commit()
    conn.close()

def init_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()

        # Cria a tabela 'users' se não existir
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Cria a tabela 'dispatch' se não existir
        c.execute('''
            CREATE TABLE IF NOT EXISTS dispatch (
                id SERIAL PRIMARY KEY,
                status TEXT,
                progress INTEGER,
                total INTEGER,
                last_email TEXT,
                user_id INTEGER REFERENCES users(id)
            )
        ''')

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao inicializar o banco de dados: {e}")

# Chama a inicialização do banco de dados
init_db()

# Rota de registro
@app.route('/register', methods=['POST'])
def register():
    # Obter dados do formulário
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    # Validar dados
    if not email or not password or not confirm_password:
        return jsonify({'error': 'Por favor, preencha todos os campos.'}), 400
    if password != confirm_password:
        return jsonify({'error': 'As senhas não coincidem.'}), 400

    # Hash da senha
    hashed_password = generate_password_hash(password)

    # Inserir usuário no banco de dados
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('INSERT INTO users (email, password) VALUES (%s, %s)', (email, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Usuário registrado com sucesso.'}), 200
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        conn.close()
        return jsonify({'error': 'Este e-mail já está cadastrado.'}), 400
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Ocorreu um erro: {e}'}), 500

# Rota de login
@app.route('/login', methods=['POST'])
def login():
    # Obter dados do formulário
    email = request.form.get('email')
    password = request.form.get('password')

    # Validar dados
    if not email or not password:
        return jsonify({'error': 'Por favor, preencha todos os campos.'}), 400

    # Buscar usuário no banco de dados
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT id, email, password FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if user and check_password_hash(user[2], password):
            # Login bem-sucedido
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj)
            conn.close()
            return jsonify({'message': 'Login realizado com sucesso.'}), 200
        else:
            conn.close()
            return jsonify({'error': 'E-mail ou senha inválidos.'}), 400
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Ocorreu um erro: {e}'}), 500

# Rota de logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout realizado com sucesso.'}), 200

# Rota para iniciar o disparo de e-mails
@app.route('/start_dispatch', methods=['POST'])
@login_required
def start_dispatch():
    # Obtém os dados do request
    data = request.form
    subject = data.get('subject')
    email_body = data.get('email_body')
    from_name = data.get('from_name')  # Captura o nome do remetente
    uploaded_file = request.files.get('file')

    if not subject or not email_body or not uploaded_file or not from_name:
        return jsonify({'error': 'Dados incompletos.'}), 400

    # Salva o arquivo
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    file_path = os.path.join('uploads', uploaded_file.filename)
    uploaded_file.save(file_path)

    # Lê os e-mails do arquivo Excel
    emails_df = pd.read_excel(file_path)
    emails_list = emails_df['Email'].dropna().tolist()
    total_emails = len(emails_list)

    if total_emails == 0:
        return jsonify({'error': 'Nenhum e-mail encontrado na planilha.'}), 400

    # Insere um novo disparo no banco de dados associado ao usuário
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('INSERT INTO dispatch (user_id, status, progress, total, last_email) VALUES (%s, %s, %s, %s, %s) RETURNING id',
                  (current_user.id, 'pendente', 0, total_emails, ''))
        dispatch_id = c.fetchone()[0]
        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Erro ao iniciar o disparo: {e}'}), 500

    # Inicia a thread de envio de e-mails
    from_email = 'aviso@condutor-govbr.blog'  # Substitua pelo seu e-mail
    password = 'Batata135-'  # Substitua pela sua senha ou use uma variável de ambiente

    threading.Thread(target=send_emails_thread, args=(emails_list, subject, email_body, from_email, from_name, password, total_emails, dispatch_id)).start()

    return jsonify({'message': 'Disparo iniciado com sucesso.', 'total': total_emails, 'dispatch_id': dispatch_id}), 200

# Rota para obter o progresso do último disparo do usuário
@app.route('/progress', methods=['GET'])
@login_required
def get_progress():
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('SELECT id, status, progress, total, last_email FROM dispatch WHERE user_id = %s ORDER BY id DESC LIMIT 1', (current_user.id,))
    result = c.fetchone()
    conn.close()
    if result:
        dispatch_id, status, progress, total, last_email = result
        return jsonify({
            'dispatch_id': dispatch_id,
            'status': status,
            'progress': progress,
            'total': total,
            'last_email': last_email
        }), 200
    else:
        return jsonify({'error': 'Nenhum disparo encontrado.'}), 404

# Rota para verificar a sessão
@app.route('/check_session', methods=['GET'])
@login_required
def check_session():
    return jsonify({'status': 'authenticated'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
