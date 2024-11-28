from flask import Flask, request, jsonify, session
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
# Remover ou comentar a linha abaixo para evitar redirecionamentos automáticos
# login_manager.login_view = 'login'

# Definir a URL do banco de dados PostgreSQL
DATABASE_URL = "postgresql://postgres:Evp5BZ0ZcriInfQG@oddly-sharp-nightcrawler.data-1.use1.tembo.io:5432/postgres"

# Classe User para Flask-Login
class User(UserMixin):
    def __init__(self, id, email, password_hash, role):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('SELECT id, email, password, role FROM users WHERE id = %s', (int(user_id),))
    user = c.fetchone()
    conn.close()
    if user:
        return User(*user)
    else:
        return None

# Handler para usuários não autorizados
@login_manager.unauthorized_handler
def unauthorized_callback():
    return jsonify({'error': 'Usuário não autenticado.'}), 401

# Função para enviar e-mail
def enviar_email(subject, body, to_email, from_email, from_name, password, smtp_server="smtp.hostinger.com", smtp_port=587, user_id=None):
    try:
        # Verifica se o usuário tem créditos suficientes
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT credits FROM users WHERE id = %s FOR UPDATE', (user_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            print("Usuário não encontrado.")
            return False
        credits = result[0]
        if credits <= 0:
            conn.close()
            print("Créditos insuficientes.")
            return False

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

        # Deduz um crédito do usuário
        new_credits = credits - 1
        c.execute('UPDATE users SET credits = %s WHERE id = %s', (new_credits, user_id))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Erro ao enviar o e-mail para {to_email}: {e}")
        return False

# Função para enviar e-mails em uma thread separada
def send_emails_thread(emails_list, subject, body, from_email, from_name, password, total_emails, dispatch_id, user_id):
    # Atualiza o status do disparo no banco de dados
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = %s, progress = %s, last_email = %s WHERE id = %s', ('executando', 0, '', dispatch_id))
    conn.commit()
    conn.close()
    for idx, to_email in enumerate(emails_list):
        # Envia o e-mail
        success = enviar_email(subject, body, to_email, from_email, from_name, password, user_id=user_id)
        if not success:
            # Se não for possível enviar (por falta de créditos), interrompe o envio
            print("Interrompendo o envio por falta de créditos.")
            break
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
                -- Não incluímos as colunas 'role' e 'credits' aqui para evitar erros se elas já existirem
            )
        ''')

        # Adiciona a coluna 'role' à tabela 'users', caso ainda não exista
        c.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_name='users' AND column_name='role'
                ) THEN
                    ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
                END IF;
            END;
            $$;
        """)

        # Adiciona a coluna 'credits' à tabela 'users', caso ainda não exista
        c.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_name='users' AND column_name='credits'
                ) THEN
                    ALTER TABLE users ADD COLUMN credits INTEGER DEFAULT 0;
                END IF;
            END;
            $$;
        """)

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

# Decorador para verificar se o usuário é administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Acesso não autorizado. Requer privilégios de administrador.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Rota de registro
@app.route('/register', methods=['POST'])
def register():
    # Obter dados do formulário
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    role = request.form.get('role', 'user')  # Adiciona o papel, padrão 'user'

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
        c.execute('INSERT INTO users (email, password, role) VALUES (%s, %s, %s)', (email, hashed_password, role))
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
        c.execute('SELECT id, email, password, role FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        if user and check_password_hash(user[2], password):
            # Login bem-sucedido
            user_obj = User(user[0], user[1], user[2], user[3])
            login_user(user_obj)
            conn.close()
            # Inclui o papel do usuário na resposta
            return jsonify({'message': 'Login realizado com sucesso.', 'role': user[3]}), 200
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

    threading.Thread(target=send_emails_thread, args=(emails_list, subject, email_body, from_email, from_name, password, total_emails, dispatch_id, current_user.id)).start()

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
    return jsonify({'status': 'authenticated', 'role': current_user.role}), 200

# Rota para obter o saldo de créditos do usuário
@app.route('/get_my_credits', methods=['GET'])
@login_required
def get_my_credits():
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('SELECT credits FROM users WHERE id = %s', (current_user.id,))
    result = c.fetchone()
    conn.close()
    if result:
        return jsonify({'credits': result[0]}), 200
    else:
        return jsonify({'error': 'Usuário não encontrado.'}), 404

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    try:
        # Parâmetros de paginação
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Estabelece a conexão com o banco de dados
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        
        # Consulta SQL para selecionar apenas usuários com role 'user' com paginação
        query = sql.SQL("SELECT id, email, credits FROM users WHERE role = %s ORDER BY id ASC LIMIT %s OFFSET %s")
        c.execute(query, ('user', limit, offset))
        
        users = c.fetchall()
        
        # Fecha a conexão com o banco de dados
        conn.close()
        
        # Converte os resultados em uma lista de dicionários
        users_list = [{'id': user[0], 'email': user[1], 'credits': user[2]} for user in users]
        
        return jsonify(users_list), 200

    except psycopg2.Error as e:
        # Log do erro (pode ser aprimorado para usar logging)
        print(f"Erro ao conectar ao banco de dados: {e}")
        return jsonify({'error': 'Erro interno do servidor.'}), 500

    except Exception as e:
        # Log de outros erros
        print(f"Erro inesperado: {e}")
        return jsonify({'error': 'Ocorreu um erro inesperado.'}), 500

# Rota para o administrador adicionar créditos a um usuário
@app.route('/admin/add_credits', methods=['POST'])
@login_required
@admin_required
def add_credits():
    data = request.get_json()
    user_id = data.get('user_id')
    credits_to_add = data.get('credits')

    if not user_id or credits_to_add is None:
        return jsonify({'error': 'Dados incompletos.'}), 400

    try:
        credits_to_add = int(credits_to_add)
        if credits_to_add <= 0:
            return jsonify({'error': 'O número de créditos deve ser positivo.'}), 400
    except ValueError:
        return jsonify({'error': 'Número de créditos inválido.'}), 400

    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('SELECT credits FROM users WHERE id = %s', (user_id,))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Usuário não encontrado.'}), 404

    new_credits = result[0] + credits_to_add
    c.execute('UPDATE users SET credits = %s WHERE id = %s', (new_credits, user_id))
    conn.commit()
    conn.close()

    return jsonify({'message': f'{credits_to_add} créditos adicionados ao usuário {user_id}. Novo saldo: {new_credits}.'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
