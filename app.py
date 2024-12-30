from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import sql, errors
from datetime import timedelta
from functools import wraps
from flask_cors import CORS
import os
import threading
import time
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

# Chave secreta para Flask e JWT
app.secret_key = 'oaa3A5O24IfbsT-IxdMuOrnb-U2wHdGvjjVfkcSrcfA'  # Mantenha esta chave segura!

# Configurações do JWT
app.config['JWT_SECRET_KEY'] = 'krR8etmh1AcVb76G_NJkntEWZifilRRmiD1a5gA6Q1YEq1TgnZuxylJgKXzFwbBB'  # Substitua por uma chave secreta segura
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)  # Tempo de expiração do token
app.config['JWT_ERROR_MESSAGE_KEY'] = 'error'
app.config['JWT_BLACKLIST_ENABLED'] = False
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'
app.config['JWT_DECODE_ALGORITHMS'] = ['HS256']
app.config['JWT_CSRF_CHECK_FORM'] = False
app.config['JWT_CSRF_IN_COOKIES'] = False

jwt = JWTManager(app)

# Handler para token expirado
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'error': 'Token expirado. Por favor, faça login novamente.'
    }), 401

# Handler para token inválido ou com assinatura incorreta
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 'error',
        'error': f'Token inválido: {error}'
    }), 422

# Handler para token ausente
@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'status': 'error',
        'error': 'Token de autorização não encontrado.'
    }), 401

# Handler para token revogado
@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'error': 'Token foi revogado.'
    }), 401

@jwt.user_lookup_error_loader
def user_lookup_error_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'error': 'Erro ao buscar usuário.'
    }), 401

# Configuração de CORS para permitir credenciais
CORS(app, supports_credentials=True, resources={r"/*": {"origins": [
    "http://127.0.0.1:5500",
    "https://disparoemailfront.vercel.app"
]}})

# Definir a URL do banco de dados PostgreSQL
DATABASE_URL = "postgresql://postgres:Evp5BZ0ZcriInfQG@oddly-sharp-nightcrawler.data-1.use1.tembo.io:5432/postgres"

# Decorador para verificar se o usuário é administrador
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        try:
            conn = psycopg2.connect(DATABASE_URL)
            c = conn.cursor()
            c.execute('SELECT role FROM users WHERE id = %s', (current_user_id,))
            result = c.fetchone()
            conn.close()
            if result and result[0] == 'admin':
                return fn(*args, **kwargs)
            else:
                return jsonify({'error': 'Acesso não autorizado. Requer privilégios de administrador.'}), 403
        except Exception as e:
            print(f"Erro ao verificar o papel do usuário: {e}")
            return jsonify({'error': 'Erro ao verificar privilégios de usuário.'}), 500
    return wrapper

# -------------------------------------------------------------------
# AJUSTE NA FUNÇÃO PARA ENVIAR E-MAIL
# Agora ela retorna (success, error_message).
# -------------------------------------------------------------------
def enviar_email(subject, body, to_email, user_id):
    try:
        # Obter as configurações de email do usuário
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            SELECT smtp_server, smtp_port, email_username, email_password, from_name, credits 
            FROM users WHERE id = %s FOR UPDATE
        ''', (user_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            print("Usuário não encontrado.")
            return (False, "Usuário não encontrado.")
        smtp_server, smtp_port, email_username, email_password, from_name, credits = result
        if not smtp_server or not smtp_port or not email_username or not email_password:
            conn.close()
            print("Configuração de e-mail incompleta.")
            return (False, "Configuração de e-mail incompleta.")
        if credits <= 0:
            conn.close()
            print("Créditos insuficientes.")
            return (False, "Créditos insuficientes.")

        # Conectando ao servidor SMTP
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_username, email_password)

            # Configurando o e-mail
            msg = MIMEMultipart()
            msg['From'] = f"{from_name} <{email_username}>" if from_name else email_username
            msg['To'] = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))

            # Enviando o e-mail
            server.sendmail(email_username, to_email, msg.as_string())
            print(f"E-mail enviado para {to_email}")

        # Deduz um crédito do usuário
        new_credits = credits - 1
        c.execute('UPDATE users SET credits = %s WHERE id = %s', (new_credits, user_id))
        conn.commit()
        conn.close()
        return (True, None)  # Nenhum erro
    except Exception as e:
        print(f"Erro ao enviar o e-mail para {to_email}: {e}")
        return (False, str(e))

# -------------------------------------------------------------------
# CRIAÇÃO DA NOVA TABELA PARA LOG DE E-MAILS
# -------------------------------------------------------------------
def create_dispatch_email_log_table(cursor):
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dispatch_email_log (
            id SERIAL PRIMARY KEY,
            dispatch_id INTEGER REFERENCES dispatch(id),
            email TEXT,
            success BOOLEAN,
            error_message TEXT
        )
    ''')

# -------------------------------------------------------------------
# AJUSTE NA THREAD DE ENVIO PARA SALVAR LOG EM dispatch_email_log
# -------------------------------------------------------------------
def send_emails_thread(emails_list, subject, body, dispatch_id, user_id):
    # Atualiza o status do disparo no banco de dados
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = %s, progress = %s, last_email = %s WHERE id = %s',
              ('executando', 0, '', dispatch_id))
    conn.commit()
    conn.close()

    for idx, to_email in enumerate(emails_list):
        # Envia o e-mail
        success, error_message = enviar_email(subject, body, to_email, user_id)

        # Salva log de cada envio
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            INSERT INTO dispatch_email_log (dispatch_id, email, success, error_message)
            VALUES (%s, %s, %s, %s)
        ''', (dispatch_id, to_email, success, error_message if error_message else None))
        conn.commit()
        conn.close()

        if not success:
            # Se não for possível enviar (por falta de créditos ou configuração), interrompe o envio
            print("Interrompendo o envio por falha na configuração ou créditos insuficientes.")
            break

        # Atualiza o progresso no banco de dados
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('UPDATE dispatch SET progress = %s, last_email = %s WHERE id = %s',
                  (idx + 1, to_email, dispatch_id))
        conn.commit()
        conn.close()

        # Aguarda 60 segundos se não for o último e-mail
        if idx < len(emails_list) - 1:
            time.sleep(60)

    # Marca o disparo como concluído (ou "concluído com erros" se não tiver enviado tudo)
    final_status = 'concluído' if idx == len(emails_list) - 1 and success else 'concluído_com_erros'
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = %s WHERE id = %s', (final_status, dispatch_id))
    conn.commit()
    conn.close()

# -------------------------------------------------------------------
# FUNÇÃO DE INICIALIZAÇÃO DO BANCO (inclui nova tabela de LOGS)
# -------------------------------------------------------------------
def init_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()

        # Cria a tabela 'users' se não existir
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                credits INTEGER DEFAULT 0,
                smtp_server TEXT,
                smtp_port INTEGER,
                email_username TEXT,
                email_password TEXT,
                from_name TEXT
            )
        ''')

        # Cria a tabela 'dispatch' se não existir
        c.execute('''
            CREATE TABLE IF NOT EXISTS dispatch (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                status TEXT,
                progress INTEGER,
                total INTEGER,
                last_email TEXT
            )
        ''')

        # Cria a tabela para log dos e-mails disparados
        create_dispatch_email_log_table(c)

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao inicializar o banco de dados: {e}")

init_db()

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
        c.execute('INSERT INTO users (email, password, role) VALUES (%s, %s, %s)',
                  (email, hashed_password, role))
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
        c.execute('SELECT id, email, password, role, credits FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            # Criação do token JWT com identidade como ID do usuário
            access_token = create_access_token(
                identity=str(user[0]),  # Convertendo para string
                additional_claims={
                    'email': user[1],
                    'role': user[3]
                }
            )
            
            print(f"Token gerado para usuário {user[1]}: {access_token}")  # Log para debug
            
            return jsonify({
                'message': 'Login realizado com sucesso.',
                'access_token': access_token,
                'role': user[3],
                'user': {
                    'id': user[0],
                    'email': user[1],
                    'credits': user[4]
                }
            }), 200
        else:
            return jsonify({'error': 'E-mail ou senha inválidos.'}), 400
    except Exception as e:
        print(f"Erro no login: {str(e)}")  # Log para debug
        return jsonify({'error': f'Ocorreu um erro: {str(e)}'}), 500

# Rota para iniciar o disparo de e-mails
@app.route('/start_dispatch', methods=['POST'])
@jwt_required()
def start_dispatch():
    # Obter a identidade do usuário a partir do token
    current_user = get_jwt_identity()
    user_id = current_user

    # Obtém os dados do request
    subject = request.form.get('subject')
    email_body = request.form.get('email_body')
    from_name = request.form.get('from_name')  # Captura o nome do remetente
    uploaded_file = request.files.get('file')

    if not subject or not email_body or not uploaded_file or not from_name:
        return jsonify({'error': 'Dados incompletos.'}), 400

    # Salva o arquivo
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    file_path = os.path.join('uploads', uploaded_file.filename)
    uploaded_file.save(file_path)

    # Lê os e-mails do arquivo Excel
    try:
        emails_df = pd.read_excel(file_path)
    except Exception as e:
        return jsonify({'error': f'Erro ao ler o arquivo Excel: {e}'}), 400

    if 'Email' not in emails_df.columns:
        return jsonify({'error': 'A planilha deve conter a coluna "Email".'}), 400

    emails_list = emails_df['Email'].dropna().tolist()
    total_emails = len(emails_list)

    if total_emails == 0:
        return jsonify({'error': 'Nenhum e-mail encontrado na planilha.'}), 400

    # Insere um novo disparo no banco de dados associado ao usuário
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            INSERT INTO dispatch (user_id, status, progress, total, last_email)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        ''', (user_id, 'pendente', 0, total_emails, ''))
        dispatch_id = c.fetchone()[0]
        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Erro ao iniciar o disparo: {e}'}), 500

    # Inicia a thread de envio de e-mails
    threading.Thread(
        target=send_emails_thread,
        args=(emails_list, subject, email_body, dispatch_id, user_id)
    ).start()

    return jsonify({
        'message': 'Disparo iniciado com sucesso.',
        'total': total_emails,
        'dispatch_id': dispatch_id
    }), 200

# Rota para obter o progresso do último disparo do usuário
@app.route('/progress', methods=['GET'])
@jwt_required()
def get_progress():
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            SELECT id, status, progress, total, last_email
            FROM dispatch
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 1
        ''', (current_user_id,))
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
    except Exception as e:
        print(f"Erro ao obter o progresso: {e}")
        return jsonify({'error': 'Erro ao obter o progresso.'}), 500

# -------------------------------------------------------------------
# NOVA ROTA PARA OBTER O PROGRESSO DE UM DISPARO ESPECÍFICO
# -------------------------------------------------------------------
@app.route('/dispatch/<int:dispatch_id>/progress', methods=['GET'])
@jwt_required()
def get_dispatch_progress(dispatch_id):
    """
    Retorna o status, progresso, total e último e-mail enviado
    de um disparo específico.
    """
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        # Verifica se o dispatch pertence ao usuário ou se o usuário é admin
        c.execute('SELECT user_id FROM dispatch WHERE id = %s', (dispatch_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Disparo não encontrado.'}), 404
        
        owner_id = row[0]
        # Se não for o dono e não for admin, bloqueia
        c.execute('SELECT role FROM users WHERE id = %s', (current_user_id,))
        user_role = c.fetchone()[0]

        if (str(owner_id) != str(current_user_id)) and (user_role != 'admin'):
            conn.close()
            return jsonify({'error': 'Acesso não autorizado.'}), 403
        
        # Retorna as informações do dispatch
        c.execute('''
            SELECT status, progress, total, last_email
            FROM dispatch
            WHERE id = %s
        ''', (dispatch_id,))
        result = c.fetchone()
        conn.close()

        if result:
            status, progress, total, last_email = result
            return jsonify({
                'dispatch_id': dispatch_id,
                'status': status,
                'progress': progress,
                'total': total,
                'last_email': last_email
            }), 200
        else:
            return jsonify({'error': 'Disparo não encontrado.'}), 404

    except Exception as e:
        print(f"Erro ao obter o progresso do disparo: {e}")
        return jsonify({'error': 'Erro ao obter o progresso do disparo.'}), 500

# -------------------------------------------------------------------
# NOVA ROTA PARA OBTER CONTAGEM DE SUCESSOS, ERROS E LOG DE ERROS
# -------------------------------------------------------------------
@app.route('/dispatch/<int:dispatch_id>/results', methods=['GET'])
@jwt_required()
def get_dispatch_results(dispatch_id):
    """
    Retorna quantos e-mails tiveram sucesso, quantos tiveram erro
    e a lista (email, error_message) dos que falharam.
    """
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()

        # Verifica se o dispatch pertence ao usuário ou se o usuário é admin
        c.execute('SELECT user_id FROM dispatch WHERE id = %s', (dispatch_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Disparo não encontrado.'}), 404
        
        owner_id = row[0]
        # Se não for o dono e não for admin, bloqueia
        c.execute('SELECT role FROM users WHERE id = %s', (current_user_id,))
        user_role = c.fetchone()[0]

        if (str(owner_id) != str(current_user_id)) and (user_role != 'admin'):
            conn.close()
            return jsonify({'error': 'Acesso não autorizado.'}), 403
        
        # Conta sucessos e erros
        c.execute('''
            SELECT COUNT(*) FROM dispatch_email_log
            WHERE dispatch_id = %s AND success = TRUE
        ''', (dispatch_id,))
        success_count = c.fetchone()[0]

        c.execute('''
            SELECT COUNT(*) FROM dispatch_email_log
            WHERE dispatch_id = %s AND success = FALSE
        ''', (dispatch_id,))
        error_count = c.fetchone()[0]

        # Lista de erros
        c.execute('''
            SELECT email, error_message
            FROM dispatch_email_log
            WHERE dispatch_id = %s AND success = FALSE
        ''', (dispatch_id,))
        errors = c.fetchall()

        conn.close()

        # Monta a lista de erros (email, error_message)
        error_logs = []
        for email, error_msg in errors:
            error_logs.append({
                'email': email,
                'error_message': error_msg
            })

        return jsonify({
            'dispatch_id': dispatch_id,
            'success_count': success_count,
            'error_count': error_count,
            'error_logs': error_logs
        }), 200

    except Exception as e:
        print(f"Erro ao obter resultados do disparo: {e}")
        return jsonify({'error': 'Erro ao obter resultados do disparo.'}), 500

# Rota para verificar o token
@app.route('/check_token', methods=['GET'])
@jwt_required()
def check_token():
    try:
        current_user_id = get_jwt_identity()
        print(f"Token válido para o usuário ID: {current_user_id}")  # Log para depuração
        print(f"Headers recebidos: {request.headers}")  # Log dos headers
        print(f"Authorization header: {request.headers.get('Authorization')}")  # Log do token

        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT id, email, role FROM users WHERE id = %s', (int(current_user_id),))  # Convertendo para int
        user = c.fetchone()
        conn.close()

        if user:
            response_data = {
                'status': 'authenticated',
                'user': {
                    'id': user[0],
                    'email': user[1],
                    'role': user[2]
                }
            }
            print(f"Resposta sendo enviada: {response_data}")  # Log da resposta
            return jsonify(response_data), 200
        else:
            print(f"Usuário não encontrado para ID: {current_user_id}")  # Log de usuário não encontrado
            return jsonify({
                'status': 'error',
                'message': 'Usuário não encontrado'
            }), 404

    except Exception as e:
        print(f"Erro na verificação do token: {str(e)}")  # Log detalhado do erro
        print(f"Tipo do erro: {type(e)}")  # Log do tipo do erro
        return jsonify({
            'status': 'error',
            'message': f'Erro ao verificar o token: {str(e)}'
        }), 500

# Rota para obter o saldo de créditos do usuário
@app.route('/get_my_credits', methods=['GET'])
@jwt_required()
def get_my_credits():
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT credits FROM users WHERE id = %s', (current_user_id,))
        result = c.fetchone()
        conn.close()
        if result:
            return jsonify({'credits': result[0]}), 200
        else:
            return jsonify({'error': 'Usuário não encontrado.'}), 404
    except Exception as e:
        print(f"Erro ao obter créditos: {e}")
        return jsonify({'error': 'Erro ao obter créditos.'}), 500

# Rota para configurar o e-mail do usuário (corrigida)
@app.route('/set_email_config', methods=['POST'])
@jwt_required()
def set_email_config():
    data = request.get_json()
    smtp_server = data.get('smtp_server')
    smtp_port = data.get('smtp_port')
    email_username = data.get('email_username')
    email_password = data.get('email_password')
    from_name = data.get('from_name')

    if not smtp_server or not smtp_port or not email_username or not email_password:
        return jsonify({'status': 'error', 'message': 'Dados incompletos.'}), 400

    current_user_id = get_jwt_identity()

    # Atualizar as configurações de email do usuário no banco de dados
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            UPDATE users
            SET smtp_server = %s,
                smtp_port = %s,
                email_username = %s,
                email_password = %s,
                from_name = %s
            WHERE id = %s
        ''', (smtp_server, smtp_port, email_username, email_password, from_name, current_user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'status': 'error', 'message': f'Erro ao atualizar configuração de email: {str(e)}'}), 500

    return jsonify({'status': 'success', 'message': 'Configuração de email atualizada com sucesso.'}), 200

# Rota para obter as configurações de e-mail do usuário
@app.route('/get_email_config', methods=['GET'])
@jwt_required()
def get_email_config():
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('''
            SELECT smtp_server, smtp_port, email_username, from_name 
            FROM users WHERE id = %s
        ''', (current_user_id,))
        result = c.fetchone()
        conn.close()

        if result:
            smtp_server, smtp_port, email_username, from_name = result
            return jsonify({
                'status': 'success',
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'email_username': email_username,
                'from_name': from_name
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Usuário não encontrado'}), 404

    except Exception as e:
        print(f"Erro ao obter configuração de email: {e}")
        return jsonify({'status': 'error', 'message': 'Erro ao obter configuração de email.'}), 500

# Rotas de Administração para Gerenciar Créditos
@app.route('/admin/users', methods=['GET'])
@admin_required
def get_users():
    try:
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        
        # Consulta apenas usuários com role 'user', com paginação
        query = sql.SQL("""
            SELECT id, email, credits
            FROM users
            WHERE role = %s
            ORDER BY id ASC
            LIMIT %s OFFSET %s
        """)
        c.execute(query, ('user', limit, offset))
        
        users = c.fetchall()
        conn.close()
        
        # Converte os resultados em lista de dicionários
        users_list = [{'id': user[0], 'email': user[1], 'credits': user[2]} for user in users]
        
        return jsonify(users_list), 200

    except psycopg2.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return jsonify({'error': 'Erro interno do servidor.'}), 500
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return jsonify({'error': 'Ocorreu um erro inesperado.'}), 500

# Rota para o administrador adicionar créditos a um usuário
@app.route('/admin/add_credits', methods=['POST'])
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

    try:
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

        return jsonify({
            'message': f'{credits_to_add} créditos adicionados ao usuário {user_id}. Novo saldo: {new_credits}.'
        }), 200
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Erro ao adicionar créditos: {str(e)}'}), 500

# Rota para Administradores obterem os créditos de um usuário
@app.route('/admin/get_credits/<int:user_id>', methods=['GET'])
@admin_required
def get_credits(user_id):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT credits FROM users WHERE id = %s', (user_id,))
        user = c.fetchone()
        conn.close()

        if not user:
            return jsonify({'status': 'error', 'message': 'Usuário não encontrado.'}), 404

        return jsonify({'status': 'success', 'user_id': user_id, 'credits': user[0]}), 200
    except Exception as e:
        print(f"Erro ao obter créditos: {e}")
        return jsonify({'error': 'Erro ao obter créditos.'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
