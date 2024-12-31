import re
import dns.resolver
import smtplib
import socket
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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# --------------------------------------------------
# CÓDIGO DE VALIDAÇÃO DE EMAILS
# --------------------------------------------------

# Exemplo de lista estática de domínios descartáveis
DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "temp-mail.org",
    "10minutemail.com",
    # Adicione outros domínios descartáveis aqui
}

def is_valid_format(email: str) -> bool:
    """
    Verifica se o formato do e-mail é válido usando uma expressão regular.
    """
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def is_disposable_domain(domain: str) -> bool:
    """
    Verifica se o domínio está em uma lista de domínios descartáveis.
    """
    return domain.lower() in DISPOSABLE_DOMAINS

def has_mx_record(domain: str) -> bool:
    """
    Verifica se o domínio possui um registro MX.
    Retorna True se encontrar algum registro MX.
    """
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return False

def smtp_verify(email: str) -> bool:
    """
    Tenta verificar o e-mail utilizando SMTP.
    Retorna True se o e-mail for considerado válido, False caso contrário.
    """
    domain = email.split('@')[-1]
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = records[0].exchange.to_text()
    except Exception as e:
        print(f"Erro ao obter registros MX para {domain}: {e}")
        return False

    try:
        server = smtplib.SMTP(mx_record)
        server.set_debuglevel(0)
        server.ehlo()
        server.starttls()
        server.ehlo()

        # Ajustar o e-mail de teste se desejar
        server.mail("teste@seuservidor.com")
        code, message = server.rcpt(email)
        server.quit()

        if code == 250 or code == 251:
            return True
        else:
            return False

    except smtplib.SMTPServerDisconnected:
        print("Falha ao conectar-se ao servidor SMTP.")
        return False
    except smtplib.SMTPConnectError:
        print("Erro de conexão SMTP.")
        return False
    except smtplib.SMTPHeloError:
        print("Erro no HELO SMTP.")
        return False
    except smtplib.SMTPRecipientsRefused:
        print("Recipiente SMTP recusado.")
        return False
    except smtplib.SMTPDataError:
        print("Erro de dados SMTP.")
        return False
    except Exception as e:
        print(f"Erro desconhecido durante verificação SMTP: {e}")
        return False

def validate_email_address(email: str):
    """
    Função principal que realiza as validações:
      1) Formato
      2) Domínio descartável
      3) Registro MX
      4) Verificação SMTP
    Retorna um dicionário com os resultados.
    """
    email = email.strip().lower()

    # 1. Verificar formato
    valid_format = is_valid_format(email)

    if not valid_format:
        return {
            "email": email,
            "valid_format": False,
            "disposable_domain": False,
            "mx_found": False,
            "smtp_valid": False,
            "valid_email": False
        }

    # 2. Extrair domínio
    domain = email.split('@')[-1]

    # 3. Verificar se é domínio descartável
    disposable = is_disposable_domain(domain)

    # 4. Verificar registro MX
    mx_found = has_mx_record(domain)

    # 5. Verificação SMTP
    smtp_valid = False
    if mx_found and not disposable:
        smtp_valid = smtp_verify(email)

    # 6. Lógica final
    valid_email = valid_format and not disposable and mx_found and smtp_valid

    return {
        "email": email,
        "valid_format": valid_format,
        "disposable_domain": disposable,
        "mx_found": mx_found,
        "smtp_valid": smtp_valid,
        "valid_email": valid_email
    }

# --------------------------------------------------
# INÍCIO DO CÓDIGO PRINCIPAL DE FLASK E ENVIO
# --------------------------------------------------

app = Flask(__name__)

# Configuração do CORS
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

# Chave secreta para Flask e JWT
app.secret_key = 'oaa3A5O24IfbsT-IxdMuOrnb-U2wHdGvjjVfkcSrcfA'

# Configurações do JWT
app.config['JWT_SECRET_KEY'] = 'krR8etmh1AcVb76G_NJkntEWZifilRRmiD1a5gA6Q1YEq1TgnZuxylJgKXzFwbBB'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)  
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

# ----------------- Handlers de erro do JWT -----------------
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'status': 'error',
        'error': 'Token expirado. Por favor, faça login novamente.'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'status': 'error',
        'error': f'Token inválido: {error}'
    }), 422

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'status': 'error',
        'error': 'Token de autorização não encontrado.'
    }), 401

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
# FUNÇÃO DE ENVIAR E-MAIL (agora com validação embutida)
# -------------------------------------------------------------------
def enviar_email(subject, body, to_email, user_id):
    """
    Retorna (success, error_message).
    Antes de enviar, valida se o e-mail é realmente válido.
    """
    # Primeiro, validamos o e-mail com a função de validação unificada
    validation_result = validate_email_address(to_email)
    if not validation_result['valid_email']:
        # Se for inválido, retornamos False com a razão
        return (False, f"Email inválido: {validation_result}")

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
# Tabela para LOG dos e-mails
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
# THREAD que envia e-mails, agora chamando a função que valida
#   e evitando interromper todo o processo se for só e-mail inválido.
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
        # Envia (e valida) o e-mail
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

        # --- Aqui está a lógica de continuar ou parar ---
        if not success:
            # Se for especificamente "Email inválido", continua para o próximo
            if error_message and "Email inválido" in error_message:
                print(f"E-mail inválido detectado ({to_email}). Pulando para o próximo.")
                # Não incrementamos progress porque foi falha, mas
                # se quiser contar falhas no progress, pode-se alterar
                continue
            else:
                # Caso seja falta de créditos, config incorreta, etc., paramos o disparo
                print("Interrompendo o envio por falha global (créditos, config, etc.).")
                break

        # Se deu certo, atualiza o progresso
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('UPDATE dispatch SET progress = %s, last_email = %s WHERE id = %s',
                  (idx + 1, to_email, dispatch_id))
        conn.commit()
        conn.close()

        # Aguarda 60 segundos se não for o último e-mail (ajuste se quiser)
        if idx < len(emails_list) - 1:
            time.sleep(60)

    # Marca o disparo como concluído (ou concluído com erros)
    final_status = 'concluído'
    if idx < len(emails_list) - 1:
        # Se paramos antes de mandar todos (por algum erro global)
        final_status = 'concluído_com_erros'

    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = %s WHERE id = %s', (final_status, dispatch_id))
    conn.commit()
    conn.close()

# -------------------------------------------------------------------
# INICIALIZAÇÃO DO BANCO (inclui tabela dispatch_email_log)
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

# -------------------------------------------------------------
# ROTA QUE VALIDA EMAIL (caso queira expor no seu sistema)
# -------------------------------------------------------------
@app.route("/validate-email", methods=["POST"])
def validate_email():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Requisição inválida. Informe um campo 'email'."}), 400

    email = data["email"]
    result = validate_email_address(email)
    return jsonify(result)

# -------------------------------------------------------------
# ROTA DE REGISTRO DE USUÁRIOS
# -------------------------------------------------------------
@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    role = request.form.get('role', 'user')

    if not email or not password or not confirm_password:
        return jsonify({'error': 'Por favor, preencha todos os campos.'}), 400
    if password != confirm_password:
        return jsonify({'error': 'As senhas não coincidem.'}), 400

    hashed_password = generate_password_hash(password)

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

# -------------------------------------------------------------
# ROTA DE LOGIN DE USUÁRIOS
# -------------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({'error': 'Por favor, preencha todos os campos.'}), 400

    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT id, email, password, role, credits FROM users WHERE email = %s', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            access_token = create_access_token(
                identity=str(user[0]),  # Convertendo para string
                additional_claims={
                    'email': user[1],
                    'role': user[3]
                }
            )
            print(f"Token gerado para usuário {user[1]}: {access_token}")
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
        print(f"Erro no login: {str(e)}")
        return jsonify({'error': f'Ocorreu um erro: {str(e)}'}), 500

# -------------------------------------------------------------
# ROTA PARA INICIAR O DISPARO
# -------------------------------------------------------------
@app.route('/start_dispatch', methods=['POST'])
@jwt_required()
def start_dispatch():
    current_user = get_jwt_identity()
    user_id = current_user

    subject = request.form.get('subject')
    email_body = request.form.get('email_body')
    from_name = request.form.get('from_name')
    uploaded_file = request.files.get('file')

    if not subject or not email_body or not uploaded_file or not from_name:
        return jsonify({'error': 'Dados incompletos.'}), 400

    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    file_path = os.path.join('uploads', uploaded_file.filename)
    uploaded_file.save(file_path)

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

    # Inicia a thread de envio
    threading.Thread(
        target=send_emails_thread,
        args=(emails_list, subject, email_body, dispatch_id, user_id)
    ).start()

    return jsonify({
        'message': 'Disparo iniciado com sucesso.',
        'total': total_emails,
        'dispatch_id': dispatch_id
    }), 200

# -------------------------------------------------------------
# Rota para obter o progresso do último disparo do usuário
# -------------------------------------------------------------
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

# -------------------------------------------------------------
# Rota para obter o progresso de um disparo específico
# -------------------------------------------------------------
@app.route('/dispatch/<int:dispatch_id>/progress', methods=['GET'])
@jwt_required()
def get_dispatch_progress(dispatch_id):
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT user_id FROM dispatch WHERE id = %s', (dispatch_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Disparo não encontrado.'}), 404
        
        owner_id = row[0]
        c.execute('SELECT role FROM users WHERE id = %s', (current_user_id,))
        user_role = c.fetchone()[0]

        if (str(owner_id) != str(current_user_id)) and (user_role != 'admin'):
            conn.close()
            return jsonify({'error': 'Acesso não autorizado.'}), 403
        
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

# -------------------------------------------------------------
# Rota para obter contagem de sucessos, erros e logs de erros
# -------------------------------------------------------------
@app.route('/dispatch/<int:dispatch_id>/results', methods=['GET'])
@jwt_required()
def get_dispatch_results(dispatch_id):
    current_user_id = get_jwt_identity()
    try:
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()

        c.execute('SELECT user_id FROM dispatch WHERE id = %s', (dispatch_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Disparo não encontrado.'}), 404
        
        owner_id = row[0]
        c.execute('SELECT role FROM users WHERE id = %s', (current_user_id,))
        user_role = c.fetchone()[0]

        if (str(owner_id) != str(current_user_id)) and (user_role != 'admin'):
            conn.close()
            return jsonify({'error': 'Acesso não autorizado.'}), 403
        
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

        c.execute('''
            SELECT email, error_message
            FROM dispatch_email_log
            WHERE dispatch_id = %s AND success = FALSE
        ''', (dispatch_id,))
        errors = c.fetchall()

        conn.close()

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

# -------------------------------------------------------------
# Rota para verificar o token
# -------------------------------------------------------------
@app.route('/check_token', methods=['GET'])
@jwt_required()
def check_token():
    try:
        current_user_id = get_jwt_identity()
        print(f"Token válido para o usuário ID: {current_user_id}")  
        print(f"Headers recebidos: {request.headers}")  
        print(f"Authorization header: {request.headers.get('Authorization')}")  

        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        c.execute('SELECT id, email, role FROM users WHERE id = %s', (int(current_user_id),))
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
            print(f"Resposta sendo enviada: {response_data}")
            return jsonify(response_data), 200
        else:
            print(f"Usuário não encontrado para ID: {current_user_id}")
            return jsonify({
                'status': 'error',
                'message': 'Usuário não encontrado'
            }), 404

    except Exception as e:
        print(f"Erro na verificação do token: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Erro ao verificar o token: {str(e)}'
        }), 500

# -------------------------------------------------------------
# Rota para obter saldo de créditos do usuário
# -------------------------------------------------------------
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

# -------------------------------------------------------------
# Rota para configurar o e-mail do usuário (SMTP, etc.)
# -------------------------------------------------------------
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

# -------------------------------------------------------------
# Rota para obter as configurações de e-mail do usuário
# -------------------------------------------------------------
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

# -------------------------------------------------------------
# ROTAS DE ADMINISTRAÇÃO PARA GERENCIAR CRÉDITOS
# -------------------------------------------------------------
@app.route('/admin/users', methods=['GET'])
@admin_required
def get_users():
    try:
        limit = request.args.get('limit', 10, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = psycopg2.connect(DATABASE_URL)
        c = conn.cursor()
        
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
        
        users_list = [{'id': user[0], 'email': user[1], 'credits': user[2]} for user in users]
        
        return jsonify(users_list), 200

    except psycopg2.Error as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return jsonify({'error': 'Erro interno do servidor.'}), 500
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return jsonify({'error': 'Ocorreu um erro inesperado.'}), 500

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

# -------------------------------------------------------------
# MAIN
# -------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
