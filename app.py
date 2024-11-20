from flask import Flask, request, jsonify
import threading
import time
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sqlite3
import os
from flask_cors import CORS  # Importante para lidar com CORS

app = Flask(__name__)
CORS(app)  # Habilita CORS para todas as rotas

# Definir o caminho absoluto para o banco de dados
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')

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
def send_emails_thread(emails_list, subject, body, from_email, from_name, password, total_emails):
    # Atualiza o status do disparo no banco de dados
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = ?, progress = ?, last_email = ? WHERE id = ?', ('executando', 0, '', 1))
    conn.commit()
    conn.close()
    for idx, to_email in enumerate(emails_list):
        # Envia o e-mail
        enviar_email(subject, body, to_email, from_email, from_name, password)
        # Atualiza o progresso no banco de dados
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE dispatch SET progress = ?, last_email = ? WHERE id = ?', (idx+1, to_email, 1))
        conn.commit()
        conn.close()
        # Aguarda 60 segundos se não for o último e-mail
        if idx < len(emails_list) - 1:
            time.sleep(60)
    # Marca o disparo como concluído
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE dispatch SET status = ? WHERE id = ?', ('concluído', 1))
    # Libera o lock
    c.execute('UPDATE lock SET locked = 0 WHERE id = 1')
    conn.commit()
    conn.close()

# Inicializa o banco de dados
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS dispatch (
                id INTEGER PRIMARY KEY,
                status TEXT,
                progress INTEGER,
                total INTEGER,
                last_email TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS lock (
                id INTEGER PRIMARY KEY,
                locked INTEGER
            )
        ''')
        c.execute('INSERT OR IGNORE INTO lock (id, locked) VALUES (1, 0)')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao inicializar o banco de dados: {e}")

# Função para verificar as tabelas no banco de dados (opcional)
def check_tables():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = c.fetchall()
    conn.close()
    print(f"Tabelas no banco de dados: {tables}")

# Chama a inicialização do banco de dados
init_db()
# Verifica as tabelas (opcional)
# check_tables()

@app.route('/start_dispatch', methods=['POST'])
def start_dispatch():
    # Verifica se um disparo já está em execução
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT locked FROM lock WHERE id = 1')
    locked = c.fetchone()[0]
    if locked:
        conn.close()
        return jsonify({'error': 'Outro disparo está em execução. Por favor, aguarde até que seja concluído.'}), 400
    else:
        # Obtém os dados do request
        data = request.form
        subject = data.get('subject')
        email_body = data.get('email_body')
        uploaded_file = request.files.get('file')

        if not subject or not email_body or not uploaded_file:
            conn.close()
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
            conn.close()
            return jsonify({'error': 'Nenhum e-mail encontrado na planilha.'}), 400

        # Atualiza o status do disparo no banco de dados
        c.execute('DELETE FROM dispatch WHERE id = 1')
        c.execute('INSERT INTO dispatch (id, status, progress, total, last_email) VALUES (1, ?, ?, ?, ?)', ('pendente', 0, total_emails, ''))
        # Bloqueia novos disparos
        c.execute('UPDATE lock SET locked = 1 WHERE id = 1')
        conn.commit()
        conn.close()

        # Inicia a thread de envio de e-mails
        from_email = 'aviso@condutor-govbr.blog'
        from_name = 'Gov'
        password = 'Batata135-'  # Utilize variáveis de ambiente ou um método seguro de armazenar senhas

        threading.Thread(target=send_emails_thread, args=(emails_list, subject, email_body, from_email, from_name, password, total_emails)).start()

        return jsonify({'message': 'Disparo iniciado com sucesso.'}), 200

@app.route('/progress', methods=['GET'])
def get_progress():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT status, progress, total, last_email FROM dispatch WHERE id = 1')
    result = c.fetchone()
    conn.close()
    if result:
        status, progress, total, last_email = result
        return jsonify({
            'status': status,
            'progress': progress,
            'total': total,
            'last_email': last_email
        })
    else:
        return jsonify({'status': 'nenhum_disparo'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
