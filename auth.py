
import hashlib
import os
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, jsonify, redirect, url_for

class AuthManager:
    def __init__(self, users_file='users.json', sessions_file='sessions.json'):
        self.users_file = users_file
        self.sessions_file = sessions_file
        self.ensure_files_exist()
    
    def ensure_files_exist(self):
        """Garante que os arquivos de usuários e sessões existam"""
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump({}, f)
        
        if not os.path.exists(self.sessions_file):
            with open(self.sessions_file, 'w') as f:
                json.dump({}, f)
    
    def hash_password(self, password):
        """Hash da senha com salt"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}:{password_hash.hex()}"
    
    def verify_password(self, password, hashed_password):
        """Verifica se a senha está correta"""
        try:
            salt, password_hash = hashed_password.split(':')
            new_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return password_hash == new_hash.hex()
        except:
            return False
    
    def load_users(self):
        """Carrega usuários do arquivo"""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def save_users(self, users):
        """Salva usuários no arquivo"""
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=2, default=str)
    
    def load_sessions(self):
        """Carrega sessões do arquivo"""
        try:
            with open(self.sessions_file, 'r') as f:
                sessions = json.load(f)
                # Remove sessões expiradas
                current_time = datetime.now()
                valid_sessions = {}
                for session_id, session_data in sessions.items():
                    expires_at = datetime.fromisoformat(session_data['expires_at'])
                    if expires_at > current_time:
                        valid_sessions[session_id] = session_data
                
                if len(valid_sessions) != len(sessions):
                    self.save_sessions(valid_sessions)
                
                return valid_sessions
        except:
            return {}
    
    def save_sessions(self, sessions):
        """Salva sessões no arquivo"""
        with open(self.sessions_file, 'w') as f:
            json.dump(sessions, f, indent=2, default=str)
    
    def register_user(self, username, email, password, full_name=None):
        """Registra um novo usuário"""
        users = self.load_users()
        
        # Validações
        if not username or len(username) < 3:
            return {'success': False, 'error': 'Nome de usuário deve ter pelo menos 3 caracteres'}
        
        if not email or '@' not in email:
            return {'success': False, 'error': 'Email inválido'}
        
        if not password or len(password) < 6:
            return {'success': False, 'error': 'Senha deve ter pelo menos 6 caracteres'}
        
        # Verifica se usuário já existe
        if username in users:
            return {'success': False, 'error': 'Nome de usuário já existe'}
        
        # Verifica se email já existe
        for user_data in users.values():
            if user_data.get('email') == email:
                return {'success': False, 'error': 'Email já está em uso'}
        
        # Cria novo usuário
        users[username] = {
            'email': email,
            'password': self.hash_password(password),
            'full_name': full_name or username,
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'is_active': True
        }
        
        self.save_users(users)
        
        return {'success': True, 'message': 'Usuário registrado com sucesso'}
    
    def login_user(self, username, password):
        """Autentica um usuário"""
        users = self.load_users()
        
        if username not in users:
            return {'success': False, 'error': 'Usuário não encontrado'}
        
        user_data = users[username]
        
        if not user_data.get('is_active', True):
            return {'success': False, 'error': 'Conta desativada'}
        
        if not self.verify_password(password, user_data['password']):
            return {'success': False, 'error': 'Senha incorreta'}
        
        # Cria sessão
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=7)  # Sessão válida por 7 dias
        
        sessions = self.load_sessions()
        sessions[session_id] = {
            'username': username,
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat(),
            'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
            'user_agent': request.environ.get('HTTP_USER_AGENT', '')
        }
        
        self.save_sessions(sessions)
        
        # Atualiza último login
        users[username]['last_login'] = datetime.now().isoformat()
        self.save_users(users)
        
        # Define sessão no Flask
        session['session_id'] = session_id
        session['username'] = username
        session['logged_in'] = True
        
        return {
            'success': True,
            'message': 'Login realizado com sucesso',
            'user': {
                'username': username,
                'email': user_data['email'],
                'full_name': user_data['full_name']
            }
        }
    
    def logout_user(self):
        """Faz logout do usuário"""
        session_id = session.get('session_id')
        
        if session_id:
            sessions = self.load_sessions()
            if session_id in sessions:
                del sessions[session_id]
                self.save_sessions(sessions)
        
        session.clear()
        return {'success': True, 'message': 'Logout realizado com sucesso'}
    
    def get_current_user(self):
        """Retorna dados do usuário atual"""
        if not session.get('logged_in'):
            return None
        
        session_id = session.get('session_id')
        username = session.get('username')
        
        if not session_id or not username:
            return None
        
        # Verifica se sessão ainda é válida
        sessions = self.load_sessions()
        if session_id not in sessions:
            session.clear()
            return None
        
        session_data = sessions[session_id]
        if session_data['username'] != username:
            session.clear()
            return None
        
        # Busca dados do usuário
        users = self.load_users()
        if username not in users:
            session.clear()
            return None
        
        user_data = users[username]
        return {
            'username': username,
            'email': user_data['email'],
            'full_name': user_data['full_name'],
            'last_login': user_data.get('last_login'),
            'created_at': user_data.get('created_at')
        }
    
    def is_authenticated(self):
        """Verifica se usuário está autenticado"""
        return self.get_current_user() is not None
    
    def change_password(self, username, old_password, new_password):
        """Altera senha do usuário"""
        users = self.load_users()
        
        if username not in users:
            return {'success': False, 'error': 'Usuário não encontrado'}
        
        user_data = users[username]
        
        if not self.verify_password(old_password, user_data['password']):
            return {'success': False, 'error': 'Senha atual incorreta'}
        
        if len(new_password) < 6:
            return {'success': False, 'error': 'Nova senha deve ter pelo menos 6 caracteres'}
        
        users[username]['password'] = self.hash_password(new_password)
        self.save_users(users)
        
        return {'success': True, 'message': 'Senha alterada com sucesso'}

# Instância global do gerenciador de autenticação
auth_manager = AuthManager()

def login_required(f):
    """Decorator que exige autenticação"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not auth_manager.is_authenticated():
            if request.is_json:
                return jsonify({'success': False, 'error': 'Autenticação necessária'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function
