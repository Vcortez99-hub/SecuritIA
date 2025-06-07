from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
import os
from dotenv import load_dotenv

load_dotenv()

# Configurações
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Contexto de criptografia
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthManager:
    def __init__(self):
        self.secret_key = SECRET_KEY
        self.algorithm = ALGORITHM
        self.token_expire_minutes = ACCESS_TOKEN_EXPIRE_MINUTES
        
        # Dados fictícios para desenvolvimento - senhas claras para teste
        self.fake_users_db = {
            "admin": {
                "username": "admin",
                "hashed_password": pwd_context.hash("admin123"),  # Senha: admin123
                "role": "admin",
                "email": "admin@securitia.com",
                "active": True
            },
            "user": {
                "username": "user", 
                "hashed_password": pwd_context.hash("user123"),   # Senha: user123
                "role": "user",
                "email": "user@securitia.com",
                "active": True
            },
            "test": {
                "username": "test",
                "hashed_password": pwd_context.hash("123456"),    # Senha: 123456
                "role": "user", 
                "email": "test@securitia.com",
                "active": True
            }
        }

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verificar senha"""
        try:
            result = pwd_context.verify(plain_password, hashed_password)
            print(f"[DEBUG] Verificando senha: {result}")  # Debug
            return result
        except Exception as e:
            print(f"[ERROR] Erro na verificação da senha: {e}")
            return False

    def get_password_hash(self, password: str) -> str:
        """Gerar hash da senha"""
        return pwd_context.hash(password)

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Criar token de acesso JWT"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.token_expire_minutes)
        
        to_encode.update({
            "exp": expire, 
            "iat": datetime.utcnow(),
            "sub": str(data.get("username"))  # Adicionar subject
        })
        
        try:
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            print(f"[DEBUG] Token criado com sucesso para: {data.get('username')}")
            return encoded_jwt
        except Exception as e:
            print(f"[ERROR] Erro ao criar token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erro interno do servidor ao criar token"
            )

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verificar e decodificar token JWT"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            print(f"[DEBUG] Token válido para: {payload.get('sub')}")
            return payload
        except jwt.ExpiredSignatureError:
            print("[DEBUG] Token expirado")
            return None
        except jwt.JWTError as e:
            print(f"[DEBUG] Token inválido: {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Erro inesperado na verificação do token: {e}")
            return None

    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Autenticar usuário"""
        print(f"[DEBUG] Tentativa de login para: {username}")
        
        # Verificar se usuário existe
        user = self.fake_users_db.get(username.lower())
        if not user:
            print(f"[DEBUG] Usuário '{username}' não encontrado")
            return None
        
        # Verificar se usuário está ativo
        if not user.get("active", True):
            print(f"[DEBUG] Usuário '{username}' está inativo")
            return None
        
        # Verificar senha
        if not self.verify_password(password, user["hashed_password"]):
            print(f"[DEBUG] Senha incorreta para usuário '{username}'")
            return None
        
        print(f"[DEBUG] Login bem-sucedido para: {username}")
        return {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "active": user["active"]
        }

    def get_current_user_from_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Obter usuário atual a partir do token"""
        payload = self.verify_token(token)
        if not payload:
            return None
        
        username = payload.get("sub") or payload.get("username")
        if not username:
            return None
        
        user = self.fake_users_db.get(username.lower())
        if not user or not user.get("active", True):
            return None
        
        return {
            "username": user["username"],
            "role": user["role"], 
            "email": user["email"],
            "active": user["active"]
        }

# Instância global
auth_manager = AuthManager()

# Funções auxiliares para compatibilidade
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    return auth_manager.create_access_token(data, expires_delta)

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    return auth_manager.verify_token(token)

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    return auth_manager.authenticate_user(username, password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return auth_manager.verify_password(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return auth_manager.get_password_hash(password)

def get_current_user_from_token(token: str) -> Optional[Dict[str, Any]]:
    return auth_manager.get_current_user_from_token(token)

# Para facilitar o teste, imprimir as credenciais disponíveis
if __name__ == "__main__":
    print("=== CREDENCIAIS DE TESTE ===")
    print("admin / admin123")
    print("user / user123") 
    print("test / 123456")
    print("===========================")