import os
import sqlite3
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Configuração simples do banco de dados
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./securitia.db")

class SimpleDatabase:
    def __init__(self):
        self.db_path = "./securitia.db"
        self.init_tables()
    
    def init_tables(self):
        """Criar tabelas básicas"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabela de usuários
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabela de scans
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Inserir usuário admin padrão
            cursor.execute('''
                INSERT OR IGNORE INTO users (username, hashed_password, role)
                VALUES (?, ?, ?)
            ''', ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewQOPg.x1sxKX5uu', 'admin'))
            
            conn.commit()
            conn.close()
            logger.info("Banco de dados inicializado com sucesso!")
            
        except Exception as e:
            logger.error(f"Erro ao inicializar banco: {str(e)}")

# Função de inicialização
async def init_db():
    """Inicializar banco de dados"""
    db = SimpleDatabase()
    return db

# Funções auxiliares
def get_db():
    return SimpleDatabase()