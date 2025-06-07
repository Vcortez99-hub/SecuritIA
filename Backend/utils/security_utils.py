import re
import ipaddress
import socket
import ssl
import hashlib
import secrets
import base64
import logging
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urlparse
import dns.resolver
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bcrypt
import jwt
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecurityUtils:
    """Utilitários de segurança para validação e verificação"""
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], severity: str = 'INFO'):
        """Registrar evento de segurança"""
        try:
            security_log = {
                'timestamp': datetime.utcnow().isoformat(),
                'event_type': event_type,
                'severity': severity,
                'details': details,
                'source': 'security_utils'
            }
            
            # Log do evento
            log_message = f"Security Event [{severity}]: {event_type} - {details}"
            
            if severity == 'CRITICAL':
                logger.critical(log_message)
            elif severity == 'ERROR':
                logger.error(log_message)
            elif severity == 'WARNING':
                logger.warning(log_message)
            else:
                logger.info(log_message)
            
            # Aqui você pode adicionar envio para SIEM, alertas, etc.
            
        except Exception as e:
            logger.error(f"Erro no log de evento de segurança: {str(e)}")
    
    @staticmethod
    def check_ip_reputation(ip: str, reputation_services: List[str] = None) -> Dict[str, Any]:
        """Verificar reputação de IP"""
        reputation = {
            'ip': ip,
            'is_malicious': False,
            'reputation_score': 0.0,
            'sources': [],
            'details': {}
        }
        
        try:
            # Lista de IPs conhecidamente maliciosos (exemplo)
            known_malicious = [
                '192.168.1.100',  # Exemplo
                '10.0.0.100'      # Exemplo
            ]
            
            if ip in known_malicious:
                reputation['is_malicious'] = True
                reputation['reputation_score'] = 1.0
                reputation['sources'].append('local_blacklist')
            
            # Verificar se é IP privado
            if SecurityUtils.is_private_ip(ip):
                reputation['details']['is_private'] = True
            
            # Aqui você pode integrar com serviços reais como:
            # - VirusTotal
            # - AbuseIPDB
            # - IBM X-Force
            # - Shodan
            
        except Exception as e:
            logger.error(f"Erro na verificação de reputação: {str(e)}")
        
        return reputation
    
    @staticmethod
    def check_domain_reputation(domain: str) -> Dict[str, Any]:
        """Verificar reputação de domínio"""
        reputation = {
            'domain': domain,
            'is_malicious': False,
            'reputation_score': 0.0,
            'categories': [],
            'details': {}
        }
        
        try:
            # Verificar se é domínio suspeito
            suspicious_tlds = [
                '.tk', '.ml', '.ga', '.cf'  # TLDs frequentemente usados para phishing
            ]
            
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    reputation['reputation_score'] += 0.3
                    reputation['categories'].append('suspicious_tld')
            
            # Verificar padrões suspeitos no nome
            suspicious_patterns = [
                r'[0-9]{5,}',  # Muitos números
                r'[a-z]{20,}',  # String muito longa
                r'(paypal|amazon|google|microsoft).*[0-9]',  # Imitação de marcas
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, domain.lower()):
                    reputation['reputation_score'] += 0.2
                    reputation['categories'].append('suspicious_pattern')
            
            # Verificar se domain é muito novo (seria necessário integração com whois)
            
            if reputation['reputation_score'] >= 0.7:
                reputation['is_malicious'] = True
            
        except Exception as e:
            logger.error(f"Erro na verificação de reputação do domínio: {str(e)}")
        
        return reputation
    
    @staticmethod
    def create_security_headers() -> Dict[str, str]:
        """Criar headers de segurança para HTTP"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
    
    @staticmethod
    def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
        """Mascarar dados sensíveis"""
        try:
            if not data or len(data) <= visible_chars:
                return mask_char * len(data) if data else ''
            
            visible_part = data[-visible_chars:]
            masked_part = mask_char * (len(data) - visible_chars)
            
            return masked_part + visible_part
            
        except Exception:
            return mask_char * 8
    
    @staticmethod
    def generate_csrf_token() -> str:
        """Gerar token CSRF"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_csrf_token(token: str, session_token: str) -> bool:
        """Validar token CSRF"""
        try:
            return secrets.compare_digest(token, session_token)
        except Exception:
            return False
    
    @staticmethod
    def clean_html_input(html_content: str) -> str:
        """Limpar conteúdo HTML de elementos perigosos"""
        try:
            # Lista de tags permitidas
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li']
            
            # Remover scripts
            html_content = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', html_content, flags=re.IGNORECASE)
            
            # Remover eventos JavaScript
            html_content = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
            
            # Remover javascript: URLs
            html_content = re.sub(r'javascript:', '', html_content, flags=re.IGNORECASE)
            
            # Remover tags não permitidas (implementação básica)
            # Em produção, use uma biblioteca como bleach
            
            return html_content
            
        except Exception as e:
            logger.error(f"Erro na limpeza de HTML: {str(e)}")
            return ""
    
    @staticmethod
    def check_suspicious_user_agent(user_agent: str) -> bool:
        """Verificar se User-Agent é suspeito"""
        if not user_agent:
            return True
        
        suspicious_patterns = [
            r'bot',
            r'crawler',
            r'spider',
            r'scraper',
            r'curl',
            r'wget',
            r'python',
            r'java',
            r'sqlmap',
            r'nikto',
            r'nessus'
        ]
        
        user_agent_lower = user_agent.lower()
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent_lower):
                return True
        
        return False
    
    @staticmethod
    def generate_api_key(prefix: str = 'sk', length: int = 32) -> str:
        """Gerar chave de API"""
        random_part = secrets.token_urlsafe(length)
        return f"{prefix}_{random_part}"
    
    @staticmethod
    def validate_api_key_format(api_key: str) -> bool:
        """Validar formato de chave de API"""
        try:
            # Formato esperado: prefix_randomstring
            if '_' not in api_key:
                return False
            
            prefix, key_part = api_key.split('_', 1)
            
            # Verificar se prefix é válido
            if len(prefix) < 2 or len(prefix) > 10:
                return False
            
            # Verificar se parte aleatória tem tamanho adequado
            if len(key_part) < 20:
                return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def create_audit_log_entry(action: str, user_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Criar entrada de log de auditoria"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'user_id': user_id,
            'details': details,
            'ip_address': details.get('ip_address', 'unknown'),
            'user_agent': details.get('user_agent', 'unknown'),
            'session_id': details.get('session_id', 'unknown')
        }
    
    @staticmethod
    def detect_brute_force_attempt(failed_attempts: List[datetime], threshold: int = 5, window_minutes: int = 15) -> bool:
        """Detectar tentativa de força bruta"""
        try:
            if len(failed_attempts) < threshold:
                return False
            
            # Verificar se há muitas tentativas no período
            now = datetime.utcnow()
            cutoff_time = now - timedelta(minutes=window_minutes)
            
            recent_attempts = [attempt for attempt in failed_attempts if attempt > cutoff_time]
            
            return len(recent_attempts) >= threshold
            
        except Exception:
            return False
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calcular entropia de uma string"""
        try:
            import math
            from collections import Counter
            
            if not data:
                return 0.0
            
            # Contar frequência de caracteres
            char_counts = Counter(data)
            data_length = len(data)
            
            # Calcular entropia
            entropy = 0.0
            for count in char_counts.values():
                probability = count / data_length
                entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception:
            return 0.0
    
    @staticmethod
    def is_base64_encoded(data: str) -> bool:
        """Verificar se string está codificada em Base64"""
        try:
            # Verificar formato
            if len(data) % 4 != 0:
                return False
            
            base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}staticmethod
    def validate_target(target: str) -> bool:
        """Validar se o target é válido e seguro"""
        try:
            # Verificar se não está vazio
            if not target or not target.strip():
                return False
            
            target = target.strip()
            
            # Verificar se é IP válido
            if SecurityUtils.is_valid_ip(target):
                # Verificar se não é IP privado/interno
                return not SecurityUtils.is_private_ip(target)
            
            # Verificar se é domínio válido
            if SecurityUtils.is_valid_domain(target):
                # Verificar se não é domínio local/interno
                return not SecurityUtils.is_internal_domain(target)
            
            return False
            
        except Exception as e:
            logger.error(f"Erro na validação do target: {str(e)}")
            return False
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Verificar se é um IP válido"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Verificar se é um IP privado"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Verificar se é um domínio válido"""
        try:
            # Regex para domínio válido
            domain_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            
            if not domain_pattern.match(domain):
                return False
            
            # Verificar se tem pelo menos um ponto
            if '.' not in domain:
                return False
            
            # Verificar se as partes não são muito longas
            parts = domain.split('.')
            for part in parts:
                if len(part) > 63:
                    return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def is_internal_domain(domain: str) -> bool:
        """Verificar se é um domínio interno"""
        internal_domains = [
            'localhost',
            'local',
            'internal',
            'corp',
            'lan',
            'intranet'
        ]
        
        domain_lower = domain.lower()
        
        # Verificar domínios exatos
        if domain_lower in internal_domains:
            return True
        
        # Verificar subdomínios
        for internal in internal_domains:
            if domain_lower.endswith(f'.{internal}'):
                return True
        
        return False
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitizar entrada do usuário"""
        if not input_string:
            return ""
        
        # Limitar tamanho
        sanitized = input_string[:max_length]
        
        # Remover caracteres perigosos
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remover múltiplos espaços
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validar formato de email"""
        try:
            email_pattern = re.compile(
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            )
            return bool(email_pattern.match(email))
        except Exception:
            return False
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validar formato de URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def check_sql_injection_patterns(input_string: str) -> bool:
        """Verificar padrões de SQL injection"""
        if not input_string:
            return False
        
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"('|\"|`).*(OR|AND).*(=|<|>)",
            r"(;|\||&)",
            r"(-{2}|/\*|\*/)",
            r"(\bEXEC\b|\bEXECUTE\b)",
            r"(\bSP_\w+)",
            r"(\bXP_\w+)"
        ]
        
        input_upper = input_string.upper()
        
        for pattern in sql_patterns:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def check_xss_patterns(input_string: str) -> bool:
        """Verificar padrões de XSS"""
        if not input_string:
            return False
        
        xss_patterns = [
            r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"<iframe\b",
            r"<object\b",
            r"<embed\b"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Gerar token seguro"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Gerar hash de senha usando bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verificar senha contra hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> Dict[str, str]:
        """Criptografar dados usando Fernet"""
        try:
            if key is None:
                key = Fernet.generate_key()
            
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            
            return {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'key': base64.b64encode(key).decode()
            }
        except Exception as e:
            logger.error(f"Erro na criptografia: {str(e)}")
            return {}
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: str) -> Optional[str]:
        """Descriptografar dados"""
        try:
            key_bytes = base64.b64decode(key.encode())
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            
            fernet = Fernet(key_bytes)
            decrypted_data = fernet.decrypt(encrypted_bytes)
            
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Erro na descriptografia: {str(e)}")
            return None
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Dict[str, str]:
        """Gerar par de chaves RSA"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            public_key = private_key.public_key()
            
            # Serializar chaves
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'private_key': private_pem.decode(),
                'public_key': public_pem.decode()
            }
        except Exception as e:
            logger.error(f"Erro na geração de chaves RSA: {str(e)}")
            return {}
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calcular hash de arquivo"""
        try:
            hash_algorithms = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha256': hashlib.sha256(),
                'sha512': hashlib.sha512()
            }
            
            if algorithm not in hash_algorithms:
                return None
            
            hasher = hash_algorithms[algorithm]
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Erro no cálculo de hash: {str(e)}")
            return None
    
    @staticmethod
    def validate_jwt_token(token: str, secret: str) -> Optional[Dict[str, Any]]:
        """Validar token JWT"""
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token JWT expirado")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Token JWT inválido")
            return None
    
    @staticmethod
    def create_jwt_token(payload: Dict[str, Any], secret: str, expires_in: int = 3600) -> str:
        """Criar token JWT"""
        try:
            payload['exp'] = datetime.utcnow() + timedelta(seconds=expires_in)
            payload['iat'] = datetime.utcnow()
            
            token = jwt.encode(payload, secret, algorithm='HS256')
            return token
        except Exception as e:
            logger.error(f"Erro na criação do token JWT: {str(e)}")
            return ""
    
    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Verificar força da senha"""
        strength = {
            'score': 0,
            'issues': [],
            'suggestions': []
        }
        
        # Verificar comprimento
        if len(password) >= 12:
            strength['score'] += 2
        elif len(password) >= 8:
            strength['score'] += 1
        else:
            strength['issues'].append('Senha muito curta')
            strength['suggestions'].append('Use pelo menos 8 caracteres')
        
        # Verificar caracteres
        if re.search(r'[a-z]', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta letra minúscula')
            strength['suggestions'].append('Inclua letras minúsculas')
        
        if re.search(r'[A-Z]', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta letra maiúscula')
            strength['suggestions'].append('Inclua letras maiúsculas')
        
        if re.search(r'\d', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta número')
            strength['suggestions'].append('Inclua números')
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta caractere especial')
            strength['suggestions'].append('Inclua caracteres especiais')
        
        # Verificar padrões comuns
        common_patterns = [
            r'123456',
            r'password',
            r'qwerty',
            r'abc123'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                strength['score'] -= 2
                strength['issues'].append('Contém padrão comum')
                strength['suggestions'].append('Evite sequências óbvias')
                break
        
        # Normalizar score
        strength['score'] = max(0, min(strength['score'], 5))
        
        # Classificar força
        if strength['score'] >= 4:
            strength['level'] = 'strong'
        elif strength['score'] >= 2:
            strength['level'] = 'medium'
        else:
            strength['level'] = 'weak'
        
        return strength
    
    @staticmethod
    def rate_limit_check(identifier: str, limit: int, window: int, redis_client=None) -> bool:
        """Verificar rate limiting"""
        try:
            if not redis_client:
                # Implementação em memória simples (não persistente)
                import time
                current_time = int(time.time())
                
                # Esta é uma implementação simplificada
                # Em produção, use Redis ou banco de dados
                return True
            
            # Implementação com Redis
            key = f"rate_limit:{identifier}"
            current_time = int(time.time())
            window_start = current_time - window
            
            # Remover entradas antigas
            redis_client.zremrangebyscore(key, 0, window_start)
            
            # Contar requests no window atual
            current_requests = redis_client.zcard(key)
            
            if current_requests >= limit:
                return False
            
            # Adicionar request atual
            redis_client.zadd(key, {str(current_time): current_time})
            redis_client.expire(key, window)
            
            return True
            
        except Exception as e:
            logger.error(f"Erro no rate limiting: {str(e)}")
            return True  # Em caso de erro, permitir request
    
    @staticmethod
    def validate_file_upload(file_data: bytes, allowed_types: List[str], max_size: int) -> Dict[str, Any]:
        """Validar upload de arquivo"""
        validation = {
            'valid': False,
            'issues': [],
            'file_info': {}
        }
        
        try:
            # Verificar tamanho
            file_size = len(file_data)
            validation['file_info']['size'] = file_size
            
            if file_size > max_size:
                validation['issues'].append(f'Arquivo muito grande: {file_size} bytes')
                return validation
            
            # Verificar tipo de arquivo pelos magic bytes
            file_type = SecurityUtils.detect_file_type(file_data)
            validation['file_info']['detected_type'] = file_type
            
            if file_type not in allowed_types:
                validation['issues'].append(f'Tipo de arquivo não permitido: {file_type}')
                return validation
            
            # Verificar se não é arquivo malicioso
            if SecurityUtils.scan_for_malicious_patterns(file_data):
                validation['issues'].append('Padrões suspeitos detectados no arquivo')
                return validation
            
            validation['valid'] = True
            
        except Exception as e:
            validation['issues'].append(f'Erro na validação: {str(e)}')
        
        return validation
    
    @staticmethod
    def detect_file_type(file_data: bytes) -> str:
        """Detectar tipo de arquivo pelos magic bytes"""
        if not file_data:
            return 'unknown'
        
        magic_signatures = {
            b'\x89PNG\r\n\x1a\n': 'png',
            b'\xff\xd8\xff': 'jpg',
            b'GIF87a': 'gif',
            b'GIF89a': 'gif',
            b'%PDF': 'pdf',
            b'PK\x03\x04': 'zip',
            b'\x50\x4b\x03\x04': 'zip',
            b'\x1f\x8b\x08': 'gz',
            b'BM': 'bmp',
            b'RIFF': 'wav'  # ou webp, precisa verificar mais bytes
        }
        
        for signature, file_type in magic_signatures.items():
            if file_data.startswith(signature):
                return file_type
        
        return 'unknown'
    
    @staticmethod
    def scan_for_malicious_patterns(file_data: bytes) -> bool:
        """Verificar padrões maliciosos em arquivos"""
        try:
            # Converter para string para análise de padrões
            try:
                content = file_data.decode('utf-8', errors='ignore')
            except:
                content = str(file_data)
            
            malicious_patterns = [
                r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
                r'javascript:',
                r'vbscript:',
                r'eval\s*\(',
                r'document\.write',
                r'window\.location',
                r'\.htaccess',
                r'passwd',
                r'shadow',
                r'SELECT.*FROM',
                r'INSERT.*INTO',
                r'DELETE.*FROM',
                r'DROP.*TABLE'
            ]
            
            for pattern in malicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro na verificação de padrões maliciosos: {str(e)}")
            return False
    
    @staticmethod
    def generate_secure_filename(original_filename: str) -> str:
        """Gerar nome de arquivo seguro"""
        try:
            # Remover caminho
            filename = os.path.basename(original_filename)
            
            # Remover caracteres perigosos
            safe_chars = re.sub(r'[^a-zA-Z0-9.-]', '_', filename)
            
            # Limitar tamanho
            if len(safe_chars) > 100:
                name, ext = os.path.splitext(safe_chars)
                safe_chars = name[:90] + ext
            
            # Adicionar timestamp para unicidade
            timestamp = str(int(time.time()))
            name, ext = os.path.splitext(safe_chars)
            
            return f"{name}_{timestamp}{ext}"
            
        except Exception:
            return f"file_{int(time.time())}.dat"
    
    @)
            if not base64_pattern.match(data):
                return False
            
            # Tentar decodificar
            base64.b64decode(data)
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def extract_urls_from_text(text: str) -> List[str]:
        """Extrair URLs de texto"""
        try:
            url_pattern = re.compile(
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            )
            
            return url_pattern.findall(text)
            
        except Exception:
            return []
    
    @staticmethod
    def check_weak_ssl_ciphers(hostname: str, port: int = 443) -> Dict[str, Any]:
        """Verificar cifras SSL fracas"""
        result = {
            'hostname': hostname,
            'port': port,
            'weak_ciphers': [],
            'strong_ciphers': [],
            'ssl_version': None,
            'certificate_info': {}
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result['ssl_version'] = ssock.version()
                    
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Verificar se é cifra fraca
                        weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
                        if any(weak in cipher_name for weak in weak_patterns):
                            result['weak_ciphers'].append(cipher_name)
                        else:
                            result['strong_ciphers'].append(cipher_name)
                    
                    # Informações do certificado
                    cert = ssock.getpeercert()
                    if cert:
                        result['certificate_info'] = {
                            'subject': cert.get('subject'),
                            'issuer': cert.get('issuer'),
                            'not_after': cert.get('notAfter'),
                            'not_before': cert.get('notBefore')
                        }
        
        except Exception as e:
            result['error'] = str(e)
        
        return resultstaticmethod
    def validate_target(target: str) -> bool:
        """Validar se o target é válido e seguro"""
        try:
            # Verificar se não está vazio
            if not target or not target.strip():
                return False
            
            target = target.strip()
            
            # Verificar se é IP válido
            if SecurityUtils.is_valid_ip(target):
                # Verificar se não é IP privado/interno
                return not SecurityUtils.is_private_ip(target)
            
            # Verificar se é domínio válido
            if SecurityUtils.is_valid_domain(target):
                # Verificar se não é domínio local/interno
                return not SecurityUtils.is_internal_domain(target)
            
            return False
            
        except Exception as e:
            logger.error(f"Erro na validação do target: {str(e)}")
            return False
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Verificar se é um IP válido"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Verificar se é um IP privado"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Verificar se é um domínio válido"""
        try:
            # Regex para domínio válido
            domain_pattern = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            
            if not domain_pattern.match(domain):
                return False
            
            # Verificar se tem pelo menos um ponto
            if '.' not in domain:
                return False
            
            # Verificar se as partes não são muito longas
            parts = domain.split('.')
            for part in parts:
                if len(part) > 63:
                    return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def is_internal_domain(domain: str) -> bool:
        """Verificar se é um domínio interno"""
        internal_domains = [
            'localhost',
            'local',
            'internal',
            'corp',
            'lan',
            'intranet'
        ]
        
        domain_lower = domain.lower()
        
        # Verificar domínios exatos
        if domain_lower in internal_domains:
            return True
        
        # Verificar subdomínios
        for internal in internal_domains:
            if domain_lower.endswith(f'.{internal}'):
                return True
        
        return False
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitizar entrada do usuário"""
        if not input_string:
            return ""
        
        # Limitar tamanho
        sanitized = input_string[:max_length]
        
        # Remover caracteres perigosos
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r', '\n']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remover múltiplos espaços
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validar formato de email"""
        try:
            email_pattern = re.compile(
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            )
            return bool(email_pattern.match(email))
        except Exception:
            return False
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validar formato de URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def check_sql_injection_patterns(input_string: str) -> bool:
        """Verificar padrões de SQL injection"""
        if not input_string:
            return False
        
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"('|\"|`).*(OR|AND).*(=|<|>)",
            r"(;|\||&)",
            r"(-{2}|/\*|\*/)",
            r"(\bEXEC\b|\bEXECUTE\b)",
            r"(\bSP_\w+)",
            r"(\bXP_\w+)"
        ]
        
        input_upper = input_string.upper()
        
        for pattern in sql_patterns:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def check_xss_patterns(input_string: str) -> bool:
        """Verificar padrões de XSS"""
        if not input_string:
            return False
        
        xss_patterns = [
            r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"<iframe\b",
            r"<object\b",
            r"<embed\b"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Gerar token seguro"""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Gerar hash de senha usando bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verificar senha contra hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> Dict[str, str]:
        """Criptografar dados usando Fernet"""
        try:
            if key is None:
                key = Fernet.generate_key()
            
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            
            return {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'key': base64.b64encode(key).decode()
            }
        except Exception as e:
            logger.error(f"Erro na criptografia: {str(e)}")
            return {}
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: str) -> Optional[str]:
        """Descriptografar dados"""
        try:
            key_bytes = base64.b64decode(key.encode())
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            
            fernet = Fernet(key_bytes)
            decrypted_data = fernet.decrypt(encrypted_bytes)
            
            return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Erro na descriptografia: {str(e)}")
            return None
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Dict[str, str]:
        """Gerar par de chaves RSA"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            public_key = private_key.public_key()
            
            # Serializar chaves
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'private_key': private_pem.decode(),
                'public_key': public_pem.decode()
            }
        except Exception as e:
            logger.error(f"Erro na geração de chaves RSA: {str(e)}")
            return {}
    
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calcular hash de arquivo"""
        try:
            hash_algorithms = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha256': hashlib.sha256(),
                'sha512': hashlib.sha512()
            }
            
            if algorithm not in hash_algorithms:
                return None
            
            hasher = hash_algorithms[algorithm]
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Erro no cálculo de hash: {str(e)}")
            return None
    
    @staticmethod
    def validate_jwt_token(token: str, secret: str) -> Optional[Dict[str, Any]]:
        """Validar token JWT"""
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token JWT expirado")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Token JWT inválido")
            return None
    
    @staticmethod
    def create_jwt_token(payload: Dict[str, Any], secret: str, expires_in: int = 3600) -> str:
        """Criar token JWT"""
        try:
            payload['exp'] = datetime.utcnow() + timedelta(seconds=expires_in)
            payload['iat'] = datetime.utcnow()
            
            token = jwt.encode(payload, secret, algorithm='HS256')
            return token
        except Exception as e:
            logger.error(f"Erro na criação do token JWT: {str(e)}")
            return ""
    
    @staticmethod
    def check_password_strength(password: str) -> Dict[str, Any]:
        """Verificar força da senha"""
        strength = {
            'score': 0,
            'issues': [],
            'suggestions': []
        }
        
        # Verificar comprimento
        if len(password) >= 12:
            strength['score'] += 2
        elif len(password) >= 8:
            strength['score'] += 1
        else:
            strength['issues'].append('Senha muito curta')
            strength['suggestions'].append('Use pelo menos 8 caracteres')
        
        # Verificar caracteres
        if re.search(r'[a-z]', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta letra minúscula')
            strength['suggestions'].append('Inclua letras minúsculas')
        
        if re.search(r'[A-Z]', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta letra maiúscula')
            strength['suggestions'].append('Inclua letras maiúsculas')
        
        if re.search(r'\d', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta número')
            strength['suggestions'].append('Inclua números')
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            strength['score'] += 1
        else:
            strength['issues'].append('Falta caractere especial')
            strength['suggestions'].append('Inclua caracteres especiais')
        
        # Verificar padrões comuns
        common_patterns = [
            r'123456',
            r'password',
            r'qwerty',
            r'abc123'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                strength['score'] -= 2
                strength['issues'].append('Contém padrão comum')
                strength['suggestions'].append('Evite sequências óbvias')
                break
        
        # Normalizar score
        strength['score'] = max(0, min(strength['score'], 5))
        
        # Classificar força
        if strength['score'] >= 4:
            strength['level'] = 'strong'
        elif strength['score'] >= 2:
            strength['level'] = 'medium'
        else:
            strength['level'] = 'weak'
        
        return strength
    
    @staticmethod
    def rate_limit_check(identifier: str, limit: int, window: int, redis_client=None) -> bool:
        """Verificar rate limiting"""
        try:
            if not redis_client:
                # Implementação em memória simples (não persistente)
                import time
                current_time = int(time.time())
                
                # Esta é uma implementação simplificada
                # Em produção, use Redis ou banco de dados
                return True
            
            # Implementação com Redis
            key = f"rate_limit:{identifier}"
            current_time = int(time.time())
            window_start = current_time - window
            
            # Remover entradas antigas
            redis_client.zremrangebyscore(key, 0, window_start)
            
            # Contar requests no window atual
            current_requests = redis_client.zcard(key)
            
            if current_requests >= limit:
                return False
            
            # Adicionar request atual
            redis_client.zadd(key, {str(current_time): current_time})
            redis_client.expire(key, window)
            
            return True
            
        except Exception as e:
            logger.error(f"Erro no rate limiting: {str(e)}")
            return True  # Em caso de erro, permitir request
    
    @staticmethod
    def validate_file_upload(file_data: bytes, allowed_types: List[str], max_size: int) -> Dict[str, Any]:
        """Validar upload de arquivo"""
        validation = {
            'valid': False,
            'issues': [],
            'file_info': {}
        }
        
        try:
            # Verificar tamanho
            file_size = len(file_data)
            validation['file_info']['size'] = file_size
            
            if file_size > max_size:
                validation['issues'].append(f'Arquivo muito grande: {file_size} bytes')
                return validation
            
            # Verificar tipo de arquivo pelos magic bytes
            file_type = SecurityUtils.detect_file_type(file_data)
            validation['file_info']['detected_type'] = file_type
            
            if file_type not in allowed_types:
                validation['issues'].append(f'Tipo de arquivo não permitido: {file_type}')
                return validation
            
            # Verificar se não é arquivo malicioso
            if SecurityUtils.scan_for_malicious_patterns(file_data):
                validation['issues'].append('Padrões suspeitos detectados no arquivo')
                return validation
            
            validation['valid'] = True
            
        except Exception as e:
            validation['issues'].append(f'Erro na validação: {str(e)}')
        
        return validation
    
    @staticmethod
    def detect_file_type(file_data: bytes) -> str:
        """Detectar tipo de arquivo pelos magic bytes"""
        if not file_data:
            return 'unknown'
        
        magic_signatures = {
            b'\x89PNG\r\n\x1a\n': 'png',
            b'\xff\xd8\xff': 'jpg',
            b'GIF87a': 'gif',
            b'GIF89a': 'gif',
            b'%PDF': 'pdf',
            b'PK\x03\x04': 'zip',
            b'\x50\x4b\x03\x04': 'zip',
            b'\x1f\x8b\x08': 'gz',
            b'BM': 'bmp',
            b'RIFF': 'wav'  # ou webp, precisa verificar mais bytes
        }
        
        for signature, file_type in magic_signatures.items():
            if file_data.startswith(signature):
                return file_type
        
        return 'unknown'
    
    @staticmethod
    def scan_for_malicious_patterns(file_data: bytes) -> bool:
        """Verificar padrões maliciosos em arquivos"""
        try:
            # Converter para string para análise de padrões
            try:
                content = file_data.decode('utf-8', errors='ignore')
            except:
                content = str(file_data)
            
            malicious_patterns = [
                r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',
                r'javascript:',
                r'vbscript:',
                r'eval\s*\(',
                r'document\.write',
                r'window\.location',
                r'\.htaccess',
                r'passwd',
                r'shadow',
                r'SELECT.*FROM',
                r'INSERT.*INTO',
                r'DELETE.*FROM',
                r'DROP.*TABLE'
            ]
            
            for pattern in malicious_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erro na verificação de padrões maliciosos: {str(e)}")
            return False
    
    @staticmethod
    def generate_secure_filename(original_filename: str) -> str:
        """Gerar nome de arquivo seguro"""
        try:
            # Remover caminho
            filename = os.path.basename(original_filename)
            
            # Remover caracteres perigosos
            safe_chars = re.sub(r'[^a-zA-Z0-9.-]', '_', filename)
            
            # Limitar tamanho
            if len(safe_chars) > 100:
                name, ext = os.path.splitext(safe_chars)
                safe_chars = name[:90] + ext
            
            # Adicionar timestamp para unicidade
            timestamp = str(int(time.time()))
            name, ext = os.path.splitext(safe_chars)
            
            return f"{name}_{timestamp}{ext}"
            
        except Exception:
            return f"file_{int(time.time())}.dat"
    
    @