import asyncio
import logging
import subprocess
import time
import socket
import requests
from typing import Optional, Dict, Any
import stem
from stem import Signal
from stem.control import Controller
import os
import signal
import psutil

logger = logging.getLogger(__name__)

class TorManager:
    def __init__(self, 
                 tor_port: int = 9050, 
                 control_port: int = 9051,
                 control_password: Optional[str] = None):
        self.tor_port = tor_port
        self.control_port = control_port
        self.control_password = control_password
        self.tor_process = None
        self.controller = None
        self.is_running = False
        self.session = None
        
    async def start(self) -> bool:
        """Iniciar serviço Tor"""
        try:
            logger.info("Iniciando serviço Tor...")
            
            # Verificar se Tor já está rodando
            if self.is_tor_running():
                logger.info("Tor já está rodando")
                self.is_running = True
                await self.setup_controller()
                return True
            
            # Iniciar processo Tor
            success = await self.start_tor_process()
            if not success:
                return False
            
            # Aguardar Tor inicializar
            await self.wait_for_tor()
            
            # Configurar controlador
            await self.setup_controller()
            
            # Configurar sessão HTTP
            self.setup_session()
            
            self.is_running = True
            logger.info("Serviço Tor iniciado com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao iniciar Tor: {str(e)}")
            return False
    
    async def stop(self):
        """Parar serviço Tor"""
        try:
            logger.info("Parando serviço Tor...")
            
            # Fechar controlador
            if self.controller:
                self.controller.close()
                self.controller = None
            
            # Fechar sessão
            if self.session:
                self.session.close()
                self.session = None
            
            # Parar processo Tor
            if self.tor_process:
                self.tor_process.terminate()
                try:
                    self.tor_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.tor_process.kill()
                
                self.tor_process = None
            
            self.is_running = False
            logger.info("Serviço Tor parado")
            
        except Exception as e:
            logger.error(f"Erro ao parar Tor: {str(e)}")
    
    def is_tor_running(self) -> bool:
        """Verificar se Tor está rodando"""
        try:
            # Verificar se porta está aberta
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', self.tor_port))
            sock.close()
            
            return result == 0
            
        except Exception:
            return False
    
    async def start_tor_process(self) -> bool:
        """Iniciar processo Tor"""
        try:
            # Configuração Tor
            tor_config = [
                'tor',
                '--SocksPort', str(self.tor_port),
                '--ControlPort', str(self.control_port),
                '--CookieAuthentication', '1',
                '--DataDirectory', '/tmp/tor_data',
                '--Log', 'notice stdout'
            ]
            
            # Criar diretório de dados
            os.makedirs('/tmp/tor_data', exist_ok=True)
            
            # Iniciar processo
            self.tor_process = subprocess.Popen(
                tor_config,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            return True
            
        except FileNotFoundError:
            logger.error("Tor não encontrado. Instale o Tor: apt-get install tor")
            return False
        except Exception as e:
            logger.error(f"Erro ao iniciar processo Tor: {str(e)}")
            return False
    
    async def wait_for_tor(self, timeout: int = 30):
        """Aguardar Tor inicializar completamente"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.is_tor_running():
                # Testar conectividade
                if await self.test_tor_connection():
                    return True
            
            await asyncio.sleep(1)
        
        raise TimeoutError("Timeout aguardando Tor inicializar")
    
    async def test_tor_connection(self) -> bool:
        """Testar conexão Tor"""
        try:
            # Configurar proxy SOCKS
            proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_port}'
            }
            
            # Testar com check.torproject.org
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=proxies,
                timeout=10
            )
            
            data = response.json()
            return data.get('IsTor', False)
            
        except Exception as e:
            logger.debug(f"Erro no teste de conexão Tor: {str(e)}")
            return False
    
    async def setup_controller(self):
        """Configurar controlador Tor"""
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            
        except Exception as e:
            logger.warning(f"Erro ao configurar controlador Tor: {str(e)}")
            self.controller = None
    
    def setup_session(self):
        """Configurar sessão HTTP com proxy Tor"""
        try:
            self.session = requests.Session()
            
            # Configurar proxy SOCKS
            self.session.proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_port}'
            }
            
            # Headers para anonimato
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
            })
            
        except Exception as e:
            logger.error(f"Erro ao configurar sessão: {str(e)}")
    
    async def new_identity(self) -> bool:
        """Renovar identidade Tor (novo circuito)"""
        try:
            if not self.controller:
                logger.warning("Controlador Tor não disponível")
                return False
            
            logger.info("Renovando identidade Tor...")
            self.controller.signal(Signal.NEWNYM)
            
            # Aguardar nova identidade
            await asyncio.sleep(5)
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao renovar identidade: {str(e)}")
            return False
    
    async def get_current_ip(self) -> Optional[str]:
        """Obter IP atual através do Tor"""
        try:
            if not self.session:
                return None
            
            response = self.session.get(
                'https://httpbin.org/ip',
                timeout=10
            )
            
            data = response.json()
            return data.get('origin')
            
        except Exception as e:
            logger.error(f"Erro ao obter IP atual: {str(e)}")
            return None
    
    async def make_request(self, 
                          url: str, 
                          method: str = 'GET',
                          **kwargs) -> Optional[requests.Response]:
        """Fazer requisição HTTP através do Tor"""
        try:
            if not self.session:
                logger.error("Sessão Tor não configurada")
                return None
            
            # Timeout padrão
            kwargs.setdefault('timeout', 30)
            
            # Fazer requisição
            if method.upper() == 'GET':
                response = self.session.get(url, **kwargs)
            elif method.upper() == 'POST':
                response = self.session.post(url, **kwargs)
            else:
                response = self.session.request(method, url, **kwargs)
            
            return response
            
        except Exception as e:
            logger.error(f"Erro na requisição Tor: {str(e)}")
            return None
    
    async def get_tor_status(self) -> Dict[str, Any]:
        """Obter status do serviço Tor"""
        status = {
            'running': self.is_running,
            'tor_port': self.tor_port,
            'control_port': self.control_port,
            'controller_connected': self.controller is not None,
            'session_configured': self.session is not None,
            'current_ip': None,
            'circuits': 0
        }
        
        try:
            if self.is_running:
                # Obter IP atual
                status['current_ip'] = await self.get_current_ip()
                
                # Obter informações dos circuitos
                if self.controller:
                    circuits = self.controller.get_circuits()
                    status['circuits'] = len(circuits)
            
        except Exception as e:
            logger.error(f"Erro ao obter status: {str(e)}")
        
        return status
    
    async def check_tor_health(self) -> Dict[str, Any]:
        """Verificar saúde do serviço Tor"""
        health = {
            'status': 'unknown',
            'issues': [],
            'recommendations': []
        }
        
        try:
            # Verificar se está rodando
            if not self.is_running:
                health['status'] = 'down'
                health['issues'].append('Serviço Tor não está rodando')
                health['recommendations'].append('Iniciar serviço Tor')
                return health
            
            # Testar conectividade
            if not await self.test_tor_connection():
                health['status'] = 'degraded'
                health['issues'].append('Conexão Tor não funcional')
                health['recommendations'].append('Reiniciar serviço Tor')
            
            # Verificar controlador
            if not self.controller:
                health['issues'].append('Controlador Tor não conectado')
                health['recommendations'].append('Verificar configuração do controlador')
            
            # Verificar performance
            response_time = await self.measure_response_time()
            if response_time and response_time > 30:
                health['issues'].append(f'Tempo de resposta alto: {response_time:.2f}s')
                health['recommendations'].append('Considerar renovar identidade')
            
            # Determinar status final
            if not health['issues']:
                health['status'] = 'healthy'
            elif len(health['issues']) == 1 and 'controlador' in health['issues'][0].lower():
                health['status'] = 'degraded'
            else:
                health['status'] = 'unhealthy'
            
        except Exception as e:
            health['status'] = 'error'
            health['issues'].append(f'Erro na verificação: {str(e)}')
        
        return health
    
    async def measure_response_time(self) -> Optional[float]:
        """Medir tempo de resposta da conexão Tor"""
        try:
            start_time = time.time()
            
            response = await self.make_request('https://httpbin.org/ip')
            
            if response and response.status_code == 200:
                return time.time() - start_time
            
            return None
            
        except Exception as e:
            logger.debug(f"Erro ao medir tempo de resposta: {str(e)}")
            return None
    
    async def rotate_identity_periodically(self, interval_minutes: int = 10):
        """Rotacionar identidade periodicamente"""
        try:
            logger.info(f"Iniciando rotação automática de identidade a cada {interval_minutes} minutos")
            
            while self.is_running:
                await asyncio.sleep(interval_minutes * 60)
                
                if self.is_running:
                    success = await self.new_identity()
                    if success:
                        logger.info("Identidade Tor renovada automaticamente")
                    else:
                        logger.warning("Falha na renovação automática de identidade")
            
        except Exception as e:
            logger.error(f"Erro na rotação automática: {str(e)}")
    
    def get_tor_info(self) -> Dict[str, Any]:
        """Obter informações detalhadas do Tor"""
        info = {
            'version': None,
            'config': {},
            'network_status': {},
            'bandwidth': {}
        }
        
        try:
            if self.controller:
                # Versão do Tor
                info['version'] = self.controller.get_version()
                
                # Configurações
                info['config'] = {
                    'socks_port': self.controller.get_conf('SocksPort'),
                    'control_port': self.controller.get_conf('ControlPort'),
                    'exit_policy': self.controller.get_conf('ExitPolicy'),
                    'bandwidth_rate': self.controller.get_conf('BandwidthRate')
                }
                
                # Status da rede
                info['network_status'] = {
                    'circuits': len(self.controller.get_circuits()),
                    'streams': len(self.controller.get_streams()),
                    'relays': len(self.controller.get_network_statuses())
                }
        
        except Exception as e:
            logger.debug(f"Erro ao obter informações do Tor: {str(e)}")
        
        return info
    
    async def configure_tor_for_security(self):
        """Configurar Tor para máxima segurança"""
        try:
            if not self.controller:
                logger.warning("Controlador não disponível para configuração")
                return
            
            # Configurações de segurança
            security_configs = {
                'EnforceDistinctSubnets': '1',
                'NewCircuitPeriod': '60',  # Novo circuito a cada 60 segundos
                'MaxCircuitDirtiness': '300',  # Circuitos expiram em 5 min
                'UseEntryGuards': '1',
                'NumEntryGuards': '3',
                'StrictNodes': '1'
            }
            
            for config, value in security_configs.items():
                try:
                    self.controller.set_conf(config, value)
                    logger.debug(f"Configurado {config}={value}")
                except Exception as e:
                    logger.warning(f"Erro ao configurar {config}: {str(e)}")
            
            logger.info("Configurações de segurança aplicadas")
            
        except Exception as e:
            logger.error(f"Erro na configuração de segurança: {str(e)}")
    
    async def get_exit_nodes(self) -> List[Dict[str, Any]]:
        """Obter lista de nós de saída disponíveis"""
        exit_nodes = []
        
        try:
            if not self.controller:
                return exit_nodes
            
            # Obter status da rede
            network_statuses = self.controller.get_network_statuses()
            
            for status in network_statuses:
                if 'Exit' in status.flags:
                    exit_nodes.append({
                        'fingerprint': status.fingerprint,
                        'nickname': status.nickname,
                        'address': status.address,
                        'or_port': status.or_port,
                        'bandwidth': status.bandwidth,
                        'country': getattr(status, 'country_code', 'Unknown')
                    })
            
            # Ordenar por bandwidth
            exit_nodes.sort(key=lambda x: x['bandwidth'], reverse=True)
            
        except Exception as e:
            logger.error(f"Erro ao obter nós de saída: {str(e)}")
        
        return exit_nodes[:50]  # Top 50
    
    async def select_exit_country(self, country_code: str) -> bool:
        """Selecionar país específico para saída"""
        try:
            if not self.controller:
                logger.warning("Controlador não disponível")
                return False
            
            # Configurar país de saída
            self.controller.set_conf('ExitNodes', f'{{{country_code}}}')
            self.controller.set_conf('StrictNodes', '1')
            
            # Renovar circuitos
            await self.new_identity()
            
            logger.info(f"País de saída configurado: {country_code}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao configurar país de saída: {str(e)}")
            return False
    
    async def monitor_tor_logs(self, callback=None):
        """Monitorar logs do Tor"""
        try:
            if not self.controller:
                logger.warning("Controlador não disponível para monitoramento")
                return
            
            def log_handler(event):
                message = f"[{event.arrived_at}] {event.message}"
                
                if callback:
                    callback(message)
                else:
                    logger.info(f"Tor Log: {message}")
            
            # Registrar handler para eventos
            self.controller.add_event_listener(log_handler, stem.control.EventType.NOTICE)
            self.controller.add_event_listener(log_handler, stem.control.EventType.WARN)
            self.controller.add_event_listener(log_handler, stem.control.EventType.ERR)
            
            logger.info("Monitoramento de logs Tor iniciado")
            
        except Exception as e:
            logger.error(f"Erro no monitoramento de logs: {str(e)}")
    
    async def get_circuit_info(self) -> List[Dict[str, Any]]:
        """Obter informações detalhadas dos circuitos"""
        circuits_info = []
        
        try:
            if not self.controller:
                return circuits_info
            
            circuits = self.controller.get_circuits()
            
            for circuit in circuits:
                circuit_info = {
                    'id': circuit.id,
                    'status': circuit.status,
                    'purpose': circuit.purpose,
                    'path': [],
                    'built_time': circuit.created,
                    'bytes_read': 0,
                    'bytes_written': 0
                }
                
                # Informações do caminho
                for hop in circuit.path:
                    relay_info = {
                        'fingerprint': hop[0],
                        'nickname': hop[1] if len(hop) > 1 else 'Unknown'
                    }
                    circuit_info['path'].append(relay_info)
                
                circuits_info.append(circuit_info)
            
        except Exception as e:
            logger.error(f"Erro ao obter informações dos circuitos: {str(e)}")
        
        return circuits_info
    
    async def test_hidden_service_connectivity(self, onion_url: str) -> Dict[str, Any]:
        """Testar conectividade com serviço oculto"""
        test_result = {
            'url': onion_url,
            'accessible': False,
            'response_time': None,
            'status_code': None,
            'error': None
        }
        
        try:
            start_time = time.time()
            
            response = await self.make_request(onion_url)
            
            test_result['response_time'] = time.time() - start_time
            
            if response:
                test_result['accessible'] = True
                test_result['status_code'] = response.status_code
            else:
                test_result['error'] = 'No response received'
            
        except Exception as e:
            test_result['error'] = str(e)
        
        return test_result
    
    def cleanup_tor_data(self):
        """Limpar dados temporários do Tor"""
        try:
            import shutil
            
            data_dir = '/tmp/tor_data'
            if os.path.exists(data_dir):
                shutil.rmtree(data_dir)
                logger.info("Dados temporários do Tor removidos")
            
        except Exception as e:
            logger.error(f"Erro na limpeza de dados: {str(e)}")
    
    async def get_bandwidth_usage(self) -> Dict[str, int]:
        """Obter uso de bandwidth"""
        bandwidth = {
            'bytes_read': 0,
            'bytes_written': 0,
            'read_rate': 0,
            'write_rate': 0
        }
        
        try:
            if self.controller:
                # Obter informações de bandwidth
                info = self.controller.get_info(['traffic/read', 'traffic/written'])
                
                bandwidth['bytes_read'] = int(info.get('traffic/read', 0))
                bandwidth['bytes_written'] = int(info.get('traffic/written', 0))
        
        except Exception as e:
            logger.debug(f"Erro ao obter bandwidth: {str(e)}")
        
        return bandwidth
    
    async def __aenter__(self):
        """Context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.stop()

# Funções utilitárias globais
async def create_tor_session() -> Optional[TorManager]:
    """Criar sessão Tor com configuração padrão"""
    try:
        tor_manager = TorManager()
        success = await tor_manager.start()
        
        if success:
            return tor_manager
        else:
            await tor_manager.stop()
            return None
    
    except Exception as e:
        logger.error(f"Erro ao criar sessão Tor: {str(e)}")
        return None

def is_tor_available() -> bool:
    """Verificar se Tor está disponível no sistema"""
    try:
        result = subprocess.run(['tor', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

async def test_tor_connectivity() -> bool:
    """Testar conectividade básica do Tor"""
    try:
        async with TorManager() as tor:
            if tor and tor.is_running:
                ip = await tor.get_current_ip()
                return ip is not None
        return False
    except Exception:
        return False