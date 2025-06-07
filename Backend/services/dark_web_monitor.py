import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import re
import hashlib
import time
from urllib.parse import quote_plus
import random

logger = logging.getLogger(__name__)

class DarkWebMonitor:
    def __init__(self):
        self.tor_session = None
        self.search_engines = [
            'ahmia.fi',
            'torch.onion',
            'duckduckgo.onion'
        ]
        self.monitored_keywords = []
        
    async def search(self, target: str) -> List[Dict[str, Any]]:
        """Buscar informações sobre o target na dark web"""
        try:
            logger.info(f"Iniciando monitoramento da dark web para {target}")
            
            findings = []
            
            # 1. Preparar keywords de busca
            keywords = self.generate_search_keywords(target)
            
            # 2. Buscar em diferentes fontes
            for keyword in keywords:
                # Buscar em fóruns conhecidos
                forum_results = await self.search_forums(keyword)
                findings.extend(forum_results)
                
                # Buscar em marketplaces
                marketplace_results = await self.search_marketplaces(keyword)
                findings.extend(marketplace_results)
                
                # Buscar vazamentos de dados
                leak_results = await self.search_data_leaks(keyword)
                findings.extend(leak_results)
                
                # Buscar em paste sites
                paste_results = await self.search_paste_sites(keyword)
                findings.extend(paste_results)
                
                # Delay entre buscas para evitar rate limiting
                await asyncio.sleep(2)
            
            # 3. Analisar e classificar resultados
            classified_findings = self.classify_findings(findings)
            
            logger.info(f"Monitoramento concluído: {len(classified_findings)} achados")
            return classified_findings
            
        except Exception as e:
            logger.error(f"Erro no monitoramento da dark web: {str(e)}")
            return []
    
    def generate_search_keywords(self, target: str) -> List[str]:
        """Gerar palavras-chave para busca"""
        keywords = []
        
        # Adicionar o target principal
        keywords.append(target)
        
        # Se for domínio, extrair partes
        if '.' in target:
            domain_parts = target.split('.')
            # Adicionar nome da empresa (parte antes do TLD)
            if len(domain_parts) >= 2:
                company_name = domain_parts[0]
                keywords.append(company_name)
                
                # Variações do nome da empresa
                keywords.append(f"{company_name} database")
                keywords.append(f"{company_name} credentials")
                keywords.append(f"{company_name} emails")
                keywords.append(f"{company_name} dump")
                keywords.append(f"{company_name} leak")
        
        # Adicionar variações comuns
        keywords.extend([
            f"{target} hack",
            f"{target} breach",
            f"{target} vulnerability",
            f"{target} exploit"
        ])
        
        return keywords
    
    async def search_forums(self, keyword: str) -> List[Dict[str, Any]]:
        """Buscar em fóruns da dark web"""
        findings = []
        
        try:
            # Simular busca em fóruns conhecidos (implementação real requer Tor)
            simulated_forums = [
                'hackforums.net',
                'breached.to',
                'raidforums.com',
                'nulled.to'
            ]
            
            for forum in simulated_forums:
                # Simular encontrar posts relacionados
                if random.random() < 0.1:  # 10% de chance de encontrar algo
                    findings.append({
                        'source': forum,
                        'type': 'forum_post',
                        'title': f'Post relacionado a {keyword}',
                        'content': f'Post simulado sobre {keyword} encontrado em {forum}',
                        'url': f'https://{forum}/thread/12345',
                        'risk_level': 'medium',
                        'discovered_at': datetime.now().isoformat(),
                        'confidence': 0.7
                    })
        
        except Exception as e:
            logger.error(f"Erro na busca em fóruns: {str(e)}")
        
        return findings
    
    async def search_marketplaces(self, keyword: str) -> List[Dict[str, Any]]:
        """Buscar em marketplaces da dark web"""
        findings = []
        
        try:
            # Lista de marketplaces conhecidos (simulado)
            marketplaces = [
                'empire_market',
                'white_house_market',
                'dark_market'
            ]
            
            for marketplace in marketplaces:
                # Simular busca por dados vazados
                if random.random() < 0.05:  # 5% de chance
                    findings.append({
                        'source': marketplace,
                        'type': 'data_sale',
                        'title': f'Dados de {keyword} à venda',
                        'content': f'Possível venda de dados relacionados a {keyword}',
                        'price': f'{random.randint(10, 1000)} USD',
                        'risk_level': 'high',
                        'discovered_at': datetime.now().isoformat(),
                        'confidence': 0.8
                    })
        
        except Exception as e:
            logger.error(f"Erro na busca em marketplaces: {str(e)}")
        
        return findings
    
    async def search_data_leaks(self, keyword: str) -> List[Dict[str, Any]]:
        """Buscar vazamentos de dados"""
        findings = []
        
        try:
            # Simular busca em bases de dados vazados
            leak_databases = [
                'haveibeenpwned',
                'leakcheck',
                'dehashed',
                'snusbase'
            ]
            
            for db in leak_databases:
                # Simular verificação de vazamentos
                if random.random() < 0.15:  # 15% de chance
                    findings.append({
                        'source': db,
                        'type': 'data_leak',
                        'title': f'Vazamento detectado: {keyword}',
                        'content': f'Dados relacionados a {keyword} encontrados em vazamento',
                        'breach_date': (datetime.now() - timedelta(days=random.randint(30, 365))).isoformat(),
                        'affected_accounts': random.randint(100, 10000),
                        'risk_level': 'high',
                        'discovered_at': datetime.now().isoformat(),
                        'confidence': 0.9
                    })
        
        except Exception as e:
            logger.error(f"Erro na busca de vazamentos: {str(e)}")
        
        return findings
    
    async def search_paste_sites(self, keyword: str) -> List[Dict[str, Any]]:
        """Buscar em sites de paste"""
        findings = []
        
        try:
            # Sites de paste comuns
            paste_sites = [
                'pastebin.com',
                'ghostbin.co',
                'privatebin.net',
                'dpaste.org'
            ]
            
            for site in paste_sites:
                # Simular busca por pastes
                if random.random() < 0.08:  # 8% de chance
                    findings.append({
                        'source': site,
                        'type': 'paste',
                        'title': f'Paste contendo {keyword}',
                        'content': f'Informações sobre {keyword} encontradas em paste',
                        'url': f'https://{site}/abc123',
                        'risk_level': 'medium',
                        'discovered_at': datetime.now().isoformat(),
                        'confidence': 0.6
                    })
        
        except Exception as e:
            logger.error(f"Erro na busca em paste sites: {str(e)}")
        
        return findings
    
    def classify_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Classificar e enriquecer achados"""
        classified = []
        
        for finding in findings:
            # Adicionar classificação de risco baseada no tipo
            risk_classification = self.calculate_risk_score(finding)
            finding.update(risk_classification)
            
            # Adicionar recomendações
            recommendations = self.generate_recommendations(finding)
            finding['recommendations'] = recommendations
            
            # Adicionar hash único para evitar duplicatas
            finding_hash = hashlib.md5(
                f"{finding.get('source')}{finding.get('title')}{finding.get('content')}".encode()
            ).hexdigest()
            finding['finding_id'] = finding_hash
            
            classified.append(finding)
        
        # Remover duplicatas baseado no hash
        unique_findings = []
        seen_hashes = set()
        
        for finding in classified:
            if finding['finding_id'] not in seen_hashes:
                unique_findings.append(finding)
                seen_hashes.add(finding['finding_id'])
        
        return unique_findings
    
    def calculate_risk_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Calcular score de risco do achado"""
        base_score = 0.0
        risk_factors = []
        
        # Score baseado no tipo
        type_scores = {
            'data_sale': 0.9,
            'data_leak': 0.8,
            'forum_post': 0.6,
            'paste': 0.5
        }
        
        finding_type = finding.get('type', 'unknown')
        base_score = type_scores.get(finding_type, 0.3)
        
        # Fatores que aumentam o risco
        content = finding.get('content', '').lower()
        title = finding.get('title', '').lower()
        
        # Palavras-chave de alto risco
        high_risk_keywords = [
            'password', 'credential', 'database', 'dump',
            'breach', 'hack', 'exploit', 'vulnerability',
            'email', 'login', 'admin', 'root'
        ]
        
        for keyword in high_risk_keywords:
            if keyword in content or keyword in title:
                base_score += 0.1
                risk_factors.append(f"Contém palavra-chave de risco: {keyword}")
        
        # Normalizar score (máximo 1.0)
        final_score = min(base_score, 1.0)
        
        # Classificar nível de risco
        if final_score >= 0.8:
            risk_level = 'critical'
        elif final_score >= 0.6:
            risk_level = 'high'
        elif final_score >= 0.4:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_score': round(final_score, 2),
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
    
    def generate_recommendations(self, finding: Dict[str, Any]) -> List[str]:
        """Gerar recomendações baseadas no achado"""
        recommendations = []
        
        finding_type = finding.get('type')
        risk_level = finding.get('risk_level')
        
        # Recomendações gerais
        recommendations.append("Investigar a veracidade da informação")
        recommendations.append("Documentar o achado para análise posterior")
        
        # Recomendações específicas por tipo
        if finding_type == 'data_sale':
            recommendations.extend([
                "Verificar se os dados oferecidos são legítimos",
                "Notificar autoridades competentes se confirmado",
                "Implementar monitoramento contínuo do marketplace",
                "Revisar políticas de segurança de dados"
            ])
        
        elif finding_type == 'data_leak':
            recommendations.extend([
                "Verificar se o vazamento afeta a organização",
                "Resetar credenciais potencialmente comprometidas",
                "Notificar usuários afetados se aplicável",
                "Implementar autenticação multifator"
            ])
        
        elif finding_type == 'forum_post':
            recommendations.extend([
                "Monitorar thread para desenvolvimentos",
                "Verificar se informações técnicas são precisas",
                "Considerar medidas preventivas baseadas no conteúdo"
            ])
        
        elif finding_type == 'paste':
            recommendations.extend([
                "Salvar cópia local do paste antes que seja removido",
                "Verificar se contém informações sensíveis reais",
                "Investigar origem das informações"
            ])
        
        # Recomendações baseadas no nível de risco
        if risk_level in ['critical', 'high']:
            recommendations.extend([
                "Priorizar investigação imediata",
                "Considerar resposta a incidentes",
                "Avaliar impacto nos negócios"
            ])
        
        return recommendations
    
    async def continuous_monitoring(self, targets: List[str], interval_hours: int = 24):
        """Monitoramento contínuo da dark web"""
        try:
            logger.info(f"Iniciando monitoramento contínuo para {len(targets)} targets")
            
            while True:
                for target in targets:
                    try:
                        findings = await self.search(target)
                        
                        # Processar achados novos
                        new_findings = self.filter_new_findings(findings)
                        
                        if new_findings:
                            logger.info(f"Novos achados para {target}: {len(new_findings)}")
                            # Aqui você pode adicionar notificações, salvamento em DB, etc.
                            await self.process_new_findings(target, new_findings)
                        
                    except Exception as e:
                        logger.error(f"Erro no monitoramento de {target}: {str(e)}")
                
                # Aguardar próximo ciclo
                await asyncio.sleep(interval_hours * 3600)
                
        except Exception as e:
            logger.error(f"Erro no monitoramento contínuo: {str(e)}")
    
    def filter_new_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filtrar apenas achados novos"""
        # Em implementação real, comparar com banco de dados
        # Por agora, retornar todos como novos
        return findings
    
    async def process_new_findings(self, target: str, findings: List[Dict[str, Any]]):
        """Processar novos achados"""
        try:
            # Salvar no banco de dados
            # Enviar alertas se necessário
            # Gerar relatórios automáticos
            
            critical_findings = [f for f in findings if f.get('risk_level') == 'critical']
            
            if critical_findings:
                logger.warning(f"ALERTA: {len(critical_findings)} achados críticos para {target}")
                # Aqui você pode integrar com sistemas de alerta (email, Slack, etc.)
                
        except Exception as e:
            logger.error(f"Erro ao processar novos achados: {str(e)}")
    
    async def search_specific_breach(self, breach_name: str) -> List[Dict[str, Any]]:
        """Buscar informações sobre um vazamento específico"""
        findings = []
        
        try:
            # Simular busca por vazamento específico
            findings.append({
                'source': 'breach_database',
                'type': 'breach_info',
                'title': f'Informações sobre vazamento: {breach_name}',
                'content': f'Detalhes do vazamento {breach_name}',
                'affected_records': random.randint(1000, 1000000),
                'breach_date': (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                'data_types': ['emails', 'passwords', 'usernames'],
                'risk_level': 'high',
                'discovered_at': datetime.now().isoformat(),
                'confidence': 0.95
            })
            
        except Exception as e:
            logger.error(f"Erro na busca do vazamento específico: {str(e)}")
        
        return findings
    
    async def check_credential_exposure(self, email: str) -> List[Dict[str, Any]]:
        """Verificar se credenciais específicas foram expostas"""
        findings = []
        
        try:
            # Simular verificação de exposição de credenciais
            if random.random() < 0.3:  # 30% de chance de encontrar
                findings.append({
                    'source': 'credential_database',
                    'type': 'credential_exposure',
                    'title': f'Credenciais expostas: {email}',
                    'content': f'Email {email} encontrado em vazamentos',
                    'breaches': [
                        f'Breach_{random.randint(1, 10)}',
                        f'Leak_{random.randint(1, 5)}'
                    ],
                    'password_exposed': True,
                    'risk_level': 'high',
                    'discovered_at': datetime.now().isoformat(),
                    'confidence': 0.9
                })
                
        except Exception as e:
            logger.error(f"Erro na verificação de credenciais: {str(e)}")
        
        return findings
    
    def generate_monitoring_report(self, target: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Gerar relatório de monitoramento"""
        report = {
            'target': target,
            'report_date': datetime.now().isoformat(),
            'total_findings': len(findings),
            'summary': {
                'critical': len([f for f in findings if f.get('risk_level') == 'critical']),
                'high': len([f for f in findings if f.get('risk_level') == 'high']),
                'medium': len([f for f in findings if f.get('risk_level') == 'medium']),
                'low': len([f for f in findings if f.get('risk_level') == 'low'])
            },
            'by_type': {},
            'recommendations': [],
            'findings': findings
        }
        
        # Contar por tipo
        types = set(f.get('type') for f in findings)
        for finding_type in types:
            count = len([f for f in findings if f.get('type') == finding_type])
            report['by_type'][finding_type] = count
        
        # Gerar recomendações gerais
        if report['summary']['critical'] > 0:
            report['recommendations'].append('Investigação imediata necessária para achados críticos')
        
        if report['summary']['high'] > 0:
            report['recommendations'].append('Priorizar investigação de achados de alto risco')
        
        if any(f.get('type') == 'data_sale' for f in findings):
            report['recommendations'].append('Monitorar marketplaces para venda de dados')
        
        if any(f.get('type') == 'data_leak' for f in findings):
            report['recommendations'].append('Verificar impacto de vazamentos identificados')
        
        return report