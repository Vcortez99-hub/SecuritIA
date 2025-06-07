import asyncio
import logging
from typing import Dict, List, Any, Optional
import json
import os
from datetime import datetime
from pathlib import Path
import base64
import io

# Importações para geração de relatórios
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from jinja2 import Template, Environment, FileSystemLoader
import matplotlib.pyplot as plt
import seaborn as sns
from fpdf import FPDF
import pandas as pd

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.templates_dir = Path("templates")
        self.reports_dir = Path("reports")
        self.static_dir = Path("static")
        
        # Criar diretórios se não existirem
        self.templates_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        self.static_dir.mkdir(exist_ok=True)
        
        # Configurar Jinja2
        self.jinja_env = Environment(loader=FileSystemLoader(self.templates_dir))
        
        # Configurar estilos matplotlib
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    async def generate_report(self, scan_id: str, format_type: str = "pdf") -> Dict[str, Any]:
        """Gerar relatório do scan"""
        try:
            logger.info(f"Gerando relatório {format_type} para scan {scan_id}")
            
            # Obter dados do scan (em implementação real, buscar do banco)
            scan_data = await self.get_scan_data(scan_id)
            
            if format_type.lower() == "pdf":
                report_path = await self.generate_pdf_report(scan_data)
            elif format_type.lower() == "html":
                report_path = await self.generate_html_report(scan_data)
            elif format_type.lower() == "json":
                report_path = await self.generate_json_report(scan_data)
            elif format_type.lower() == "excel":
                report_path = await self.generate_excel_report(scan_data)
            else:
                raise ValueError(f"Formato não suportado: {format_type}")
            
            return {
                "report_id": f"report_{scan_id}_{format_type}",
                "file_path": str(report_path),
                "format": format_type,
                "generated_at": datetime.now().isoformat(),
                "size_mb": self.get_file_size_mb(report_path)
            }
            
        except Exception as e:
            logger.error(f"Erro na geração de relatório: {str(e)}")
            raise
    
    async def get_scan_data(self, scan_id: str) -> Dict[str, Any]:
        """Obter dados do scan (simulado)"""
        # Em implementação real, buscar do banco de dados
        return {
            "scan_id": scan_id,
            "target": "example.com",
            "scan_date": datetime.now().isoformat(),
            "scan_type": "comprehensive",
            "status": "completed",
            "vulnerabilities": [
                {
                    "name": "SQL Injection",
                    "severity": "HIGH",
                    "cvss_score": 8.5,
                    "port": 80,
                    "service": "http",
                    "description": "Aplicação vulnerável a injeção SQL",
                    "recommendation": "Implementar prepared statements"
                },
                {
                    "name": "Cross-Site Scripting (XSS)",
                    "severity": "MEDIUM",
                    "cvss_score": 6.1,
                    "port": 443,
                    "service": "https",
                    "description": "XSS refletido detectado",
                    "recommendation": "Sanitizar entrada do usuário"
                }
            ],
            "pentest_results": {
                "findings": [
                    {
                        "type": "web_app_pentest",
                        "title": "Authentication Bypass",
                        "severity": "CRITICAL",
                        "risk_level": "critical"
                    }
                ]
            },
            "dark_web_findings": [
                {
                    "source": "forum_abc",
                    "type": "data_leak",
                    "title": "Dados de usuários expostos",
                    "risk_level": "high"
                }
            ],
            "ai_analysis": {
                "overall_score": 6.5,
                "risk_assessment": {
                    "risk_level": "HIGH",
                    "overall_risk_score": 0.75
                }
            }
        }
    
    async def generate_pdf_report(self, scan_data: Dict[str, Any]) -> Path:
        """Gerar relatório em PDF"""
        try:
            filename = f"security_report_{scan_data['scan_id']}.pdf"
            filepath = self.reports_dir / filename
            
            # Criar documento PDF
            doc = SimpleDocTemplate(str(filepath), pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Estilos customizados
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=15,
                textColor=colors.darkred
            )
            
            # Título
            story.append(Paragraph("RELATÓRIO DE SEGURANÇA CIBERNÉTICA", title_style))
            story.append(Spacer(1, 20))
            
            # Informações gerais
            story.append(Paragraph("INFORMAÇÕES GERAIS", heading_style))
            
            general_info = [
                ["Target:", scan_data.get('target', 'N/A')],
                ["Data do Scan:", scan_data.get('scan_date', 'N/A')],
                ["Tipo de Scan:", scan_data.get('scan_type', 'N/A')],
                ["Status:", scan_data.get('status', 'N/A')],
                ["Score Geral:", f"{scan_data.get('ai_analysis', {}).get('overall_score', 0)}/10"]
            ]
            
            general_table = Table(general_info, colWidths=[2*inch, 4*inch])
            general_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (0, 0), (0, -1), colors.grey),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
            ]))
            
            story.append(general_table)
            story.append(Spacer(1, 20))
            
            # Resumo executivo
            story.append(Paragraph("RESUMO EXECUTIVO", heading_style))
            
            risk_level = scan_data.get('ai_analysis', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
            vuln_count = len(scan_data.get('vulnerabilities', []))
            
            executive_summary = f"""
            O scan de segurança do sistema {scan_data.get('target')} identificou {vuln_count} 
            vulnerabilidades com nível de risco geral classificado como <b>{risk_level}</b>.
            <br/><br/>
            Este relatório apresenta uma análise detalhada das vulnerabilidades encontradas, 
            resultados de testes de penetração e monitoramento da dark web, com recomendações 
            específicas para mitigação dos riscos identificados.
            """
            
            story.append(Paragraph(executive_summary, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Gráfico de vulnerabilidades
            chart_path = await self.create_vulnerability_chart(scan_data['vulnerabilities'])
            if chart_path:
                # Adicionar imagem do gráfico
                from reportlab.platypus import Image
                story.append(Paragraph("DISTRIBUIÇÃO DE VULNERABILIDADES", heading_style))
                story.append(Image(str(chart_path), width=6*inch, height=4*inch))
                story.append(Spacer(1, 20))
            
            # Vulnerabilidades detalhadas
            story.append(Paragraph("VULNERABILIDADES IDENTIFICADAS", heading_style))
            
            vuln_data = [["Vulnerabilidade", "Severidade", "CVSS", "Porta", "Recomendação"]]
            
            for vuln in scan_data.get('vulnerabilities', []):
                vuln_data.append([
                    vuln.get('name', 'N/A'),
                    vuln.get('severity', 'N/A'),
                    str(vuln.get('cvss_score', 'N/A')),
                    str(vuln.get('port', 'N/A')),
                    vuln.get('recommendation', 'N/A')[:50] + '...'
                ])
            
            vuln_table = Table(vuln_data, colWidths=[2*inch, 1*inch, 0.8*inch, 0.8*inch, 2.4*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(vuln_table)
            story.append(PageBreak())
            
            # Resultados do Pentest
            if scan_data.get('pentest_results'):
                story.append(Paragraph("RESULTADOS DO TESTE DE PENETRAÇÃO", heading_style))
                
                pentest_findings = scan_data.get('pentest_results', {}).get('findings', [])
                if pentest_findings:
                    for finding in pentest_findings:
                        story.append(Paragraph(f"<b>{finding.get('title', 'N/A')}</b>", styles['Normal']))
                        story.append(Paragraph(f"Tipo: {finding.get('type', 'N/A')}", styles['Normal']))
                        story.append(Paragraph(f"Severidade: {finding.get('severity', 'N/A')}", styles['Normal']))
                        story.append(Spacer(1, 10))
                
                story.append(Spacer(1, 20))
            
            # Achados da Dark Web
            if scan_data.get('dark_web_findings'):
                story.append(Paragraph("MONITORAMENTO DA DARK WEB", heading_style))
                
                for finding in scan_data.get('dark_web_findings', []):
                    story.append(Paragraph(f"<b>{finding.get('title', 'N/A')}</b>", styles['Normal']))
                    story.append(Paragraph(f"Fonte: {finding.get('source', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"Tipo: {finding.get('type', 'N/A')}", styles['Normal']))
                    story.append(Paragraph(f"Nível de Risco: {finding.get('risk_level', 'N/A')}", styles['Normal']))
                    story.append(Spacer(1, 10))
                
                story.append(Spacer(1, 20))
            
            # Recomendações
            story.append(Paragraph("RECOMENDAÇÕES", heading_style))
            
            recommendations = [
                "Implementar correções para vulnerabilidades críticas imediatamente",
                "Estabelecer programa de testes de segurança regulares",
                "Implementar monitoramento contínuo de segurança",
                "Treinar equipe em práticas de desenvolvimento seguro",
                "Estabelecer processo de resposta a incidentes"
            ]
            
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
                story.append(Spacer(1, 5))
            
            # Gerar PDF
            doc.build(story)
            
            logger.info(f"Relatório PDF gerado: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erro na geração do PDF: {str(e)}")
            raise
    
    async def create_vulnerability_chart(self, vulnerabilities: List[Dict[str, Any]]) -> Optional[Path]:
        """Criar gráfico de vulnerabilidades"""
        try:
            if not vulnerabilities:
                return None
            
            # Contar severidades
            severities = [v.get('severity', 'UNKNOWN') for v in vulnerabilities]
            severity_counts = {}
            for severity in severities:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Criar gráfico
            plt.figure(figsize=(10, 6))
            colors_map = {
                'CRITICAL': '#d32f2f',
                'HIGH': '#f57c00',
                'MEDIUM': '#fbc02d',
                'LOW': '#388e3c',
                'INFO': '#1976d2'
            }
            
            labels = list(severity_counts.keys())
            values = list(severity_counts.values())
            chart_colors = [colors_map.get(label, '#757575') for label in labels]
            
            plt.pie(values, labels=labels, colors=chart_colors, autopct='%1.1f%%', startangle=90)
            plt.title('Distribuição de Vulnerabilidades por Severidade', fontsize=14, fontweight='bold')
            
            # Salvar gráfico
            chart_path = self.static_dir / f"vuln_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Erro na criação do gráfico: {str(e)}")
            return None
    
    async def generate_html_report(self, scan_data: Dict[str, Any]) -> Path:
        """Gerar relatório em HTML"""
        try:
            filename = f"security_report_{scan_data['scan_id']}.html"
            filepath = self.reports_dir / filename
            
            # Template HTML
            html_template = """
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Relatório de Segurança - {{ target }}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
                    h1 { color: #1a237e; text-align: center; border-bottom: 3px solid #1a237e; padding-bottom: 10px; }
                    h2 { color: #d32f2f; border-left: 4px solid #d32f2f; padding-left: 15px; }
                    .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
                    .info-card { background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #2196f3; }
                    .vulnerability { background: #fff3e0; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid #ff9800; }
                    .severity-critical { border-left-color: #d32f2f; background: #ffebee; }
                    .severity-high { border-left-color: #f57c00; background: #fff3e0; }
                    .severity-medium { border-left-color: #fbc02d; background: #fffde7; }
                    .severity-low { border-left-color: #388e3c; background: #e8f5e8; }
                    .score { font-size: 2em; font-weight: bold; color: #1a237e; text-align: center; }
                    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                    th { background-color: #1a237e; color: white; }
                    .recommendation { background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 10px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>RELATÓRIO DE SEGURANÇA CIBERNÉTICA</h1>
                    
                    <div class="info-grid">
                        <div class="info-card">
                            <h3>Informações do Scan</h3>
                            <p><strong>Target:</strong> {{ target }}</p>
                            <p><strong>Data:</strong> {{ scan_date }}</p>
                            <p><strong>Tipo:</strong> {{ scan_type }}</p>
                            <p><strong>Status:</strong> {{ status }}</p>
                        </div>
                        <div class="info-card">
                            <h3>Score de Segurança</h3>
                            <div class="score">{{ overall_score }}/10</div>
                            <p style="text-align: center;"><strong>Nível de Risco: {{ risk_level }}</strong></p>
                        </div>
                    </div>
                    
                    <h2>Vulnerabilidades Identificadas</h2>
                    {% for vuln in vulnerabilities %}
                    <div class="vulnerability severity-{{ vuln.severity.lower() }}">
                        <h4>{{ vuln.name }}</h4>
                        <p><strong>Severidade:</strong> {{ vuln.severity }} | <strong>CVSS:</strong> {{ vuln.cvss_score }} | <strong>Porta:</strong> {{ vuln.port }}</p>
                        <p><strong>Descrição:</strong> {{ vuln.description }}</p>
                        <p><strong>Recomendação:</strong> {{ vuln.recommendation }}</p>
                    </div>
                    {% endfor %}
                    
                    {% if pentest_findings %}
                    <h2>Resultados do Teste de Penetração</h2>
                    {% for finding in pentest_findings %}
                    <div class="vulnerability">
                        <h4>{{ finding.title }}</h4>
                        <p><strong>Tipo:</strong> {{ finding.type }}</p>
                        <p><strong>Severidade:</strong> {{ finding.severity }}</p>
                    </div>
                    {% endfor %}
                    {% endif %}
                    
                    {% if dark_web_findings %}
                    <h2>Monitoramento da Dark Web</h2>
                    {% for finding in dark_web_findings %}
                    <div class="vulnerability">
                        <h4>{{ finding.title }}</h4>
                        <p><strong>Fonte:</strong> {{ finding.source }}</p>
                        <p><strong>Tipo:</strong> {{ finding.type }}</p>
                        <p><strong>Nível de Risco:</strong> {{ finding.risk_level }}</p>
                    </div>
                    {% endfor %}
                    {% endif %}
                    
                    <h2>Recomendações</h2>
                    <div class="recommendation">
                        <h4>Ações Imediatas</h4>
                        <ul>
                            <li>Corrigir vulnerabilidades críticas imediatamente</li>
                            <li>Implementar monitoramento adicional</li>
                            <li>Revisar configurações de segurança</li>
                        </ul>
                    </div>
                    
                    <div class="recommendation">
                        <h4>Ações de Médio Prazo</h4>
                        <ul>
                            <li>Estabelecer programa de testes regulares</li>
                            <li>Treinar equipe em segurança</li>
                            <li>Implementar processo de resposta a incidentes</li>
                        </ul>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Renderizar template
            template = Template(html_template)
            
            context = {
                'target': scan_data.get('target', 'N/A'),
                'scan_date': scan_data.get('scan_date', 'N/A'),
                'scan_type': scan_data.get('scan_type', 'N/A'),
                'status': scan_data.get('status', 'N/A'),
                'overall_score': scan_data.get('ai_analysis', {}).get('overall_score', 0),
                'risk_level': scan_data.get('ai_analysis', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                'vulnerabilities': scan_data.get('vulnerabilities', []),
                'pentest_findings': scan_data.get('pentest_results', {}).get('findings', []),
                'dark_web_findings': scan_data.get('dark_web_findings', [])
            }
            
            html_content = template.render(**context)
            
            # Salvar arquivo
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Relatório HTML gerado: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erro na geração do HTML: {str(e)}")
            raise
    
    async def generate_json_report(self, scan_data: Dict[str, Any]) -> Path:
        """Gerar relatório em JSON"""
        try:
            filename = f"security_report_{scan_data['scan_id']}.json"
            filepath = self.reports_dir / filename
            
            # Adicionar metadados do relatório
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "generator": "SECURIT IA",
                    "version": "1.0.0",
                    "format": "json"
                },
                "scan_data": scan_data
            }
            
            # Salvar JSON
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Relatório JSON gerado: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erro na geração do JSON: {str(e)}")
            raise
    
    async def generate_excel_report(self, scan_data: Dict[str, Any]) -> Path:
        """Gerar relatório em Excel"""
        try:
            filename = f"security_report_{scan_data['scan_id']}.xlsx"
            filepath = self.reports_dir / filename
            
            # Criar workbook
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                
                # Aba 1: Resumo
                summary_data = {
                    'Métrica': ['Target', 'Data do Scan', 'Tipo', 'Status', 'Score Geral', 'Nível de Risco'],
                    'Valor': [
                        scan_data.get('target', 'N/A'),
                        scan_data.get('scan_date', 'N/A'),
                        scan_data.get('scan_type', 'N/A'),
                        scan_data.get('status', 'N/A'),
                        scan_data.get('ai_analysis', {}).get('overall_score', 0),
                        scan_data.get('ai_analysis', {}).get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
                    ]
                }
                
                df_summary = pd.DataFrame(summary_data)
                df_summary.to_excel(writer, sheet_name='Resumo', index=False)
                
                # Aba 2: Vulnerabilidades
                if scan_data.get('vulnerabilities'):
                    df_vulns = pd.DataFrame(scan_data['vulnerabilities'])
                    df_vulns.to_excel(writer, sheet_name='Vulnerabilidades', index=False)
                
                # Aba 3: Pentest
                if scan_data.get('pentest_results', {}).get('findings'):
                    df_pentest = pd.DataFrame(scan_data['pentest_results']['findings'])
                    df_pentest.to_excel(writer, sheet_name='Pentest', index=False)
                
                # Aba 4: Dark Web
                if scan_data.get('dark_web_findings'):
                    df_darkweb = pd.DataFrame(scan_data['dark_web_findings'])
                    df_darkweb.to_excel(writer, sheet_name='Dark Web', index=False)
            
            logger.info(f"Relatório Excel gerado: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Erro na geração do Excel: {str(e)}")
            raise
    
    def get_file_size_mb(self, filepath: Path) -> float:
        """Obter tamanho do arquivo em MB"""
        try:
            size_bytes = filepath.stat().st_size
            return round(size_bytes / (1024 * 1024), 2)
        except Exception:
            return 0.0
    
    async def generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gerar resumo executivo"""
        try:
            vulnerabilities = scan_data.get('vulnerabilities', [])
            ai_analysis = scan_data.get('ai_analysis', {})
            
            # Contar severidades
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Calcular métricas
            total_vulns = len(vulnerabilities)
            critical_vulns = severity_counts.get('CRITICAL', 0)
            high_vulns = severity_counts.get('HIGH', 0)
            
            risk_level = ai_analysis.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
            overall_score = ai_analysis.get('overall_score', 0)
            
            # Determinar status geral
            if critical_vulns > 0 or risk_level == 'CRITICAL':
                status = 'CRÍTICO'
                status_color = '#d32f2f'
            elif high_vulns > 0 or risk_level == 'HIGH':
                status = 'ALTO RISCO'
                status_color = '#f57c00'
            elif risk_level == 'MEDIUM':
                status = 'RISCO MODERADO'
                status_color = '#fbc02d'
            else:
                status = 'BAIXO RISCO'
                status_color = '#388e3c'
            
            summary = {
                'target': scan_data.get('target', 'N/A'),
                'scan_date': scan_data.get('scan_date', 'N/A'),
                'status': status,
                'status_color': status_color,
                'overall_score': overall_score,
                'risk_level': risk_level,
                'total_vulnerabilities': total_vulns,
                'critical_vulnerabilities': critical_vulns,
                'high_vulnerabilities': high_vulns,
                'severity_distribution': severity_counts,
                'key_findings': self.extract_key_findings(scan_data),
                'top_recommendations': self.get_top_recommendations(scan_data),
                'compliance_status': self.assess_compliance_status(scan_data)
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Erro na geração do resumo executivo: {str(e)}")
            return {}
    
    def extract_key_findings(self, scan_data: Dict[str, Any]) -> List[str]:
        """Extrair principais achados"""
        findings = []
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        
        if critical_vulns:
            findings.append(f"{len(critical_vulns)} vulnerabilidades críticas identificadas")
        
        if high_vulns:
            findings.append(f"{len(high_vulns)} vulnerabilidades de alta severidade encontradas")
        
        # Achados do pentest
        pentest_results = scan_data.get('pentest_results', {})
        if pentest_results.get('findings'):
            critical_pentest = [f for f in pentest_results['findings'] if f.get('risk_level') == 'critical']
            if critical_pentest:
                findings.append(f"Testes de penetração identificaram {len(critical_pentest)} falhas críticas")
        
        # Achados da dark web
        dark_web_findings = scan_data.get('dark_web_findings', [])
        if dark_web_findings:
            high_risk_findings = [f for f in dark_web_findings if f.get('risk_level') in ['high', 'critical']]
            if high_risk_findings:
                findings.append(f"Monitoramento da dark web detectou {len(high_risk_findings)} ameaças ativas")
        
        return findings[:5]  # Top 5 achados
    
    def get_top_recommendations(self, scan_data: Dict[str, Any]) -> List[str]:
        """Obter principais recomendações"""
        recommendations = []
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        
        if critical_vulns:
            recommendations.append("Corrigir imediatamente todas as vulnerabilidades críticas")
        
        # Verificar tipos comuns de vulnerabilidades
        vuln_types = [v.get('name', '').lower() for v in vulnerabilities]
        
        if any('sql' in name or 'injection' in name for name in vuln_types):
            recommendations.append("Implementar prepared statements e validação de entrada")
        
        if any('xss' in name or 'script' in name for name in vuln_types):
            recommendations.append("Implementar sanitização de saída e Content Security Policy")
        
        if any('ssl' in name or 'tls' in name for name in vuln_types):
            recommendations.append("Atualizar configurações SSL/TLS e certificados")
        
        # Recomendações gerais
        recommendations.extend([
            "Estabelecer programa de testes de segurança regulares",
            "Implementar monitoramento contínuo de segurança",
            "Treinar equipe em desenvolvimento seguro"
        ])
        
        return recommendations[:5]  # Top 5 recomendações
    
    def assess_compliance_status(self, scan_data: Dict[str, Any]) -> Dict[str, str]:
        """Avaliar status de compliance"""
        compliance = {
            'OWASP_Top_10': 'PARCIAL',
            'PCI_DSS': 'NÃO_CONFORME',
            'ISO_27001': 'PARCIAL',
            'LGPD': 'NECESSITA_REVISÃO'
        }
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        
        # Lógica simplificada de compliance
        if critical_count == 0:
            compliance['OWASP_Top_10'] = 'CONFORME'
            compliance['ISO_27001'] = 'CONFORME'
        elif critical_count > 5:
            compliance['OWASP_Top_10'] = 'NÃO_CONFORME'
            compliance['ISO_27001'] = 'NÃO_CONFORME'
        
        return compliance
    
    async def generate_comparison_report(self, scan_ids: List[str]) -> Dict[str, Any]:
        """Gerar relatório comparativo entre múltiplos scans"""
        try:
            comparison_data = {
                'report_type': 'comparison',
                'generated_at': datetime.now().isoformat(),
                'scans_compared': len(scan_ids),
                'scan_summaries': [],
                'trend_analysis': {},
                'recommendations': []
            }
            
            # Obter dados de cada scan
            scan_data_list = []
            for scan_id in scan_ids:
                scan_data = await self.get_scan_data(scan_id)
                scan_data_list.append(scan_data)
                
                # Resumo do scan
                summary = await self.generate_executive_summary(scan_data)
                comparison_data['scan_summaries'].append(summary)
            
            # Análise de tendências
            comparison_data['trend_analysis'] = self.analyze_trends(scan_data_list)
            
            # Gerar relatório
            filename = f"comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = self.reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(comparison_data, f, indent=2, ensure_ascii=False)
            
            return {
                'report_path': str(filepath),
                'comparison_data': comparison_data
            }
            
        except Exception as e:
            logger.error(f"Erro na geração do relatório comparativo: {str(e)}")
            raise
    
    def analyze_trends(self, scan_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisar tendências entre scans"""
        trends = {
            'vulnerability_trend': 'stable',
            'risk_trend': 'stable',
            'score_trend': 'stable',
            'details': {}
        }
        
        if len(scan_data_list) < 2:
            return trends
        
        # Analisar tendência de vulnerabilidades
        vuln_counts = [len(scan.get('vulnerabilities', [])) for scan in scan_data_list]
        if vuln_counts[-1] > vuln_counts[0]:
            trends['vulnerability_trend'] = 'increasing'
        elif vuln_counts[-1] < vuln_counts[0]:
            trends['vulnerability_trend'] = 'decreasing'
        
        # Analisar tendência de score
        scores = [scan.get('ai_analysis', {}).get('overall_score', 0) for scan in scan_data_list]
        if scores[-1] > scores[0]:
            trends['score_trend'] = 'improving'
        elif scores[-1] < scores[0]:
            trends['score_trend'] = 'declining'
        
        trends['details'] = {
            'vulnerability_counts': vuln_counts,
            'scores': scores,
            'improvement_percentage': ((scores[-1] - scores[0]) / scores[0] * 100) if scores[0] > 0 else 0
        }
        
        return trends
    
    async def generate_scheduled_report(self, target: str, frequency: str = 'weekly') -> Dict[str, Any]:
        """Gerar relatório agendado"""
        try:
            # Obter scans recentes do target
            recent_scans = await self.get_recent_scans(target, frequency)
            
            if not recent_scans:
                return {'error': 'Nenhum scan recente encontrado'}
            
            # Gerar relatório do scan mais recente
            latest_scan = recent_scans[0]
            report_data = await self.generate_report(latest_scan['scan_id'], 'pdf')
            
            # Adicionar análise de tendências se houver múltiplos scans
            if len(recent_scans) > 1:
                scan_ids = [scan['scan_id'] for scan in recent_scans]
                comparison_data = await self.generate_comparison_report(scan_ids)
                report_data['trend_analysis'] = comparison_data['comparison_data']['trend_analysis']
            
            return report_data
            
        except Exception as e:
            logger.error(f"Erro na geração do relatório agendado: {str(e)}")
            raise
    
    async def get_recent_scans(self, target: str, frequency: str) -> List[Dict[str, Any]]:
        """Obter scans recentes para um target"""
        # Em implementação real, buscar do banco de dados
        # Por agora, retornar dados simulados
        
        days_back = {
            'daily': 1,
            'weekly': 7,
            'monthly': 30
        }.get(frequency, 7)
        
        # Simular scans recentes
        recent_scans = []
        for i in range(min(3, days_back)):  # Máximo 3 scans
            scan_date = datetime.now() - timedelta(days=i)
            recent_scans.append({
                'scan_id': f"scan_{target}_{scan_date.strftime('%Y%m%d')}",
                'target': target,
                'date': scan_date.isoformat(),
                'status': 'completed'
            })
        
        return recent_scans
    
    async def generate_dashboard_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gerar dados para dashboard"""
        try:
            dashboard_data = {
                'summary_cards': await self.generate_summary_cards(scan_data),
                'charts_data': await self.generate_charts_data(scan_data),
                'recent_activities': await self.generate_recent_activities(scan_data),
                'risk_indicators': await self.generate_risk_indicators(scan_data)
            }
            
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Erro na geração de dados do dashboard: {str(e)}")
            return {}
    
    async def generate_summary_cards(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Gerar cards de resumo para dashboard"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        ai_analysis = scan_data.get('ai_analysis', {})
        
        cards = [
            {
                'title': 'Score Geral',
                'value': f"{ai_analysis.get('overall_score', 0)}/10",
                'icon': 'shield',
                'color': 'blue'
            },
            {
                'title': 'Vulnerabilidades',
                'value': len(vulnerabilities),
                'icon': 'alert-triangle',
                'color': 'red'
            },
            {
                'title': 'Nível de Risco',
                'value': ai_analysis.get('risk_assessment', {}).get('risk_level', 'UNKNOWN'),
                'icon': 'trending-up',
                'color': 'orange'
            },
            {
                'title': 'Status',
                'value': scan_data.get('status', 'unknown'),
                'icon': 'check-circle',
                'color': 'green'
            }
        ]
        
        return cards
    
    async def generate_charts_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gerar dados para gráficos"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        
        # Distribuição por severidade
        severity_data = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            severity_data[severity] = severity_data.get(severity, 0) + 1
        
        # Distribuição por porta
        port_data = {}
        for vuln in vulnerabilities:
            port = vuln.get('port', 'Unknown')
            port_data[str(port)] = port_data.get(str(port), 0) + 1
        
        charts_data = {
            'severity_distribution': {
                'labels': list(severity_data.keys()),
                'data': list(severity_data.values())
            },
            'port_distribution': {
                'labels': list(port_data.keys())[:10],  # Top 10 portas
                'data': list(port_data.values())[:10]
            }
        }
        
        return charts_data
    
    async def generate_recent_activities(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Gerar atividades recentes"""
        activities = [
            {
                'timestamp': scan_data.get('scan_date', datetime.now().isoformat()),
                'action': 'Scan Completed',
                'description': f"Security scan completed for {scan_data.get('target', 'unknown')}",
                'icon': 'activity',
                'status': 'success'
            }
        ]
        
        # Adicionar atividades baseadas em vulnerabilidades críticas
        vulnerabilities = scan_data.get('vulnerabilities', [])
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        
        for vuln in critical_vulns[:3]:  # Máximo 3
            activities.append({
                'timestamp': scan_data.get('scan_date', datetime.now().isoformat()),
                'action': 'Critical Vulnerability Found',
                'description': vuln.get('name', 'Unknown vulnerability'),
                'icon': 'alert-circle',
                'status': 'error'
            })
        
        return activities
    
    async def generate_risk_indicators(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Gerar indicadores de risco"""
        vulnerabilities = scan_data.get('vulnerabilities', [])
        ai_analysis = scan_data.get('ai_analysis', {})
        
        # Calcular indicadores
        total_vulns = len(vulnerabilities)
        critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        
        risk_score = ai_analysis.get('risk_assessment', {}).get('overall_risk_score', 0)
        
        indicators = {
            'overall_risk': {
                'value': risk_score,
                'status': 'high' if risk_score > 0.7 else 'medium' if risk_score > 0.4 else 'low',
                'trend': 'stable'
            },
            'vulnerability_density': {
                'value': total_vulns,
                'status': 'high' if total_vulns > 10 else 'medium' if total_vulns > 5 else 'low',
                'trend': 'stable'
            },
            'critical_exposure': {
                'value': critical_vulns + high_vulns,
                'status': 'high' if (critical_vulns + high_vulns) > 5 else 'medium' if (critical_vulns + high_vulns) > 2 else 'low',
                'trend': 'stable'
            }
        }
        
        return indicators
    
    async def cleanup_old_reports(self, days_to_keep: int = 30):
        """Limpar relatórios antigos"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            deleted_count = 0
            for report_file in self.reports_dir.glob("*"):
                if report_file.is_file():
                    # Verificar data de modificação
                    file_modified = datetime.fromtimestamp(report_file.stat().st_mtime)
                    
                    if file_modified < cutoff_date:
                        report_file.unlink()
                        deleted_count += 1
            
            logger.info(f"Limpeza concluída: {deleted_count} relatórios removidos")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Erro na limpeza de relatórios: {str(e)}")
            return 0