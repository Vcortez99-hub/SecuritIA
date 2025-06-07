# Análise de falsos positivos
            analysis['false_positive_analysis'] = await self.analyze_false_positives(vulnerabilities)
            
        except Exception as e:
            logger.error(f"Erro na análise de vulnerabilidades: {str(e)}")
        
        return analysis
    
    def categorize_vulnerabilities(self, vuln_types: List[str]) -> Dict[str, Any]:
        """Categorizar vulnerabilidades por tipo"""
        categories = {
            'injection': [],
            'authentication': [],
            'authorization': [],
            'data_exposure': [],
            'security_misconfiguration': [],
            'vulnerable_components': [],
            'other': []
        }
        
        patterns = {
            'injection': ['sql', 'xss', 'injection', 'script', 'command'],
            'authentication': ['auth', 'login', 'password', 'credential', 'session'],
            'authorization': ['access', 'privilege', 'permission', 'bypass'],
            'data_exposure': ['disclosure', 'exposure', 'leak', 'information'],
            'security_misconfiguration': ['config', 'default', 'header', 'ssl', 'tls'],
            'vulnerable_components': ['version', 'outdated', 'cve', 'component']
        }
        
        for vuln_type in vuln_types:
            categorized = False
            for category, keywords in patterns.items():
                if any(keyword in vuln_type for keyword in keywords):
                    categories[category].append(vuln_type)
                    categorized = True
                    break
            
            if not categorized:
                categories['other'].append(vuln_type)
        
        # Calcular estatísticas
        result = {}
        for category, vulns in categories.items():
            result[category] = {
                'count': len(vulns),
                'percentage': (len(vulns) / len(vuln_types) * 100) if vuln_types else 0,
                'vulnerabilities': vulns[:5]  # Primeiras 5 para exemplo
            }
        
        return result
    
    async def cluster_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Agrupar vulnerabilidades similares usando clustering"""
        try:
            if len(vulnerabilities) < 3:
                return {'message': 'Poucos dados para clustering'}
            
            # Extrair textos para análise
            texts = []
            for vuln in vulnerabilities:
                text = f"{vuln.get('name', '')} {vuln.get('description', '')}"
                texts.append(text)
            
            # Vetorização TF-IDF
            vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
            tfidf_matrix = vectorizer.fit_transform(texts)
            
            # Clustering K-means
            n_clusters = min(5, len(vulnerabilities) // 2 + 1)
            kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            clusters = kmeans.fit_predict(tfidf_matrix)
            
            # Organizar resultados
            cluster_analysis = {}
            for i in range(n_clusters):
                cluster_vulns = [vulnerabilities[j] for j, cluster in enumerate(clusters) if cluster == i]
                cluster_analysis[f'cluster_{i}'] = {
                    'count': len(cluster_vulns),
                    'vulnerabilities': [v.get('name', 'Unknown') for v in cluster_vulns],
                    'common_theme': self.extract_cluster_theme(cluster_vulns)
                }
            
            return cluster_analysis
            
        except Exception as e:
            logger.error(f"Erro no clustering: {str(e)}")
            return {'error': str(e)}
    
    def extract_cluster_theme(self, cluster_vulns: List[Dict[str, Any]]) -> str:
        """Extrair tema comum de um cluster"""
        names = [v.get('name', '').lower() for v in cluster_vulns]
        
        # Encontrar palavras mais comuns
        words = []
        for name in names:
            words.extend(name.split())
        
        word_count = {}
        for word in words:
            if len(word) > 3:  # Ignorar palavras muito curtas
                word_count[word] = word_count.get(word, 0) + 1
        
        if word_count:
            most_common = max(word_count, key=word_count.get)
            return f"Vulnerabilidades relacionadas a '{most_common}'"
        
        return "Tema não identificado"
    
    async def predict_exploitability(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Predizer exploitabilidade das vulnerabilidades"""
        predictions = {
            'high_exploitability': [],
            'medium_exploitability': [],
            'low_exploitability': [],
            'exploit_likelihood_scores': {}
        }
        
        try:
            for vuln in vulnerabilities:
                score = self.calculate_exploit_score(vuln)
                vuln_name = vuln.get('name', 'Unknown')
                
                predictions['exploit_likelihood_scores'][vuln_name] = score
                
                if score >= 0.8:
                    predictions['high_exploitability'].append(vuln_name)
                elif score >= 0.5:
                    predictions['medium_exploitability'].append(vuln_name)
                else:
                    predictions['low_exploitability'].append(vuln_name)
            
        except Exception as e:
            logger.error(f"Erro na predição de exploitabilidade: {str(e)}")
        
        return predictions
    
    def calculate_exploit_score(self, vuln: Dict[str, Any]) -> float:
        """Calcular score de exploitabilidade"""
        score = 0.0
        
        # Fatores baseados na severidade
        severity = vuln.get('severity', 'LOW')
        severity_scores = {'CRITICAL': 0.9, 'HIGH': 0.7, 'MEDIUM': 0.5, 'LOW': 0.3, 'INFO': 0.1}
        score += severity_scores.get(severity, 0.3)
        
        # Fatores baseados no CVSS
        cvss_score = vuln.get('cvss_score', 0)
        if cvss_score:
            score += min(cvss_score / 10.0, 0.9)
        
        # Fatores baseados no tipo de vulnerabilidade
        name = vuln.get('name', '').lower()
        if any(keyword in name for keyword in ['injection', 'rce', 'command']):
            score += 0.3
        elif any(keyword in name for keyword in ['xss', 'csrf']):
            score += 0.2
        
        # Fatores baseados na porta/serviço
        port = vuln.get('port', 0)
        if port in [22, 3389, 21]:  # SSH, RDP, FTP
            score += 0.2
        elif port in [80, 443]:  # HTTP/HTTPS
            score += 0.1
        
        return min(score, 1.0)
    
    async def analyze_false_positives(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisar possíveis falsos positivos"""
        analysis = {
            'potential_false_positives': [],
            'confidence_scores': {},
            'validation_needed': []
        }
        
        try:
            for vuln in vulnerabilities:
                confidence = self.calculate_confidence_score(vuln)
                vuln_name = vuln.get('name', 'Unknown')
                
                analysis['confidence_scores'][vuln_name] = confidence
                
                if confidence < 0.6:
                    analysis['potential_false_positives'].append({
                        'name': vuln_name,
                        'confidence': confidence,
                        'reasons': self.get_low_confidence_reasons(vuln)
                    })
                elif confidence < 0.8:
                    analysis['validation_needed'].append(vuln_name)
            
        except Exception as e:
            logger.error(f"Erro na análise de falsos positivos: {str(e)}")
        
        return analysis
    
    def calculate_confidence_score(self, vuln: Dict[str, Any]) -> float:
        """Calcular score de confiança da vulnerabilidade"""
        confidence = 0.5  # Score base
        
        # Fatores que aumentam confiança
        if vuln.get('cvss_score'):
            confidence += 0.2
        
        if vuln.get('port') and vuln.get('service'):
            confidence += 0.2
        
        if vuln.get('description') and len(vuln.get('description', '')) > 50:
            confidence += 0.1
        
        # Fatores que diminuem confiança
        name = vuln.get('name', '').lower()
        if 'potential' in name or 'possible' in name:
            confidence -= 0.2
        
        if vuln.get('severity') == 'INFO':
            confidence -= 0.1
        
        return max(0.0, min(confidence, 1.0))
    
    def get_low_confidence_reasons(self, vuln: Dict[str, Any]) -> List[str]:
        """Obter razões para baixa confiança"""
        reasons = []
        
        if not vuln.get('cvss_score'):
            reasons.append("CVSS score não disponível")
        
        if not vuln.get('description') or len(vuln.get('description', '')) < 20:
            reasons.append("Descrição insuficiente")
        
        name = vuln.get('name', '').lower()
        if 'potential' in name or 'possible' in name:
            reasons.append("Indicadores de incerteza no nome")
        
        if vuln.get('severity') == 'INFO':
            reasons.append("Severidade informativa")
        
        return reasons
    
    async def analyze_pentest_patterns(self, pentest_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analisar padrões nos resultados do pentest"""
        analysis = {
            'attack_patterns': {},
            'success_rate': {},
            'time_analysis': {},
            'technique_effectiveness': {}
        }
        
        try:
            findings = pentest_results.get('findings', [])
            
            # Analisar padrões de ataque
            attack_types = {}
            for finding in findings:
                attack_type = finding.get('category', 'unknown')
                if attack_type not in attack_types:
                    attack_types[attack_type] = []
                attack_types[attack_type].append(finding)
            
            analysis['attack_patterns'] = {
                'total_attacks': len(findings),
                'attack_distribution': {k: len(v) for k, v in attack_types.items()},
                'most_successful': self.find_most_successful_attacks(attack_types)
            }
            
            # Taxa de sucesso por categoria
            for category, category_findings in attack_types.items():
                successful = len([f for f in category_findings if f.get('risk_level') in ['high', 'critical']])
                analysis['success_rate'][category] = {
                    'total_attempts': len(category_findings),
                    'successful': successful,
                    'success_rate': successful / len(category_findings) if category_findings else 0
                }
            
        except Exception as e:
            logger.error(f"Erro na análise de padrões de pentest: {str(e)}")
        
        return analysis
    
    def find_most_successful_attacks(self, attack_types: Dict[str, List]) -> List[str]:
        """Encontrar ataques mais bem-sucedidos"""
        success_scores = {}
        
        for attack_type, findings in attack_types.items():
            score = 0
            for finding in findings:
                if finding.get('risk_level') == 'critical':
                    score += 3
                elif finding.get('risk_level') == 'high':
                    score += 2
                elif finding.get('risk_level') == 'medium':
                    score += 1
            
            success_scores[attack_type] = score
        
        # Retornar top 3
        sorted_attacks = sorted(success_scores.items(), key=lambda x: x[1], reverse=True)
        return [attack for attack, score in sorted_attacks[:3]]
    
    async def analyze_threat_intelligence(self, dark_web_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisar inteligência de ameaças da dark web"""
        analysis = {
            'threat_level': 'LOW',
            'active_threats': [],
            'threat_trends': {},
            'attribution': {},
            'timeline_analysis': {}
        }
        
        try:
            if not dark_web_findings:
                return analysis
            
            # Calcular nível de ameaça
            threat_scores = []
            for finding in dark_web_findings:
                risk_level = finding.get('risk_level', 'low')
                risk_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
                threat_scores.append(risk_scores.get(risk_level, 1))
            
            avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 1
            
            if avg_threat >= 3.5:
                analysis['threat_level'] = 'CRITICAL'
            elif avg_threat >= 2.5:
                analysis['threat_level'] = 'HIGH'
            elif avg_threat >= 1.5:
                analysis['threat_level'] = 'MEDIUM'
            
            # Identificar ameaças ativas
            analysis['active_threats'] = [
                f for f in dark_web_findings 
                if f.get('risk_level') in ['high', 'critical']
            ]
            
            # Analisar tendências
            threat_types = {}
            for finding in dark_web_findings:
                threat_type = finding.get('type', 'unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            analysis['threat_trends'] = threat_types
            
        except Exception as e:
            logger.error(f"Erro na análise de inteligência de ameaças: {str(e)}")
        
        return analysis
    
    async def calculate_overall_risk(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calcular risco geral do alvo"""
        risk_assessment = {
            'overall_risk_score': 0.0,
            'risk_level': 'LOW',
            'contributing_factors': [],
            'risk_breakdown': {},
            'trend_analysis': {}
        }
        
        try:
            total_score = 0.0
            factor_count = 0
            
            # Pontuação baseada em vulnerabilidades
            vulnerabilities = scan_results.get('vulnerabilities', [])
            if vulnerabilities:
                vuln_score = self.calculate_vulnerability_risk_score(vulnerabilities)
                total_score += vuln_score
                factor_count += 1
                risk_assessment['risk_breakdown']['vulnerabilities'] = vuln_score
                
                if vuln_score > 0.7:
                    risk_assessment['contributing_factors'].append('High number of critical vulnerabilities')
            
            # Pontuação baseada em pentest
            pentest_results = scan_results.get('pentest_results')
            if pentest_results:
                pentest_score = self.calculate_pentest_risk_score(pentest_results)
                total_score += pentest_score
                factor_count += 1
                risk_assessment['risk_breakdown']['pentest'] = pentest_score
                
                if pentest_score > 0.6:
                    risk_assessment['contributing_factors'].append('Successful penetration test attacks')
            
            # Pontuação baseada em dark web
            dark_web_findings = scan_results.get('dark_web_findings', [])
            if dark_web_findings:
                darkweb_score = self.calculate_darkweb_risk_score(dark_web_findings)
                total_score += darkweb_score
                factor_count += 1
                risk_assessment['risk_breakdown']['dark_web'] = darkweb_score
                
                if darkweb_score > 0.5:
                    risk_assessment['contributing_factors'].append('Active threats identified on dark web')
            
            # Calcular score final
            if factor_count > 0:
                risk_assessment['overall_risk_score'] = total_score / factor_count
            
            # Determinar nível de risco
            score = risk_assessment['overall_risk_score']
            if score >= 0.8:
                risk_assessment['risk_level'] = 'CRITICAL'
            elif score >= 0.6:
                risk_assessment['risk_level'] = 'HIGH'
            elif score >= 0.4:
                risk_assessment['risk_level'] = 'MEDIUM'
            else:
                risk_assessment['risk_level'] = 'LOW'
            
        except Exception as e:
            logger.error(f"Erro no cálculo de risco geral: {str(e)}")
        
        return risk_assessment
    
    def calculate_vulnerability_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calcular score de risco baseado em vulnerabilidades"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0.0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            weight = self.risk_weights.get(severity, 0.2)
            
            # Adicionar peso baseado no tipo
            name = vuln.get('name', '').lower()
            for vuln_type, type_weight in self.risk_weights.items():
                if vuln_type in name:
                    weight += type_weight * 0.3
                    break
            
            total_score += min(weight, 1.0)
        
        # Normalizar pelo número de vulnerabilidades
        return min(total_score / len(vulnerabilities), 1.0)
    
    def calculate_pentest_risk_score(self, pentest_results: Dict[str, Any]) -> float:
        """Calcular score de risco baseado em pentest"""
        findings = pentest_results.get('findings', [])
        if not findings:
            return 0.0
        
        high_risk_count = len([f for f in findings if f.get('risk_level') in ['critical', 'high']])
        return min(high_risk_count / len(findings), 1.0)
    
    def calculate_darkweb_risk_score(self, dark_web_findings: List[Dict[str, Any]]) -> float:
        """Calcular score de risco baseado em achados da dark web"""
        if not dark_web_findings:
            return 0.0
        
        risk_sum = 0.0
        for finding in dark_web_findings:
            risk_level = finding.get('risk_level', 'low')
            risk_values = {'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4}
            risk_sum += risk_values.get(risk_level, 0.4)
        
        return min(risk_sum / len(dark_web_findings), 1.0)
    
    async def analyze_attack_surface(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analisar superfície de ataque"""
        attack_surface = {
            'network_exposure': {},
            'web_exposure': {},
            'service_exposure': {},
            'data_exposure': {},
            'total_surface_score': 0.0
        }
        
        try:
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            # Analisar exposição de rede
            network_ports = set()
            web_services = []
            exposed_services = []
            
            for vuln in vulnerabilities:
                port = vuln.get('port')
                service = vuln.get('service', '')
                
                if port:
                    network_ports.add(port)
                    
                    if port in [80, 443, 8080, 8443]:
                        web_services.append(service)
                    else:
                        exposed_services.append(f"{service}:{port}")
            
            attack_surface['network_exposure'] = {
                'open_ports': len(network_ports),
                'web_services': len(web_services),
                'other_services': len(exposed_services),
                'critical_ports': [p for p in network_ports if p in [22, 3389, 21, 23]]
            }
            
            # Calcular score da superfície de ataque
            surface_score = 0.0
            surface_score += min(len(network_ports) / 10.0, 1.0) * 0.3
            surface_score += min(len(web_services) / 5.0, 1.0) * 0.3
            surface_score += min(len(exposed_services) / 10.0, 1.0) * 0.4
            
            attack_surface['total_surface_score'] = surface_score
            
        except Exception as e:
            logger.error(f"Erro na análise da superfície de ataque: {str(e)}")
        
        return attack_surface
    
    async def check_compliance(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Verificar compliance com standards de segurança"""
        compliance = {
            'owasp_top10': {},
            'pci_dss': {},
            'iso27001': {},
            'nist': {},
            'overall_compliance_score': 0.0
        }
        
        try:
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            # Verificar OWASP Top 10
            owasp_categories = {
                'A01_Broken_Access_Control': 0,
                'A02_Cryptographic_Failures': 0,
                'A03_Injection': 0,
                'A04_Insecure_Design': 0,
                'A05_Security_Misconfiguration': 0,
                'A06_Vulnerable_Components': 0,
                'A07_Authentication_Failures': 0,
                'A08_Software_Data_Integrity': 0,
                'A09_Security_Logging': 0,
                'A10_Server_Side_Request_Forgery': 0
            }
            
            for vuln in vulnerabilities:
                name = vuln.get('name', '').lower()
                
                if any(keyword in name for keyword in ['injection', 'sql', 'xss']):
                    owasp_categories['A03_Injection'] += 1
                elif any(keyword in name for keyword in ['auth', 'credential']):
                    owasp_categories['A07_Authentication_Failures'] += 1
                elif any(keyword in name for keyword in ['config', 'default']):
                    owasp_categories['A05_Security_Misconfiguration'] += 1
                elif any(keyword in name for keyword in ['ssl', 'tls', 'crypto']):
                    owasp_categories['A02_Cryptographic_Failures'] += 1
            
            compliance['owasp_top10'] = owasp_categories
            
            # Calcular score de compliance geral
            total_issues = sum(owasp_categories.values())
            compliance_score = max(0.0, 1.0 - (total_issues / 50.0))  # Normalizar
            compliance['overall_compliance_score'] = compliance_score
            
        except Exception as e:
            logger.error(f"Erro na verificação de compliance: {str(e)}")
        
        return compliance
    
    async def generate_smart_recommendations(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Gerar recomendações inteligentes baseadas na análise"""
        recommendations = {
            'immediate_actions': [],
            'short_term_actions': [],
            'long_term_actions': [],
            'risk_mitigation': [],
            'prioritized_fixes': []
        }
        
        try:
            # Recomendações baseadas no risco geral
            risk_level = analysis.get('risk_assessment', {}).get('risk_level', 'LOW')
            
            if risk_level == 'CRITICAL':
                recommendations['immediate_actions'].extend([
                    'Implementar resposta a incidentes imediatamente',
                    'Isolar sistemas críticos comprometidos',
                    'Notificar stakeholders e autoridades'
                ])
            
            # Recomendações baseadas em vulnerabilidades
            vuln_analysis = analysis.get('vulnerability_analysis', {})
            high_exploit = vuln_analysis.get('exploit_prediction', {}).get('high_exploitability', [])
            
            if high_exploit:
                recommendations['immediate_actions'].append(
                    f'Corrigir vulnerabilidades de alta exploitabilidade: {", ".join(high_exploit[:3])}'
                )
            
            # Recomendações baseadas em compliance
            compliance = analysis.get('compliance_check', {})
            owasp_issues = compliance.get('owasp_top10', {})
            
            for category, count in owasp_issues.items():
                if count > 0:
                    recommendations['short_term_actions'].append(
                        f'Abordar {count} issues de {category.replace("_", " ")}'
                    )
            
            # Recomendações baseadas em superfície de ataque
            attack_surface = analysis.get('attack_surface', {})
            network_exposure = attack_surface.get('network_exposure', {})
            
            if network_exposure.get('critical_ports'):
                recommendations['immediate_actions'].append(
                    'Revisar exposição de portas críticas (SSH, RDP, FTP)'
                )
            
            # Recomendações baseadas em threat intelligence
            threat_intel = analysis.get('threat_intelligence', {})
            if threat_intel.get('threat_level') in ['HIGH', 'CRITICAL']:
                recommendations['immediate_actions'].append(
                    'Implementar monitoramento adicional devido a ameaças ativas'
                )
            
            # Priorizar correções
            recommendations['prioritized_fixes'] = self.prioritize_fixes(analysis)
            
        except Exception as e:
            logger.error(f"Erro na geração de recomendações: {str(e)}")
        
        return recommendations
    
    def prioritize_fixes(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Priorizar correções baseado na análise"""
        fixes = []
        
        # Extrair vulnerabilidades de alta prioridade
        vuln_analysis = analysis.get('vulnerability_analysis', {})
        high_exploit = vuln_analysis.get('exploit_prediction', {}).get('high_exploitability', [])
        
        for vuln in high_exploit[:5]:  # Top 5
            fixes.append({
                'vulnerability': vuln,
                'priority': 'CRITICAL',
                'effort': 'Medium',
                'impact': 'High'
            })
        
        return fixes
    
    def calculate_overall_score(self, analysis: Dict[str, Any]) -> float:
        """Calcular score geral da análise"""
        try:
            risk_score = analysis.get('risk_assessment', {}).get('overall_risk_score', 0.5)
            compliance_score = analysis.get('compliance_check', {}).get('overall_compliance_score', 0.5)
            surface_score = analysis.get('attack_surface', {}).get('total_surface_score', 0.5)
            
            # Score inverso (menor é melhor para segurança)
            overall_score = 10.0 * (1.0 - ((risk_score + (1.0 - compliance_score) + surface_score) / 3.0))
            
            return round(max(0.0, min(overall_score, 10.0)), 2)
            
        except Exception as e:
            logger.error(f"Erro no cálculo do score geral: {str(e)}")
            return 5.0
    
    async def generate_ai_summary(self, analysis: Dict[str, Any]) -> str:
        """Gerar resumo da análise usando IA"""
        try:
            if self.openai_client:
                # Usar OpenAI para gerar resumo
                prompt = self.create_summary_prompt(analysis)
                
                response = await self.openai_client.ChatCompletion.acreate(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=500
                )
                
                return response.choices[0].message.content
            else:
                # Gerar resumo local
                return self.generate_local_summary(analysis)
                
        except Exception as e:
            logger.error(f"Erro na geração de resumo IA: {str(e)}")
            return self.generate_local_summary(analysis)
    
    def create_summary_prompt(self, analysis: Dict[str, Any]) -> str:
        """Criar prompt para resumo IA"""
        risk_level = analysis.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        vuln_count = analysis.get('vulnerability_analysis', {}).get('total_vulnerabilities', 0)
        score = analysis.get('overall_score', 0)
        
        prompt = f"""
        Analise os seguintes resultados de segurança e forneça um resumo executivo:
        
        - Nível de Risco Geral: {risk_level}
        - Vulnerabilidades Encontradas: {vuln_count}
        - Score de Segurança: {score}/10
        
        Gere um resumo executivo de 2-3 parágrafos destacando:
        1. Status geral de segurança
        2. Principais riscos identificados
        3. Recomendações prioritárias
        
        Mantenha linguagem técnica mas acessível para executivos.
        """
        
        return prompt
    
    def generate_local_summary(self, analysis: Dict[str, Any]) -> str:
        """Gerar resumo local sem IA externa"""
        risk_level = analysis.get('risk_assessment', {}).get('risk_level', 'UNKNOWN')
        vuln_count = analysis.get('vulnerability_analysis', {}).get('total_vulnerabilities', 0)
        score = analysis.get('overall_score', 0)
        
        summary = f"""
        RESUMO EXECUTIVO DE SEGURANÇA
        
        O sistema analisado apresenta um nível de risco {risk_level.lower()} com {vuln_count} vulnerabilidades 
        identificadas e score de segurança de {score}/10.
        
        """
        
        if risk_level in ['CRITICAL', 'HIGH']:
            summary += """Ação imediata é necessária para mitigar os riscos identificados. 
        Recomenda-se implementar medidas de segurança urgentes e considerar isolamento 
        de sistemas críticos até que as vulnerabilidades sejam corrigidas.
        """
        elif risk_level == 'MEDIUM':
            summary += """O sistema requer atenção para melhorar sua postura de segurança. 
        As vulnerabilidades identificadas devem ser corrigidas em ordem de prioridade 
        para reduzir a superfície de ataque.
        """
        else:
            summary += """O sistema apresenta uma postura de segurança adequada, mas 
        melhorias contínuas são recomendadas para manter a proteção contra ameaças emergentes.
        """
        
        return summary.strip()import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
import json
import numpy as np
from datetime import datetime
import re
import openai
import os
from transformers import pipeline, AutoTokenizer, AutoModel
import torch
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

class AIAnalyzer:
    def __init__(self):
        self.openai_client = None
        self.local_models = {}
        self.vulnerability_patterns = self.load_vulnerability_patterns()
        self.risk_weights = self.load_risk_weights()
        
        # Inicializar modelos
        asyncio.create_task(self.initialize_models())
    
    async def initialize_models(self):
        """Inicializar modelos de IA"""
        try:
            logger.info("Inicializando modelos de IA...")
            
            # Configurar OpenAI se disponível
            openai_key = os.getenv("OPENAI_API_KEY")
            if openai_key:
                openai.api_key = openai_key
                self.openai_client = openai
                logger.info("OpenAI configurado")
            
            # Carregar modelos locais
            try:
                # Modelo para análise de sentimento/classificação
                self.local_models['classifier'] = pipeline(
                    "text-classification",
                    model="distilbert-base-uncased-finetuned-sst-2-english",
                    return_all_scores=True
                )
                
                # Modelo para embeddings
                self.local_models['embedder'] = pipeline(
                    "feature-extraction",
                    model="sentence-transformers/all-MiniLM-L6-v2"
                )
                
                logger.info("Modelos locais carregados")
                
            except Exception as e:
                logger.warning(f"Erro ao carregar modelos locais: {str(e)}")
            
        except Exception as e:
            logger.error(f"Erro na inicialização dos modelos: {str(e)}")
    
    def load_vulnerability_patterns(self) -> Dict[str, List[str]]:
        """Carregar padrões de vulnerabilidades"""
        return {
            'sql_injection': [
                r"sql.*error",
                r"mysql_fetch",
                r"ora-\d+",
                r"microsoft.*ole.*db",
                r"unclosed.*quotation.*mark"
            ],
            'xss': [
                r"<script.*?>",
                r"javascript:",
                r"onerror.*=",
                r"onload.*=",
                r"alert\s*\("
            ],
            'lfi': [
                r"root:.*:/bin/",
                r"etc/passwd",
                r"windows/system32",
                r"boot\.ini"
            ],
            'rce': [
                r"command.*executed",
                r"sh:.*command.*not.*found",
                r"uid=\d+.*gid=\d+",
                r"whoami"
            ],
            'path_traversal': [
                r"\.\./\.\./",
                r"\.\.\\\.\.\\",
                r"directory.*traversal"
            ]
        }
    
    def load_risk_weights(self) -> Dict[str, float]:
        """Carregar pesos de risco para diferentes tipos de vulnerabilidades"""
        return {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.6,
            'LOW': 0.4,
            'INFO': 0.2,
            'sql_injection': 0.9,
            'xss': 0.7,
            'rce': 1.0,
            'lfi': 0.8,
            'csrf': 0.6,
            'open_port': 0.5,
            'ssl_issue': 0.7,
            'default_creds': 0.9,
            'info_disclosure': 0.4
        }
    
    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analisar resultados completos do scan"""
        try:
            logger.info("Iniciando análise IA dos resultados")
            
            analysis = {
                'scan_id': scan_results.get('scan_id'),
                'target': scan_results.get('target'),
                'analysis_timestamp': datetime.now().isoformat(),
                'vulnerability_analysis': {},
                'risk_assessment': {},
                'pattern_analysis': {},
                'threat_intelligence': {},
                'recommendations': {},
                'attack_surface': {},
                'compliance_check': {},
                'overall_score': 0.0
            }
            
            # 1. Análise de vulnerabilidades
            vulnerabilities = scan_results.get('vulnerabilities', [])
            if vulnerabilities:
                analysis['vulnerability_analysis'] = await self.analyze_vulnerabilities(vulnerabilities)
            
            # 2. Análise de resultados de pentest
            pentest_results = scan_results.get('pentest_results')
            if pentest_results:
                analysis['pattern_analysis'] = await self.analyze_pentest_patterns(pentest_results)
            
            # 3. Análise de achados da dark web
            dark_web_findings = scan_results.get('dark_web_findings', [])
            if dark_web_findings:
                analysis['threat_intelligence'] = await self.analyze_threat_intelligence(dark_web_findings)
            
            # 4. Avaliação de risco geral
            analysis['risk_assessment'] = await self.calculate_overall_risk(scan_results)
            
            # 5. Análise da superfície de ataque
            analysis['attack_surface'] = await self.analyze_attack_surface(scan_results)
            
            # 6. Verificação de compliance
            analysis['compliance_check'] = await self.check_compliance(scan_results)
            
            # 7. Gerar recomendações inteligentes
            analysis['recommendations'] = await self.generate_smart_recommendations(analysis)
            
            # 8. Score geral
            analysis['overall_score'] = self.calculate_overall_score(analysis)
            
            logger.info(f"Análise IA concluída. Score geral: {analysis['overall_score']}")
            return analysis
            
        except Exception as e:
            logger.error(f"Erro na análise IA: {str(e)}")
            return {'error': str(e)}
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analisar vulnerabilidades usando IA"""
        analysis = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': {},
            'vulnerability_types': {},
            'clustering_analysis': {},
            'exploit_prediction': {},
            'false_positive_analysis': {}
        }
        
        try:
            # Distribuição por severidade
            severities = [v.get('severity', 'UNKNOWN') for v in vulnerabilities]
            for severity in set(severities):
                analysis['severity_distribution'][severity] = severities.count(severity)
            
            # Tipos de vulnerabilidades
            vuln_types = [v.get('name', 'Unknown').lower() for v in vulnerabilities]
            analysis['vulnerability_types'] = self.categorize_vulnerabilities(vuln_types)
            
            # Clustering de vulnerabilidades similares
            analysis['clustering_analysis'] = await self.cluster_vulnerabilities(vulnerabilities)
            
            # Predição de exploitabilidade
            analysis['exploit_prediction'] = await self.predict_exploitability(vulnerabilities)
            
            # Análise de falsos positivos
            analysis['false_positive_analysis'] = await self.analyze_false_positives(vulnerabilities)