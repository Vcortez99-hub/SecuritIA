#!/usr/bin/env python3
"""
SECURIT IA - Advanced Cybersecurity Vulnerability Scanner with AI Integration
Complete vulnerability assessment platform with AI-powered analysis and recommendations
"""

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import asyncio
import logging
import json
import os
import socket
import ssl
import time
import uuid
from datetime import datetime
from contextlib import asynccontextmanager
import concurrent.futures
import re
import hashlib
import ipaddress
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import sqlite3
from services.auth import auth_manager, authenticate_user, create_access_token
from fastapi import Header
from fastapi.security import HTTPBearer
from fastapi import Form
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Form
from typing import Optional



# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('securit_ia.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variables for scan management
active_scans = {}
scan_results = {}

# Vulnerability severity mapping
SEVERITY_SCORES = {
    'CRITICAL': 10,
    'HIGH': 8,
    'MEDIUM': 5,
    'LOW': 3,
    'INFO': 1
}

# Enhanced vulnerability database with AI-powered analysis
VULNERABILITY_DATABASE = {
    'web_vulnerabilities': {
        'sql_injection': {
            'severity': 'CRITICAL',
            'cvss_score': 9.8,
            'description': 'SQL Injection vulnerabilities allow attackers to manipulate database queries',
            'impact': 'Complete database compromise, data theft, privilege escalation',
            'ai_context': 'Modern web applications with dynamic SQL queries are highly susceptible',
            'remediation_priority': 1,
            'business_impact': 'Severe - Complete data breach possible'
        },
        'xss': {
            'severity': 'HIGH',
            'cvss_score': 7.2,
            'description': 'Cross-Site Scripting allows injection of malicious scripts',
            'impact': 'Session hijacking, credential theft, defacement',
            'ai_context': 'Client-side attacks targeting user browsers and sessions',
            'remediation_priority': 2,
            'business_impact': 'High - User data and sessions at risk'
        },
        'csrf': {
            'severity': 'MEDIUM',
            'cvss_score': 6.1,
            'description': 'Cross-Site Request Forgery enables unauthorized actions',
            'impact': 'Unauthorized state changes, account takeover',
            'ai_context': 'Social engineering attacks leveraging user trust',
            'remediation_priority': 3,
            'business_impact': 'Medium - Unauthorized actions possible'
        }
    },
    'network_vulnerabilities': {
        'open_ports': {
            'severity': 'VARIES',
            'description': 'Unnecessary open ports increase attack surface',
            'ai_context': 'Each open port represents a potential entry point',
            'remediation_priority': 4
        },
        'weak_ssl': {
            'severity': 'HIGH',
            'cvss_score': 7.4,
            'description': 'Weak SSL/TLS configurations enable man-in-the-middle attacks',
            'impact': 'Data interception, credential theft, session hijacking',
            'ai_context': 'Transport layer security is fundamental to web security',
            'remediation_priority': 2,
            'business_impact': 'High - All communications at risk'
        }
    }
}

# AI-powered vulnerability patterns with context
ENHANCED_VULN_PATTERNS = {
    'sql_injection': {
        'patterns': [
            r"(?i)(mysql_fetch_array|mysql_num_rows|pg_query|mssql_query)",
            r"(?i)(syntax.*error|mysql.*error|postgresql.*error|oracle.*error)",
            r"(?i)(warning.*mysql|warning.*postgresql|warning.*sqlite)",
            r"(?i)(unclosed.*quotation.*mark|unterminated.*string)",
            r"(?i)(you have an error in your sql syntax)",
            r"(?i)(ora-\d+.*error)",
            r"(?i)(microsoft.*odbc.*sql server driver)"
        ],
        'confidence_weights': [0.9, 0.95, 0.8, 0.85, 0.98, 0.92, 0.88],
        'context_indicators': ['database', 'query', 'sql', 'select', 'insert', 'update']
    },
    'xss': {
        'patterns': [
            r"(?i)(<script[^>]*>.*</script>)",
            r"(?i)(javascript:)",
            r"(?i)(onerror\s*=|onload\s*=|onclick\s*=)",
            r"(?i)(<iframe|<object|<embed|<applet)",
            r"(?i)(alert\(|confirm\(|prompt\()"
        ],
        'confidence_weights': [0.95, 0.9, 0.85, 0.8, 0.92],
        'context_indicators': ['html', 'dom', 'browser', 'client']
    },
    'lfi': {
        'patterns': [
            r"(?i)(root:.*:/bin/|etc/passwd|boot\.ini|win\.ini)",
            r"(?i)(windows/system32|/etc/shadow|/proc/version)",
            r"(?i)(\.\.\/|\.\.\\|\.\./|\.\.\\"
        ],
        'confidence_weights': [0.98, 0.95, 0.7],
        'context_indicators': ['file', 'path', 'directory', 'system']
    }
}

# Known vulnerable ports with AI context
VULNERABLE_PORTS = {
    21: {
        'service': 'FTP',
        'risks': ['Anonymous login', 'Weak encryption', 'Banner disclosure'],
        'ai_severity': 'MEDIUM',
        'modern_relevance': 'Legacy protocol, rarely needed in modern applications',
        'attack_vectors': ['Brute force', 'Anonymous access', 'Data interception']
    },
    22: {
        'service': 'SSH',
        'risks': ['Brute force', 'Weak ciphers', 'Root login'],
        'ai_severity': 'MEDIUM',
        'modern_relevance': 'Essential for server management but requires hardening',
        'attack_vectors': ['Password attacks', 'Key compromise', 'Protocol exploits']
    },
    23: {
        'service': 'Telnet',
        'risks': ['Unencrypted', 'Default credentials', 'Session hijacking'],
        'ai_severity': 'CRITICAL',
        'modern_relevance': 'Obsolete protocol, should never be exposed',
        'attack_vectors': ['Plain text interception', 'Session hijacking', 'Credential theft']
    },
    80: {
        'service': 'HTTP',
        'risks': ['Unencrypted', 'Directory traversal', 'XSS'],
        'ai_severity': 'HIGH',
        'modern_relevance': 'Should redirect to HTTPS in modern applications',
        'attack_vectors': ['Traffic interception', 'MITM attacks', 'Data theft']
    },
    443: {
        'service': 'HTTPS',
        'risks': ['Weak ciphers', 'Certificate issues', 'BEAST/CRIME'],
        'ai_severity': 'LOW',
        'modern_relevance': 'Standard secure web port, requires proper configuration',
        'attack_vectors': ['Certificate attacks', 'Protocol downgrade', 'Cipher exploitation']
    },
    3306: {
        'service': 'MySQL',
        'risks': ['SQL injection', 'Weak passwords', 'Remote root'],
        'ai_severity': 'CRITICAL',
        'modern_relevance': 'Database should never be directly exposed to internet',
        'attack_vectors': ['SQL injection', 'Authentication bypass', 'Data extraction']
    },
    3389: {
        'service': 'RDP',
        'risks': ['BlueKeep', 'Weak passwords', 'Man-in-the-middle'],
        'ai_severity': 'CRITICAL',
        'modern_relevance': 'Remote desktop, extremely dangerous when exposed',
        'attack_vectors': ['BlueKeep exploit', 'Credential attacks', 'Lateral movement']
    },
    5432: {
        'service': 'PostgreSQL',
        'risks': ['SQL injection', 'Weak auth', 'Privilege escalation'],
        'ai_severity': 'CRITICAL',
        'modern_relevance': 'Database should be behind firewall',
        'attack_vectors': ['SQL injection', 'Authentication bypass', 'Privilege escalation']
    }
}


# AI Security Analyst Class
class AISecurityAnalyst:
    def __init__(self):
        self.knowledge_base = VULNERABILITY_DATABASE
        self.patterns = ENHANCED_VULN_PATTERNS

    def analyze_vulnerability_context(
        self,
        vuln_type: str,
        evidence: str,
        target_info: Dict
    ) -> Dict[str, Any]:
        """AI-powered vulnerability context analysis"""
        try:
            analysis = {
                'confidence_score': 0.5,
                'severity_justification': '',
                'attack_likelihood': 'Unknown',
                'business_impact': 'To be assessed',
                'remediation_urgency': 'Medium',
                'contextual_factors': [],
                'ai_recommendations': []
            }

            # Pattern-based confidence scoring
            if vuln_type in self.patterns:
                pattern_data = self.patterns[vuln_type]
                confidence_scores = []

                for i, pattern in enumerate(pattern_data['patterns']):
                    if re.search(pattern, evidence, re.IGNORECASE):
                        weight = (
                            pattern_data['confidence_weights'][i]
                            if i < len(pattern_data['confidence_weights'])
                            else 0.7
                        )
                        confidence_scores.append(weight)

                if confidence_scores:
                    analysis['confidence_score'] = max(confidence_scores)

            # Context analysis
            analysis.update(self._analyze_target_context(target_info))
            analysis.update(
                self._generate_ai_recommendations(vuln_type, evidence, target_info)
            )

            return analysis

        except Exception as e:
            logger.error(f"Error in AI vulnerability analysis: {str(e)}")
            return analysis

    def _analyze_target_context(self, target_info: Dict) -> Dict[str, Any]:
        """Analyze target context for better assessment"""
        context = {
            'contextual_factors': [],
            'business_impact': 'Medium',
            'attack_likelihood': 'Medium'
        }

        # Analyze open ports
        open_ports = target_info.get('open_ports', [])
        if len(open_ports) > 10:
            context['contextual_factors'].append(
                'Large attack surface - many open ports'
            )
            context['attack_likelihood'] = 'High'

        # Check for critical services
        critical_ports = [21, 23, 3389, 3306, 5432]
        exposed_critical = [
            port for port in open_ports if port in critical_ports
        ]
        if exposed_critical:
            context['contextual_factors'].append(
                f'Critical services exposed: {exposed_critical}'
            )
            context['business_impact'] = 'High'
            context['attack_likelihood'] = 'High'

        # Web presence analysis
        web_ports = [80, 443, 8080, 8443]
        if any(port in open_ports for port in web_ports):
            context['contextual_factors'].append('Web application detected')
            if 80 in open_ports and 443 not in open_ports:
                context['contextual_factors'].append(
                    'HTTP without HTTPS - insecure configuration'
                )

        return context

    def _generate_ai_recommendations(
        self,
        vuln_type: str,
        evidence: str,
        target_info: Dict
    ) -> Dict[str, Any]:
        """Generate AI-powered recommendations"""
        recommendations = {
            'ai_recommendations': [],
            'remediation_urgency': 'Medium',
            'severity_justification': ''
        }

        # Vulnerability-specific recommendations
        if vuln_type == 'sql_injection':
            recommendations['ai_recommendations'] = [
                'Implement parameterized queries immediately',
                'Deploy Web Application Firewall (WAF)',
                'Conduct thorough code review of database interactions',
                'Implement input validation and sanitization',
                'Use ORM frameworks with built-in protections'
            ]
            recommendations['remediation_urgency'] = 'Critical'
            recommendations['severity_justification'] = (
                'SQL injection allows complete database compromise'
            )

        elif vuln_type == 'xss':
            recommendations['ai_recommendations'] = [
                'Implement Content Security Policy (CSP)',
                'Use output encoding/escaping for all user input',
                'Deploy XSS protection headers',
                'Sanitize user input on both client and server side',
                'Regular security testing of user input handling'
            ]
            recommendations['remediation_urgency'] = 'High'
            recommendations['severity_justification'] = (
                'XSS enables client-side attacks and session hijacking'
            )

        elif vuln_type == 'open_dangerous_port':
            port = target_info.get('current_port', 0)
            if port in VULNERABLE_PORTS:
                port_info = VULNERABLE_PORTS[port]
                recommendations['ai_recommendations'] = [
                    f'Close port {port} if {port_info["service"]} is not required',
                    'Implement network segmentation and firewall rules',
                    'Use VPN or bastion hosts for administrative access',
                    'Regular port scanning and monitoring',
                    'Principle of least privilege for network access'
                ]
                recommendations['remediation_urgency'] = (
                    'High' if port in [23, 3389, 3306] else 'Medium'
                )
                recommendations['severity_justification'] = (
                    f'{port_info["modern_relevance"]}'
                )

        return recommendations

    def generate_executive_summary(
        self,
        vulnerabilities: List[Dict],
        target_info: Dict
    ) -> Dict[str, Any]:
        """Generate AI-powered executive summary"""
        try:
            summary = {
                'overall_risk_level': 'Unknown',
                'key_findings': [],
                'business_impact_assessment': '',
                'immediate_actions': [],
                'strategic_recommendations': [],
                'compliance_implications': [],
                'attack_scenario': ''
            }

            # Risk level calculation
            critical_count = len([
                v for v in vulnerabilities
                if v.get('severity') == 'CRITICAL'
            ])
            high_count = len([
                v for v in vulnerabilities
                if v.get('severity') == 'HIGH'
            ])

            if critical_count > 0:
                summary['overall_risk_level'] = 'CRITICAL'
            elif high_count > 2:
                summary['overall_risk_level'] = 'HIGH'
            elif high_count > 0:
                summary['overall_risk_level'] = 'MEDIUM'
            else:
                summary['overall_risk_level'] = 'LOW'

            # Key findings
            if critical_count > 0:
                summary['key_findings'].append(
                    f'{critical_count} critical vulnerabilities requiring immediate attention'
                )

            # Business impact
            if critical_count > 0 or high_count > 1:
                summary['business_impact_assessment'] = (
                    'High risk of data breach, service disruption, '
                    'and regulatory compliance violations'
                )
            else:
                summary['business_impact_assessment'] = (
                    'Moderate security risks that should be addressed systematically'
                )

            # Immediate actions
            summary['immediate_actions'] = [
                'Prioritize critical and high-severity vulnerabilities',
                'Implement emergency patches for known CVEs',
                'Review and harden network security configurations',
                'Enhance monitoring and incident response capabilities'
            ]

            # Strategic recommendations
            summary['strategic_recommendations'] = [
                'Establish regular vulnerability assessment schedule',
                'Implement DevSecOps practices in development lifecycle',
                'Deploy comprehensive security monitoring solution',
                'Conduct security awareness training for development teams',
                'Establish incident response and business continuity plans'
            ]

            return summary

        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return summary


# Enhanced Port Scanner with AI integration
class NativePortScanner:
    def __init__(self):
        self.timeout = 3
        self.max_threads = 50

    def parse_port_range(self, port_string: str) -> List[int]:
        """Parse port range string into list of ports"""
        ports = []

        if not port_string:
            # Default comprehensive port list
            return (
                list(range(1, 1001)) +
                [1433, 1521, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
            )

        for part in port_string.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))

        return sorted(list(set(ports)))

    def scan_port(
        self,
        target: str,
        port: int,
        timeout: int = None
    ) -> Dict[str, Any]:
        """Enhanced port scanning with service detection"""
        if timeout is None:
            timeout = self.timeout

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                return {'port': port, 'state': 'open', 'protocol': 'tcp'}
            else:
                return {'port': port, 'state': 'closed', 'protocol': 'tcp'}
        except Exception as e:
            return {
                'port': port,
                'state': 'filtered',
                'protocol': 'tcp',
                'error': str(e)
            }

    def scan_ports(
        self,
        target: str,
        ports: List[int]
    ) -> Dict[int, Dict[str, Any]]:
        """Scan multiple ports with progress tracking"""
        results = {}
        total_ports = len(ports)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target, port): port
                for port in ports
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1

                try:
                    result = future.result(timeout=10)
                    results[port] = result

                    # Log progress for large scans
                    if total_ports > 100 and completed % 100 == 0:
                        logger.info(
                            f"Port scan progress: {completed}/{total_ports} "
                            f"({(completed/total_ports)*100:.1f}%)"
                        )

                except Exception as e:
                    results[port] = {
                        'port': port,
                        'state': 'error',
                        'error': str(e)
                    }

        return results

    def grab_banner(
        self,
        target: str,
        port: int,
        timeout: int = 5
    ) -> str:
        """Enhanced banner grabbing with multiple probes"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            # Send appropriate probe based on port
            probes = {
                80: (
                    b'GET / HTTP/1.1\r\nHost: ' +
                    target.encode() +
                    b'\r\nUser-Agent: SecuritIA-Scanner\r\n\r\n'
                ),
                443: (
                    b'GET / HTTP/1.1\r\nHost: ' +
                    target.encode() +
                    b'\r\nUser-Agent: SecuritIA-Scanner\r\n\r\n'
                ),
                21: b'',  # FTP sends banner automatically
                22: b'',  # SSH sends banner automatically
                25: b'EHLO securitia.local\r\n',
                23: b'',  # Telnet
                3306: b'',  # MySQL
                5432: b'',  # PostgreSQL
            }

            if port in probes:
                if probes[port]:
                    sock.send(probes[port])
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner

        except Exception:
            return ""

    def detect_service(
        self,
        target: str,
        port: int,
        banner: str = ""
    ) -> Dict[str, str]:
        """Enhanced service detection with AI context"""
        service_info = {
            'service': 'unknown',
            'version': '',
            'product': '',
            'confidence': 0.5
        }

        if not banner:
            banner = self.grab_banner(target, port)

        if not banner:
            if port in VULNERABLE_PORTS:
                service_info['service'] = VULNERABLE_PORTS[port]['service'].lower()
                service_info['confidence'] = 0.7
            return service_info

        # Enhanced pattern matching
        patterns = {
            r'HTTP/1\.[01].*Server:\s*Apache/([^\s]+)': ('apache', 'http', 0.9),
            r'HTTP/1\.[01].*Server:\s*nginx/([^\s]+)': ('nginx', 'http', 0.9),
            r'SSH-2\.0-OpenSSH_([^\s]+)': ('openssh', 'ssh', 0.95),
            r'220.*vsftpd\s+([^\s]+)': ('vsftpd', 'ftp', 0.9),
            r'220.*ProFTPD\s+([^\s]+)': ('proftpd', 'ftp', 0.9),
            r'220.*Microsoft.*ESMTP': ('exchange', 'smtp', 0.85),
            r'MySQL.*([0-9]+\.[0-9]+\.[0-9]+)': ('mysql', 'mysql', 0.9),
            r'PostgreSQL.*([0-9]+\.[0-9]+)': ('postgresql', 'postgresql', 0.9),
        }

        for pattern, (product, service, confidence) in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service_info['service'] = service
                service_info['product'] = product
                service_info['confidence'] = confidence
                if match.groups():
                    service_info['version'] = match.group(1)
                break

        return service_info


# Enhanced Vulnerability Scanner with AI
class VulnerabilityScanner:
    def __init__(self):
        self.port_scanner = NativePortScanner()
        self.ai_analyst = AISecurityAnalyst()
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.session.headers.update({
            'User-Agent': 'SecuritIA-Scanner/2.0 (Security Assessment Tool)'
        })

    def clean_target(self, target: str) -> str:
        """Clean target URL to extract hostname"""
        try:
            if target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                target = parsed.hostname or parsed.netloc

            if '/' in target:
                target = target.split('/')[0]

            if ':' in target and not target.count(':') > 1:
                target = target.split(':')[0]

            return target.strip()

        except Exception as e:
            logger.error(f"Error cleaning target: {str(e)}")
            return target

    def validate_target(self, target: str) -> bool:
        """Enhanced target validation"""
        try:
            if target.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                target = parsed.hostname or parsed.netloc
                logger.info(f"Extracted hostname from URL: {target}")

            if '/' in target:
                target = target.split('/')[0]
                logger.info(f"Cleaned target: {target}")

            try:
                ipaddress.ip_address(target)
                logger.info(f"Target {target} is a valid IP address")
                return True
            except ValueError:
                pass

            if len(target) > 0 and '.' in target:
                parts = target.split('.')
                if len(parts) >= 2:
                    for part in parts:
                        if not part or not all(
                            c.isalnum() or c == '-' for c in part
                        ):
                            logger.error(
                                f"Invalid character in domain part: {part}"
                            )
                            return False
                        if part.startswith('-') or part.endswith('-'):
                            logger.error(
                                f"Domain part cannot start/end with hyphen: {part}"
                            )
                            return False
                    logger.info(f"Target {target} is a valid domain")
                    return True

            logger.error(f"Target {target} failed all validation checks")
            return False

        except Exception as e:
            logger.error(f"Error validating target: {str(e)}")
            return False

    async def comprehensive_scan(
        self,
        target: str,
        scan_config: 'ScanRequest'
    ) -> Dict[str, Any]:
        """Enhanced comprehensive vulnerability assessment with AI analysis"""
        scan_id = str(uuid.uuid4())
        start_time = datetime.now()

        original_target = target
        cleaned_target = self.clean_target(target)
        logger.info(
            f"Original target: {original_target}, Cleaned target: {cleaned_target}"
        )

        try:
            result = {
                'scan_id': scan_id,
                'target': cleaned_target,
                'original_target': original_target,
                'status': 'running',
                'started_at': start_time,
                'scan_type': scan_config.scan_type,
                'vulnerabilities': [],
                'services': {},
                'open_ports': [],
                'ssl_analysis': {},
                'web_analysis': {},
                'ai_analysis': {},
                'executive_summary': {},
                'total_ports_scanned': 0
            }

            active_scans[scan_id] = result

            # Phase 1: Network Discovery with AI context
            logger.info(f"Phase 1: Enhanced network discovery for {cleaned_target}")
            network_info = await self.network_discovery(cleaned_target, scan_config)
            result.update(network_info)

            # Phase 2: Service Detection with AI analysis
            logger.info(f"Phase 2: AI-enhanced service detection for {cleaned_target}")
            service_info = await self.service_detection(
                cleaned_target,
                result['open_ports']
            )
            result['services'] = service_info

            # Phase 3: Comprehensive Vulnerability Detection
            logger.info(
                f"Phase 3: AI-powered vulnerability detection for {cleaned_target}"
            )
            vulnerabilities = await self.vulnerability_detection(
                cleaned_target,
                result
            )
            result['vulnerabilities'].extend(vulnerabilities)

            # Phase 4: Enhanced SSL Analysis
            if scan_config.include_ssl_scan:
                logger.info(
                    f"Phase 4: Enhanced SSL/TLS analysis for {cleaned_target}"
                )
                ssl_vulns = await self.ssl_analysis(
                    cleaned_target,
                    result['open_ports']
                )
                result['ssl_analysis'] = ssl_vulns['analysis']
                result['vulnerabilities'].extend(ssl_vulns['vulnerabilities'])

            # Phase 5: Comprehensive Web Application Analysis
            if scan_config.include_web_scan:
                logger.info(
                    f"Phase 5: AI-enhanced web application analysis for {cleaned_target}"
                )
                web_vulns = await self.web_application_scan(
                    cleaned_target,
                    result['open_ports']
                )
                result['web_analysis'] = web_vulns['analysis']
                result['vulnerabilities'].extend(web_vulns['vulnerabilities'])

            # Phase 6: AI Analysis and Recommendations
            logger.info(f"Phase 6: AI-powered risk analysis for {cleaned_target}")
            result['ai_analysis'] = await self.ai_vulnerability_analysis(result)
            result['executive_summary'] = self.ai_analyst.generate_executive_summary(
                result['vulnerabilities'],
                result
            )

            # Complete scan
            end_time = datetime.now()
            result['completed_at'] = end_time
            result['duration'] = str(end_time - start_time)
            result['status'] = 'completed'
            result['risk_score'] = self.calculate_enhanced_risk_score(
                result['vulnerabilities']
            )
            result['summary'] = self.generate_enhanced_summary(result)

            scan_results[scan_id] = result
            logger.info(f"Enhanced scan {scan_id} completed successfully")

            return result

        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            logger.error(f"Error in comprehensive scan: {str(e)}")
            logger.error(f"Full traceback: {error_details}")

            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['error'] = str(e)
            raise

    async def network_discovery(
        self,
        target: str,
        config: 'ScanRequest'
    ) -> Dict[str, Any]:
        """Enhanced network discovery with intelligent port selection"""
        try:
            if not self.validate_target(target):
                raise ValueError(f"Invalid target: {target}")

            if config.ports:
                ports = self.port_scanner.parse_port_range(config.ports)
            elif config.scan_type == "quick":
                # Smart quick scan - most common vulnerable ports
                ports = [
                    21, 22, 23, 25, 53, 80, 135, 139, 443, 445,
                    993, 995, 3306, 3389, 5432, 5900, 8080, 8443
                ]
            elif config.scan_type == "comprehensive":
                # Comprehensive scan with focus on known vulnerable services
                ports = (
                    list(range(1, 1025)) +
                    [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]
                )
            else:
                ports = list(range(1, 1001))

            logger.info(f"Scanning {len(ports)} ports on {target}")
            scan_results_dict = self.port_scanner.scan_ports(target, ports)

            open_ports = [
                port for port, result in scan_results_dict.items()
                if result.get('state') == 'open'
            ]

            logger.info(f"Found {len(open_ports)} open ports: {open_ports}")

            return {
                'open_ports': sorted(open_ports),
                'total_ports_scanned': len(ports),
                'host_status': 'up' if open_ports else 'down'
            }

        except Exception as e:
            logger.error(f"Error in network discovery: {str(e)}")
            return {
                'open_ports': [],
                'total_ports_scanned': 0,
                'error': str(e)
            }

    async def service_detection(
        self,
        target: str,
        open_ports: List[int]
    ) -> Dict[int, Dict[str, Any]]:
        """Enhanced service detection with AI confidence scoring"""
        services = {}

        for port in open_ports:
            try:
                banner = self.port_scanner.grab_banner(target, port)
                service_info = self.port_scanner.detect_service(
                    target,
                    port,
                    banner
                )

                # Enhanced service information
                service_info.update({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'banner': banner,
                    'fingerprint': (
                        hashlib.md5(banner.encode()).hexdigest()[:16]
                        if banner else ''
                    ),
                    'security_implications': self._assess_service_security(
                        port,
                        service_info
                    ),
                    'recommended_actions': self._get_service_recommendations(
                        port,
                        service_info
                    )
                })

                services[port] = service_info
                logger.info(
                    f"Detected service on port {port}: "
                    f"{service_info.get('service', 'unknown')} "
                    f"(confidence: {service_info.get('confidence', 0.5)})"
                )

            except Exception as e:
                logger.error(f"Error detecting service on port {port}: {str(e)}")
                services[port] = {'error': str(e)}

        return services

    def _assess_service_security(
        self,
        port: int,
        service_info: Dict
    ) -> List[str]:
        """Assess security implications of detected service"""
        implications = []

        if port in VULNERABLE_PORTS:
            port_data = VULNERABLE_PORTS[port]
            implications.extend(port_data['risks'])
            implications.append(
                f"AI Assessment: {port_data['modern_relevance']}"
            )

        service = service_info.get('service', '').lower()
        if 'ftp' in service:
            implications.append("Unencrypted file transfer protocol")
        elif 'telnet' in service:
            implications.append("Unencrypted remote access - CRITICAL RISK")
        elif 'mysql' in service or 'postgresql' in service:
            implications.append("Database service exposed to network")
        elif 'ssh' in service:
            implications.append("Remote access service - ensure proper hardening")

        return implications

    def _get_service_recommendations(
        self,
        port: int,
        service_info: Dict
    ) -> List[str]:
        """Get AI-powered recommendations for service security"""
        recommendations = []

        if port in VULNERABLE_PORTS:
            port_data = VULNERABLE_PORTS[port]
            if port_data['ai_severity'] == 'CRITICAL':
                recommendations.append(
                    "IMMEDIATE ACTION: Close this port or implement strict access controls"
                )

        service = service_info.get('service', '').lower()

        if 'http' in service and port == 80:
            recommendations.extend([
                "Implement HTTPS redirect",
                "Consider disabling HTTP entirely",
                "Deploy security headers"
            ])
        elif 'ssh' in service:
            recommendations.extend([
                "Disable password authentication",
                "Use key-based authentication only",
                "Implement fail2ban or similar protection",
                "Change default port if possible"
            ])
        elif 'mysql' in service or 'postgresql' in service:
            recommendations.extend([
                "CRITICAL: Database should not be internet-facing",
                "Implement firewall rules to restrict access",
                "Use VPN or bastion hosts for remote access",
                "Ensure strong authentication mechanisms"
            ])

        return recommendations

    async def vulnerability_detection(
        self,
        target: str,
        scan_result: Dict
    ) -> List[Dict[str, Any]]:
        """Enhanced vulnerability detection with AI analysis"""
        vulnerabilities = []

        # Network-level vulnerabilities with AI context
        network_vulns = await self.detect_network_vulnerabilities(
            target,
            scan_result
        )
        vulnerabilities.extend(network_vulns)

        # Service-specific vulnerabilities
        service_vulns = await self.detect_service_vulnerabilities(
            target,
            scan_result['services']
        )
        vulnerabilities.extend(service_vulns)

        # Configuration vulnerabilities
        config_vulns = await self.detect_configuration_vulnerabilities(
            target,
            scan_result
        )
        vulnerabilities.extend(config_vulns)

        # AI-enhanced vulnerability analysis
        for vuln in vulnerabilities:
            ai_analysis = self.ai_analyst.analyze_vulnerability_context(
                vuln.get('vulnerability_type', 'unknown'),
                vuln.get('evidence', ''),
                scan_result
            )
            vuln.update(ai_analysis)

        logger.info(f"Total vulnerabilities detected: {len(vulnerabilities)}")
        return vulnerabilities

    async def detect_network_vulnerabilities(
        self,
        target: str,
        scan_result: Dict
    ) -> List[Dict[str, Any]]:
        """Enhanced network vulnerability detection"""
        vulnerabilities = []
        open_ports = scan_result.get('open_ports', [])

        # Dangerous ports analysis
        critical_ports = [23, 3389, 3306, 5432]
        high_risk_ports = [21, 135, 139, 445, 1433, 5900]

        for port in open_ports:
            if port in critical_ports:
                port_info = VULNERABLE_PORTS.get(port, {})
                vulnerabilities.append({
                    'id': f"critical_port_{port}",
                    'name': (
                        f"CRITICAL: {port_info.get('service', 'Unknown')} "
                        f"Service Exposed"
                    ),
                    'severity': 'CRITICAL',
                    'cvss_score': 9.8,
                    'vulnerability_type': 'open_dangerous_port',
                    'description': (
                        f"Port {port} ({port_info.get('service', 'Unknown')}) "
                        f"is critically dangerous when exposed"
                    ),
                    'port': port,
                    'evidence': f"Port {port} is open and accessible",
                    'impact': 'Complete system compromise possible',
                    'attack_vectors': port_info.get('attack_vectors', []),
                    'recommendation': (
                        f"IMMEDIATE: Close port {port} or implement "
                        f"strict network controls"
                    ),
                    'discovered_at': datetime.now()
                })
            elif port in high_risk_ports:
                port_info = VULNERABLE_PORTS.get(port, {})
                vulnerabilities.append({
                    'id': f"high_risk_port_{port}",
                    'name': f"High Risk Port: {port_info.get('service', 'Unknown')}",
                    'severity': 'HIGH',
                    'cvss_score': 7.5,
                    'vulnerability_type': 'open_dangerous_port',
                    'description': f"Port {port} presents significant security risks",
                    'port': port,
                    'evidence': f"Port {port} is open",
                    'impact': port_info.get('modern_relevance', 'Security risk'),
                    'recommendation': (
                        f"Review necessity of port {port} and implement "
                        f"access controls"
                    ),
                    'discovered_at': datetime.now()
                })

        # Attack surface analysis
        if len(open_ports) > 15:
            vulnerabilities.append({
                'id': 'large_attack_surface',
                'name': 'Excessive Attack Surface',
                'severity': 'MEDIUM',
                'cvss_score': 5.3,
                'vulnerability_type': 'configuration',
                'description': (
                    f'{len(open_ports)} open ports create large attack surface'
                ),
                'evidence': f'Open ports: {open_ports}',
                'recommendation': 'Review and close unnecessary services',
                'discovered_at': datetime.now()
            })

        return vulnerabilities

    async def detect_service_vulnerabilities(
        self,
        target: str,
        services: Dict[int, Dict]
    ) -> List[Dict[str, Any]]:
        """Enhanced service vulnerability detection"""
        vulnerabilities = []

        for port, service_info in services.items():
            if 'error' in service_info:
                continue

            service_name = service_info.get('service', '').lower()
            version = service_info.get('version', '')

            # Service-specific vulnerability checks
            if 'ssh' in service_name:
                ssh_vulns = await self.check_ssh_vulnerabilities(
                    target,
                    port,
                    service_info
                )
                vulnerabilities.extend(ssh_vulns)
            elif service_name in ['http', 'https']:
                http_vulns = await self.check_http_vulnerabilities(
                    target,
                    port,
                    service_info
                )
                vulnerabilities.extend(http_vulns)
            elif service_name in ['mysql', 'postgresql']:
                db_vulns = self.check_database_vulnerabilities(
                    target,
                    port,
                    service_info
                )
                vulnerabilities.extend(db_vulns)
            elif 'ftp' in service_name:
                ftp_vulns = self.check_ftp_vulnerabilities(
                    target,
                    port,
                    service_info
                )
                vulnerabilities.extend(ftp_vulns)

        return vulnerabilities

    async def check_ssh_vulnerabilities(
        self,
        target: str,
        port: int,
        service_info: Dict
    ) -> List[Dict[str, Any]]:
        """Enhanced SSH vulnerability checking"""
        vulnerabilities = []
        version = service_info.get('version', '')
        banner = service_info.get('banner', '')

        # Basic SSH exposure
        vulnerabilities.append({
            'id': f'ssh_exposed_{port}',
            'name': 'SSH Service Internet Exposure',
            'severity': 'MEDIUM',
            'cvss_score': 5.3,
            'vulnerability_type': 'service_exposure',
            'description': (
                'SSH service accessible from internet - '
                'potential brute force target'
            ),
            'port': port,
            'evidence': f'SSH banner: {banner[:100]}',
            'recommendation': (
                'Implement key-based auth, fail2ban, and network restrictions'
            ),
            'discovered_at': datetime.now()
        })

        # Version-specific checks
        if version and 'openssh' in banner.lower():
            try:
                # Extract version number
                version_match = re.search(
                    r'openssh[_\s](\d+\.\d+)',
                    banner.lower()
                )
                if version_match:
                    ssh_version = float(version_match.group(1))
                    if ssh_version < 7.4:
                        vulnerabilities.append({
                            'id': f'ssh_outdated_{port}',
                            'name': 'Outdated SSH Version',
                            'severity': 'HIGH',
                            'cvss_score': 7.5,
                            'vulnerability_type': 'outdated_software',
                            'description': (
                                f'SSH version {ssh_version} contains '
                                f'known vulnerabilities'
                            ),
                            'port': port,
                            'evidence': f'OpenSSH version: {ssh_version}',
                            'recommendation': 'Update SSH to latest version immediately',
                            'discovered_at': datetime.now()
                        })
            except:
                pass

        return vulnerabilities

    async def check_http_vulnerabilities(
        self,
        target: str,
        port: int,
        service_info: Dict
    ) -> List[Dict[str, Any]]:
        """Enhanced HTTP/HTTPS vulnerability checking"""
        vulnerabilities = []

        try:
            protocol = 'https' if port == 443 else 'http'
            base_url = f"{protocol}://{target}:{port}"

            response = self.session.get(base_url, timeout=10)

            # Security headers analysis
            headers_vulns = await self.analyze_security_headers(response, port)
            vulnerabilities.extend(headers_vulns)

            # Basic web vulnerabilities
            web_vulns = await self.test_web_vulnerabilities(base_url)
            vulnerabilities.extend(web_vulns)

            # HTTP vs HTTPS analysis
            if port == 80:
                vulnerabilities.append({
                    'id': f'http_unencrypted_{port}',
                    'name': 'Unencrypted HTTP Traffic',
                    'severity': 'MEDIUM',
                    'cvss_score': 5.3,
                    'vulnerability_type': 'encryption',
                    'description': (
                        'Web traffic not encrypted - susceptible to interception'
                    ),
                    'port': port,
                    'evidence': 'HTTP protocol in use',
                    'recommendation': 'Implement HTTPS and redirect HTTP traffic',
                    'discovered_at': datetime.now()
                })

        except Exception as e:
            logger.error(f"Error checking HTTP vulnerabilities: {str(e)}")

        return vulnerabilities

    async def analyze_security_headers(
        self,
        response,
        port: int
    ) -> List[Dict[str, Any]]:
        """Analyze security headers with AI recommendations"""
        vulnerabilities = []
        headers = response.headers

        security_headers = {
            'X-Content-Type-Options': {
                'description': 'MIME type sniffing protection missing',
                'severity': 'MEDIUM',
                'cvss_score': 4.3
            },
            'X-Frame-Options': {
                'description': 'Clickjacking protection missing',
                'severity': 'MEDIUM',
                'cvss_score': 4.3
            },
            'Strict-Transport-Security': {
                'description': 'HSTS header missing - vulnerable to downgrade attacks',
                'severity': 'HIGH',
                'cvss_score': 6.1
            },
            'Content-Security-Policy': {
                'description': 'CSP header missing - vulnerable to XSS attacks',
                'severity': 'HIGH',
                'cvss_score': 6.1
            },
            'X-XSS-Protection': {
                'description': 'XSS protection header missing',
                'severity': 'LOW',
                'cvss_score': 3.1
            }
        }

        for header, config in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'id': f'missing_header_{header.lower().replace("-", "_")}_{port}',
                    'name': f'Missing Security Header: {header}',
                    'severity': config['severity'],
                    'cvss_score': config['cvss_score'],
                    'vulnerability_type': 'missing_security_header',
                    'description': config['description'],
                    'port': port,
                    'evidence': f'Header {header} not found in response',
                    'recommendation': (
                        f'Implement {header} security header with appropriate values'
                    ),
                    'discovered_at': datetime.now()
                })

        return vulnerabilities

    async def test_web_vulnerabilities(
        self,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """Test for common web vulnerabilities"""
        vulnerabilities = []

        try:
            # SQL Injection testing
            sqli_vulns = await self.test_sql_injection(base_url)
            vulnerabilities.extend(sqli_vulns)

            # XSS testing
            xss_vulns = await self.test_xss(base_url)
            vulnerabilities.extend(xss_vulns)

            # Directory traversal
            lfi_vulns = await self.test_directory_traversal(base_url)
            vulnerabilities.extend(lfi_vulns)

        except Exception as e:
            logger.error(f"Error in web vulnerability testing: {str(e)}")

        return vulnerabilities

    async def test_sql_injection(
        self,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []

        payloads = [
            "'",
            "1' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--"
        ]

        for payload in payloads:
            try:
                test_url = f"{base_url}/?id={payload}"
                response = self.session.get(test_url, timeout=10)

                if self._detect_sql_error(response.text):
                    vulnerabilities.append({
                        'id': 'sql_injection_detected',
                        'name': 'SQL Injection Vulnerability',
                        'severity': 'CRITICAL',
                        'cvss_score': 9.8,
                        'vulnerability_type': 'sql_injection',
                        'description': (
                            'Application vulnerable to SQL injection attacks'
                        ),
                        'evidence': f'SQL error triggered with payload: {payload}',
                        'impact': (
                            'Complete database compromise, data theft, '
                            'privilege escalation'
                        ),
                        'recommendation': (
                            'Implement parameterized queries and input '
                            'validation immediately'
                        ),
                        'discovered_at': datetime.now()
                    })
                    break
            except:
                continue

        return vulnerabilities

    def _detect_sql_error(self, response_text: str) -> bool:
        """Enhanced SQL error detection"""
        error_patterns = [
            r"(?i)(mysql_fetch_array|mysql_num_rows|pg_query|mssql_query)",
            r"(?i)(syntax.*error|mysql.*error|postgresql.*error|oracle.*error)",
            r"(?i)(warning.*mysql|warning.*postgresql|warning.*sqlite)",
            r"(?i)(you have an error in your sql syntax)",
            r"(?i)(ora-\d+.*error)",
            r"(?i)(microsoft.*odbc.*sql server driver)"
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_text):
                return True
        return False

    async def test_xss(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in payloads:
            try:
                test_url = f"{base_url}/?search={payload}"
                response = self.session.get(test_url, timeout=10)

                if payload in response.text:
                    vulnerabilities.append({
                        'id': 'xss_reflected',
                        'name': 'Reflected Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'cvss_score': 7.2,
                        'vulnerability_type': 'xss',
                        'description': (
                            'Application reflects user input without '
                            'proper sanitization'
                        ),
                        'evidence': f'XSS payload reflected: {payload}',
                        'impact': (
                            'Session hijacking, credential theft, '
                            'malicious content injection'
                        ),
                        'recommendation': (
                            'Implement input validation and output encoding'
                        ),
                        'discovered_at': datetime.now()
                    })
                    break
            except:
                continue

        return vulnerabilities

    async def test_directory_traversal(
        self,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []

        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        ]

        for payload in payloads:
            try:
                test_url = f"{base_url}/?file={payload}"
                response = self.session.get(test_url, timeout=10)

                if re.search(r'root:.*:/bin/', response.text):
                    vulnerabilities.append({
                        'id': 'directory_traversal',
                        'name': 'Directory Traversal / Local File Inclusion',
                        'severity': 'CRITICAL',
                        'cvss_score': 9.1,
                        'vulnerability_type': 'lfi',
                        'description': (
                            'Application allows access to local files '
                            'through path traversal'
                        ),
                        'evidence': f'Local file accessed with payload: {payload}',
                        'impact': 'Sensitive file access, potential code execution',
                        'recommendation': (
                            'Implement proper input validation and '
                            'file access controls'
                        ),
                        'discovered_at': datetime.now()
                    })
                    break
            except:
                continue

        return vulnerabilities

    def check_database_vulnerabilities(
        self,
        target: str,
        port: int,
        service_info: Dict
    ) -> List[Dict[str, Any]]:
        """Enhanced database vulnerability checking"""
        vulnerabilities = []
        service = service_info.get('service', '').lower()

        # Database exposed to internet - CRITICAL
        vulnerabilities.append({
            'id': f'database_exposed_{service}_{port}',
            'name': f'{service.upper()} Database Internet Exposure',
            'severity': 'CRITICAL',
            'cvss_score': 9.1,
            'vulnerability_type': 'database_exposure',
            'description': (
                f'{service.upper()} database directly accessible from internet'
            ),
            'port': port,
            'evidence': f'Database service detected on port {port}',
            'impact': (
                'Complete database compromise, data theft, ransomware risk'
            ),
            'recommendation': (
                'IMMEDIATE: Move database behind firewall, use VPN for access'
            ),
            'discovered_at': datetime.now()
        })

        return vulnerabilities

    def check_ftp_vulnerabilities(
        self,
        target: str,
        port: int,
        service_info: Dict
    ) -> List[Dict[str, Any]]:
        """Enhanced FTP vulnerability checking"""
        vulnerabilities = []
        banner = service_info.get('banner', '')

        # FTP is inherently insecure
        vulnerabilities.append({
            'id': f'ftp_insecure_{port}',
            'name': 'Insecure FTP Service',
            'severity': 'HIGH',
            'cvss_score': 7.5,
            'vulnerability_type': 'insecure_protocol',
            'description': 'FTP transmits credentials and data in plain text',
            'port': port,
            'evidence': f'FTP service detected: {banner[:100]}',
            'impact': 'Credential interception, data theft, unauthorized access',
            'recommendation': 'Replace with SFTP or FTPS, disable FTP if possible',
            'discovered_at': datetime.now()
        })

        return vulnerabilities

    async def detect_configuration_vulnerabilities(
        self,
        target: str,
        scan_result: Dict
    ) -> List[Dict[str, Any]]:
        """Detect configuration-related vulnerabilities"""
        vulnerabilities = []

        # Version disclosure analysis
        for port, service_info in scan_result.get('services', {}).items():
            version = service_info.get('version', '')
            if version and 'error' not in service_info:
                vulnerabilities.append({
                    'id': f'version_disclosure_{port}',
                    'name': 'Service Version Disclosure',
                    'severity': 'LOW',
                    'cvss_score': 2.7,
                    'vulnerability_type': 'information_disclosure',
                    'description': (
                        f'Service version information disclosed on port {port}'
                    ),
                    'port': port,
                    'evidence': f"Version: {version}",
                    'impact': 'Information gathering for targeted attacks',
                    'recommendation': 'Configure service to hide version information',
                    'discovered_at': datetime.now()
                })

        return vulnerabilities

    async def ssl_analysis(
        self,
        target: str,
        open_ports: List[int]
    ) -> Dict[str, Any]:
        """Enhanced SSL/TLS analysis"""
        ssl_ports = [
            port for port in open_ports
            if port in [443, 8443, 993, 995]
        ]
        vulnerabilities = []
        analysis = {}

        for port in ssl_ports:
            try:
                port_analysis = await self.analyze_ssl_port(target, port)
                analysis[port] = port_analysis['analysis']
                vulnerabilities.extend(port_analysis['vulnerabilities'])

            except Exception as e:
                logger.error(f"Error analyzing SSL on port {port}: {str(e)}")
                analysis[port] = {'error': str(e)}

        return {'analysis': analysis, 'vulnerabilities': vulnerabilities}

    async def analyze_ssl_port(
        self,
        target: str,
        port: int
    ) -> Dict[str, Any]:
        """Enhanced SSL/TLS analysis for specific port"""
        vulnerabilities = []
        analysis = {}

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    analysis = {
                        'certificate_valid': cert is not None,
                        'protocol_version': version,
                        'cipher_suite': cipher[0] if cipher else None,
                        'key_size': cipher[2] if cipher and len(cipher) > 2 else None
                    }

                    # Certificate analysis
                    if cert:
                        not_after = datetime.strptime(
                            cert['notAfter'],
                            '%b %d %H:%M:%S %Y %Z'
                        )
                        not_before = datetime.strptime(
                            cert['notBefore'],
                            '%b %d %H:%M:%S %Y %Z'
                        )
                        now = datetime.now()

                        analysis['certificate_expiry'] = not_after.isoformat()
                        analysis['days_until_expiry'] = (not_after - now).days

                        # Expired certificate
                        if not_after < now:
                            vulnerabilities.append({
                                'id': f'ssl_cert_expired_{port}',
                                'name': 'Expired SSL Certificate',
                                'severity': 'HIGH',
                                'cvss_score': 7.4,
                                'vulnerability_type': 'certificate',
                                'description': (
                                    f'SSL certificate expired on {not_after}'
                                ),
                                'port': port,
                                'evidence': f'Certificate expired: {not_after}',
                                'impact': (
                                    'Browser warnings, loss of user trust, '
                                    'potential MITM attacks'
                                ),
                                'recommendation': 'Renew SSL certificate immediately',
                                'discovered_at': datetime.now()
                            })

                        # Certificate expiring soon
                        elif (not_after - now).days < 30:
                            vulnerabilities.append({
                                'id': f'ssl_cert_expiring_{port}',
                                'name': 'SSL Certificate Expiring Soon',
                                'severity': 'MEDIUM',
                                'cvss_score': 4.3,
                                'vulnerability_type': 'certificate',
                                'description': (
                                    f'SSL certificate expires in '
                                    f'{(not_after - now).days} days'
                                ),
                                'port': port,
                                'evidence': f'Certificate expires: {not_after}',
                                'recommendation': 'Plan certificate renewal',
                                'discovered_at': datetime.now()
                            })

                    # Protocol version analysis
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        severity = (
                            'CRITICAL'
                            if version in ['SSLv2', 'SSLv3']
                            else 'HIGH'
                        )
                        vulnerabilities.append({
                            'id': f'ssl_weak_version_{port}',
                            'name': f'Weak SSL/TLS Version: {version}',
                            'severity': severity,
                            'cvss_score': 9.3 if severity == 'CRITICAL' else 7.4,
                            'vulnerability_type': 'weak_encryption',
                            'description': (
                                f'Server supports weak SSL/TLS version: {version}'
                            ),
                            'port': port,
                            'evidence': f'Protocol version: {version}',
                            'impact': (
                                'Vulnerable to protocol-specific attacks, '
                                'data interception'
                            ),
                            'recommendation': (
                                'Disable weak protocols, use TLS 1.2 or higher only'
                            ),
                            'discovered_at': datetime.now()
                        })

                    # Cipher analysis
                    if cipher and len(cipher) >= 2:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', '3DES']
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            vulnerabilities.append({
                                'id': f'ssl_weak_cipher_{port}',
                                'name': 'Weak SSL Cipher Suite',
                                'severity': 'HIGH',
                                'cvss_score': 7.4,
                                'vulnerability_type': 'weak_encryption',
                                'description': f'Weak cipher suite in use: {cipher_name}',
                                'port': port,
                                'evidence': f'Cipher: {cipher_name}',
                                'impact': (
                                    'Cryptographic weakness, potential data decryption'
                                ),
                                'recommendation': (
                                    'Configure strong cipher suites only '
                                    '(AES, ChaCha20)'
                                ),
                                'discovered_at': datetime.now()
                            })

        except Exception as e:
            analysis['error'] = str(e)

        return {'analysis': analysis, 'vulnerabilities': vulnerabilities}

    async def web_application_scan(
        self,
        target: str,
        open_ports: List[int]
    ) -> Dict[str, Any]:
        """Enhanced web application vulnerability scan"""
        web_ports = [
            port for port in open_ports
            if port in [80, 443, 8080, 8443]
        ]
        vulnerabilities = []
        analysis = {}

        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                base_url = f"{protocol}://{target}:{port}"

                port_analysis = await self.scan_web_application(base_url, port)
                analysis[port] = port_analysis['analysis']
                vulnerabilities.extend(port_analysis['vulnerabilities'])

            except Exception as e:
                logger.error(
                    f"Error scanning web application on port {port}: {str(e)}"
                )
                analysis[port] = {'error': str(e)}

        return {'analysis': analysis, 'vulnerabilities': vulnerabilities}

    async def scan_web_application(
        self,
        base_url: str,
        port: int
    ) -> Dict[str, Any]:
        """Comprehensive web application security scan"""
        vulnerabilities = []
        analysis = {}

        try:
            response = self.session.get(base_url, timeout=10)
            analysis = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'technologies': self.detect_technologies(response),
                'security_score': 0
            }

            # Comprehensive vulnerability testing
            web_vulns = await self.comprehensive_web_testing(base_url, port)
            vulnerabilities.extend(web_vulns)

            # Calculate security score
            analysis['security_score'] = self.calculate_web_security_score(
                response,
                vulnerabilities
            )

        except Exception as e:
            analysis['error'] = str(e)

        return {'analysis': analysis, 'vulnerabilities': vulnerabilities}

    def detect_technologies(self, response) -> List[str]:
        """Enhanced technology detection"""
        technologies = []
        headers = response.headers
        content = response.text.lower()

        # Server detection
        if 'Server' in headers:
            technologies.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            technologies.append(f"Framework: {headers['X-Powered-By']}")

        # CMS Detection with confidence
        cms_patterns = {
            'WordPress': [
                r'wp-content', r'wordpress',
                r'/wp-admin/', r'wp-includes'
            ],
            'Drupal': [
                r'drupal', r'sites/default',
                r'/modules/'
            ],
            'Joomla': [
                r'joomla', r'com_content',
                r'/administrator/'
            ],
            'Magento': [
                r'magento', r'mage/cookies',
                r'/skin/frontend/'
            ],
            'Laravel': [
                r'laravel_session', r'csrf-token',
                r'laravel'
            ],
            'Django': [
                r'csrfmiddlewaretoken', r'django',
                r'__admin/'
            ],
            'React': [
                r'react', r'_react',
                r'react-dom'
            ],
            'Angular': [
                r'ng-', r'angular',
                r'ng-app'
            ],
            'Vue.js': [
                r'vue', r'v-if',
                r'v-for'
            ],
            'jQuery': [
                r'jquery',
                r'$(document)'
            ],
            'Bootstrap': [
                r'bootstrap', r'col-md-',
                r'container-fluid'
            ]
        }

        for tech, patterns in cms_patterns.items():
            matches = sum(
                1 for pattern in patterns
                if re.search(pattern, content)
            )
            if matches > 0:
                confidence = min(matches / len(patterns), 1.0) * 100
                technologies.append(
                    f"{tech} (confidence: {confidence:.0f}%)"
                )

        return technologies

    async def comprehensive_web_testing(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Comprehensive web application testing"""
        vulnerabilities = []

        # Common vulnerability checks
        test_functions = [
            self.test_sql_injection_advanced,
            self.test_xss_advanced,
            self.test_directory_traversal_advanced,
            self.test_csrf,
            self.test_file_upload,
            self.test_authentication_bypass,
            self.test_information_disclosure,
            self.test_admin_interfaces
        ]

        for test_func in test_functions:
            try:
                vulns = await test_func(base_url, port)
                vulnerabilities.extend(vulns)
            except Exception as e:
                logger.error(f"Error in {test_func.__name__}: {str(e)}")

        return vulnerabilities

    async def test_sql_injection_advanced(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Advanced SQL injection testing"""
        vulnerabilities = []

        # Time-based payloads
        time_payloads = [
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--",
            "1' UNION SELECT NULL,SLEEP(5),NULL--"
        ]

        # Error-based payloads
        error_payloads = [
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1' UNION SELECT NULL,@@version,NULL--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "'; SELECT pg_sleep(5)--",
            "1' OR '1'='1' UNION SELECT NULL,NULL,NULL--"
        ]

        # Test time-based injection
        for payload in time_payloads:
            try:
                start_time = time.time()
                test_url = f"{base_url}/?id={payload}"
                response = self.session.get(test_url, timeout=15)
                end_time = time.time()

                if end_time - start_time > 4:
                    vulnerabilities.append({
                        'id': f'sql_injection_time_based_{port}',
                        'name': 'Time-based Blind SQL Injection',
                        'severity': 'CRITICAL',
                        'cvss_score': 9.8,
                        'vulnerability_type': 'sql_injection',
                        'description': (
                            'Application vulnerable to time-based blind SQL injection'
                        ),
                        'port': port,
                        'evidence': (
                            f'Response delay of {end_time - start_time:.2f} '
                            f'seconds with payload: {payload}'
                        ),
                        'impact': (
                            'Complete database compromise, data extraction, '
                            'privilege escalation'
                        ),
                        'recommendation': (
                            'Implement parameterized queries and input '
                            'validation immediately'
                        ),
                        'discovered_at': datetime.now()
                    })
                    break
            except:
                continue

        # Test error-based injection
        for payload in error_payloads:
            try:
                test_url = f"{base_url}/?id={payload}"
                response = self.session.get(test_url, timeout=10)

                if self._detect_sql_error(response.text):
                    vulnerabilities.append({
                        'id': f'sql_injection_error_based_{port}',
                        'name': 'Error-based SQL Injection',
                        'severity': 'CRITICAL',
                        'cvss_score': 9.8,
                        'vulnerability_type': 'sql_injection',
                        'description': (
                            'Application vulnerable to error-based SQL injection'
                        ),
                        'port': port,
                        'evidence': f'SQL error detected with payload: {payload}',
                        'impact': (
                            'Database schema disclosure, data extraction, '
                            'potential RCE'
                        ),
                        'recommendation': (
                            'Implement parameterized queries and proper '
                            'error handling'
                        ),
                        'discovered_at': datetime.now()
                    })
                    break
            except:
                continue

        return vulnerabilities

    async def test_xss_advanced(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Advanced XSS testing"""
        vulnerabilities = []

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "'\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>"
        ]

        test_parameters = [
            'search', 'q', 'query', 'name',
            'comment', 'message', 'input', 'data'
        ]

        for param in test_parameters:
            for payload in xss_payloads:
                try:
                    test_url = f"{base_url}/?{param}={payload}"
                    response = self.session.get(test_url, timeout=10)

                    if (
                        payload in response.text or
                        payload.replace("'", "&#x27;") in response.text
                    ):
                        vulnerabilities.append({
                            'id': f'xss_reflected_{port}_{param}',
                            'name': f'Reflected XSS in {param} parameter',
                            'severity': 'HIGH',
                            'cvss_score': 7.2,
                            'vulnerability_type': 'xss',
                            'description': f'XSS vulnerability in {param} parameter',
                            'port': port,
                            'evidence': f'XSS payload reflected: {payload}',
                            'impact': (
                                'Session hijacking, credential theft, '
                                'malicious content injection'
                            ),
                            'recommendation': (
                                'Implement input validation, output encoding, '
                                'and CSP'
                            ),
                            'discovered_at': datetime.now()
                        })
                        break
                except:
                    continue

            # If XSS found in this parameter, move to next
            if any(
                v['id'].endswith(f'_{param}')
                for v in vulnerabilities
            ):
                break

        return vulnerabilities

    async def test_directory_traversal_advanced(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Advanced directory traversal testing"""
        vulnerabilities = []

        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd%00",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "....\\....\\....\\etc\\passwd",
            "php://filter/convert.base64-encode/resource=../../../etc/passwd"
        ]

        file_parameters = [
            'file', 'page', 'include',
            'doc', 'document', 'path', 'folder'
        ]

        for param in file_parameters:
            for payload in traversal_payloads:
                try:
                    test_url = f"{base_url}/?{param}={payload}"
                    response = self.session.get(test_url, timeout=10)

                    # Check for Unix passwd file or Windows hosts file
                    if (
                        re.search(r'root:.*:/bin/', response.text) or
                        'localhost' in response.text or
                        re.search(r'daemon:.*nologin', response.text)
                    ):
                        vulnerabilities.append({
                            'id': f'directory_traversal_{port}_{param}',
                            'name': f'Directory Traversal in {param} parameter',
                            'severity': 'CRITICAL',
                            'cvss_score': 9.1,
                            'vulnerability_type': 'lfi',
                            'description': (
                                f'Local file inclusion vulnerability in '
                                f'{param} parameter'
                            ),
                            'port': port,
                            'evidence': (
                                f'Local file accessed with payload: {payload}'
                            ),
                            'impact': (
                                'Sensitive file disclosure, potential code execution'
                            ),
                            'recommendation': (
                                'Implement strict input validation and '
                                'file access controls'
                            ),
                            'discovered_at': datetime.now()
                        })
                        return vulnerabilities  # Stop after first successful LFI
                except:
                    continue

        return vulnerabilities

    async def test_csrf(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Test for CSRF vulnerabilities"""
        vulnerabilities = []

        try:
            response = self.session.get(base_url, timeout=10)

            if '<form' in response.text.lower():
                csrf_indicators = [
                    'csrf', '_token', 'authenticity_token',
                    'csrfmiddlewaretoken', 'anti-forgery'
                ]
                has_csrf_protection = any(
                    indicator in response.text.lower()
                    for indicator in csrf_indicators
                )

                if not has_csrf_protection:
                    vulnerabilities.append({
                        'id': f'csrf_missing_{port}',
                        'name': 'Missing CSRF Protection',
                        'severity': 'MEDIUM',
                        'cvss_score': 6.1,
                        'vulnerability_type': 'csrf',
                        'description': 'Forms detected without CSRF protection tokens',
                        'port': port,
                        'evidence': 'HTML forms found without CSRF tokens',
                        'impact': (
                            'Unauthorized actions, account takeover, '
                            'state manipulation'
                        ),
                        'recommendation': (
                            'Implement CSRF tokens in all state-changing forms'
                        ),
                        'discovered_at': datetime.now()
                    })

        except Exception as e:
            logger.error(f"Error in CSRF test: {str(e)}")

        return vulnerabilities

    async def test_file_upload(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Test for file upload vulnerabilities"""
        vulnerabilities = []

        try:
            response = self.session.get(base_url, timeout=10)

            if 'type="file"' in response.text.lower():
                vulnerabilities.append({
                    'id': f'file_upload_detected_{port}',
                    'name': 'File Upload Functionality Detected',
                    'severity': 'MEDIUM',
                    'cvss_score': 5.3,
                    'vulnerability_type': 'file_upload',
                    'description': (
                        'File upload functionality detected - potential security risk'
                    ),
                    'port': port,
                    'evidence': 'File input detected in HTML forms',
                    'impact': (
                        'Malicious file upload, code execution, server compromise'
                    ),
                    'recommendation': (
                        'Implement strict file type validation, size limits, '
                        'and sandboxing'
                    ),
                    'discovered_at': datetime.now()
                })

        except Exception as e:
            logger.error(f"Error in file upload test: {str(e)}")

        return vulnerabilities

    async def test_authentication_bypass(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities"""
        vulnerabilities = []

        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/login', '/signin',
            '/dashboard', '/panel', '/control', '/manage', '/backend',
            '/admin.php', '/admin/', '/administrator/', '/console',
            '/cp', '/controlpanel', '/admincp', '/moderator'
        ]

        for path in admin_paths:
            try:
                test_url = f"{base_url}{path}"
                response = self.session.get(
                    test_url,
                    timeout=10,
                    allow_redirects=False
                )

                # Check if admin area is accessible without authentication
                if (
                    response.status_code == 200 and
                    any(
                        keyword in response.text.lower()
                        for keyword in [
                            'dashboard', 'admin', 'control panel',
                            'welcome', 'logout', 'settings'
                        ]
                    )
                ):
                    vulnerabilities.append({
                        'id': f'auth_bypass_{path.replace("/", "_")}_{port}',
                        'name': f'Authentication Bypass: {path}',
                        'severity': 'HIGH',
                        'cvss_score': 8.1,
                        'vulnerability_type': 'auth_bypass',
                        'description': (
                            f'Administrative area {path} accessible '
                            f'without authentication'
                        ),
                        'port': port,
                        'evidence': f'HTTP {response.status_code} response for {path}',
                        'impact': (
                            'Unauthorized administrative access, system compromise'
                        ),
                        'recommendation': (
                            'Implement proper authentication checks for admin areas'
                        ),
                        'discovered_at': datetime.now()
                    })
            except:
                continue

        return vulnerabilities

    async def test_information_disclosure(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities"""
        vulnerabilities = []

        disclosure_paths = [
            '/.git/config', '/.svn/wc.db', '/.env', '/composer.json',
            '/package.json', '/web.config', '/.htaccess', '/robots.txt',
            '/sitemap.xml', '/backup.sql', '/dump.sql', '/config.php',
            '/wp-config.php', '/database.yml', '/.DS_Store'
        ]

        for path in disclosure_paths:
            try:
                test_url = f"{base_url}{path}"
                response = self.session.get(test_url, timeout=5)

                if response.status_code == 200 and len(response.text) > 0:
                    severity = (
                        'HIGH'
                        if path in ['/.git/config', '/.env', '/backup.sql']
                        else 'MEDIUM'
                    )
                    vulnerabilities.append({
                        'id': (
                            f'info_disclosure_'
                            f'{path.replace("/", "_").replace(".", "_")}_{port}'
                        ),
                        'name': f'Information Disclosure: {path}',
                        'severity': severity,
                        'cvss_score': 7.5 if severity == 'HIGH' else 5.0,
                        'vulnerability_type': 'information_disclosure',
                        'description': f'Sensitive file {path} is accessible',
                        'port': port,
                        'evidence': f'HTTP {response.status_code} response for {path}',
                        'impact': (
                            'Information leakage, potential credential exposure'
                        ),
                        'recommendation': (
                            f'Restrict access to {path} or remove if not needed'
                        ),
                        'discovered_at': datetime.now()
                    })
            except:
                continue

        return vulnerabilities

    async def test_admin_interfaces(
        self,
        base_url: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Test for exposed admin interfaces"""
        vulnerabilities = []

        admin_interfaces = {
            '/phpmyadmin': 'phpMyAdmin Database Interface',
            '/adminer': 'Adminer Database Interface',
            '/wp-admin': 'WordPress Admin Interface',
            '/admin/': 'Generic Admin Interface',
            '/manager/html': 'Apache Tomcat Manager',
            '/solr/admin': 'Apache Solr Admin',
            '/kibana': 'Elasticsearch Kibana',
            '/grafana': 'Grafana Dashboard'
        }

        for path, interface_name in admin_interfaces.items():
            try:
                test_url = f"{base_url}{path}"
                response = self.session.get(test_url, timeout=10)

                if response.status_code in [200, 401, 403]:
                    severity = 'HIGH' if response.status_code == 200 else 'MEDIUM'
                    vulnerabilities.append({
                        'id': f'admin_interface_{path.replace("/", "_")}_{port}',
                        'name': f'Exposed Admin Interface: {interface_name}',
                        'severity': severity,
                        'cvss_score': 7.5 if severity == 'HIGH' else 5.0,
                        'vulnerability_type': 'admin_exposure',
                        'description': (
                            f'{interface_name} is accessible from internet'
                        ),
                        'port': port,
                        'evidence': f'HTTP {response.status_code} response for {path}',
                        'impact': (
                            'Administrative access, potential system compromise'
                        ),
                        'recommendation': (
                            'Restrict access to admin interfaces using IP '
                            'filtering or VPN'
                        ),
                        'discovered_at': datetime.now()
                    })
            except:
                continue

        return vulnerabilities

    def calculate_web_security_score(
        self,
        response,
        vulnerabilities: List[Dict]
    ) -> int:
        """Calculate web application security score (0-100)"""
        score = 100

        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity == 'CRITICAL':
                score -= 25
            elif severity == 'HIGH':
                score -= 15
            elif severity == 'MEDIUM':
                score -= 10
            elif severity == 'LOW':
                score -= 5

        # Check for good security practices
        headers = response.headers
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options'
        ]

        # Bonus points for security headers
        for header in security_headers:
            if header in headers:
                score += 2

        return max(0, min(100, score))

    async def ai_vulnerability_analysis(
        self,
        scan_result: Dict
    ) -> Dict[str, Any]:
        """AI-powered vulnerability analysis and prioritization"""
        vulnerabilities = scan_result.get('vulnerabilities', [])

        ai_analysis = {
            'risk_prioritization': [],
            'attack_chain_analysis': [],
            'remediation_roadmap': [],
            'business_impact_assessment': {},
            'compliance_impact': [],
            'ai_insights': []
        }

        # Risk prioritization using AI
        critical_vulns = [
            v for v in vulnerabilities
            if v.get('severity') == 'CRITICAL'
        ]
        high_vulns = [
            v for v in vulnerabilities
            if v.get('severity') == 'HIGH'
        ]

        # Generate attack chain analysis
        if critical_vulns or high_vulns:
            ai_analysis['attack_chain_analysis'] = self._analyze_attack_chains(
                vulnerabilities,
                scan_result
            )

        # Create remediation roadmap
        ai_analysis['remediation_roadmap'] = self._create_remediation_roadmap(
            vulnerabilities
        )

        # Business impact assessment
        ai_analysis['business_impact_assessment'] = self._assess_business_impact(
            vulnerabilities,
            scan_result
        )

        # AI insights
        ai_analysis['ai_insights'] = self._generate_ai_insights(
            vulnerabilities,
            scan_result
        )

        return ai_analysis

    def _analyze_attack_chains(
        self,
        vulnerabilities: List[Dict],
        scan_result: Dict
    ) -> List[Dict]:
        """Analyze potential attack chains"""
        attack_chains = []

        # Look for dangerous combinations
        vuln_types = [
            v.get('vulnerability_type', '')
            for v in vulnerabilities
        ]
        open_ports = scan_result.get('open_ports', [])

        # Database + Web vulnerabilities
        if (
            'sql_injection' in vuln_types and
            any(port in [3306, 5432, 1433] for port in open_ports)
        ):
            attack_chains.append({
                'chain_name': 'SQL Injection to Database Compromise',
                'severity': 'CRITICAL',
                'steps': [
                    'Exploit SQL injection vulnerability',
                    'Access exposed database service',
                    'Extract sensitive data',
                    'Potential lateral movement'
                ],
                'likelihood': 'High',
                'impact': 'Complete data breach'
            })

        # XSS + Admin interfaces
        if (
            'xss' in vuln_types and
            any('admin' in v.get('name', '').lower() for v in vulnerabilities)
        ):
            attack_chains.append({
                'chain_name': 'XSS to Admin Access',
                'severity': 'HIGH',
                'steps': [
                    'Exploit XSS vulnerability',
                    'Steal admin session cookies',
                    'Access admin interface',
                    'System compromise'
                ],
                'likelihood': 'Medium',
                'impact': 'Administrative compromise'
            })

        return attack_chains

    def _create_remediation_roadmap(
        self,
        vulnerabilities: List[Dict]
    ) -> List[Dict]:
        """Create AI-powered remediation roadmap"""
        roadmap = []

        # Group vulnerabilities by priority
        critical = [
            v for v in vulnerabilities
            if v.get('severity') == 'CRITICAL'
        ]
        high = [
            v for v in vulnerabilities
            if v.get('severity') == 'HIGH'
        ]
        medium = [
            v for v in vulnerabilities
            if v.get('severity') == 'MEDIUM'
        ]

        if critical:
            roadmap.append({
                'phase': 'Immediate (0-7 days)',
                'priority': 'CRITICAL',
                'actions': [
                    'Address all CRITICAL vulnerabilities immediately',
                    'Implement emergency patches',
                    'Consider taking affected services offline if necessary',
                    'Notify stakeholders and security team'
                ],
                'vulnerabilities': len(critical)
            })

        if high:
            roadmap.append({
                'phase': 'Short-term (1-4 weeks)',
                'priority': 'HIGH',
                'actions': [
                    'Address HIGH severity vulnerabilities',
                    'Implement security controls',
                    'Update affected software',
                    'Enhance monitoring'
                ],
                'vulnerabilities': len(high)
            })

        if medium:
            roadmap.append({
                'phase': 'Medium-term (1-3 months)',
                'priority': 'MEDIUM',
                'actions': [
                    'Address MEDIUM severity vulnerabilities',
                    'Implement defense-in-depth measures',
                    'Security awareness training',
                    'Process improvements'
                ],
                'vulnerabilities': len(medium)
            })

        return roadmap

    def _assess_business_impact(
        self,
        vulnerabilities: List[Dict],
        scan_result: Dict
    ) -> Dict[str, Any]:
        """Assess business impact of vulnerabilities"""
        impact = {
            'overall_risk': 'Low',
            'data_exposure_risk': 'Low',
            'service_disruption_risk': 'Low',
            'compliance_risk': 'Low',
            'financial_impact': 'Low',
            'reputation_risk': 'Low'
        }

        critical_count = len([
            v for v in vulnerabilities
            if v.get('severity') == 'CRITICAL'
        ])
        high_count = len([
            v for v in vulnerabilities
            if v.get('severity') == 'HIGH'
        ])

        if critical_count > 0:
            impact['overall_risk'] = 'Critical'
            impact['data_exposure_risk'] = 'High'
            impact['financial_impact'] = 'High'
            impact['reputation_risk'] = 'High'
        elif high_count > 2:
            impact['overall_risk'] = 'High'
            impact['data_exposure_risk'] = 'Medium'
            impact['financial_impact'] = 'Medium'

        # Database exposure increases data risk
        if any(
            port in [3306, 5432, 1433]
            for port in scan_result.get('open_ports', [])
        ):
            impact['data_exposure_risk'] = 'High'
            impact['compliance_risk'] = 'High'

        return impact

    def _generate_ai_insights(
        self,
        vulnerabilities: List[Dict],
        scan_result: Dict
    ) -> List[str]:
        """Generate AI-powered security insights"""
        insights = []

        vuln_types = [
            v.get('vulnerability_type', '')
            for v in vulnerabilities
        ]
        open_ports = scan_result.get('open_ports', [])

        # Pattern-based insights
        if 'sql_injection' in vuln_types:
            insights.append(
                "SQL injection vulnerabilities detected - indicates insufficient "
                "input validation across the application"
            )

        if len([p for p in open_ports if p in [21, 23, 135, 139, 445]]) > 2:
            insights.append(
                "Multiple legacy protocols exposed - suggests outdated "
                "infrastructure requiring modernization"
            )

        if any(port in [3306, 5432, 1433] for port in open_ports):
            insights.append(
                "Database services directly internet-facing - critical "
                "architecture security flaw"
            )

        web_vulns = len([
            v for v in vulnerabilities
            if v.get('vulnerability_type') in ['xss', 'sql_injection', 'lfi']
        ])
        if web_vulns > 3:
            insights.append(
                "Multiple web application vulnerabilities suggest need for "
                "secure development practices and code review"
            )

        return insights

    def calculate_enhanced_risk_score(
        self,
        vulnerabilities: List[Dict]
    ) -> float:
        """Enhanced risk score calculation with AI weighting"""
        if not vulnerabilities:
            return 0.0

        # Base scoring
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            base_score = SEVERITY_SCORES.get(severity, 1)

            # AI confidence multiplier
            confidence = vuln.get('confidence_score', 0.5)
            weighted_score = base_score * (0.5 + confidence * 0.5)

            total_score += weighted_score

        # Normalize to 0-10 scale
        max_possible = len(vulnerabilities) * 10
        normalized_score = (
            (total_score / max_possible) * 10
            if max_possible > 0
            else 0
        )

        return round(normalized_score, 2)

    def generate_enhanced_summary(
        self,
        scan_result: Dict
    ) -> Dict[str, Any]:
        """Generate enhanced scan summary with AI insights"""
        vulnerabilities = scan_result.get('vulnerabilities', [])

        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_distribution': {
                'CRITICAL': len([
                    v for v in vulnerabilities
                    if v.get('severity') == 'CRITICAL'
                ]),
                'HIGH': len([
                    v for v in vulnerabilities
                    if v.get('severity') == 'HIGH'
                ]),
                'MEDIUM': len([
                    v for v in vulnerabilities
                    if v.get('severity') == 'MEDIUM'
                ]),
                'LOW': len([
                    v for v in vulnerabilities
                    if v.get('severity') == 'LOW'
                ]),
                'INFO': len([
                    v for v in vulnerabilities
                    if v.get('severity') == 'INFO'
                ])
            },
            'open_ports': len(scan_result.get('open_ports', [])),
            'services_detected': len(scan_result.get('services', {})),
            'scan_duration': scan_result.get('duration', 'Unknown'),
            'risk_level': self.determine_risk_level(
                scan_result.get('risk_score', 0)
            ),
            'top_risks': self._get_top_risks(vulnerabilities),
            'remediation_priority': self._get_remediation_priority(vulnerabilities),
            'ai_confidence': self._calculate_overall_confidence(vulnerabilities)
        }

        return summary

    def _get_top_risks(self, vulnerabilities: List[Dict]) -> List[str]:
        """Get top 5 risks for executive summary"""
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: (
                SEVERITY_SCORES.get(x.get('severity', 'LOW'), 1),
                x.get('confidence_score', 0.5)
            ),
            reverse=True
        )

        return [v.get('name', 'Unknown') for v in sorted_vulns[:5]]

    def _get_remediation_priority(
        self,
        vulnerabilities: List[Dict]
    ) -> List[str]:
        """Get prioritized remediation actions"""
        priorities = []

        critical = [
            v for v in vulnerabilities
            if v.get('severity') == 'CRITICAL'
        ]
        if critical:
            priorities.append(
                f"IMMEDIATE: Address {len(critical)} critical vulnerabilities"
            )

        high = [
            v for v in vulnerabilities
            if v.get('severity') == 'HIGH'
        ]
        if high:
            priorities.append(f"HIGH: Remediate {len(high)} high-severity issues")

        return priorities[:3]  # Top 3 priorities

    def _calculate_overall_confidence(
        self,
        vulnerabilities: List[Dict]
    ) -> float:
        """Calculate overall AI confidence score"""
        if not vulnerabilities:
            return 0.0

        confidence_scores = [
            v.get('confidence_score', 0.5)
            for v in vulnerabilities
        ]
        return round(sum(confidence_scores) / len(confidence_scores), 2)

    def determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on enhanced scoring"""
        if risk_score >= 8.0:
            return 'CRITICAL'
        elif risk_score >= 6.0:
            return 'HIGH'
        elif risk_score >= 4.0:
            return 'MEDIUM'
        elif risk_score >= 2.0:
            return 'LOW'
        else:
            return 'MINIMAL'


# Initialize enhanced scanner with AI
scanner = VulnerabilityScanner()


# Pydantic Models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or domain name")
    scan_type: str = Field(
        default="comprehensive",
        description="Type of scan to perform"
    )
    ports: Optional[str] = Field(
        default=None,
        description="Custom port range"
    )
    include_web_scan: bool = Field(
        default=True,
        description="Include web application scanning"
    )
    include_vuln_scan: bool = Field(
        default=True,
        description="Include vulnerability detection"
    )
    include_ssl_scan: bool = Field(
        default=True,
        description="Include SSL/TLS analysis"
    )
    timeout: int = Field(
        default=300,
        description="Scan timeout in seconds"
    )

    # Adicione esta classe após a classe ScanRequest (por volta da linha 1130)

# SUBSTITUA a classe LoginRequest por esta:

class LoginRequest(BaseModel):
    username: Optional[str] = Field(None, description="Nome de usuário")
    email: Optional[str] = Field(None, description="Email") 
    password: str = Field(..., description="Senha do usuário")
    
    def get_username_value(self):
        """Retorna username ou email, o que estiver disponível"""
        return self.username or self.email or ""

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

# Enhanced FastAPI setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SECURIT IA Advanced AI-Powered Scanner...")
    init_database()
    logger.info("AI-Enhanced Scanner initialized!")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title="SECURIT IA - AI-Powered Vulnerability Scanner",
    description="Advanced cybersecurity vulnerability scanner with AI analysis",
    version="2.0.0-AI",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:5173",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def init_database():
    """Initialize enhanced SQLite database with proper migration"""
    try:
        conn = sqlite3.connect('securit_ia.db')
        cursor = conn.cursor()
        
        # Drop existing tables to recreate with correct schema
        cursor.execute('DROP TABLE IF EXISTS vulnerabilities')
        cursor.execute('DROP TABLE IF EXISTS scans')
        
        # Create enhanced scans table with all required columns
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                scan_type TEXT,
                risk_score REAL DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                ai_confidence REAL DEFAULT 0.5,
                result_data TEXT
            )
        ''')
        
        # Create enhanced vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                name TEXT,
                severity TEXT,
                cvss_score REAL DEFAULT 0,
                confidence_score REAL DEFAULT 0.5,
                vulnerability_type TEXT,
                port INTEGER,
                service TEXT,
                description TEXT,
                impact TEXT,
                recommendation TEXT,
                evidence TEXT,
                ai_analysis TEXT,
                discovered_at TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Enhanced database initialized successfully with all required columns")
        
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise


# Enhanced API Endpoints
# Adicione este import no topo do arquivo (se ainda não tiver)
from fastapi import Form
from typing import Union

# SUBSTITUA APENAS o endpoint @app.post("/api/auth/login") por este:

from fastapi import Request

# SUBSTITUA o endpoint @app.post("/api/auth/login") atual por este:

# SUBSTITUA o endpoint @app.post("/api/auth/login") por este:

# SUBSTITUA o endpoint de login por este:

@app.post("/api/auth/login")
async def login_flexible(request: LoginRequest):
    """Login flexível - aceita username ou email"""
    try:
        username = request.get_username_value()
        password = request.password
        
        print(f"[FLEXIBLE LOGIN] Received: {username} / {password}")
        print(f"[DEBUG] Raw request - username: {request.username}, email: {request.email}")
        
        if not username or not password:
            print(f"[ERROR] Missing credentials - username: {username}, password: {'***' if password else 'None'}")
            raise HTTPException(
                status_code=400,
                detail="Username/email and password are required"
            )
        
        # Credenciais hardcoded para teste
        valid_credentials = {
            "admin": "admin123",
            "user": "user123", 
            "test": "123456"
        }
        
        # Verificar credenciais
        if username in valid_credentials and valid_credentials[username] == password:
            print(f"[SUCCESS] Credentials valid for: {username}")
            
            # Criar token simples
            token = f"token_{username}_{datetime.now().timestamp()}"
            
            user_info = {
                "username": username,
                "role": "admin" if username == "admin" else "user",
                "email": f"{username}@securitia.com",
                "active": True
            }
            
            response = {
                "access_token": token,
                "token_type": "bearer", 
                "user": user_info
            }
            
            print(f"[SUCCESS] Login successful for: {username}")
            return response
            
        else:
            print(f"[ERROR] Invalid credentials for: {username}")
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"[CRITICAL ERROR] Unexpected error: {str(e)}")
        import traceback
        print(f"[CRITICAL ERROR] Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

# ADICIONE este endpoint também (para compatibilidade com Swagger):

@app.post("/api/auth/login-form")
async def login_form(username: str = Form(...), password: str = Form(...)):
    """Login using form data (for Swagger compatibility)"""
    try:
        print(f"[FORM LOGIN] Received: {username} / {password}")
        
        # Credenciais hardcoded para teste
        valid_credentials = {
            "admin": "admin123",
            "user": "user123", 
            "test": "123456"
        }
        
        # Verificar credenciais
        if username in valid_credentials and valid_credentials[username] == password:
            print(f"[FORM SUCCESS] Credentials valid for: {username}")
            
            # Criar token simples
            token = f"token_{username}_{datetime.now().timestamp()}"
            
            user_info = {
                "username": username,
                "role": "admin" if username == "admin" else "user",
                "email": f"{username}@securitia.com",
                "active": True
            }
            
            response = {
                "access_token": token,
                "token_type": "bearer", 
                "user": user_info
            }
            
            print(f"[FORM SUCCESS] Login successful for: {username}")
            return response
            
        else:
            print(f"[FORM ERROR] Invalid credentials for: {username}")
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"[FORM ERROR] Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Login error: {str(e)}"
        )
    
@app.post("/api/auth/login-json")
async def login_json(request: LoginRequest):
    """Login endpoint for JSON data (modern frontend compatibility)"""
    try:
        print(f"[JSON LOGIN] Received login request for: {request.username}")
        print(f"[JSON LOGIN] Password received: {request.password}")
        
        # Credenciais hardcoded para teste
        valid_credentials = {
            "admin": "admin123",
            "user": "user123", 
            "test": "123456"
        }
        
        # Verificar credenciais
        if request.username in valid_credentials and valid_credentials[request.username] == request.password:
            print(f"[JSON LOGIN] Credentials valid for: {request.username}")
            
            # Criar token simples
            token = f"token_{request.username}_{datetime.now().timestamp()}"
            
            user_info = {
                "username": request.username,
                "role": "admin" if request.username == "admin" else "user",
                "email": f"{request.username}@securitia.com",
                "active": True
            }
            
            response = {
                "access_token": token,
                "token_type": "bearer", 
                "user": user_info
            }
            
            print(f"[JSON LOGIN] Returning successful response")
            return response
            
        else:
            print(f"[JSON LOGIN] Invalid credentials for: {request.username}")
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"[JSON LOGIN ERROR] Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Login error: {str(e)}"
        )
@app.get("/api/auth/me")
async def get_current_user(authorization: str = Header(None)):
    """Get current user from token"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header"
        )
    
    token = authorization.split(" ")[1]
    user = auth_manager.get_current_user_from_token(token)
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
    
    return user

# Adicione este endpoint para compatibilidade com o frontend
@app.post("/api/login")
async def login_frontend_compatible(request: LoginRequest):
    """Login endpoint compatible with frontend expectations"""
    try:
        username = request.username or request.email or ""
        password = request.password
        
        print(f"[FRONTEND LOGIN] Received: {username}")
        
        # Credenciais hardcoded para teste
        valid_credentials = {
            "admin": "admin123",
            "user": "user123", 
            "test": "123456"
        }
        
        if username in valid_credentials and valid_credentials[username] == password:
            # Criar token simples
            token = f"token_{username}_{datetime.now().timestamp()}"
            
            return {
                "token": token,  # Frontend espera 'token' não 'access_token'
                "user": username
            }
        else:
            raise HTTPException(
                status_code=401,
                detail="Credenciais inválidas"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"[FRONTEND LOGIN ERROR] {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro no login: {str(e)}"
        )

@app.get("/api/auth/test-login")
async def test_login(username: str = "admin", password: str = "admin123"):
    """Endpoint de teste para debug"""
    try:
        print(f"[TEST LOGIN] Testing with: {username} / {password}")
        
        valid_credentials = {
            "admin": "admin123",
            "user": "user123", 
            "test": "123456"
        }
        
        if username in valid_credentials and valid_credentials[username] == password:
            return {
                "status": "success",
                "message": f"Login successful for {username}",
                "access_token": f"token_{username}_{datetime.now().timestamp()}",
                "token_type": "bearer",
                "user": {
                    "username": username,
                    "role": "admin" if username == "admin" else "user",
                    "email": f"{username}@securitia.com"
                }
            }
        else:
            return {
                "status": "error",
                "message": f"Invalid credentials for {username}"
            }
            
    except Exception as e:
        return {
            "status": "error", 
            "message": f"Error: {str(e)}"
        }


@app.post("/api/scans/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start enhanced AI-powered vulnerability scan"""
    try:
        logger.info(
            f"Received AI-enhanced scan request for target: {request.target}"
        )

        # Clean and validate target
        cleaned_target = scanner.clean_target(request.target)
        logger.info(f"Cleaned target: {cleaned_target}")

        if not scanner.validate_target(cleaned_target):
            logger.error(f"Invalid target: {cleaned_target}")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid target: {cleaned_target}"
            )

        scan_id = str(uuid.uuid4())
        logger.info(f"Starting AI-enhanced scan {scan_id}")

        # Update request with cleaned target
        request.target = cleaned_target

        # Add to active scans
        scan_data = {
            'scan_id': scan_id,
            'target': cleaned_target,
            'original_target': request.target,
            'status': 'starting',
            'started_at': datetime.now(),
            'scan_type': request.scan_type,
            'progress': 0,
            'ai_enabled': True
        }

        active_scans[scan_id] = scan_data
        logger.info(f"Added to active_scans. Total active: {len(active_scans)}")

        # Start background scan
        background_tasks.add_task(
            run_enhanced_scan,
            scan_id,
            cleaned_target,
            request
        )

        response = {
            "scan_id": scan_id,
            "status": "started",
            "message": f"AI-enhanced scan started for {cleaned_target}",
            "target": cleaned_target,
            "original_target": request.target,
            "ai_enabled": True
        }

        return response

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Error starting enhanced scan: {str(e)}")
        logger.error(f"Full traceback: {error_details}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )


async def run_enhanced_scan(
    scan_id: str,
    target: str,
    config: ScanRequest
):
    """Run enhanced AI-powered scan in background"""
    try:
        logger.info(
            f"Starting AI-enhanced background scan {scan_id} for {target}"
        )

        # Update status
        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'running'
            active_scans[scan_id]['progress'] = 10

        # Run comprehensive scan with AI
        result = await scanner.comprehensive_scan(target, config)

        # Enhanced database save
        hanced_scan_to_db(scan_id, result)
        loggesave_enr.info(f"AI-enhanced scan {scan_id} completed successfully")

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Enhanced background scan error {scan_id}: {str(e)}")
        logger.error(f"Full traceback: {error_details}")

        if scan_id in active_scans:
            active_scans[scan_id]['status'] = 'failed'
            active_scans[scan_id]['error'] = str(e)


def save_enhanced_scan_to_db(scan_id: str, result: Dict):
    """Save enhanced scan results to database with proper error handling"""
    try:
        conn = sqlite3.connect('securit_ia.db')
        cursor = conn.cursor()
        
        vulnerabilities = result.get('vulnerabilities', [])
        severity_counts = result.get('summary', {}).get('severity_distribution', {})
        
        # Save enhanced scan with all severity counts
        cursor.execute('''
            INSERT OR REPLACE INTO scans 
            (id, target, status, started_at, completed_at, scan_type, risk_score, 
             total_vulnerabilities, critical_count, high_count, medium_count, 
             low_count, info_count, ai_confidence, result_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            result.get('target', ''),
            result.get('status', 'completed'),
            result.get('started_at', datetime.now()).isoformat() if isinstance(result.get('started_at'), datetime) else result.get('started_at', ''),
            result.get('completed_at', datetime.now()).isoformat() if isinstance(result.get('completed_at'), datetime) else result.get('completed_at', ''),
            result.get('scan_type', 'comprehensive'),
            float(result.get('risk_score', 0)),
            len(vulnerabilities),
            severity_counts.get('CRITICAL', 0),
            severity_counts.get('HIGH', 0),
            severity_counts.get('MEDIUM', 0),
            severity_counts.get('LOW', 0),
            severity_counts.get('INFO', 0),
            float(result.get('summary', {}).get('ai_confidence', 0.5)),
            json.dumps(result, default=str)
        ))
        
        # Save enhanced vulnerabilities with all fields
        for vuln in vulnerabilities:
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities
                (id, scan_id, name, severity, cvss_score, confidence_score, 
                 vulnerability_type, port, service, description, impact, 
                 recommendation, evidence, ai_analysis, discovered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln.get('id', str(uuid.uuid4())),
                scan_id,
                vuln.get('name', 'Unknown Vulnerability'),
                vuln.get('severity', 'INFO'),
                float(vuln.get('cvss_score', 0)),
                float(vuln.get('confidence_score', 0.5)),
                vuln.get('vulnerability_type', 'unknown'),
                int(vuln.get('port', 0)) if vuln.get('port') else 0,
                vuln.get('service', ''),
                vuln.get('description', ''),
                vuln.get('impact', ''),
                vuln.get('recommendation', ''),
                vuln.get('evidence', ''),
                json.dumps(vuln.get('ai_recommendations', [])),
                vuln.get('discovered_at', datetime.now()).isoformat() if isinstance(vuln.get('discovered_at'), datetime) else vuln.get('discovered_at', '')
            ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Successfully saved scan {scan_id} with {len(vulnerabilities)} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Error saving enhanced scan to database: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise


@app.get("/api/scans/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get enhanced scan status and results"""
    try:
        # Check active scans first
        if scan_id in active_scans:
            return active_scans[scan_id]

        # Check completed scans
        if scan_id in scan_results:
            return scan_results[scan_id]

        # Check database
        conn = sqlite3.connect('securit_ia.db')
        cursor = conn.cursor()

        cursor.execute(
            'SELECT result_data FROM scans WHERE id = ?',
            (scan_id,)
        )
        row = cursor.fetchone()

        if row:
            result = json.loads(row[0])
            conn.close()
            return result

        conn.close()
        raise HTTPException(status_code=404, detail="Scan not found")

    except Exception as e:
        logger.error(f"Error getting enhanced scan status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving scan status"
        )


@app.get("/api/scans")
async def list_scans(limit: int = 10):
    """List enhanced scans with AI metrics"""
    try:
        conn = sqlite3.connect('securit_ia.db')
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, target, status, started_at, scan_type, risk_score, 
                   total_vulnerabilities, critical_count, high_count, ai_confidence
            FROM scans ORDER BY started_at DESC LIMIT ?
        ''', (limit,))

        scans = []
        for row in cursor.fetchall():
            scans.append({
                'scan_id': row[0],
                'target': row[1],
                'status': row[2],
                'started_at': row[3],
                'scan_type': row[4],
                'risk_score': row[5],
                'total_vulnerabilities': row[6],
                'critical_count': row[7],
                'high_count': row[8],
                'ai_confidence': row[9]
            })

        conn.close()
        return {"scans": scans, "ai_enabled": True}

    except Exception as e:
        logger.error(f"Error listing enhanced scans: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error listing scans"
        )


@app.get("/api/vulnerabilities")
async def list_vulnerabilities(
    severity: Optional[str] = None,
    limit: int = 50
):
    """List enhanced vulnerabilities with AI analysis"""
    try:
        conn = sqlite3.connect('securit_ia.db')
        cursor = conn.cursor()

        query = '''SELECT id, scan_id, name, severity, cvss_score, confidence_score, 
                          vulnerability_type, port, description, impact, recommendation
                   FROM vulnerabilities'''
        params = []

        if severity:
            query += ' WHERE severity = ?'
            params.append(severity.upper())

        query += ' ORDER BY cvss_score DESC, confidence_score DESC LIMIT ?'
        params.append(limit)

        cursor.execute(query, params)

        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                'id': row[0],
                'scan_id': row[1],
                'name': row[2],
                'severity': row[3],
                'cvss_score': row[4],
                'confidence_score': row[5],
                'vulnerability_type': row[6],
                'port': row[7],
                'description': row[8],
                'impact': row[9],
                'recommendation': row[10]
            })

        conn.close()
        return {"vulnerabilities": vulnerabilities, "ai_enhanced": True}

    except Exception as e:
        logger.error(f"Error listing enhanced vulnerabilities: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error listing vulnerabilities"
        )


@app.get("/api/statistics")
async def get_enhanced_statistics():
    """Get enhanced vulnerability statistics with AI insights"""
    try:
        conn = sqlite3.connect('securit_ia.db')
        cursor = conn.cursor()

        # Total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]

        # Vulnerability counts by severity
        cursor.execute('''
            SELECT severity, COUNT(*), AVG(confidence_score)
            FROM vulnerabilities 
            GROUP BY severity
        ''')
        severity_data = cursor.fetchall()
        severity_stats = {}
        for severity, count, avg_confidence in severity_data:
            severity_stats[severity] = {
                'count': count,
                'avg_confidence': round(avg_confidence or 0, 2)
            }

        # AI performance metrics
        cursor.execute(
            'SELECT AVG(ai_confidence) FROM scans WHERE ai_confidence IS NOT NULL'
        )
        avg_ai_confidence = cursor.fetchone()[0] or 0

        # Top vulnerability types
        cursor.execute('''
            SELECT vulnerability_type, COUNT(*) as count, AVG(cvss_score) as avg_cvss
            FROM vulnerabilities
            WHERE vulnerability_type IS NOT NULL AND vulnerability_type != ''
            GROUP BY vulnerability_type
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_vuln_types = [
            {
                'type': row[0],
                'count': row[1],
                'avg_cvss': round(row[2] or 0, 1)
            } for row in cursor.fetchall()
        ]

        conn.close()

        return {
            'total_scans': total_scans,
            'total_vulnerabilities': sum(
                s['count'] for s in severity_stats.values()
            ),
            'severity_distribution': severity_stats,
            'ai_confidence': round(avg_ai_confidence, 2),
            'top_vulnerability_types': top_vuln_types,
            'ai_enhanced': True
        }

    except Exception as e:
        logger.error(f"Error getting enhanced statistics: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error getting statistics"
        )


@app.get("/api/health")
async def health_check():
    """Enhanced health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0-AI",
        "active_scans": len(active_scans),
        "ai_enabled": True,
        "features": [
            "AI-powered vulnerability analysis",
            "Smart risk prioritization",
            "Attack chain detection",
            "Business impact assessment",
            "Automated remediation roadmaps"
        ]
    }


@app.post("/api/scans/quick")
async def quick_scan(target: str, ports: str = "80,443,22"):
    """Enhanced quick scan with AI analysis"""
    try:
        cleaned_target = scanner.clean_target(target)
        if not scanner.validate_target(cleaned_target):
            raise HTTPException(status_code=400, detail="Invalid target")

        port_list = scanner.port_scanner.parse_port_range(ports)
        results = scanner.port_scanner.scan_ports(cleaned_target, port_list)

        open_ports = [
            port for port, result in results.items()
            if result.get('state') == 'open'
        ]

        # Quick AI analysis
        risk_assessment = "Low"
        if any(port in [23, 3389, 3306, 5432] for port in open_ports):
            risk_assessment = "High"
        elif any(port in [21, 135, 139, 445] for port in open_ports):
            risk_assessment = "Medium"

        return {
            "target": cleaned_target,
            "total_ports_scanned": len(port_list),
            "open_ports": open_ports,
            "risk_assessment": risk_assessment,
            "ai_insights": [
                f"Found {len(open_ports)} open ports",
                f"Risk level: {risk_assessment}",
                "Run comprehensive scan for detailed analysis"
            ],
            "scan_time": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Enhanced quick scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ai/recommendations/{scan_id}")
async def get_ai_recommendations(scan_id: str):
    """Get AI-powered recommendations for a specific scan"""
    try:
        # Get scan data
        scan_data = None
        if scan_id in scan_results:
            scan_data = scan_results[scan_id]
        else:
            conn = sqlite3.connect('securit_ia.db')
            cursor = conn.cursor()
            cursor.execute(
                'SELECT result_data FROM scans WHERE id = ?',
                (scan_id,)
            )
            row = cursor.fetchone()

            if row:
                scan_data = json.loads(row[0])
            conn.close()

        if not scan_data:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Generate AI recommendations
        ai_analysis = scan_data.get('ai_analysis', {})
        executive_summary = scan_data.get('executive_summary', {})

        return {
            "scan_id": scan_id,
            "target": scan_data.get('target'),
            "ai_analysis": ai_analysis,
            "executive_summary": executive_summary,
            "generated_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error getting AI recommendations: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Error getting AI recommendations"
        )


if __name__ == "__main__":
    import uvicorn

    logger.info("SECURIT IA - AI-Enhanced Vulnerability Scanner")
    logger.info("=" * 60)
    logger.info("🤖 AI-POWERED FEATURES:")
    logger.info("✓ Intelligent vulnerability analysis")
    logger.info("✓ Smart risk prioritization")
    logger.info("✓ Attack chain detection")
    logger.info("✓ Business impact assessment")
    logger.info("✓ Automated remediation roadmaps")
    logger.info("✓ Executive summary generation")
    logger.info("=" * 60)
    logger.info("🔍 SCANNING CAPABILITIES:")
    logger.info("✓ Advanced port scanning")
    logger.info("✓ Service fingerprinting")
    logger.info("✓ Web application testing")
    logger.info("✓ SSL/TLS analysis")
    logger.info("✓ Database security assessment")
    logger.info("✓ Configuration review")
    logger.info("=" * 60)
    logger.info("📊 REPORTING & ANALYTICS:")
    logger.info("✓ Real-time dashboards")
    logger.info("✓ Trend analysis")
    logger.info("✓ Compliance mapping")
    logger.info("✓ Custom reports")
    logger.info("=" * 60)

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )