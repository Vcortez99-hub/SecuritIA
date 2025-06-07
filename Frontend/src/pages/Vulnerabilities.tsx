import React, { useState, useEffect } from 'react';
import MainLayout from '../components/layout/MainLayout';
import { AlertTriangle, Shield, Bug, Lock, Globe, Database, ChevronRight } from 'lucide-react';

interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  description: string;
  recommendation: string;
  cvss: number;
}

const Vulnerabilities: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [filter, setFilter] = useState('all');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);

  useEffect(() => {
    // Aqui você buscaria as vulnerabilidades do backend
    // Por enquanto, vamos usar dados mockados
    setVulnerabilities([
      {
        id: '1',
        title: 'SQL Injection em formulário de login',
        severity: 'critical',
        type: 'SQL Injection',
        description: 'Parâmetro de entrada não sanitizado permite injeção de SQL',
        recommendation: 'Usar prepared statements e validação de entrada',
        cvss: 9.8
      },
      {
        id: '2',
        title: 'Cross-Site Scripting (XSS) Refletido',
        severity: 'high',
        type: 'XSS',
        description: 'Input do usuário é refletido sem sanitização',
        recommendation: 'Implementar escape de HTML e Content Security Policy',
        cvss: 7.2
      },
      {
        id: '3',
        title: 'Cabeçalhos de segurança ausentes',
        severity: 'medium',
        type: 'Configuration',
        description: 'Faltam headers importantes como X-Frame-Options',
        recommendation: 'Adicionar headers de segurança no servidor',
        cvss: 4.3
      }
    ]);
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500';
    }
  };

  const filteredVulns = filter === 'all' 
    ? vulnerabilities 
    : vulnerabilities.filter(v => v.severity === filter);

  return (
    <MainLayout>
      <div className="flex h-full">
        {/* Lista de Vulnerabilidades */}
        <div className="w-1/3 border-r border-gray-800 overflow-y-auto">
          <div className="p-4 border-b border-gray-800">
            <h2 className="text-xl font-bold text-white mb-4">Vulnerabilidades Detectadas</h2>
            
            {/* Filtros */}
            <div className="flex space-x-2 mb-4">
              {['all', 'critical', 'high', 'medium', 'low'].map((level) => (
                <button
                  key={level}
                  onClick={() => setFilter(level)}
                  className={`px-3 py-1 rounded-lg text-sm transition-all ${
                    filter === level
                      ? 'bg-cyan-500 text-black'
                      : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {level === 'all' ? 'Todas' : level.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Estatísticas */}
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-gray-800 p-3 rounded-lg">
                <p className="text-2xl font-bold text-white">{vulnerabilities.length}</p>
                <p className="text-xs text-gray-400">Total</p>
              </div>
              <div className="bg-red-500/10 p-3 rounded-lg">
                <p className="text-2xl font-bold text-red-500">
                  {vulnerabilities.filter(v => v.severity === 'critical').length}
                </p>
                <p className="text-xs text-gray-400">Críticas</p>
              </div>
            </div>
          </div>

          {/* Lista */}
          <div className="p-4 space-y-2">
            {filteredVulns.map((vuln) => (
              <div
                key={vuln.id}
                onClick={() => setSelectedVuln(vuln)}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  selectedVuln?.id === vuln.id
                    ? 'bg-gray-800 border-cyan-500'
                    : 'bg-gray-900 border-gray-700 hover:border-gray-600'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="font-medium text-white">{vuln.title}</h3>
                    <div className="flex items-center space-x-2 mt-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      <span className="text-xs text-gray-400">CVSS {vuln.cvss}</span>
                    </div>
                  </div>
                  <ChevronRight className="w-5 h-5 text-gray-400" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Detalhes da Vulnerabilidade */}
        <div className="flex-1 overflow-y-auto">
          {selectedVuln ? (
            <div className="p-6">
              <div className="mb-6">
                <h1 className="text-2xl font-bold text-white mb-2">{selectedVuln.title}</h1>
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 rounded-lg text-sm font-medium ${getSeverityColor(selectedVuln.severity)}`}>
                    {selectedVuln.severity.toUpperCase()}
                  </span>
                  <span className="text-gray-400">CVSS Score: {selectedVuln.cvss}</span>
                  <span className="text-gray-400">•</span>
                  <span className="text-gray-400">{selectedVuln.type}</span>
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-lg font-semibold text-white mb-2 flex items-center">
                    <AlertTriangle className="w-5 h-5 mr-2 text-red-500" />
                    Descrição
                  </h3>
                  <p className="text-gray-300">{selectedVuln.description}</p>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-white mb-2 flex items-center">
                    <Shield className="w-5 h-5 mr-2 text-green-500" />
                    Recomendação
                  </h3>
                  <p className="text-gray-300">{selectedVuln.recommendation}</p>
                </div>

                <div>
                  <h3 className="text-lg font-semibold text-white mb-2">Exemplo de Código Vulnerável</h3>
                  <pre className="bg-gray-800 p-4 rounded-lg overflow-x-auto">
                    <code className="text-sm text-gray-300">{`// Vulnerável
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// Seguro
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);`}</code>
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <Bug className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">Selecione uma vulnerabilidade para ver os detalhes</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  );
};

export default Vulnerabilities;