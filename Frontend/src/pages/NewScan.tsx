import React, { useState } from 'react';
import MainLayout from '../components/layout/MainLayout';
import { Shield, Search, Globe, Server, Code, Database, AlertTriangle } from 'lucide-react';

const NewScan: React.FC = () => {
  const [scanType, setScanType] = useState('');
  const [target, setTarget] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  const scanTypes = [
    { id: 'web', name: 'Análise Web', icon: Globe, description: 'Scan de vulnerabilidades web (XSS, SQL Injection, etc.)' },
    { id: 'network', name: 'Análise de Rede', icon: Server, description: 'Scan de portas e serviços de rede' },
    { id: 'code', name: 'Análise de Código', icon: Code, description: 'Revisão de código-fonte para vulnerabilidades' },
    { id: 'database', name: 'Análise de Banco', icon: Database, description: 'Verificação de segurança em bancos de dados' },
  ];

  const handleStartScan = async () => {
    if (!scanType || !target) {
      alert('Por favor, selecione um tipo de scan e informe o alvo');
      return;
    }

    setIsScanning(true);
    
    try {
      // Aqui você fará a chamada para o backend
      const response = await fetch('http://localhost:8000/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({
          type: scanType,
          target: target
        })
      });

      if (response.ok) {
        alert('Scan iniciado com sucesso!');
        // Redirecionar para a página de vulnerabilidades ou dashboard
      }
    } catch (error) {
      console.error('Erro ao iniciar scan:', error);
      alert('Erro ao iniciar scan');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <MainLayout>
      <div className="max-w-4xl mx-auto p-6">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Nova Análise de Segurança</h1>
          <p className="text-gray-400">Selecione o tipo de análise e configure os parâmetros</p>
        </div>

        {/* Tipos de Scan */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-white mb-4">Tipo de Análise</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {scanTypes.map((type) => {
              const Icon = type.icon;
              return (
                <button
                  key={type.id}
                  onClick={() => setScanType(type.id)}
                  className={`p-4 rounded-lg border-2 transition-all ${
                    scanType === type.id
                      ? 'border-cyan-500 bg-cyan-500/10'
                      : 'border-gray-700 hover:border-gray-600 bg-gray-800/50'
                  }`}
                >
                  <div className="flex items-start space-x-3">
                    <Icon className={`w-6 h-6 ${scanType === type.id ? 'text-cyan-400' : 'text-gray-400'}`} />
                    <div className="text-left">
                      <h3 className="font-medium text-white">{type.name}</h3>
                      <p className="text-sm text-gray-400 mt-1">{type.description}</p>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Alvo do Scan */}
        <div className="mb-8">
          <h2 className="text-xl font-semibold text-white mb-4">Alvo da Análise</h2>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Ex: https://exemplo.com, 192.168.1.1, ou caminho do código"
            className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Opções Avançadas */}
        <div className="mb-8">
          <details className="group">
            <summary className="cursor-pointer text-white font-medium mb-4">
              Opções Avançadas
            </summary>
            <div className="space-y-4 mt-4">
              <label className="flex items-center space-x-3">
                <input type="checkbox" className="w-4 h-4 text-cyan-500" />
                <span className="text-gray-300">Scan profundo (mais demorado)</span>
              </label>
              <label className="flex items-center space-x-3">
                <input type="checkbox" className="w-4 h-4 text-cyan-500" />
                <span className="text-gray-300">Incluir análise de dependências</span>
              </label>
              <label className="flex items-center space-x-3">
                <input type="checkbox" className="w-4 h-4 text-cyan-500" />
                <span className="text-gray-300">Gerar relatório detalhado</span>
              </label>
            </div>
          </details>
        </div>

        {/* Botão de Iniciar */}
        <button
          onClick={handleStartScan}
          disabled={isScanning}
          className={`w-full py-3 rounded-lg font-medium transition-all ${
            isScanning
              ? 'bg-gray-700 text-gray-400 cursor-not-allowed'
              : 'bg-cyan-500 hover:bg-cyan-600 text-black'
          }`}
        >
          {isScanning ? 'Analisando...' : 'Iniciar Análise'}
        </button>
      </div>
    </MainLayout>
  );
};

export default NewScan;