import React, { useState } from 'react';
import MainLayout from '../components/layout/MainLayout';
import { FileText, Download, Calendar, Filter, Eye } from 'lucide-react';

interface Report {
  id: string;
  title: string;
  date: string;
  type: string;
  status: 'completed' | 'in-progress';
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([
    {
      id: '1',
      title: 'Análise de Segurança - Sistema Principal',
      date: '2024-01-15',
      type: 'Completo',
      status: 'completed',
      vulnerabilities: { critical: 2, high: 5, medium: 8, low: 12 }
    },
    {
      id: '2',
      title: 'Scan de Rede - Infraestrutura',
      date: '2024-01-10',
      type: 'Rede',
      status: 'completed',
      vulnerabilities: { critical: 0, high: 3, medium: 15, low: 7 }
    },
    {
      id: '3',
      title: 'Análise de Código - API REST',
      date: '2024-01-08',
      type: 'Código',
      status: 'in-progress',
      vulnerabilities: { critical: 1, high: 2, medium: 4, low: 9 }
    }
  ]);

  const handleDownloadReport = async (reportId: string) => {
    try {
      const response = await fetch(`http://localhost:8000/api/reports/${reportId}/download`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `report-${reportId}.pdf`;
        a.click();
      }
    } catch (error) {
      console.error('Erro ao baixar relatório:', error);
    }
  };

  return (
    <MainLayout>
      <div className="p-6">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Relatórios de Segurança</h1>
          <p className="text-gray-400">Visualize e exporte relatórios de análises realizadas</p>
        </div>

        {/* Filtros */}
        <div className="mb-6 flex items-center space-x-4">
          <button className="flex items-center space-x-2 px-4 py-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors">
            <Filter className="w-4 h-4" />
            <span>Filtrar</span>
          </button>
          <button className="flex items-center space-x-2 px-4 py-2 bg-gray-800 rounded-lg hover:bg-gray-700 transition-colors">
            <Calendar className="w-4 h-4" />
            <span>Período</span>
          </button>
        </div>

        {/* Lista de Relatórios */}
        <div className="grid gap-4">
          {reports.map((report) => (
            <div key={report.id} className="bg-gray-800 rounded-lg p-6 hover:bg-gray-750 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <FileText className="w-5 h-5 text-cyan-400" />
                    <h3 className="text-lg font-medium text-white">{report.title}</h3>
                    {report.status === 'in-progress' && (
                      <span className="px-2 py-1 text-xs bg-yellow-500/20 text-yellow-500 rounded">
                        Em Progresso
                      </span>
                    )}
                  </div>
                  
                  <div className="flex items-center space-x-4 text-sm text-gray-400 mb-4">
                    <span>{new Date(report.date).toLocaleDateString('pt-BR')}</span>
                    <span>•</span>
                    <span>Tipo: {report.type}</span>
                  </div>

                  {/* Resumo de Vulnerabilidades */}
                  <div className="flex items-center space-x-6">
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-red-500 rounded"></div>
                      <span className="text-sm text-gray-300">
                        {report.vulnerabilities.critical} Críticas
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-orange-500 rounded"></div>
                      <span className="text-sm text-gray-300">
                        {report.vulnerabilities.high} Altas
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-yellow-500 rounded"></div>
                      <span className="text-sm text-gray-300">
                        {report.vulnerabilities.medium} Médias
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-3 h-3 bg-blue-500 rounded"></div>
                      <span className="text-sm text-gray-300">
                        {report.vulnerabilities.low} Baixas
                      </span>
                    </div>
                  </div>
                </div>

                {/* Ações */}
                <div className="flex items-center space-x-2">
                  <button className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors">
                    <Eye className="w-5 h-5" />
                  </button>
                  <button 
                    onClick={() => handleDownloadReport(report.id)}
                    className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
                  >
                    <Download className="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </MainLayout>
  );
};

export default Reports;