import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  Shield,
  Search, 
  MessageCircle, 
  Settings, 
  ChevronRight,
  Zap,
  Network,
  Bug,
  Lock,
  FileText,
  Plus,
  Home,
  Github,
  LogOut
} from 'lucide-react';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchQuery, setSearchQuery] = useState('');

  const sidebarItems = [
    {
      id: 'sql-injection',
      title: 'SQL Injection Analysis',
      time: '2h ago',
      icon: Bug,
      path: '/analysis/sql-injection'
    },
    {
      id: 'network-pentest',
      title: 'Network Pentest Report',
      time: '1d ago',
      icon: Network,
      path: '/analysis/network-pentest'
    },
    {
      id: 'xss-prevention',
      title: 'XSS Prevention Strategy',
      time: '2d ago',
      icon: Shield,
      path: '/analysis/xss-prevention'
    },
    {
      id: 'owasp-review',
      title: 'OWASP Top 10 Review',
      time: '3d ago',
      icon: FileText,
      path: '/analysis/owasp-review'
    },
    {
      id: 'api-security',
      title: 'API Security Assessment',
      time: '1w ago',
      icon: Lock,
      path: '/analysis/api-security'
    }
  ];

  const handleNewAnalysis = () => {
    navigate('/new-scan');
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    navigate('/login');
  };

  return (
    <div className="flex h-screen bg-gray-900 text-white">
      <div className="w-80 bg-black border-r border-gray-800 flex flex-col">
        <div className="p-4 border-b border-gray-800">
          <div className="flex items-center space-x-2 mb-4">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-xl font-bold">SECURIT IA</h1>
              <p className="text-xs text-gray-400">Security Intelligence</p>
            </div>
          </div>
          
          <button
            onClick={handleNewAnalysis}
            className="w-full bg-cyan-500 hover:bg-cyan-600 text-black font-medium py-2 px-4 rounded-lg flex items-center justify-center space-x-2 transition-colors"
          >
            <Plus className="w-5 h-5" />
            <span>Nova Análise</span>
          </button>
        </div>

        <div className="p-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Buscar conversas..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-gray-800 text-white pl-10 pr-4 py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {sidebarItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            
            return (
              <div
                key={item.id}
                onClick={() => navigate(item.path)}
                className={`p-4 cursor-pointer hover:bg-gray-800 transition-colors ${
                  isActive ? 'bg-gray-800 border-l-2 border-cyan-500' : ''
                }`}
              >
                <div className="flex items-start space-x-3">
                  <div className={`p-2 rounded-lg ${
                    isActive ? 'bg-cyan-500/20' : 'bg-gray-700'
                  }`}>
                    <Icon className={`w-5 h-5 ${
                      isActive ? 'text-cyan-400' : 'text-gray-400'
                    }`} />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-sm font-medium text-white">
                      {item.title}
                    </h3>
                    <p className="text-xs text-gray-400 mt-1">{item.time}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="p-4 border-t border-gray-800">
          <button
            onClick={() => navigate('/settings')}
            className="w-full flex items-center space-x-3 p-2 hover:bg-gray-800 rounded-lg transition-colors"
          >
            <Settings className="w-5 h-5 text-gray-400" />
            <span className="text-sm text-gray-400">Configurações</span>
          </button>
        </div>
      </div>

      <div className="flex-1 flex flex-col">
        <div className="bg-gray-800 border-b border-gray-700 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={() => navigate('/')}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <Home className="w-5 h-5" />
            </button>
            <ChevronRight className="w-4 h-4 text-gray-600" />
            <span className="text-white font-medium">Análise de Segurança</span>
          </div>
          
          <div className="flex items-center space-x-4">
            <button className="text-gray-400 hover:text-white transition-colors">
              <Github className="w-5 h-5" />
            </button>
            <div className="w-px h-6 bg-gray-700" />
            <button className="text-gray-400 hover:text-white transition-colors">
              <MessageCircle className="w-5 h-5" />
            </button>
            <button
              onClick={handleLogout}
              className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              Publish
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto bg-gray-900">
          {children}
        </div>
      </div>
    </div>
  );
};

export default MainLayout;