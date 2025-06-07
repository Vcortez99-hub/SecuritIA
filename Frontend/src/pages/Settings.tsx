import React, { useState } from 'react';
import MainLayout from '../components/layout/MainLayout';
import { User, Bell, Shield, Database, Key, Save } from 'lucide-react';

const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState('profile');
  const [formData, setFormData] = useState({
    name: 'Admin',
    email: 'admin@securitia.com',
    notifications: {
      email: true,
      critical: true,
      reports: false
    },
    apiKey: '****-****-****-****'
  });

  const tabs = [
    { id: 'profile', name: 'Perfil', icon: User },
    { id: 'notifications', name: 'Notificações', icon: Bell },
    { id: 'security', name: 'Segurança', icon: Shield },
    { id: 'integrations', name: 'Integrações', icon: Database },
  ];

  const handleSave = () => {
    console.log('Salvando configurações:', formData);
    alert('Configurações salvas com sucesso!');
  };

  return (
    <MainLayout>
      <div className="flex h-full">
        {/* Sidebar de Configurações */}
        <div className="w-64 border-r border-gray-800 p-6">
          <h2 className="text-xl font-bold text-white mb-6">Configurações</h2>
          
          <nav className="space-y-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center space-x-3 px-4 py-2 rounded-lg transition-colors ${
                    activeTab === tab.id
                      ? 'bg-cyan-500/20 text-cyan-400'
                      : 'text-gray-400 hover:bg-gray-800'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span>{tab.name}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Conteúdo das Configurações */}
        <div className="flex-1 p-6">
          {activeTab === 'profile' && (
            <div className="max-w-2xl">
              <h3 className="text-2xl font-bold text-white mb-6">Perfil</h3>
              
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">
                    Nome
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-2">
                    Email
                  </label>
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <button
                  onClick={handleSave}
                  className="flex items-center space-x-2 px-6 py-2 bg-cyan-500 hover:bg-cyan-600 text-black font-medium rounded-lg transition-colors"
                >
                  <Save className="w-4 h-4" />
                  <span>Salvar Alterações</span>
                </button>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="max-w-2xl">
              <h3 className="text-2xl font-bold text-white mb-6">Notificações</h3>
              
              <div className="space-y-4">
                <label className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                  <div>
                    <p className="text-white font-medium">Notificações por Email</p>
                    <p className="text-sm text-gray-400">Receber atualizações por email</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={formData.notifications.email}
                    onChange={(e) => setFormData({
                      ...formData,
                      notifications: {...formData.notifications, email: e.target.checked}
                    })}
                    className="w-5 h-5 text-cyan-500"
                  />
                </label>

                <label className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                  <div>
                    <p className="text-white font-medium">Alertas Críticos</p>
                    <p className="text-sm text-gray-400">Notificar sobre vulnerabilidades críticas</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={formData.notifications.critical}
                    onChange={(e) => setFormData({
                      ...formData,
                      notifications: {...formData.notifications, critical: e.target.checked}
                    })}
                    className="w-5 h-5 text-cyan-500"
                  />
                </label>

                <label className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                  <div>
                    <p className="text-white font-medium">Relatórios Automáticos</p>
                    <p className="text-sm text-gray-400">Enviar relatórios semanais</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={formData.notifications.reports}
                    onChange={(e) => setFormData({
                      ...formData,
                      notifications: {...formData.notifications, reports: e.target.checked}
                    })}
                    className="w-5 h-5 text-cyan-500"
                  />
                </label>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="max-w-2xl">
              <h3 className="text-2xl font-bold text-white mb-6">Segurança</h3>
              
              <div className="space-y-6">
                <div className="p-4 bg-gray-800 rounded-lg">
                  <h4 className="text-white font-medium mb-4">Chave de API</h4>
                  <div className="flex items-center space-x-4">
                    <input
                      type="password"
                      value={formData.apiKey}
                      readOnly
                      className="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                    />
                    <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                      <Key className="w-5 h-5" />
                    </button>
                  </div>
                </div>
                <div className="p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                  <p className="text-yellow-500 text-sm">
                    <strong>Atenção:</strong> Mantenha sua chave de API segura. Não compartilhe com terceiros.
                  </p>
                </div>

                <div>
                  <button className="w-full py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 rounded-lg transition-colors">
                    Gerar Nova Chave de API
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'integrations' && (
            <div className="max-w-2xl">
              <h3 className="text-2xl font-bold text-white mb-6">Integrações</h3>
              
              <div className="space-y-4">
                <div className="p-6 bg-gray-800 rounded-lg">
                  <h4 className="text-white font-medium mb-2">GitHub</h4>
                  <p className="text-sm text-gray-400 mb-4">Conecte com GitHub para análise de código</p>
                  <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                    Conectar
                  </button>
                </div>

                <div className="p-6 bg-gray-800 rounded-lg">
                  <h4 className="text-white font-medium mb-2">Slack</h4>
                  <p className="text-sm text-gray-400 mb-4">Receba notificações no Slack</p>
                  <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                    Conectar
                  </button>
                </div>

                <div className="p-6 bg-gray-800 rounded-lg">
                  <h4 className="text-white font-medium mb-2">Webhook</h4>
                  <p className="text-sm text-gray-400 mb-4">Configure webhooks personalizados</p>
                  <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
                    Configurar
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  );
};

export default Settings;