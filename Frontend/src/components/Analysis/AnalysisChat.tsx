import React, { useState } from 'react';
import { Send, Paperclip, Mic, Copy, ThumbsUp, ThumbsDown, Shield } from 'lucide-react';


interface Message {
  id: string;
  type: 'user' | 'ai';
  content: string;
  timestamp: string;
}

const AnalysisChat: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: '1',
      type: 'ai',
      content: 'Olá! Sou o CyberSec AI, sua assistente especializada em cybersegurança. Como posso ajudá-lo hoje? Posso analisar vulnerabilidades, gerar relatórios de pentest, revisar código para falhas de segurança, ou discutir as melhores práticas de segurança.',
      timestamp: '10:30'
    },
    {
      id: '2',
      type: 'user',
      content: 'Preciso de ajuda para analisar uma possível vulnerabilidade SQL injection que encontrei no meu sistema.',
      timestamp: '10:32'
    },
    {
      id: '3',
      type: 'ai',
      content: 'Excelente! Vou ajudá-lo com a análise de SQL Injection. Para fornecer uma análise precisa, preciso de algumas informações:\n\n🔍 **Informações necessárias:**\n• Código ou query SQL suspeita\n• Contexto da aplicação (web, API, etc.)\n• Linguagem de programação utilizada\n• Tipo de banco de dados',
      timestamp: '10:33'
    }
  ]);

  const [inputMessage, setInputMessage] = useState('');

  const handleSendMessage = () => {
    if (!inputMessage.trim()) return;

    const newMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: inputMessage,
      timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
    };

    setMessages([...messages, newMessage]);
    setInputMessage('');

    // Simular resposta da IA
    setTimeout(() => {
      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        type: 'ai',
        content: 'Analisando sua consulta... Vou examinar o código fornecido para identificar possíveis vulnerabilidades de SQL Injection.',
        timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, aiResponse]);
    }, 1000);
  };

  return (
    <div className="flex flex-col h-full">
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div className={`max-w-3xl ${message.type === 'user' ? 'order-2' : ''}`}>
              <div className="flex items-start space-x-3">
                {message.type === 'ai' && (
                  <div className="w-8 h-8 bg-cyan-500 rounded-full flex items-center justify-center flex-shrink-0">
                    <Shield className="w-5 h-5 text-black" />
                  </div>
                )}
                
                <div className={`rounded-lg p-4 ${
                  message.type === 'user' 
                    ? 'bg-blue-600 text-white' 
                    : 'bg-gray-800 text-gray-100'
                }`}>
                  <p className="whitespace-pre-wrap">{message.content}</p>
                  
                  {message.type === 'ai' && (
                    <div className="flex items-center space-x-2 mt-3">
                      <button className="text-gray-400 hover:text-white">
                        <Copy className="w-4 h-4" />
                      </button>
                      <button className="text-gray-400 hover:text-white">
                        <ThumbsUp className="w-4 h-4" />
                      </button>
                      <button className="text-gray-400 hover:text-white">
                        <ThumbsDown className="w-4 h-4" />
                      </button>
                      <span className="text-xs text-gray-500 ml-2">{message.timestamp}</span>
                    </div>
                  )}
                </div>
                
                {message.type === 'user' && (
                  <div className="w-8 h-8 bg-gray-600 rounded-full flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-medium">U</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Action Buttons */}
      <div className="px-6 py-2 flex flex-wrap gap-2">
        <button className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors">
          Analisar esta vulnerabilidade
        </button>
        <button className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors">
          Como prevenir ataques XSS?
        </button>
        <button className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors">
          Gerar relatório de pentest
        </button>
        <button className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors">
          OWASP Top 10 2023
        </button>
      </div>

      {/* Input Area */}
      <div className="p-6 border-t border-gray-800">
        <form onSubmit={(e) => { e.preventDefault(); handleSendMessage(); }} className="relative">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Descreva a vulnerabilidade, ataque ou questão de segurança..."
            className="w-full bg-gray-800 text-white px-4 py-3 pr-32 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          
          <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex items-center space-x-2">
            <button
              type="button"
              className="text-gray-400 hover:text-white p-2"
            >
              <Paperclip className="w-5 h-5" />
            </button>
            <button
              type="button"
              className="text-gray-400 hover:text-white p-2"
            >
              <Mic className="w-5 h-5" />
            </button>
            <button
              type="submit"
              className="bg-cyan-500 hover:bg-cyan-600 text-black p-2 rounded-lg transition-colors"
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </form>
        
        <div className="mt-2 text-center">
          <p className="text-xs text-gray-500">
            Powered by CyberSec AI • Mantenha informações sensíveis em segurança
          </p>
        </div>
      </div>
    </div>
  );
};

export default AnalysisChat;