# Contexto para Assistente IA - SecuritIA

## 🎯 Visão Geral do Projeto
**Nome**: SecuritIA  
**Tipo**: Aplicação Full Stack de Segurança com IA  
**Estado Atual**: Em desenvolvimento  
**Última Atualização**: 2024-12-28  
**Repositório**: https://github.com/Vcortez99-hub/SecuritIA

## 🛠️ Stack Tecnológico

### Backend (Python)
- **Framework**: FastAPI
- **Banco de Dados**: SQLite (desenvolvimento), PostgreSQL (produção planejada)
- **Autenticação**: JWT Tokens
- **IA/ML**: [A definir - TensorFlow/PyTorch/Scikit-learn]
- **Logging**: Python logging + arquivo securit_ia.log
- **ORM**: SQLAlchemy (presumido)

### Frontend (JavaScript/TypeScript)
- **Framework**: React 18+ com Vite
- **Linguagem**: TypeScript
- **Estilização**: Tailwind CSS + PostCSS
- **Gerenciamento de Estado**: [A definir - Context API/Redux/Zustand]
- **Requisições HTTP**: [A definir - Axios/Fetch API]

### DevOps
- **Containerização**: Docker
- **Versionamento**: Git/GitHub
- **CI/CD**: [A definir]

## 🏗️ Arquitetura

### Backend Structure
```
Backend/
├── app/                 # Core da aplicação
│   ├── models/         # Modelos de dados
│   ├── schemas/        # Schemas Pydantic
│   └── database.py     # Configuração do BD
├── routers/            # Endpoints da API
│   ├── auth.py        # Autenticação
│   ├── monitor.py     # Monitoramento
│   └── alerts.py      # Sistema de alertas
├── services/           # Lógica de negócio
│   ├── ai_service.py  # Serviços de IA
│   └── security.py    # Análise de segurança
├── utils/              # Utilitários
│   ├── security.py    # Funções de segurança
│   └── validators.py  # Validações
└── main.py            # Entry point FastAPI
```

### Frontend Structure
```
Frontend/
├── src/
│   ├── components/     # Componentes React
│   ├── pages/         # Páginas/Rotas
│   ├── services/      # Serviços/API calls
│   ├── hooks/         # Custom hooks
│   ├── utils/         # Funções utilitárias
│   └── types/         # TypeScript types
```

## 🔑 Funcionalidades Principais

### 1. Sistema de Autenticação
- Login/Logout com JWT
- Registro de usuários
- Gestão de sessões
- Níveis de acesso (Admin/User)

### 2. Monitoramento em Tempo Real
- Dashboard com métricas
- Visualização de eventos
- Sistema de notificações

### 3. Análise com IA
- [A definir específicamente]
- Detecção de anomalias
- Predição de ameaças
- Relatórios automatizados

### 4. Sistema de Alertas
- Alertas em tempo real
- Configuração de thresholds
- Histórico de incidentes

## 📊 Modelos de Dados Principais

### User
```python
- id: int
- username: str
- email: str
- password_hash: str
- is_active: bool
- role: str (admin/user)
- created_at: datetime
```

### Alert
```python
- id: int
- title: str
- description: str
- severity: str (low/medium/high/critical)
- status: str (active/resolved)
- created_at: datetime
- resolved_at: datetime
```

### MonitoringData
```python
- id: int
- metric_name: str
- value: float
- timestamp: datetime
- source: str
```

## 🔧 Configurações e Variáveis de Ambiente

### Backend (.env)
```
DATABASE_URL=sqlite:///./securit_ia.db
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
API_VERSION=v1
```

### Frontend (.env)
```
VITE_API_URL=http://localhost:8000
VITE_APP_NAME=SecuritIA
```

## 🚨 Problemas Conhecidos
1. **Banco de dados**: Atualmente usando SQLite, migrar para PostgreSQL em produção
2. **CORS**: Configurar adequadamente para produção
3. **Rate Limiting**: Implementar limite de requisições
4. **Testes**: Adicionar cobertura de testes

## 📝 Padrões de Código

### Python (Backend)
- **Style Guide**: PEP 8
- **Docstrings**: Google Style
- **Type Hints**: Usar sempre que possível
- **Nomenclatura**: snake_case para funções, PascalCase para classes

### TypeScript (Frontend)
- **Style Guide**: Airbnb + ESLint
- **Componentes**: Functional components com hooks
- **Props**: Sempre tipar com interfaces
- **Nomenclatura**: camelCase para funções, PascalCase para componentes

## 🎯 TODO List Atual

### Alta Prioridade
- [ ] Implementar sistema de autenticação completo
- [ ] Criar dashboard principal
- [ ] Configurar WebSocket para real-time updates
- [ ] Implementar sistema de logs estruturado

### Média Prioridade
- [ ] Adicionar testes unitários (mínimo 80% coverage)
- [ ] Documentar API com Swagger/OpenAPI
- [ ] Implementar cache Redis
- [ ] Criar sistema de backup automático

### Baixa Prioridade
- [ ] Adicionar internacionalização (i18n)
- [ ] Implementar tema dark/light
- [ ] Criar aplicativo mobile
- [ ] Adicionar exportação de relatórios PDF

## 💡 Notas Importantes para o Assistente IA

1. **Segurança é prioridade**: Sempre considere implicações de segurança em qualquer mudança
2. **Performance**: O sistema deve suportar monitoramento em tempo real sem delays
3. **Escalabilidade**: Código deve ser escrito pensando em crescimento futuro
4. **Clean Code**: Manter código limpo e bem documentado
5. **Versionamento**: Sempre criar commits descritivos e usar conventional commits

## 🔗 Recursos e Referências

- **FastAPI Docs**: https://fastapi.tiangolo.com/
- **React Docs**: https://react.dev/
- **Tailwind CSS**: https://tailwindcss.com/
- **JWT**: https://jwt.io/
- **Docker**: https://docs.docker.com/

## 📚 Decisões Arquiteturais

### 2024-12-28 - Escolha do FastAPI
**Contexto**: Necessidade de API rápida e moderna  
**Decisão**: Usar FastAPI ao invés de Flask/Django  
**Motivos**: Performance superior, documentação automática, type hints nativo

### 2024-12-28 - Frontend com Vite
**Contexto**: Build tool para React  
**Decisão**: Vite ao invés de Create React App  
**Motivos**: Build mais rápido, melhor DX, suporte nativo para TypeScript