# SecuritIA 🛡️

## 📋 Descrição
SecuritIA é uma aplicação de segurança inteligente que utiliza IA para análise e monitoramento de segurança em tempo real.

## 🚀 Tecnologias Utilizadas

### Backend
- **Python 3.x** - Linguagem principal
- **FastAPI** - Framework web moderno e rápido
- **SQLite** - Banco de dados
- **Python-dotenv** - Gerenciamento de variáveis de ambiente

### Frontend
- **React + Vite** - Framework e build tool
- **TypeScript** - Tipagem estática
- **Tailwind CSS** - Estilização
- **PostCSS** - Processamento de CSS

## 📁 Estrutura do Projeto
```
SECURIT IA/
│
├── Backend/
│   ├── app/              # Aplicação principal
│   ├── routers/          # Rotas da API
│   ├── services/         # Lógica de negócio
│   ├── utils/            # Funções utilitárias
│   ├── main.py           # Ponto de entrada
│   └── requirements.txt  # Dependências Python
│
├── Frontend/
│   ├── src/              # Código fonte React
│   ├── public/           # Arquivos públicos
│   ├── index.html        # HTML principal
│   └── package.json      # Dependências Node.js
│
├── .gitignore            # Arquivos ignorados pelo Git
├── README.md             # Este arquivo
├── AI_CONTEXT.md         # Contexto para IA Assistant
└── docker-compose.yml    # Configuração Docker (se aplicável)
```

## 🔧 Instalação e Configuração

### Pré-requisitos
- Python 3.8+
- Node.js 16+
- Git

### Backend

1. **Clone o repositório**
```bash
git clone https://github.com/Vcortez99-hub/SecuritIA.git
cd SecuritIA
```

2. **Configure o ambiente Python**
```bash
cd Backend
python -m venv venv
venv\Scripts\activate  # Windows
# ou
source venv/bin/activate  # Linux/Mac
```

3. **Instale as dependências**
```bash
pip install -r requirements.txt
```

4. **Configure as variáveis de ambiente**
```bash
cp .env.example .env
# Edite o arquivo .env com suas configurações
```

5. **Execute o servidor**
```bash
python main.py
# ou
uvicorn main:app --reload
```

O backend estará disponível em `http://localhost:8000`

### Frontend

1. **Em outro terminal, navegue para o Frontend**
```bash
cd Frontend
```

2. **Instale as dependências**
```bash
npm install
```

3. **Configure as variáveis de ambiente**
```bash
cp .env.example .env
# Configure a URL da API no .env
```

4. **Execute o servidor de desenvolvimento**
```bash
npm run dev
```

O frontend estará disponível em `http://localhost:5173`

## 📡 API Endpoints

### Autenticação
- `POST /api/auth/login` - Login de usuário
- `POST /api/auth/register` - Registro de usuário
- `POST /api/auth/logout` - Logout

### Monitoramento
- `GET /api/monitor/status` - Status do sistema
- `GET /api/monitor/alerts` - Alertas ativos
- `POST /api/monitor/scan` - Iniciar varredura

## 🐳 Docker (Opcional)

Para executar com Docker:

```bash
docker-compose up -d
```

## 🧪 Testes

### Backend
```bash
cd Backend
pytest
```

### Frontend
```bash
cd Frontend
npm test
```

## 🤝 Contribuindo

1. Faça um Fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📞 Contato

Vinicius Cortez - [@Vcortez99-hub](https://github.com/Vcortez99-hub)

Link do Projeto: [https://github.com/Vcortez99-hub/SecuritIA](https://github.com/Vcortez99-hub/SecuritIA)

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.