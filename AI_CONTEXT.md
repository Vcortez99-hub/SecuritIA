# Contexto para Assistente IA

## Visão Geral do Projeto
**Nome**: [Nome do Projeto]
**Tipo**: [Aplicação de IA/ML/Web/etc]
**Estado Atual**: [Em desenvolvimento/Produção/MVP]
**Última Atualização**: [Data]

## Stack Tecnológico
### Backend
- **Linguagem**: Python 3.x
- **Framework**: [FastAPI/Flask/Django]
- **Banco de Dados**: [PostgreSQL/MongoDB/SQLite]
- **IA/ML**: [TensorFlow/PyTorch/Scikit-learn]

### Frontend (se aplicável)
- **Framework**: [React/Vue/Angular]
- **Estilização**: [Tailwind/CSS/SASS]

## Arquitetura
```
[Diagrama ASCII ou descrição da arquitetura]
```

## Módulos Principais

### 1. [Nome do Módulo]
- **Localização**: `src/models/`
- **Responsabilidade**: [O que faz]
- **Dependências**: [Lista de dependências]
- **Status**: [Completo/Em desenvolvimento/Planejado]

### 2. [Nome do Módulo]
- **Localização**: `src/utils/`
- **Responsabilidade**: [O que faz]
- **Dependências**: [Lista de dependências]
- **Status**: [Completo/Em desenvolvimento/Planejado]

## APIs e Endpoints
```
GET  /api/v1/[endpoint]  - [Descrição]
POST /api/v1/[endpoint]  - [Descrição]
```

## Modelos de Dados
```python
# Exemplo de estrutura de dados principal
class [NomeModelo]:
    id: int
    campo1: str
    campo2: float
```

## Configurações Importantes
- **Variáveis de Ambiente**: Listadas em `.env.example`
- **Portas**: [8000 para API, 3000 para frontend]
- **Limites**: [Rate limiting, tamanho de upload, etc]

## Problemas Conhecidos
1. **[Problema]**: [Descrição e possível solução]
2. **[Problema]**: [Descrição e possível solução]

## Padrões de Código
- **Nomenclatura**: snake_case para funções, PascalCase para classes
- **Documentação**: Docstrings Google Style
- **Testes**: pytest com coverage mínimo de 80%

## Fluxos de Trabalho

### Fluxo de Processamento de Dados
1. [Passo 1]
2. [Passo 2]
3. [Passo 3]

### Fluxo de Treinamento de Modelo
1. [Passo 1]
2. [Passo 2]
3. [Passo 3]

## Comandos Úteis
```bash
# Executar aplicação
python src/main.py

# Executar testes
pytest

# Treinar modelo
python scripts/train_model.py

# Gerar documentação
python scripts/generate_docs.py
```

## Histórico de Decisões

### [Data] - [Decisão]
**Contexto**: [Por que foi necessário]
**Decisão**: [O que foi decidido]
**Consequências**: [Impactos da decisão]

## TODO List Atual
- [ ] **Alta Prioridade**: [Tarefa]
- [ ] **Média Prioridade**: [Tarefa]
- [ ] **Baixa Prioridade**: [Tarefa]

## Notas para o Assistente IA
- Sempre verifique [arquivo/pasta] antes de fazer alterações em [componente]
- O módulo [X] é crítico e requer testes antes de qualquer mudança
- Preferimos [abordagem A] ao invés de [abordagem B] por [motivo]

## Links e Recursos
- **Repositório**: [URL do GitHub/GitLab]
- **Documentação Externa**: [Links]
- **Design/Mockups**: [Links]