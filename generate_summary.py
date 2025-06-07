#!/usr/bin/env python3
"""
Script para gerar um resumo do projeto para compartilhar com IA Assistant
"""

import os
import json
from datetime import datetime
from pathlib import Path

def get_project_structure(path, prefix="", ignore_dirs={'.git', '__pycache__', 'venv', 'node_modules', '.vite', 'dist', 'build'}):
    """Gera a estrutura de diretórios do projeto"""
    structure = []
    path = Path(path)
    
    try:
        items = sorted(path.iterdir(), key=lambda x: (x.is_file(), x.name))
        for item in items:
            if item.name.startswith('.') and item.name not in {'.env.example', '.gitignore'}:
                continue
            if item.name in ignore_dirs:
                continue
                
            if item.is_dir():
                structure.append(f"{prefix}├── {item.name}/")
                substructure = get_project_structure(item, prefix + "│   ", ignore_dirs)
                structure.extend(substructure)
            else:
                structure.append(f"{prefix}├── {item.name}")
    except PermissionError:
        pass
        
    return structure

def count_lines_of_code(path, extensions={'.py', '.js', '.jsx', '.ts', '.tsx', '.css'}):
    """Conta linhas de código por tipo de arquivo"""
    stats = {}
    path = Path(path)
    
    for file in path.rglob('*'):
        if file.is_file() and file.suffix in extensions:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    lines = len(f.readlines())
                    ext = file.suffix
                    stats[ext] = stats.get(ext, 0) + lines
            except:
                pass
                
    return stats

def get_recent_commits(limit=5):
    """Obtém os commits mais recentes"""
    try:
        import subprocess
        result = subprocess.run(
            ['git', 'log', f'-{limit}', '--pretty=format:%h - %s (%cr) <%an>'],
            capture_output=True,
            text=True
        )
        return result.stdout.split('\n') if result.returncode == 0 else []
    except:
        return []

def generate_summary():
    """Gera o resumo completo do projeto"""
    summary = []
    
    # Cabeçalho
    summary.append("# Resumo do Projeto para IA Assistant")
    summary.append(f"\n**Gerado em**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Estrutura do projeto
    summary.append("## Estrutura do Projeto")
    summary.append("```")
    structure = get_project_structure('.')
    summary.extend(structure[:30])  # Limita a 30 linhas
    if len(structure) > 30:
        summary.append("... (truncado)")
    summary.append("```\n")
    
    # Estatísticas de código
    summary.append("## Estatísticas de Código")
    stats = count_lines_of_code('.')
    for ext, lines in sorted(stats.items()):
        summary.append(f"- {ext}: {lines:,} linhas")
    summary.append("")
    
    # Commits recentes
    summary.append("## Commits Recentes")
    commits = get_recent_commits()
    for commit in commits:
        summary.append(f"- {commit}")
    summary.append("")
    
    # Arquivos importantes
    summary.append("## Arquivos-Chave para Consultar")
    key_files = [
        "AI_CONTEXT.md - Contexto detalhado do projeto",
        "README.md - Documentação principal",
        "requirements.txt - Dependências Python",
        ".env.example - Variáveis de ambiente necessárias"
    ]
    for file in key_files:
        summary.append(f"- {file}")
    
    # Salvar resumo
    output_path = Path("PROJECT_SUMMARY.md")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(summary))
    
    print(f"✅ Resumo gerado em: {output_path}")
    print("\n📋 Copie o conteúdo abaixo para compartilhar comigo:\n")
    print("="*50)
    print('\n'.join(summary[:20]))  # Mostra preview
    print("="*50)
    print(f"\n📄 Arquivo completo salvo em: {output_path}")

if __name__ == "__main__":
    generate_summary()