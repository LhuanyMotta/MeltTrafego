#!/usr/bin/env python3
"""
Setup Automático do MeltTrafego - Multiplataforma
"""

import os
import sys
import platform
import subprocess
import venv

def criar_ambiente_virtual():
    """Cria e configura ambiente virtual"""
    print("🐍 Criando ambiente virtual...")
    
    # Criar venv
    venv.create('melt_venv', with_pip=True)
    
    # Ativar venv e instalar dependências
    if platform.system() == "Windows":
        pip_path = os.path.join('melt_venv', 'Scripts', 'pip')
        python_path = os.path.join('melt_venv', 'Scripts', 'python')
    else:
        pip_path = os.path.join('melt_venv', 'bin', 'pip')
        python_path = os.path.join('melt_venv', 'bin', 'python')
    
    print("📦 Instalando dependências...")
    subprocess.run([pip_path, 'install', 'scapy', 'psutil', 'pandas', 'PyQt5'])
    
    return python_path

def configurar_permissoes_linux(python_path):
    """Configura permissões no Linux"""
    if platform.system() == "Linux":
        print("🔐 Configurando permissões de captura...")
        try:
            subprocess.run(['sudo', 'setcap', 'cap_net_raw,cap_net_admin=eip', python_path])
            print("✅ Permissões configuradas!")
        except:
            print("⚠️  Execute manualmente: sudo setcap cap_net_raw,cap_net_admin=eip melt_venv/bin/python3")

def criar_scripts_execucao(python_path):
    """Cria scripts de execução"""
    print("🚀 Criando scripts de execução...")
    
    # Script para GUI
    if platform.system() == "Windows":
        with open('melt_gui.bat', 'w') as f:
            f.write(f'@echo off\n"{python_path}" melt_gui.py\npause\n')
        
        with open('melt_cli.bat', 'w') as f:
            f.write(f'@echo off\n"{python_path}" melt_cli.py --interativo\npause\n')
    else:
        with open('melt_gui.sh', 'w') as f:
            f.write(f'#!/bin/bash\n"{python_path}" melt_gui.py\n')
        os.chmod('melt_gui.sh', 0o755)
        
        with open('melt_cli.sh', 'w') as f:
            f.write(f'#!/bin/bash\n"{python_path}" melt_cli.py --interativo\n')
        os.chmod('melt_cli.sh', 0o755)

def main():
    print("🚀 CONFIGURAÇÃO AUTOMÁTICA MELTTRÁFEGO")
    print("=" * 50)
    
    python_path = criar_ambiente_virtual()
    configurar_permissoes_linux(python_path)
    criar_scripts_execucao(python_path)
    
    print("\n🎉 CONFIGURAÇÃO CONCLUÍDA!")
    print(f"💡 Use: {python_path} melt_gui.py")
    print("📁 Ou execute os scripts criados!")

if __name__ == "__main__":
    main()