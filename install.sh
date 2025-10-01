#!/bin/bash
echo "🔧 Instalando MeltTrafego no Linux..."

cd "$(dirname "$0")"

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 não encontrado. Instalando..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

# Criar pastas necessárias
echo "📁 Criando estrutura de pastas..."
mkdir -p relatorios assets

# Detectar distribuição Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi

echo "💻 Distribuição detectada: $DISTRO"

# Instalar dependências do sistema
echo "📦 Instalando dependências do sistema..."

case $DISTRO in
    ubuntu|debian)
        sudo apt update
        sudo apt install -y tcpdump wireshark-common libpcap-dev python3-dev
        ;;
    fedora|centos|rhel)
        sudo dnf install -y tcpdump wireshark-cli libpcap-devel python3-devel
        ;;
    arch|manjaro)
        sudo pacman -S --noconfirm tcpdump wireshark-qt libpcap python
        ;;
    opensuse)
        sudo zypper install -y tcpdump wireshark libpcap-devel python3-devel
        ;;
    *)
        echo "⚠️  Distribuição não reconhecida. Instale manualmente:"
        echo "   tcpdump, wireshark-common, libpcap-dev"
        ;;
esac

# Rodar setup.py
echo "🐍 Configurando ambiente Python..."
python3 setup.py

echo ""
echo "🎉 INSTALAÇÃO CONCLUÍDA!"
echo "   Ativar ambiente: source melt_venv/bin/activate"
echo "   Interface gráfica: ./melt_gui.sh"
echo "   Linha de comando: ./melt_cli.sh --interativo"
