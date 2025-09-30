#!/bin/bash
echo "🔧 Instalando MeltTrafego no Linux (Sem necessidade de sudo)..."

# Mudar para o diretório do script
cd "$(dirname "$0")"

# Verificar se é executado como root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Não execute como root/sudo!"
    echo "💡 Execute como usuário normal: ./install.sh"
    exit 1
fi

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 não encontrado. Instalando..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv python3-full
fi

# Configurar permissões
echo "🔐 Configurando permissões..."
chmod +x install.sh melt_cli.py melt_captura.sh melt_gui.py melt_core.py 2>/dev/null || true

# Criar pastas necessárias
echo "📁 Criando estrutura de pastas..."
mkdir -p relatorios logs exemplos assets

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
        echo "📥 Instalando tcpdump e dependências..."
        sudo apt update
        sudo apt install -y tcpdump wireshark-common libpcap-dev python3-dev build-essential python3-full
        ;;
    fedora|centos|rhel)
        sudo dnf install -y tcpdump wireshark-cli libpcap-devel python3-devel gcc
        ;;
    arch|manjaro)
        sudo pacman -S --noconfirm tcpdump wireshark-qt libpcap python base-devel
        ;;
    opensuse)
        sudo zypper install -y tcpdump wireshark libpcap-devel python3-devel gcc
        ;;
    *)
        echo "⚠️  Distribuição não reconhecida. Instale manualmente:"
        echo "   tcpdump, wireshark-common, libpcap-dev, python3-full"
        ;;
esac

# Criar ambiente virtual
echo "🐍 Configurando ambiente Python..."
python3 -m venv melt_venv
source melt_venv/bin/activate

# Atualizar pip
pip install --upgrade pip

# Instalar dependências Python
echo "📦 Instalando dependências Python..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "📋 Instalando dependências manualmente..."
    pip install scapy psutil pandas PyQt5
fi

# Configurar permissões de captura SEM SUDO
echo "🔧 Configurando permissões de captura (sem sudo necessários)..."
if command -v setcap &> /dev/null; then
    # Dar permissão para captura de pacotes sem sudo
    sudo setcap cap_net_raw,cap_net_admin+eip melt_venv/bin/python3 2>/dev/null && \
        echo "✅ Permissões de captura configuradas" || \
        echo "❌ Não foi possível configurar permissões automaticamente"
    
    # Também configurar para tcpdump
    sudo groupadd pcap 2>/dev/null || true
    sudo usermod -a -G pcap $USER 2>/dev/null || true
    sudo chgrp pcap /usr/sbin/tcpdump 2>/dev/null || true
    sudo chmod 750 /usr/sbin/tcpdump 2>/dev/null || true
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump 2>/dev/null || true
else
    echo "⚠️  setcap não disponível. Configurando alternativas..."
fi

# Configurar grupo para captura
echo "👥 Configurando grupo de captura..."
if getent group pcap >/dev/null; then
    sudo usermod -a -G pcap $USER && echo "✅ Usuário adicionado ao grupo pcap"
else
    echo "⚠️  Grupo pcap não encontrado"
fi

# Verificar instalação
echo "🔍 Verificando instalação..."
if melt_venv/bin/python -c "import scapy, psutil, pandas, PyQt5; print('✅ Todas as dependências instaladas com sucesso!')" &>/dev/null; then
    echo "✅ Todas as dependências foram instaladas corretamente"
else
    echo "❌ Algumas dependências podem não estar instaladas"
    echo "💡 Tente: pip install --upgrade scapy psutil pandas PyQt5"
fi

# Verificar permissões de captura
echo "🔒 Verificando permissões de captura..."
if melt_venv/bin/python -c "
import os
import socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.close()
    print('✅ Permissões de captura: OK')
except PermissionError:
    print('❌ Permissões de captura: FALHA - Execute o aplicativo normalmente, sem sudo')
" 2>/dev/null; then
    echo "🎉 Tudo configurado! Agora você pode usar sem sudo."
else
    echo "❌ Ainda é necessário configurar permissões manualmente"
fi

# Criar script de ativação
cat > activate_melt.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source melt_venv/bin/activate
echo "🚀 Ambiente MeltTrafego ativado!"
echo "💡 Use: python3 melt_cli.py --interativo"
echo "🖥️  Ou: python3 melt_gui.py"
echo "🔒 Agora funciona SEM SUDO!"
EOF
chmod +x activate_melt.sh

# Criar launcher desktop
cat > MeltTrafego.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=MeltTrafego
Comment=Analisador de Tráfego de Rede
Exec=$PWD/activate_melt.sh
Path=$PWD
Icon=network-wired
Terminal=true
Categories=Network;Security;
Keywords=network;security;analyzer;
EOF

chmod +x MeltTrafego.desktop

echo ""
echo "🎉 INSTALAÇÃO CONCLUÍDA!"
echo ""
echo "🚀 COMO USAR (SEM SUDO!):"
echo "   ./activate_melt.sh"
echo "   python3 melt_gui.py"
echo ""
echo "📋 Ou use o atalho: MeltTrafego.desktop"
echo ""
echo "🔧 Se ainda pedir sudo:"
echo "   1. Faça logout e login novamente"
echo "   2. Ou reinicie o computador"
echo "   3. Isso atualiza as permissões do grupo"
echo ""
echo "📁 Estrutura criada:"
echo "   relatorios/    - Relatórios de análise"
echo "   logs/          - Logs do sistema"
echo "   exemplos/      - Arquivos de exemplo"
echo "   assets/        - Recursos adicionais"

# Mensagem final importante
echo ""
echo "⚠️  IMPORTANTE: Faça LOGOUT e LOGIN novamente para as permissões do grupo surtirem efeito!"