#!/bin/bash
echo "🔧 Instalando MeltTrafego no Linux..."

# Mudar para o diretório do script
cd "$(dirname "$0")"

# Verificar se é executado como root
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  Executando como root. Isso pode causar problemas de permissão."
    echo "💡 Recomendado: Execute como usuário normal e use sudo quando necessário"
    read -p "Continuar mesmo assim? (s/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        exit 1
    fi
fi

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 não encontrado. Instalando..."
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

# Configurar permissões (corrigido: nome do script de captura)
echo "🔐 Configurando permissões..."
chmod +x install.sh melt_cli.py melt_captura.sh 2>/dev/null || true

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

# Criar ambiente virtual
echo "🐍 Configurando ambiente Python..."
python3 -m venv melt_venv
source melt_venv/bin/activate

# Instalar dependências Python
echo "📦 Instalando dependências Python..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    # PyQt5 não está no requirements.txt por padrão; instalar se necessário
    pip install PyQt5 || true
else
    echo "📋 Instalando dependências manualmente..."
    pip install scapy psutil pandas PyQt5
fi

# Configurar permissões de captura
echo "🔧 Configurando permissões de captura..."
if command -v setcap &> /dev/null; then
    # Dar permissão para captura de pacotes sem sudo para o binário Python do venv
    PYTHON_BIN="$(pwd)/melt_venv/bin/python3"
    if [ -f "$PYTHON_BIN" ]; then
        sudo setcap cap_net_raw+eip "$PYTHON_BIN" 2>/dev/null && \
            echo "✅ Permissões de captura configuradas" || \
            echo "⚠️  Não foi possível configurar permissões automáticas"
    else
        echo "⚠️  Binário Python do venv não encontrado em $PYTHON_BIN"
    fi
else
    echo "⚠️  setcap não disponível. Será necessário sudo para captura."
fi

# Verificar instalação
echo "🔍 Verificando instalação..."
if melt_venv/bin/python -c "import scapy, psutil, pandas" &>/dev/null; then
    echo "✅ Dependências instaladas com sucesso!"
else
    echo "❌ Algumas dependências podem não estar instaladas"
    echo "💡 Tente: pip install --upgrade scapy psutil pandas PyQt5"
fi

# Criar script de ativação
cat > activate_melt.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source melt_venv/bin/activate
echo "🚀 Ambiente MeltTrafego ativado!"
echo "💡 Use: python3 melt_cli.py --interativo"
EOF
chmod +x activate_melt.sh

echo ""
echo "🎉 INSTALAÇÃO CONCLUÍDA!"
echo ""
echo "🚀 COMO USAR:"
echo "   Ativar ambiente: source melt_venv/bin/activate"
echo "   Ou usar: ./activate_melt.sh"
echo ""
echo "   Modo interativo:  python3 melt_cli.py --interativo"
echo "   Captura direta:   sudo python3 melt_cli.py --capturar eth0 -t 30"
echo "   Listar interfaces: python3 melt_cli.py --interfaces"
echo ""
echo "⚠️  IMPORTANTE:"
echo "   Para captura de pacotes, pode ser necessário:"
echo "   - Executar com sudo: sudo python3 melt_cli.py ..."
echo "   - Ou configurar permissões: sudo setcap cap_net_raw+eip /path/to/python"
echo ""
echo "📁 Estrutura criada:"
echo "   relatorios/    - Relatórios de análise"
echo "   logs/          - Logs do sistema"
echo "   exemplos/      - Arquivos de exemplo"
echo "   assets/        - Recursos adicionais"
