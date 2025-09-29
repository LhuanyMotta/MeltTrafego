#!/bin/bash
echo "🔧 Instalando MeltTrafego no Linux..."
echo "📡 Plataforma: $(uname -s)"
echo ""

# Criar estrutura de diretórios
mkdir -p logs relatorios exemplos assets

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 não encontrado. Instale com:"
    echo "   sudo apt install python3 python3-pip"
    exit 1
fi

echo "✅ Python3 encontrado: $(python3 --version)"

# Verificar/instalar tcpdump
if ! command -v tcpdump &> /dev/null; then
    echo "📦 Instalando tcpdump..."
    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y tcpdump
    elif command -v yum &> /dev/null; then
        sudo yum install -y tcpdump
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y tcpdump
    elif command -v pacman &> /dev/null; then
        sudo pacman -S tcpdump
    else
        echo "⚠️  Gerenciador de pacotes não reconhecido. Instale tcpdump manualmente."
    fi
else
    echo "✅ tcpdump encontrado: $(tcpdump --version 2>&1 | head -n1)"
fi

# Instalar dependências Python
echo "🐍 Instalando dependências Python..."
pip3 install -r requirements.txt

# Configurar permissões
echo "🔐 Configurando permissões..."
if getent group wireshark &>/dev/null; then
    echo "💡 Dica: Adicione seu usuário ao grupo wireshark para captura sem sudo:"
    echo "   sudo usermod -aG wireshark $USER"
    echo "   ⚠️  Faça logout e login novamente após este comando"
fi

# Tornar scripts executáveis
chmod +x melt_cli.py melt_gui.py

echo ""
echo "✅ MeltTrafego instalado com sucesso!"
echo ""
echo "🚀 COMO USAR:"
echo "   Interface Gráfica: ./melt_gui.py"
echo "   Linha de Comando:  ./melt_cli.py [comando]"
echo ""
echo "📖 EXEMPLOS:"
echo "   ./melt_cli.py status"
echo "   ./melt_cli.py interfaces" 
echo "   ./melt_cli.py capturar -i eth0 -t 30"
echo "   ./melt_cli.py analisar trafego.txt -o relatorio.csv"
echo ""
echo "💡 DICA: Para captura real, execute com sudo ou configure permissões"