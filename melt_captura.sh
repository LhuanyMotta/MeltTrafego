#!/bin/bash
# MeltTrafego - Script Auxiliar de Captura (Linux)

INTERFACE=${1:-any}
TEMPO=${2:-60}
ARQUIVO="relatorios/trafego_captura_$(date +%Y%m%d_%H%M%S).txt"

echo "🔍 MeltTrafego - Iniciando captura..."
echo "Interface: $INTERFACE"
echo "Tempo: $TEMPO segundos"
echo "Arquivo: $ARQUIVO"

# Verificar se tcpdump está instalado
if ! command -v tcpdump &> /dev/null; then
    echo "❌ ERRO: tcpdump não encontrado. Instale com:"
    echo "  Ubuntu: sudo apt install tcpdump"
    echo "  CentOS: sudo yum install tcpdump"
    exit 1
fi

# Verificar se interface existe
if [ "$INTERFACE" != "any" ]; then
    if ! ip link show "$INTERFACE" &> /dev/null; then
        echo "❌ ERRO: Interface $INTERFACE não encontrada."
        echo "📡 Interfaces disponíveis:"
        ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' '
        exit 1
    fi
fi

# Verificar permissões
if [ "$EUID" -ne 0 ] && ! getcap "$(which python3)" | grep -q cap_net_raw; then
    echo "⚠️  Executando com sudo (permissões de captura necessárias)..."
    sudo timeout $TEMPO tcpdump -i $INTERFACE -nn -ttt -s0 ip > $ARQUIVO
else
    timeout $TEMPO tcpdump -i $INTERFACE -nn -ttt -s0 ip > $ARQUIVO
fi

CAPTURA_LINHAS=$(wc -l < "$ARQUIVO" 2>/dev/null || echo 0)

if [ "$CAPTURA_LINHAS" -gt 0 ]; then
    echo "✅ Captura concluída: $ARQUIVO"
    echo "📊 Linhas capturadas: $CAPTURA_LINHAS"
else
    echo "⚠️  Captura concluída, mas nenhum dado foi capturado."
    echo "💡 Verifique:"
    echo "   - Se a interface está correta"
    echo "   - Se há tráfego de rede"
    echo "   - Permissões de captura"
fi