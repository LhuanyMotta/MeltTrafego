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

# Verificar permissões
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Executando com sudo..."
    sudo timeout "$TEMPO" tcpdump -i "$INTERFACE" -nn -ttt ip > "$ARQUIVO"
else
    timeout "$TEMPO" tcpdump -i "$INTERFACE" -nn -ttt ip > "$ARQUIVO"
fi

echo "✅ Captura concluída: $ARQUIVO"
echo "📊 Linhas capturadas: $(wc -l < "$ARQUIVO")"
