"""
MeltTrafego - Configurações do Sistema Multiplataforma
"""

import platform

# Configurações de Análise
JANELA_TEMPO = 60
LIMITE_PORTAS = 10
TEMPO_CAPTURA_PADRAO = 60

# Configurações por Plataforma
if platform.system() == "Windows":
    INTERFACE_PADRAO = "0"  # Primeira interface no Windows
    TCPDUMP_PATH = "tcpdump"  # Assume que está no PATH
else:
    INTERFACE_PADRAO = "any"  # Todas as interfaces no Linux/macOS
    TCPDUMP_PATH = "tcpdump"

# Arquivos
LOG_FILE = "logs/melt_trafego.log"
RELATORIOS_DIR = "relatorios"

# Cores para GUI
CORES = {
    'sucesso': '#4CAF50',
    'erro': '#f44336', 
    'alerta': '#ff9800',
    'info': '#2196F3',
    'destaque': '#FF5722'
}

# Configurações de Rede
IGNORAR_IPS = [
    "127.0.0.1",           # Localhost
    "0.0.0.0",             # Endereço indefinido
    "255.255.255.255"      # Broadcast
]