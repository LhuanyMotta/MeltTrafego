"""
MeltTrafego - Configurações do Sistema Multiplataforma
"""

import platform

# Configurações de Análise
JANELA_TEMPO = 60
LIMITE_PORTAS = 10
TEMPO_CAPTURA_PADRAO = 60

# Configurações específicas por plataforma
SISTEMA = platform.system()

if SISTEMA == "Linux":
    INTERFACE_PADRAO = "any"
    TCPDUMP_PATH = "/usr/sbin/tcpdump"
    PERMISSOES_CAPTURA = True
    REQUER_SUDO = False
elif SISTEMA == "Windows":
    INTERFACE_PADRAO = None  # Scapy detecta automaticamente
    PERMISSOES_CAPTURA = False  # Npcap lida com permissões
    REQUER_SUDO = False
else:  # macOS
    INTERFACE_PADRAO = "en0"
    TCPDUMP_PATH = "/usr/sbin/tcpdump"
    PERMISSOES_CAPTURA = True
    REQUER_SUDO = False

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
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255"
]