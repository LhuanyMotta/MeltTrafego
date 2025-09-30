#!/usr/bin/env python3
"""
MeltTrafego - Interface Gráfica Linux (Sem necessidade de sudo)
"""

import sys
import os
import platform
from datetime import datetime

# Adicionar o ambiente virtual ao path
venv_path = os.path.join(os.path.dirname(__file__), 'melt_venv')
if os.path.exists(venv_path):
    sys.path.insert(0, os.path.join(venv_path, 'lib', f'python{sys.version_info.major}.{sys.version_info.minor}', 'site-packages'))

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                                QComboBox, QSpinBox, QProgressBar, QTabWidget,
                                QGroupBox, QListWidget, QListWidgetItem, QMessageBox,
                                QSplitter, QFrame)
    from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QColor
except ImportError as e:
    print(f"❌ Erro: PyQt5 não encontrado: {e}")
    print("💡 Execute: pip install PyQt5")
    sys.exit(1)

try:
    import psutil
    import pandas as pd
except ImportError as e:
    print(f"❌ Erro: Dependências não encontradas: {e}")
    print("💡 Execute: pip install psutil pandas")
    sys.exit(1)

# Tentar importar scapy, mas continuar mesmo se falhar
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy não disponível. Modo de demonstração ativado.")

class CapturaThread(QThread):
    """Thread para captura de pacotes em background"""
    pacote_capturado = pyqtSignal(dict)
    captura_finalizada = pyqtSignal(list)
    erro_captura = pyqtSignal(str)
    status_captura = pyqtSignal(str)
    
    def __init__(self, interface, duracao):
        super().__init__()
        self.interface = interface
        self.duracao = duracao
        self.pacotes = []
        self.capturando = False
        
    def run(self):
        """Executa a captura"""
        if not SCAPY_AVAILABLE:
            self.erro_captura.emit(
                "Scapy não disponível. Modo de demonstração ativado.\n"
                "Gerando dados de exemplo..."
            )
            self.gerar_dados_exemplo()
            return
            
        self.capturando = True
        self.pacotes = []
        
        try:
            # Testar permissões primeiro
            self.status_captura.emit("🔍 Testando permissões de captura...")
            
            # Tentar captura simples
            filter_str = "ip or ip6"
            
            if self.interface and self.interface != "any":
                sniff(prn=self.processar_pacote, timeout=self.duracao, 
                      iface=self.interface, filter=filter_str, store=False)
            else:
                sniff(prn=self.processar_pacote, timeout=self.duracao, 
                      filter=filter_str, store=False)
                
            self.capturando = False
            self.captura_finalizada.emit(self.pacotes)
            
        except PermissionError as e:
            self.capturando = False
            self.erro_captura.emit(
                "🔒 Erro de permissão.\n\n"
                "Soluções:\n"
                "1. Execute: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)\n"
                "2. Ou adicione seu usuário ao grupo pcap: sudo usermod -a -G pcap $USER\n"
                "3. Faça logout e login novamente\n\n"
                "Ativando modo de demonstração..."
            )
            self.gerar_dados_exemplo()
        except Exception as e:
            self.capturando = False
            self.erro_captura.emit(f"Erro na captura: {str(e)}\nAtivando modo de demonstração...")
            self.gerar_dados_exemplo()
    
    def processar_pacote(self, pacote):
        """Processa cada pacote capturado"""
        if not self.capturando:
            return
            
        info = {
            'timestamp': datetime.now(),
            'tamanho': len(pacote)
        }
        
        if pacote.haslayer(IP):
            info['ip_origem'] = pacote[IP].src
            info['ip_destino'] = pacote[IP].dst
            info['protocolo'] = pacote[IP].proto
            
            if pacote.haslayer(TCP):
                info['porta_origem'] = pacote[TCP].sport
                info['porta_destino'] = pacote[TCP].dport
                info['tipo'] = 'TCP'
            elif pacote.haslayer(UDP):
                info['porta_origem'] = pacote[UDP].sport
                info['porta_destino'] = pacote[UDP].dport
                info['tipo'] = 'UDP'
            elif pacote.haslayer(ICMP):
                info['tipo'] = 'ICMP'
            else:
                info['tipo'] = 'Outro'
        else:
            info['tipo'] = 'Não-IP'
        
        self.pacotes.append(info)
        self.pacote_capturado.emit(info)
    
    def gerar_dados_exemplo(self):
        """Gera dados de exemplo quando a captura real não está disponível"""
        import random
        import time
        
        self.status_captura.emit("🎭 Gerando dados de demonstração...")
        
        ips_origem = ["192.168.1.100", "192.168.1.101", "10.0.0.15", "203.0.113.45"]
        ips_destino = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "142.251.32.110"]
        tipos = ["TCP", "UDP", "ICMP"]
        
        for i in range(50):
            if not self.capturando:
                break
                
            info = {
                'timestamp': datetime.now(),
                'tamanho': random.randint(64, 1500),
                'ip_origem': random.choice(ips_origem),
                'ip_destino': random.choice(ips_destino),
                'tipo': random.choice(tipos),
                'porta_origem': random.randint(1024, 65535),
                'porta_destino': random.choice([80, 443, 53, 22, 3389]),
                'demo': True  # Marcar como dados de demonstração
            }
            
            self.pacotes.append(info)
            self.pacote_capturado.emit(info)
            
            # Pequena pausa para simular tráfego real
            time.sleep(0.1)
        
        self.capturando = False
        self.captura_finalizada.emit(self.pacotes)

class MeltTrafegoGUI(QMainWindow):
    """Interface gráfica principal do MeltTrafego"""
    
    def __init__(self):
        super().__init__()
        self.captura_thread = None
        self.dados_captura = []
        self.init_ui()
        
    def init_ui(self):
        """Inicializa a interface do usuário"""
        self.setWindowTitle("🚀 MeltTrafego - Analisador de Tráfego (Sem Sudo)")
        self.setGeometry(100, 100, 1000, 700)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        layout = QVBoxLayout(central_widget)
        
        # Título
        titulo = QLabel("🌐 MeltTrafego - Analisador de Tráfego de Rede")
        titulo.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(titulo)
        
        # Subtítulo
        subtitulo = QLabel("🔒 Funciona sem sudo - Modo de demonstração disponível")
        subtitulo.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(subtitulo)
        
        # Divisor
        linha = QFrame()
        linha.setFrameShape(QFrame.HLine)
        linha.setFrameShadow(QFrame.Sunken)
        layout.addWidget(linha)
        
        # Controles de captura
        self.criar_controles_captura(layout)
        
        # Área de abas
        self.criar_abas_principal(layout)
        
        # Barra de status
        self.criar_barra_status(layout)
        
        # Verificar se scapy está disponível
        if not SCAPY_AVAILABLE:
            self.mostrar_aviso("Scapy não encontrado. Modo de demonstração ativado.")
        
    def criar_controles_captura(self, layout):
        """Cria os controles de captura"""
        grupo = QGroupBox("🎯 Controles de Captura")
        layout_controles = QHBoxLayout()
        
        # Interface
        layout_controles.addWidget(QLabel("📡 Interface:"))
        self.combo_interface = QComboBox()
        self.combo_interface.addItems(["any", "eth0", "wlan0", "lo"])
        layout_controles.addWidget(self.combo_interface)
        
        # Tempo
        layout_controles.addWidget(QLabel("⏰ Tempo (s):"))
        self.spin_tempo = QSpinBox()
        self.spin_tempo.setRange(5, 300)
        self.spin_tempo.setValue(30)
        layout_controles.addWidget(self.spin_tempo)
        
        # Botões
        self.btn_capturar = QPushButton("🎬 Iniciar Captura")
        self.btn_capturar.clicked.connect(self.iniciar_captura)
        self.btn_capturar.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        layout_controles.addWidget(self.btn_capturar)
        
        self.btn_parar = QPushButton("⏹️ Parar")
        self.btn_parar.clicked.connect(self.parar_captura)
        self.btn_parar.setEnabled(False)
        self.btn_parar.setStyleSheet("background-color: #f44336; color: white;")
        layout_controles.addWidget(self.btn_parar)
        
        layout_controles.addStretch()
        grupo.setLayout(layout_controles)
        layout.addWidget(grupo)
    
    def criar_abas_principal(self, layout):
        """Cria as abas principais"""
        self.tabs = QTabWidget()
        
        # Aba 1: Tempo Real
        aba1 = QWidget()
        layout1 = QVBoxLayout(aba1)
        
        # Área de logs
        grupo_logs = QGroupBox("📊 Tráfego em Tempo Real")
        layout_logs = QVBoxLayout()
        
        self.texto_logs = QTextEdit()
        self.texto_logs.setFont(QFont("Monospace", 9))
        layout_logs.addWidget(self.texto_logs)
        
        # Contadores
        layout_contadores = QHBoxLayout()
        self.label_pacotes = QLabel("📦 Pacotes: 0")
        self.label_tcp = QLabel("🔗 TCP: 0")
        self.label_udp = QLabel("📨 UDP: 0")
        self.label_taxa = QLabel("⚡ Taxa: 0 B/s")
        
        for label in [self.label_pacotes, self.label_tcp, self.label_udp, self.label_taxa]:
            layout_contadores.addWidget(label)
        
        layout_contadores.addStretch()
        layout_logs.addLayout(layout_contadores)
        grupo_logs.setLayout(layout_logs)
        layout1.addWidget(grupo_logs)
        
        self.tabs.addTab(aba1, "🎯 Tempo Real")
        
        # Aba 2: Estatísticas
        aba2 = QWidget()
        layout2 = QVBoxLayout(aba2)
        
        self.texto_estatisticas = QTextEdit()
        self.texto_estatisticas.setFont(QFont("Monospace", 10))
        layout2.addWidget(self.texto_estatisticas)
        
        self.tabs.addTab(aba2, "📊 Estatísticas")
        
        layout.addWidget(self.tabs)
        
        # Inicializar contadores
        self.contadores = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
        self.bytes_total = 0
    
    def criar_barra_status(self, layout):
        """Cria a barra de status"""
        grupo = QGroupBox("📊 Status")
        layout_status = QHBoxLayout()
        
        self.label_status = QLabel("🟢 Pronto para capturar")
        self.barra_progresso = QProgressBar()
        self.barra_progresso.setVisible(False)
        
        layout_status.addWidget(self.label_status)
        layout_status.addWidget(self.barra_progresso)
        layout_status.addStretch()
        
        # Indicador de modo
        modo = "🔓 Normal" if SCAPY_AVAILABLE else "🎭 Demonstração"
        self.label_modo = QLabel(f"Modo: {modo}")
        layout_status.addWidget(self.label_modo)
        
        grupo.setLayout(layout_status)
        layout.addWidget(grupo)
    
    def iniciar_captura(self):
        """Inicia a captura de pacotes"""
        interface = self.combo_interface.currentText()
        tempo = self.spin_tempo.value()
        
        # Limpar dados anteriores
        self.dados_captura = []
        self.contadores = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0}
        self.bytes_total = 0
        self.texto_logs.clear()
        
        # Iniciar thread de captura
        self.captura_thread = CapturaThread(interface, tempo)
        self.captura_thread.pacote_capturado.connect(self.adicionar_pacote)
        self.captura_thread.captura_finalizada.connect(self.captura_concluida)
        self.captura_thread.erro_captura.connect(self.mostrar_erro)
        self.captura_thread.status_captura.connect(self.label_status.setText)
        
        self.captura_thread.start()
        
        # Atualizar UI
        self.btn_capturar.setEnabled(False)
        self.btn_parar.setEnabled(True)
        self.barra_progresso.setVisible(True)
        self.barra_progresso.setMaximum(tempo)
        self.barra_progresso.setValue(0)
        
        # Timer para progresso
        self.timer_progresso = QTimer()
        self.timer_progresso.timeout.connect(self.atualizar_progresso)
        self.timer_progresso.start(1000)
        
        self.tempo_inicio = datetime.now()
    
    def parar_captura(self):
        """Para a captura"""
        if self.captura_thread and self.captura_thread.isRunning():
            self.captura_thread.capturando = False
            self.captura_thread.terminate()
            self.captura_thread.wait()
        
        self.captura_concluida(self.dados_captura)
    
    def atualizar_progresso(self):
        """Atualiza a barra de progresso"""
        if hasattr(self, 'tempo_inicio'):
            tempo_decorrido = (datetime.now() - self.tempo_inicio).seconds
            self.barra_progresso.setValue(tempo_decorrido)
            
            if tempo_decorrido >= self.spin_tempo.value():
                self.timer_progresso.stop()
    
    def adicionar_pacote(self, info):
        """Adiciona um pacote à interface"""
        self.dados_captura.append(info)
        
        # Atualizar contadores
        self.contadores['total'] += 1
        tipo = info.get('tipo', '').lower()
        if tipo in self.contadores:
            self.contadores[tipo] += 1
        
        self.bytes_total += info['tamanho']
        
        # Adicionar ao log
        timestamp = info['timestamp'].strftime('%H:%M:%S')
        demo = "🎭 " if info.get('demo') else ""
        linha = f"{demo}{timestamp} | {info['tipo']} | {info.get('ip_origem', 'N/A')} → {info.get('ip_destino', 'N/A')} | {info['tamanho']}B"
        self.texto_logs.append(linha)
        
        # Atualizar labels
        self.atualizar_contadores()
    
    def atualizar_contadores(self):
        """Atualiza os contadores na interface"""
        self.label_pacotes.setText(f"📦 Pacotes: {self.contadores['total']}")
        self.label_tcp.setText(f"🔗 TCP: {self.contadores['tcp']}")
        self.label_udp.setText(f"📨 UDP: {self.contadores['udp']}")
        
        tempo_decorrido = (datetime.now() - self.tempo_inicio).seconds
        if tempo_decorrido > 0:
            taxa = self.bytes_total / tempo_decorrido
            self.label_taxa.setText(f"⚡ Taxa: {taxa:.0f} B/s")
    
    def captura_concluida(self, dados):
        """Callback quando a captura termina"""
        self.btn_capturar.setEnabled(True)
        self.btn_parar.setEnabled(False)
        self.barra_progresso.setVisible(False)
        self.label_status.setText("✅ Captura concluída")
        
        if self.timer_progresso and self.timer_progresso.isActive():
            self.timer_progresso.stop()
        
        # Gerar estatísticas
        self.gerar_estatisticas()
        
        # Mostrar resumo
        modo = "demonstração" if any(d.get('demo') for d in dados) else "real"
        QMessageBox.information(self, "Captura Concluída", 
                               f"✅ Captura finalizada ({modo})!\n"
                               f"📦 Pacotes: {len(dados)}\n"
                               f"📊 Bytes: {self.bytes_total}")
    
    def gerar_estatisticas(self):
        """Gera estatísticas dos dados capturados"""
        if not self.dados_captura:
            self.texto_estatisticas.setText("Nenhum dado capturado.")
            return
        
        df = pd.DataFrame(self.dados_captura)
        
        estatisticas = f"""📊 RELATÓRIO DE CAPTURA

📦 ESTATÍSTICAS:
• Total de pacotes: {len(df)}
• Total de bytes: {self.bytes_total}
• TCP: {self.contadores['tcp']}
• UDP: {self.contadores['udp']}
• ICMP: {self.contadores['icmp']}

🌐 INFORMAÇÕES:"""

        if any(d.get('demo') for d in self.dados_captura):
            estatisticas += "\n• 🎭 MODO DEMONSTRAÇÃO - Dados de exemplo"
        else:
            estatisticas += "\n• 🔓 MODO REAL - Captura ao vivo"

        if 'ip_origem' in df.columns:
            top_ips = df['ip_origem'].value_counts().head(3)
            estatisticas += "\n\n🔝 TOP IPs:"
            for ip, count in top_ips.items():
                estatisticas += f"\n• {ip}: {count} pacotes"

        self.texto_estatisticas.setText(estatisticas)
    
    def mostrar_aviso(self, mensagem):
        """Mostra um aviso"""
        QMessageBox.warning(self, "Aviso", mensagem)
    
    def mostrar_erro(self, mensagem):
        """Mostra uma mensagem de erro"""
        QMessageBox.critical(self, "Erro", mensagem)
        self.label_status.setText(f"❌ {mensagem[:30]}...")

def main():
    """Função principal"""
    # Verificar se estamos no Linux
    if platform.system() != "Linux":
        print("❌ Esta aplicação foi desenvolvida para Linux")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    app.setApplicationName("MeltTrafego")
    
    janela = MeltTrafegoGUI()
    janela.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()