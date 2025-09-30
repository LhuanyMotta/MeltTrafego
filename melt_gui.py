#!/usr/bin/env python3
"""
MeltTrafego - Interface Gráfica Multiplataforma
Interface moderna para análise de tráfego de rede
"""

import sys
import os
import platform
from datetime import datetime

# Configuração multiplataforma
SISTEMA = platform.system()

# Verificar se estamos no ambiente virtual
venv_path = os.path.join(os.path.dirname(__file__), 'melt_venv')
if os.path.exists(venv_path):
    if SISTEMA == "Windows":
        activate_this = os.path.join(venv_path, 'Scripts', 'activate_this.py')
    else:
        activate_this = os.path.join(venv_path, 'bin', 'activate_this.py')
    
    if os.path.exists(activate_this):
        with open(activate_this) as f:
            exec(f.read(), {'__file__': activate_this})

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                QHBoxLayout, QPushButton, QLabel, QTextEdit, 
                                QComboBox, QSpinBox, QProgressBar, QTabWidget,
                                QGroupBox, QListWidget, QListWidgetItem, QMessageBox,
                                QSplitter, QFrame, QSystemTrayIcon, QMenu, QAction,
                                QStyle, QDialog, QDialogButtonBox, QFormLayout,
                                QLineEdit, QCheckBox, QFileDialog)
    from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap
except ImportError as e:
    print(f"❌ Erro: Dependências PyQt5 não encontradas: {e}")
    print("💡 Instale com: pip install PyQt5")
    sys.exit(1)

try:
    from scapy.all import *
    import psutil
    import pandas as pd
except ImportError as e:
    print(f"❌ Erro: Dependências Python não encontradas: {e}")
    print("💡 Instale com: pip install scapy psutil pandas")
    sys.exit(1)

class AnaliseThread(QThread):
    """Thread para análise de arquivo em background"""
    analise_concluida = pyqtSignal(dict)
    erro_analise = pyqtSignal(str)
    
    def __init__(self, arquivo):
        super().__init__()
        self.arquivo = arquivo
        
    def run(self):
        """Executa a análise do arquivo"""
        try:
            # Verificar se o arquivo existe
            if not os.path.exists(self.arquivo):
                self.erro_analise.emit(f"Arquivo não encontrado: {self.arquivo}")
                return
            
            # Ler e analisar o arquivo
            with open(self.arquivo, 'r', encoding='utf-8', errors='ignore') as f:
                linhas = f.readlines()
            
            if not linhas:
                self.erro_analise.emit("Arquivo vazio ou sem dados válidos")
                return
            
            # Análise básica do arquivo
            total_linhas = len(linhas)
            tipos_linhas = {}
            ips_unicos = set()
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                # Classificar tipo de linha
                if 'TCP' in linha.upper():
                    tipo = 'TCP'
                elif 'UDP' in linha.upper():
                    tipo = 'UDP'
                elif 'ICMP' in linha.upper():
                    tipo = 'ICMP'
                elif 'IP' in linha:
                    tipo = 'IP'
                else:
                    tipo = 'Outro'
                
                tipos_linhas[tipo] = tipos_linhas.get(tipo, 0) + 1
                
                # Extrair IPs (busca simples)
                import re
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', linha)
                ips_unicos.update(ips)
            
            resultado = {
                'arquivo': self.arquivo,
                'total_linhas': total_linhas,
                'tipos_linhas': tipos_linhas,
                'ips_unicos': len(ips_unicos),
                'timestamp_analise': datetime.now().isoformat(),
                'tamanho_arquivo': os.path.getsize(self.arquivo)
            }
            
            self.analise_concluida.emit(resultado)
            
        except Exception as e:
            self.erro_analise.emit(f"Erro na análise: {str(e)}")

class CapturaThread(QThread):
    """Thread para captura de pacotes em background - Multiplataforma"""
    pacote_capturado = pyqtSignal(dict)
    captura_finalizada = pyqtSignal(list)
    erro_captura = pyqtSignal(str)
    
    def __init__(self, interface, duracao):
        super().__init__()
        self.interface = interface
        self.duracao = duracao
        self.pacotes = []
        self.capturando = False
        self.sistema = platform.system()
        
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
                info['flags'] = str(pacote[TCP].flags)
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
    
    def run(self):
        """Executa a captura - Multiplataforma"""
        self.capturando = True
        self.pacotes = []
        
        try:
            # Configurar interface para Windows
            if self.sistema == "Windows" and self.interface == "any":
                interface_captura = None  # Scapy detecta automaticamente
            else:
                interface_captura = self.interface
            
            # Configurar filtro
            filter_str = "ip or ip6"
            
            # Capturar pacotes
            sniff(prn=self.processar_pacote, timeout=self.duracao, 
                  iface=interface_captura, filter=filter_str)
                
            self.capturando = False
            self.captura_finalizada.emit(self.pacotes)
            
        except PermissionError as e:
            self.capturando = False
            if self.sistema == "Linux":
                mensagem_erro = (
                    "Erro de permissão. Execute com sudo ou configure permissões:\n"
                    "sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
                )
            else:
                mensagem_erro = (
                    "Erro de permissão no Windows.\n"
                    "Execute como Administrador ou verifique a instalação do Npcap."
                )
            self.erro_captura.emit(mensagem_erro)
        except Exception as e:
            self.capturando = False
            self.erro_captura.emit(f"Erro na captura: {str(e)}")

class MeltTrafegoGUI(QMainWindow):
    """Interface gráfica principal do MeltTrafego - Multiplataforma"""
    
    def __init__(self):
        super().__init__()
        self.captura_thread = None
        self.analise_thread = None
        self.dados_captura = []
        self.interface_atual = None
        self.sistema = platform.system()
        self.init_ui()
        
    def init_ui(self):
        """Inicializa a interface do usuário"""
        titulo = "🚀 MeltTrafego - Analisador de Tráfego"
        if self.sistema == "Windows":
            titulo += " Windows"
        else:
            titulo += " Linux"
            
        self.setWindowTitle(titulo)
        self.setGeometry(100, 100, 1200, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        layout = QVBoxLayout(central_widget)
        
        # Barra superior
        self.criar_barra_superior(layout)
        
        # Divisor
        layout.addWidget(self.criar_divisor())
        
        # Área principal com abas
        self.criar_abas_principal(layout)
        
        # Barra de status
        self.criar_barra_status(layout)
        
        # Timer para atualizações em tempo real
        self.timer = QTimer()
        self.timer.timeout.connect(self.atualizar_status_sistema)
        self.timer.start(2000)  # Atualizar a cada 2 segundos
        
        # Atualizar interfaces disponíveis
        self.atualizar_interfaces()
        
    def criar_barra_superior(self, layout):
        """Cria a barra superior de controle"""
        grupo_controles = QGroupBox("🎯 Controles de Captura")
        layout_controles = QHBoxLayout()
        
        # Seleção de interface
        layout_controles.addWidget(QLabel("📡 Interface:"))
        self.combo_interfaces = QComboBox()
        self.combo_interfaces.setMinimumWidth(200)
        layout_controles.addWidget(self.combo_interfaces)
        
        # Tempo de captura
        layout_controles.addWidget(QLabel("⏰ Tempo (s):"))
        self.spin_tempo = QSpinBox()
        self.spin_tempo.setRange(5, 3600)
        self.spin_tempo.setValue(60)
        self.spin_tempo.setMinimumWidth(80)
        layout_controles.addWidget(self.spin_tempo)
        
        # Botões de ação
        self.btn_capturar = QPushButton("🎬 Iniciar Captura")
        self.btn_capturar.clicked.connect(self.iniciar_captura)
        self.btn_capturar.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; border-radius: 4px; }")
        layout_controles.addWidget(self.btn_capturar)
        
        self.btn_parar = QPushButton("⏹️ Parar")
        self.btn_parar.clicked.connect(self.parar_captura)
        self.btn_parar.setEnabled(False)
        self.btn_parar.setStyleSheet("QPushButton { background-color: #f44336; color: white; padding: 8px; border-radius: 4px; }")
        layout_controles.addWidget(self.btn_parar)
        
        self.btn_limpar = QPushButton("🗑️ Limpar")
        self.btn_limpar.clicked.connect(self.limpar_dados)
        self.btn_limpar.setStyleSheet("QPushButton { background-color: #FF9800; color: white; padding: 8px; border-radius: 4px; }")
        layout_controles.addWidget(self.btn_limpar)
        
        self.btn_analisar = QPushButton("🔍 Analisar Arquivo")
        self.btn_analisar.clicked.connect(self.analisar_arquivo)
        self.btn_analisar.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 8px; border-radius: 4px; }")
        layout_controles.addWidget(self.btn_analisar)
        
        # Botão de informações da plataforma
        self.btn_plataforma = QPushButton(f"💻 {self.sistema}")
        self.btn_plataforma.clicked.connect(self.mostrar_info_plataforma)
        self.btn_plataforma.setStyleSheet("QPushButton { background-color: #9C27B0; color: white; padding: 8px; border-radius: 4px; }")
        layout_controles.addWidget(self.btn_plataforma)
        
        layout_controles.addStretch()
        
        grupo_controles.setLayout(layout_controles)
        layout.addWidget(grupo_controles)
    
    def criar_divisor(self):
        """Cria um divisor visual"""
        linha = QFrame()
        linha.setFrameShape(QFrame.HLine)
        linha.setFrameShadow(QFrame.Sunken)
        return linha
    
    def criar_abas_principal(self, layout):
        """Cria as abas principais da aplicação"""
        self.tabs = QTabWidget()
        
        # Aba: Monitoramento em Tempo Real
        self.criar_aba_tempo_real()
        
        # Aba: Estatísticas
        self.criar_aba_estatisticas()
        
        # Aba: Conexões
        self.criar_aba_conexoes()
        
        # Aba: Sistema
        self.criar_aba_sistema()
        
        layout.addWidget(self.tabs)
    
    def criar_aba_tempo_real(self):
        """Cria a aba de monitoramento em tempo real"""
        aba = QWidget()
        layout = QVBoxLayout(aba)
        
        # Área de logs em tempo real
        grupo_logs = QGroupBox("📊 Tráfego em Tempo Real")
        layout_logs = QVBoxLayout()
        
        self.texto_logs = QTextEdit()
        self.texto_logs.setMaximumHeight(300)
        self.texto_logs.setFont(QFont("Monospace", 9))
        layout_logs.addWidget(self.texto_logs)
        
        # Contadores
        layout_contadores = QHBoxLayout()
        
        self.label_contador_pacotes = QLabel("📦 Pacotes: 0")
        self.label_contador_tcp = QLabel("🔗 TCP: 0")
        self.label_contador_udp = QLabel("📨 UDP: 0")
        self.label_contador_icmp = QLabel("📡 ICMP: 0")
        self.label_taxa_transferencia = QLabel("⚡ Taxa: 0 B/s")
        
        layout_contadores.addWidget(self.label_contador_pacotes)
        layout_contadores.addWidget(self.label_contador_tcp)
        layout_contadores.addWidget(self.label_contador_udp)
        layout_contadores.addWidget(self.label_contador_icmp)
        layout_contadores.addWidget(self.label_taxa_transferencia)
        layout_contadores.addStretch()
        
        layout_logs.addLayout(layout_contadores)
        grupo_logs.setLayout(layout_logs)
        layout.addWidget(grupo_logs)
        
        # Alertas
        grupo_alertas = QGroupBox("⚠️ Alertas e Detecções")
        layout_alertas = QVBoxLayout()
        
        self.lista_alertas = QListWidget()
        layout_alertas.addWidget(self.lista_alertas)
        
        grupo_alertas.setLayout(layout_alertas)
        layout.addWidget(grupo_alertas)
        
        self.tabs.addTab(aba, "🎯 Tempo Real")
        
        # Inicializar contadores
        self.contadores = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'outros': 0
        }
        self.ultimo_timestamp = None
        self.bytes_total = 0
    
    def criar_aba_estatisticas(self):
        """Cria a aba de estatísticas"""
        aba = QWidget()
        layout = QVBoxLayout(aba)
        
        # Estatísticas gerais
        grupo_estatisticas = QGroupBox("📈 Estatísticas Gerais")
        layout_estatisticas = QVBoxLayout()
        
        self.texto_estatisticas = QTextEdit()
        self.texto_estatisticas.setFont(QFont("Monospace", 10))
        layout_estatisticas.addWidget(self.texto_estatisticas)
        
        grupo_estatisticas.setLayout(layout_estatisticas)
        layout.addWidget(grupo_estatisticas)
        
        # Botões de exportação
        layout_botoes = QHBoxLayout()
        
        btn_exportar_json = QPushButton("💾 Exportar JSON")
        btn_exportar_json.clicked.connect(lambda: self.exportar_relatorio('json'))
        btn_exportar_json.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 6px; border-radius: 4px; }")
        layout_botoes.addWidget(btn_exportar_json)
        
        btn_exportar_csv = QPushButton("📊 Exportar CSV")
        btn_exportar_csv.clicked.connect(lambda: self.exportar_relatorio('csv'))
        btn_exportar_csv.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 6px; border-radius: 4px; }")
        layout_botoes.addWidget(btn_exportar_csv)
        
        btn_gerar_relatorio = QPushButton("📋 Gerar Relatório")
        btn_gerar_relatorio.clicked.connect(self.gerar_relatorio_completo)
        btn_gerar_relatorio.setStyleSheet("QPushButton { background-color: #FF9800; color: white; padding: 6px; border-radius: 4px; }")
        layout_botoes.addWidget(btn_gerar_relatorio)
        
        layout_botoes.addStretch()
        layout.addLayout(layout_botoes)
        
        self.tabs.addTab(aba, "📊 Estatísticas")
    
    def criar_aba_conexoes(self):
        """Cria a aba de conexões ativas"""
        aba = QWidget()
        layout = QVBoxLayout(aba)
        
        # Lista de conexões
        grupo_conexoes = QGroupBox("🔗 Conexões de Rede")
        layout_conexoes = QVBoxLayout()
        
        self.lista_conexoes = QListWidget()
        layout_conexoes.addWidget(self.lista_conexoes)
        
        # Botão para atualizar conexões
        btn_atualizar = QPushButton("🔄 Atualizar Conexões")
        btn_atualizar.clicked.connect(self.atualizar_conexoes)
        btn_atualizar.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 8px; border-radius: 4px; }")
        layout_conexoes.addWidget(btn_atualizar)
        
        grupo_conexoes.setLayout(layout_conexoes)
        layout.addWidget(grupo_conexoes)
        
        self.tabs.addTab(aba, "🔗 Conexões")
    
    def criar_aba_sistema(self):
        """Cria a aba de informações do sistema"""
        aba = QWidget()
        layout = QVBoxLayout(aba)
        
        # Informações da rede
        grupo_rede = QGroupBox("🌐 Informações de Rede")
        layout_rede = QVBoxLayout()
        
        self.texto_info_rede = QTextEdit()
        self.texto_info_rede.setFont(QFont("Monospace", 9))
        layout_rede.addWidget(self.texto_info_rede)
        
        grupo_rede.setLayout(layout_rede)
        layout.addWidget(grupo_rede)
        
        # Estatísticas do sistema
        grupo_sistema = QGroupBox("💻 Estatísticas do Sistema")
        layout_sistema = QVBoxLayout()
        
        self.texto_info_sistema = QTextEdit()
        self.texto_info_sistema.setFont(QFont("Monospace", 9))
        layout_sistema.addWidget(self.texto_info_sistema)
        
        grupo_sistema.setLayout(layout_sistema)
        layout.addWidget(grupo_sistema)
        
        self.tabs.addTab(aba, "💻 Sistema")
    
    def criar_barra_status(self, layout):
        """Cria a barra de status"""
        grupo_status = QGroupBox("📊 Status")
        layout_status = QHBoxLayout()
        
        plataforma_text = f"💻 {self.sistema} | "
        self.label_status = QLabel(plataforma_text + "🟢 Pronto para capturar")
        self.barra_progresso = QProgressBar()
        self.barra_progresso.setVisible(False)
        
        layout_status.addWidget(self.label_status)
        layout_status.addWidget(self.barra_progresso)
        layout_status.addStretch()
        
        grupo_status.setLayout(layout_status)
        layout.addWidget(grupo_status)
    
    def analisar_arquivo(self):
        """Abre diálogo para selecionar e analisar arquivo"""
        arquivo, _ = QFileDialog.getOpenFileName(
            self,
            "🔍 Selecionar arquivo para análise",
            "",
            "Todos os arquivos (*.*);;Arquivos de texto (*.txt *.log);;Arquivos CSV (*.csv);;Arquivos JSON (*.json)"
        )
        
        if arquivo:
            self.label_status.setText(f"🔍 Analisando arquivo: {os.path.basename(arquivo)}...")
            
            # Iniciar thread de análise
            self.analise_thread = AnaliseThread(arquivo)
            self.analise_thread.analise_concluida.connect(self.analise_concluida)
            self.analise_thread.erro_analise.connect(self.mostrar_erro)
            self.analise_thread.start()
    
    def analise_concluida(self, resultado):
        """Callback quando a análise é concluída"""
        # Mostrar resultados na aba de estatísticas
        relatorio = f"""🔍 RELATÓRIO DE ANÁLISE DE ARQUIVO

📁 Arquivo: {resultado['arquivo']}
📊 Tamanho: {resultado['tamanho_arquivo']:,} bytes
📈 Total de linhas: {resultado['total_linhas']:,}
🌐 IPs únicos encontrados: {resultado['ips_unicos']}
⏰ Análise realizada em: {resultado['timestamp_analise']}

📋 DISTRIBUIÇÃO POR TIPO:
"""
        
        for tipo, quantidade in resultado['tipos_linhas'].items():
            percentual = (quantidade / resultado['total_linhas']) * 100
            relatorio += f"   • {tipo}: {quantidade} linhas ({percentual:.1f}%)\n"
        
        relatorio += f"\n💡 DICAS DE ANÁLISE:\n"
        relatorio += f"   • Arquivos com muitos IPs únicos podem indicar varredura\n"
        relatorio += f"   • Alto volume de TCP pode indicar conexões estabelecidas\n"
        relatorio += f"   • Tráfego UDP é comum em DNS e streaming\n"
        
        self.texto_estatisticas.setText(relatorio)
        self.tabs.setCurrentIndex(1)  # Mudar para aba de estatísticas
        self.label_status.setText(f"✅ Análise concluída: {os.path.basename(resultado['arquivo'])}")
        
        QMessageBox.information(self, "Análise Concluída", 
                               f"✅ Análise do arquivo concluída!\n\n"
                               f"📁 Arquivo: {os.path.basename(resultado['arquivo'])}\n"
                               f"📊 Linhas analisadas: {resultado['total_linhas']:,}\n"
                               f"🌐 IPs únicos: {resultado['ips_unicos']}\n"
                               f"📈 Tamanho: {resultado['tamanho_arquivo']:,} bytes")
    
    def atualizar_interfaces(self):
        """Atualiza a lista de interfaces de rede - Multiplataforma"""
        self.combo_interfaces.clear()
        
        try:
            if self.sistema == "Windows":
                # No Windows, adicionar opção para detecção automática
                self.combo_interfaces.addItem("Auto-detecção", None)
                
                try:
                    from scapy.all import get_windows_if_list
                    interfaces = get_windows_if_list()
                    
                    for interface in interfaces:
                        nome = interface.get('name', '')
                        descricao = interface.get('description', '')
                        if nome:
                            texto = f"{nome} - {descricao}" if descricao else nome
                            self.combo_interfaces.addItem(texto, nome)
                except Exception as e:
                    print(f"Erro ao obter interfaces Windows: {e}")
                    # Fallback para psutil
                    interfaces = psutil.net_if_addrs()
                    for interface in interfaces.keys():
                        self.combo_interfaces.addItem(interface, interface)
            
            else:  # Linux e outros
                self.combo_interfaces.addItem("any", "any")
                interfaces = psutil.net_if_addrs()
                for interface in interfaces.keys():
                    self.combo_interfaces.addItem(interface, interface)
                    
        except Exception as e:
            self.mostrar_erro(f"Erro ao listar interfaces: {e}")
    
    def iniciar_captura(self):
        """Inicia a captura de pacotes - Multiplataforma"""
        interface = self.combo_interfaces.currentData()
        tempo = self.spin_tempo.value()
        
        # Configurações específicas por plataforma
        if self.sistema == "Windows" and interface == "any":
            interface = None  # Scapy detecta automaticamente no Windows
        
        if self.sistema != "Windows" and not interface:
            self.mostrar_erro("Selecione uma interface de rede")
            return
        
        # Limpar dados anteriores
        self.dados_captura = []
        self.contadores = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'outros': 0}
        self.bytes_total = 0
        self.texto_logs.clear()
        self.lista_alertas.clear()
        
        # Configurar interface
        self.interface_atual = interface
        
        # Iniciar thread de captura
        self.captura_thread = CapturaThread(interface, tempo)
        self.captura_thread.pacote_capturado.connect(self.adicionar_pacote)
        self.captura_thread.captura_finalizada.connect(self.captura_concluida)
        self.captura_thread.erro_captura.connect(self.mostrar_erro)
        
        self.captura_thread.start()
        
        # Atualizar UI
        self.btn_capturar.setEnabled(False)
        self.btn_parar.setEnabled(True)
        self.barra_progresso.setVisible(True)
        self.barra_progresso.setMaximum(tempo)
        self.barra_progresso.setValue(0)
        
        interface_text = interface if interface else "Auto-detecção"
        self.label_status.setText(f"🎬 Capturando na {interface_text}...")
        
        # Timer para atualizar barra de progresso
        self.timer_progresso = QTimer()
        self.timer_progresso.timeout.connect(self.atualizar_progresso)
        self.timer_progresso.start(1000)
        
        self.tempo_inicio = datetime.now()
    
    def parar_captura(self):
        """Para a captura de pacotes"""
        if self.captura_thread and self.captura_thread.isRunning():
            self.captura_thread.capturando = False
            self.captura_thread.terminate()
            self.captura_thread.wait()
        
        self.captura_concluida(self.dados_captura)
    
    def atualizar_progresso(self):
        """Atualiza a barra de progresso da captura"""
        if hasattr(self, 'tempo_inicio'):
            tempo_decorrido = (datetime.now() - self.tempo_inicio).seconds
            self.barra_progresso.setValue(tempo_decorrido)
            
            if tempo_decorrido >= self.spin_tempo.value():
                self.timer_progresso.stop()
    
    def adicionar_pacote(self, info_pacote):
        """Adiciona um pacote capturado à interface"""
        self.dados_captura.append(info_pacote)
        
        # Atualizar contadores
        self.contadores['total'] += 1
        tipo = info_pacote.get('tipo', 'outros').lower()
        if tipo in self.contadores:
            self.contadores[tipo] += 1
        else:
            self.contadores['outros'] += 1
        
        # Atualizar bytes
        self.bytes_total += info_pacote['tamanho']
        
        # Formatar linha do log
        timestamp = info_pacote['timestamp'].strftime('%H:%M:%S')
        proto_char = 'T' if tipo == 'tcp' else 'U' if tipo == 'udp' else 'I' if tipo == 'icmp' else 'O'
        origem = f"{info_pacote.get('ip_origem', 'N/A')}:{info_pacote.get('porta_origem', '')}"
        destino = f"{info_pacote.get('ip_destino', 'N/A')}:{info_pacote.get('porta_destino', '')}"
        tamanho = info_pacote['tamanho']
        
        linha = f"{timestamp} | {proto_char} | {origem:20} → {destino:20} | {tamanho:4}B"
        self.texto_logs.append(linha)
        
        # Manter apenas as últimas 1000 linhas
        if self.texto_logs.document().lineCount() > 1000:
            cursor = self.texto_logs.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.select(cursor.LineUnderCursor)
            cursor.removeSelectedText()
        
        # Atualizar labels de contador
        self.atualizar_contadores()
        
        # Detectar atividades suspeitas
        self.detectar_anomalias(info_pacote)
    
    def atualizar_contadores(self):
        """Atualiza os contadores na interface"""
        self.label_contador_pacotes.setText(f"📦 Pacotes: {self.contadores['total']}")
        self.label_contador_tcp.setText(f"🔗 TCP: {self.contadores['tcp']}")
        self.label_contador_udp.setText(f"📨 UDP: {self.contadores['udp']}")
        self.label_contador_icmp.setText(f"📡 ICMP: {self.contadores['icmp']}")
        
        # Calcular taxa de transferência
        if hasattr(self, 'tempo_inicio'):
            tempo_decorrido = (datetime.now() - self.tempo_inicio).seconds
            if tempo_decorrido > 0:
                taxa = self.bytes_total / tempo_decorrido
                if taxa > 1024*1024:
                    self.label_taxa_transferencia.setText(f"⚡ Taxa: {taxa/1024/1024:.2f} MB/s")
                elif taxa > 1024:
                    self.label_taxa_transferencia.setText(f"⚡ Taxa: {taxa/1024:.2f} KB/s")
                else:
                    self.label_taxa_transferencia.setText(f"⚡ Taxa: {taxa:.0f} B/s")
    
    def detectar_anomalias(self, pacote):
        """Detecta atividades suspeitas nos pacotes"""
        alertas = []
        
        # Detectar port scanning
        if pacote.get('tipo') == 'TCP' and pacote.get('flags') == 'S':
            # SYN sem outros flags pode indicar port scanning
            alertas.append("SYN scan detectado")
        
        # Detectar tráfego suspeito em portas conhecidas
        porta_destino = pacote.get('porta_destino')
        if porta_destino in [21, 22, 23, 25, 53, 80, 443, 3389]:
            # Tráfego em portas sensíveis
            alertas.append(f"Tráfego em porta sensível: {porta_destino}")
        
        # Adicionar alertas à lista
        for alerta in alertas:
            item = QListWidgetItem(f"⚠️ {alerta} - {pacote.get('ip_origem', 'N/A')}")
            self.lista_alertas.addItem(item)
    
    def captura_concluida(self, dados):
        """Callback quando a captura é concluída"""
        self.btn_capturar.setEnabled(True)
        self.btn_parar.setEnabled(False)
        self.barra_progresso.setVisible(False)
        self.label_status.setText("✅ Captura concluída")
        
        if hasattr(self, 'timer_progresso') and self.timer_progresso.isActive():
            self.timer_progresso.stop()
        
        # Gerar estatísticas
        self.gerar_estatisticas()
        
        # Mostrar resumo
        QMessageBox.information(self, "Captura Concluída", 
                               f"✅ Captura finalizada!\n"
                               f"📦 Total de pacotes: {len(dados)}\n"
                               f"⏰ Duração: {self.spin_tempo.value()}s\n"
                               f"📊 Dados capturados: {self.bytes_total} bytes")
    
    def gerar_estatisticas(self):
        """Gera estatísticas dos dados capturados"""
        if not self.dados_captura:
            self.texto_estatisticas.setText("Nenhum dado disponível para análise.")
            return
        
        df = pd.DataFrame(self.dados_captura)
        
        # Estatísticas básicas
        total_pacotes = len(df)
        total_bytes = df['tamanho'].sum()
        tempo_captura = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        
        # Estatísticas por protocolo
        stats_protocolo = df['tipo'].value_counts()
        
        # Top IPs
        top_ips_origem = df['ip_origem'].value_counts().head(5) if 'ip_origem' in df.columns else pd.Series()
        top_ips_destino = df['ip_destino'].value_counts().head(5) if 'ip_destino' in df.columns else pd.Series()
        
        # Montar relatório
        relatorio = f"""📊 RELATÓRIO DE CAPTURA

📦 ESTATÍSTICAS GERAIS:
   • Total de pacotes: {total_pacotes:,}
   • Total de bytes: {total_bytes:,}
   • Duração da captura: {tempo_captura:.1f}s
   • Taxa média: {total_bytes/max(tempo_captura,1):.0f} B/s

🚦 DISTRIBUIÇÃO POR PROTOCOLO:"""
        
        for protocolo, count in stats_protocolo.items():
            relatorio += f"\n   • {protocolo}: {count} pacotes ({count/total_pacotes*100:.1f}%)"
        
        if not top_ips_origem.empty:
            relatorio += "\n\n🌐 TOP IPs DE ORIGEM:"
            for ip, count in top_ips_origem.items():
                relatorio += f"\n   • {ip}: {count} pacotes"
        
        if not top_ips_destino.empty:
            relatorio += "\n\n🎯 TOP IPs DE DESTINO:"
            for ip, count in top_ips_destino.items():
                relatorio += f"\n   • {ip}: {count} pacotes"
        
        self.texto_estatisticas.setText(relatorio)
    
    def exportar_relatorio(self, formato):
        """Exporta o relatório para arquivo"""
        if not self.dados_captura:
            self.mostrar_erro("Nenhum dado disponível para exportar")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"relatorios/relatorio_{timestamp}"
            
            # Garantir que o diretório existe
            os.makedirs("relatorios", exist_ok=True)
            
            if formato == 'json':
                # Converter dados para formato serializável
                dados_serializaveis = []
                for dado in self.dados_captura:
                    dado_serial = dado.copy()
                    dado_serial['timestamp'] = dado['timestamp'].isoformat()
                    dados_serializaveis.append(dado_serial)
                
                with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                    import json
                    json.dump(dados_serializaveis, f, indent=2, ensure_ascii=False)
                
                QMessageBox.information(self, "Exportação Concluída", 
                                      f"✅ Relatório exportado como:\n{filename}.json")
            
            elif formato == 'csv':
                df = pd.DataFrame(self.dados_captura)
                df.to_csv(f"{filename}.csv", index=False, encoding='utf-8')
                
                QMessageBox.information(self, "Exportação Concluída", 
                                      f"✅ Relatório exportado como:\n{filename}.csv")
        
        except Exception as e:
            self.mostrar_erro(f"Erro ao exportar relatório: {e}")
    
    def gerar_relatorio_completo(self):
        """Gera um relatório completo em nova janela"""
        if not self.dados_captura:
            self.mostrar_erro("Nenhum dado disponível para relatório")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("📋 Relatório Completo")
        dialog.setGeometry(200, 200, 800, 600)
        
        layout = QVBoxLayout(dialog)
        
        texto_relatorio = QTextEdit()
        texto_relatorio.setFont(QFont("Monospace", 9))
        
        # Gerar relatório detalhado
        relatorio = self.gerar_relatorio_detalhado()
        texto_relatorio.setText(relatorio)
        
        layout.addWidget(texto_relatorio)
        
        # Botões
        botoes = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Save)
        botoes.accepted.connect(dialog.accept)
        botoes.button(QDialogButtonBox.Save).clicked.connect(
            lambda: self.salvar_relatorio(relatorio)
        )
        layout.addWidget(botoes)
        
        dialog.exec_()
    
    def gerar_relatorio_detalhado(self):
        """Gera um relatório detalhado dos dados"""
        df = pd.DataFrame(self.dados_captura)
        
        relatorio = f"""🚀 MELTTRÁFEGO - RELATÓRIO COMPLETO
📅 Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
💻 Plataforma: {self.sistema}
🌐 Interface: {self.interface_atual or 'Auto-detecção'}
⏰ Duração: {self.spin_tempo.value()} segundos

📊 ESTATÍSTICAS GERAIS:
   • Total de pacotes: {len(df):,}
   • Total de bytes: {df['tamanho'].sum():,}
   • Pacote médio: {df['tamanho'].mean():.1f} bytes
   • Maior pacote: {df['tamanho'].max()} bytes
   • Menor pacote: {df['tamanho'].min()} bytes

📈 DISTRIBUIÇÃO POR PROTOCOLO:
"""
        
        # Estatísticas por protocolo
        for protocolo, count in df['tipo'].value_counts().items():
            percentual = count / len(df) * 100
            relatorio += f"   • {protocolo}: {count} pacotes ({percentual:.1f}%)\n"
        
        # Top IPs
        if 'ip_origem' in df.columns:
            relatorio += "\n🌐 TOP 5 IPs DE ORIGEM:\n"
            for ip, count in df['ip_origem'].value_counts().head(5).items():
                relatorio += f"   • {ip}: {count} pacotes\n"
        
        if 'ip_destino' in df.columns:
            relatorio += "\n🎯 TOP 5 IPs DE DESTINO:\n"
            for ip, count in df['ip_destino'].value_counts().head(5).items():
                relatorio += f"   • {ip}: {count} pacotes\n"
        
        # Portas mais acessadas
        if 'porta_destino' in df.columns:
            relatorio += "\n🔢 TOP 5 PORTAS DE DESTINO:\n"
            for porta, count in df['porta_destino'].value_counts().head(5).items():
                relatorio += f"   • {porta}: {count} conexões\n"
        
        # Alertas de segurança
        relatorio += "\n⚠️ RESUMO DE SEGURANÇA:\n"
        relatorio += f"   • Total de alertas: {self.lista_alertas.count()}\n"
        relatorio += f"   • TCP SYNs: {self.contadores['tcp']}\n"
        relatorio += f"   • Tráfego UDP: {self.contadores['udp']}\n"
        
        return relatorio
    
    def salvar_relatorio(self, conteudo):
        """Salva o relatório em arquivo de texto"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"relatorios/relatorio_completo_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(conteudo)
            
            QMessageBox.information(self, "Relatório Salvo", 
                                  f"✅ Relatório salvo como:\n{filename}")
        
        except Exception as e:
            self.mostrar_erro(f"Erro ao salvar relatório: {e}")
    
    def atualizar_conexoes(self):
        """Atualiza a lista de conexões de rede"""
        self.lista_conexoes.clear()
        
        try:
            conexoes = psutil.net_connections()
            
            for conn in conexoes:
                if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                    item_text = f"{conn.laddr.ip}:{conn.laddr.port} ↔ {conn.raddr.ip}:{conn.raddr.port}"
                    item = QListWidgetItem(item_text)
                    self.lista_conexoes.addItem(item)
        
        except Exception as e:
            self.mostrar_erro(f"Erro ao obter conexões: {e}")
    
    def atualizar_status_sistema(self):
        """Atualiza as informações do sistema"""
        # Informações de rede
        try:
            info_rede = "🌐 ESTATÍSTICAS DE REDE:\n\n"
            
            # Estatísticas por interface
            io_counters = psutil.net_io_counters(pernic=True)
            for interface, stats in io_counters.items():
                info_rede += f"📡 {interface}:\n"
                info_rede += f"   ↑ Enviados: {stats.bytes_sent:,} bytes\n"
                info_rede += f"   ↓ Recebidos: {stats.bytes_recv:,} bytes\n"
                info_rede += f"   📦 Pacotes enviados: {stats.packets_sent:,}\n"
                info_rede += f"   📦 Pacotes recebidos: {stats.packets_recv:,}\n\n"
            
            self.texto_info_rede.setText(info_rede)
        
        except Exception as e:
            self.texto_info_rede.setText(f"Erro ao obter informações de rede: {e}")
        
        # Informações do sistema
        try:
            info_sistema = "💻 INFORMAÇÕES DO SISTEMA\n\n"
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            info_sistema += f"⚡ CPU: {cpu_percent}% utilizada\n"
            
            # Memória
            memoria = psutil.virtual_memory()
            info_sistema += f"💾 Memória: {memoria.percent}% utilizada\n"
            info_sistema += f"   ({memoria.used//1024//1024}MB / {memoria.total//1024//1024}MB)\n\n"
            
            # Load average (apenas Linux/Unix)
            if self.sistema != "Windows":
                load_avg = os.getloadavg()
                info_sistema += f"📊 Load Average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}\n\n"
            
            # Plataforma
            info_sistema += f"💻 Sistema: {platform.system()} {platform.release()}\n"
            info_sistema += f"🐍 Python: {platform.python_version()}\n"
            info_sistema += f"📦 Scapy: {scapy.__version__ if 'scapy' in globals() else 'N/A'}\n"
            
            self.texto_info_sistema.setText(info_sistema)
        
        except Exception as e:
            self.texto_info_sistema.setText(f"Erro ao obter informações do sistema: {e}")
    
    def limpar_dados(self):
        """Limpa todos os dados capturados"""
        self.dados_captura = []
        self.contadores = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'outros': 0}
        self.bytes_total = 0
        self.texto_logs.clear()
        self.lista_alertas.clear()
        self.texto_estatisticas.clear()
        self.label_status.setText("🗑️ Dados limpos")
        QMessageBox.information(self, "Limpeza Concluída", "✅ Todos os dados foram limpos!")
    
    def mostrar_info_plataforma(self):
        """Mostra informações da plataforma"""
        info = f"""💻 INFORMAÇÕES DA PLATAFORMA

Sistema: {platform.system()} {platform.release()}
Arquitetura: {platform.architecture()[0]}
Python: {platform.python_version()}

📦 DEPENDÊNCIAS:
Scapy: {'✅' if 'scapy' in sys.modules else '❌'}
Psutil: {'✅' if 'psutil' in sys.modules else '❌'}
Pandas: {'✅' if 'pandas' in sys.modules else '❌'}
PyQt5: {'✅' if 'PyQt5' in sys.modules else '❌'}

💡 CONFIGURAÇÃO:
• Linux: Requer tcpdump e permissões de captura
• Windows: Requer Npcap instalado
• Execute como Admin se tiver problemas de permissão
"""
        QMessageBox.information(self, "Informações da Plataforma", info)
    
    def mostrar_erro(self, mensagem):
        """Exibe uma mensagem de erro"""
        QMessageBox.critical(self, "Erro", mensagem)
        self.label_status.setText(f"❌ {mensagem[:50]}...")

def main():
    """Função principal da aplicação GUI - Multiplataforma"""
    sistema = platform.system()
    
    # Verificações específicas por plataforma
    if sistema == "Windows":
        print("🪟 Executando MeltTrafego no Windows")
        # Verificar se Npcap está instalado
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
            winreg.CloseKey(key)
            print("✅ Npcap detectado")
        except:
            print("⚠️  Npcap não encontrado. A captura pode não funcionar.")
            print("💡 Instale em: https://npcap.com/#download")
    
    elif sistema == "Linux":
        print("🐧 Executando MeltTrafego no Linux")
        # Verificar permissões
        if os.geteuid() != 0:
            print("⚠️  Executando sem privilégios de root")
            print("💡 Algumas funcionalidades podem requerer sudo")
    else:
        print(f"🔧 Executando MeltTrafego no {sistema}")
    
    app = QApplication(sys.argv)
    app.setApplicationName("MeltTrafego")
    app.setApplicationVersion("2.0")
    
    # Criar e mostrar janela principal
    janela = MeltTrafegoGUI()
    janela.show()
    
    # Executar aplicação
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()