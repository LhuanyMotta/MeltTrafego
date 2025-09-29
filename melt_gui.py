#!/usr/bin/env python3
"""
MeltTrafego - Interface Gráfica
"""

import sys
import os
import threading
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTextEdit, QLabel, 
                             QLineEdit, QComboBox, QProgressBar, QTabWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QGroupBox, QSpinBox, QFileDialog, QMessageBox,
                             QSplitter, QListWidget, QListWidgetItem)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon

from melt_core import MeltTrafegoCore

class MeltTrafegoGUI(QMainWindow):
    update_log = pyqtSignal(str)
    update_progress = pyqtSignal(int)
    analysis_complete = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.melt = MeltTrafegoCore()
        self.captura_thread = None
        self.analise_thread = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("MeltTrafego - Analisador de Tráfego de Rede")
        self.setGeometry(100, 100, 1200, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        layout = QVBoxLayout(central_widget)
        
        # Barra de título
        title_label = QLabel("🌐 MeltTrafego - Sistema de Análise de Tráfego")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title_label)
        
        # Abas
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # Aba 1: Captura
        tab_captura = QWidget()
        tabs.addTab(tab_captura, "🎯 Captura")
        self.setup_captura_tab(tab_captura)
        
        # Aba 2: Análise
        tab_analise = QWidget()
        tabs.addTab(tab_analise, "📊 Análise")
        self.setup_analise_tab(tab_analise)
        
        # Aba 3: Resultados
        tab_resultados = QWidget()
        tabs.addTab(tab_resultados, "📈 Resultados")
        self.setup_resultados_tab(tab_resultados)
        
        # Área de log
        log_group = QGroupBox("📝 Log do Sistema")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setMaximumHeight(150)
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        # Barra de progresso
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Conectar sinais
        self.update_log.connect(self.add_log)
        self.update_progress.connect(self.progress_bar.setValue)
        self.analysis_complete.connect(self.on_analysis_complete)
        
        self.log("Sistema MeltTrafego inicializado")
        
    def setup_captura_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # Configurações de captura
        config_group = QGroupBox("⚙️ Configurações de Captura")
        config_layout = QVBoxLayout()
        
        # Interface
        interface_layout = QHBoxLayout()
        interface_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["any", "eth0", "wlan0", "enp0s3", "ens33"])
        self.interface_combo.setEditable(True)
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addStretch()
        config_layout.addLayout(interface_layout)
        
        # Tempo
        tempo_layout = QHBoxLayout()
        tempo_layout.addWidget(QLabel("Tempo (segundos):"))
        self.tempo_spin = QSpinBox()
        self.tempo_spin.setRange(10, 3600)
        self.tempo_spin.setValue(60)
        tempo_layout.addWidget(self.tempo_spin)
        tempo_layout.addStretch()
        config_layout.addLayout(tempo_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Botões de ação
        button_layout = QHBoxLayout()
        
        self.capturar_btn = QPushButton("🎯 Iniciar Captura")
        self.capturar_btn.clicked.connect(self.iniciar_captura)
        self.capturar_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        button_layout.addWidget(self.capturar_btn)
        
        self.parar_btn = QPushButton("⏹️ Parar Captura")
        self.parar_btn.clicked.connect(self.parar_captura)
        self.parar_btn.setEnabled(False)
        self.parar_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; }")
        button_layout.addWidget(self.parar_btn)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
    def setup_analise_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # Seleção de arquivo
        file_group = QGroupBox("📁 Arquivo de Tráfego")
        file_layout = QVBoxLayout()
        
        file_select_layout = QHBoxLayout()
        self.arquivo_edit = QLineEdit()
        self.arquivo_edit.setPlaceholderText("Selecione um arquivo de tráfego...")
        file_select_layout.addWidget(self.arquivo_edit)
        
        browse_btn = QPushButton("Procurar...")
        browse_btn.clicked.connect(self.selecionar_arquivo)
        file_select_layout.addWidget(browse_btn)
        
        file_layout.addLayout(file_select_layout)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Configurações de análise
        analise_config_group = QGroupBox("🔧 Configurações de Análise")
        analise_config_layout = QVBoxLayout()
        
        # Janela temporal
        janela_layout = QHBoxLayout()
        janela_layout.addWidget(QLabel("Janela temporal (s):"))
        self.janela_spin = QSpinBox()
        self.janela_spin.setRange(10, 300)
        self.janela_spin.setValue(60)
        janela_layout.addWidget(self.janela_spin)
        janela_layout.addStretch()
        analise_config_layout.addLayout(janela_layout)
        
        # Limite de portas
        portas_layout = QHBoxLayout()
        portas_layout.addWidget(QLabel("Limite de portas:"))
        self.portas_spin = QSpinBox()
        self.portas_spin.setRange(1, 100)
        self.portas_spin.setValue(10)
        portas_layout.addWidget(self.portas_spin)
        portas_layout.addStretch()
        analise_config_layout.addLayout(portas_layout)
        
        analise_config_group.setLayout(analise_config_layout)
        layout.addWidget(analise_config_group)
        
        # Botão de análise
        self.analisar_btn = QPushButton("📊 Analisar Tráfego")
        self.analisar_btn.clicked.connect(self.iniciar_analise)
        self.analisar_btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; font-weight: bold; }")
        layout.addWidget(self.analisar_btn)
        
        layout.addStretch()
        
    def setup_resultados_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        splitter = QSplitter(Qt.Vertical)
        
        # Estatísticas
        stats_group = QGroupBox("📈 Estatísticas")
        stats_layout = QVBoxLayout()
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(150)
        stats_layout.addWidget(self.stats_text)
        stats_group.setLayout(stats_layout)
        splitter.addWidget(stats_group)
        
        # Tabela de resultados
        table_group = QGroupBox("📋 Resultados Detalhados")
        table_layout = QVBoxLayout()
        self.resultados_table = QTableWidget()
        self.resultados_table.setColumnCount(5)
        self.resultados_table.setHorizontalHeaderLabels([
            "IP", "Total Eventos", "Portas Únicas", "Port Scan", "Severidade"
        ])
        table_layout.addWidget(self.resultados_table)
        table_group.setLayout(table_layout)
        splitter.addWidget(table_group)
        
        # Alertas - CORREÇÃO AQUI: criar layout próprio para alertas_group
        alertas_group = QGroupBox("🚨 Alertas")
        alertas_layout = QVBoxLayout()
        self.alertas_list = QListWidget()
        alertas_layout.addWidget(self.alertas_list)
        alertas_group.setLayout(alertas_layout)  # CORREÇÃO: usar alertas_group
        splitter.addWidget(alertas_group)
        
        layout.addWidget(splitter)
        
        # Botões de exportação
        export_layout = QHBoxLayout()
        
        self.export_csv_btn = QPushButton("💾 Exportar CSV")
        self.export_csv_btn.clicked.connect(self.exportar_csv)
        self.export_csv_btn.setEnabled(False)
        export_layout.addWidget(self.export_csv_btn)
        
        self.export_json_btn = QPushButton("💾 Exportar JSON")
        self.export_json_btn.clicked.connect(self.exportar_json)
        self.export_json_btn.setEnabled(False)
        export_layout.addWidget(self.export_json_btn)
        
        layout.addLayout(export_layout)
        
    def log(self, mensagem):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {mensagem}")
        
    def add_log(self, mensagem):
        self.log(mensagem)
        
    def iniciar_captura(self):
        interface = self.interface_combo.currentText()
        tempo = self.tempo_spin.value()
        
        self.log(f"Iniciando captura na interface {interface} por {tempo} segundos...")
        
        self.capturar_btn.setEnabled(False)
        self.parar_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, tempo)
        
        # Executar captura em thread separada
        self.captura_thread = threading.Thread(
            target=self.executar_captura,
            args=(interface, tempo)
        )
        self.captura_thread.start()
        
        # Atualizar progresso
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.atualizar_progresso)
        self.progress_timer.start(1000)
        self.progress_counter = 0
        
    def executar_captura(self, interface, tempo):
        arquivo, sucesso, mensagem = self.melt.capturar_trafego(interface, tempo)
        
        self.update_log.emit(mensagem)
        if sucesso:
            self.update_log.emit(f"Captura salva em: {arquivo}")
            self.arquivo_edit.setText(arquivo)
        else:
            self.update_log.emit("❌ Falha na captura")
            
        self.captura_completa = True
        
    def atualizar_progresso(self):
        self.progress_counter += 1
        self.update_progress.emit(self.progress_counter)
        
        if self.progress_counter >= self.tempo_spin.value():
            self.progress_timer.stop()
            self.capturar_btn.setEnabled(True)
            self.parar_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            
    def parar_captura(self):
        # Implementar parada da captura
        self.log("Captura interrompida pelo usuário")
        self.capturar_btn.setEnabled(True)
        self.parar_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        if hasattr(self, 'progress_timer'):
            self.progress_timer.stop()
            
    def selecionar_arquivo(self):
        arquivo, _ = QFileDialog.getOpenFileName(
            self, 
            "Selecionar arquivo de tráfego",
            "",
            "Arquivos de texto (*.txt);;Todos os arquivos (*)"
        )
        if arquivo:
            self.arquivo_edit.setText(arquivo)
            
    def iniciar_analise(self):
        arquivo = self.arquivo_edit.text()
        if not arquivo or not os.path.exists(arquivo):
            QMessageBox.warning(self, "Erro", "Selecione um arquivo válido para análise")
            return
            
        self.log(f"Iniciando análise do arquivo: {arquivo}")
        
        # Configurar parâmetros
        self.melt.janela_tempo = self.janela_spin.value()
        self.melt.limite_portas = self.portas_spin.value()
        
        self.analisar_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Progresso indeterminado
        
        # Executar análise em thread separada
        self.analise_thread = threading.Thread(
            target=self.executar_analise,
            args=(arquivo,)
        )
        self.analise_thread.start()
        
    def executar_analise(self, arquivo):
        try:
            # Parsear
            eventos, stats = self.melt.parse_trafego(arquivo)
            self.update_log.emit(f"✅ {stats['linhas_processadas']} eventos processados")
            
            if not eventos:
                self.update_log.emit("❌ Nenhum evento válido encontrado")
                return
                
            # Analisar
            contagem_total, port_scans, portas_por_ip, alertas = self.melt.analisar_comportamento(eventos)
            
            # Preparar resultados
            resultados = {
                'eventos': eventos,
                'contagem_total': contagem_total,
                'port_scans': port_scans,
                'portas_por_ip': portas_por_ip,
                'alertas': alertas,
                'estatisticas': self.melt.obter_estatisticas(eventos, contagem_total, port_scans)
            }
            
            self.analysis_complete.emit(resultados)
            
        except Exception as e:
            self.update_log.emit(f"❌ Erro na análise: {e}")
            
    def on_analysis_complete(self, resultados):
        self.analisar_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Atualizar estatísticas
        stats = resultados['estatisticas']
        stats_text = f"""
📊 ANÁLISE CONCLUÍDA - {stats['timestamp_analise']}

• Total de Eventos: {stats['total_eventos']}
• IPs Analisados: {stats['total_ips']}
• Port Scans Detectados: {stats['port_scans_detectados']} ⚠️
• IPs Normais: {stats['ips_normais']} ✅

🏆 IPs Mais Ativos:
"""
        for ip, count in stats['top_ips']:
            status = "🚨 PORT SCAN" if resultados['port_scans'].get(ip, False) else "✅ Normal"
            stats_text += f"  {ip}: {count} eventos - {status}\n"
            
        self.stats_text.setPlainText(stats_text)
        
        # Atualizar tabela
        self.atualizar_tabela(resultados)
        
        # Atualizar alertas
        self.atualizar_alertas(resultados['alertas'])
        
        # Habilitar exportação
        self.export_csv_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        self.resultados = resultados
        
        self.log("Análise concluída com sucesso!")
        
    def atualizar_tabela(self, resultados):
        self.resultados_table.setRowCount(len(resultados['contagem_total']))
        
        for row, (ip, total) in enumerate(resultados['contagem_total'].items()):
            portas_unicas = len(resultados['portas_por_ip'].get(ip, set()))
            port_scan = resultados['port_scans'].get(ip, False)
            
            self.resultados_table.setItem(row, 0, QTableWidgetItem(ip))
            self.resultados_table.setItem(row, 1, QTableWidgetItem(str(total)))
            self.resultados_table.setItem(row, 2, QTableWidgetItem(str(portas_unicas)))
            self.resultados_table.setItem(row, 3, QTableWidgetItem("Sim" if port_scan else "Não"))
            self.resultados_table.setItem(row, 4, QTableWidgetItem("ALTA" if port_scan else "BAIXA"))
            
        self.resultados_table.resizeColumnsToContents()
        
    def atualizar_alertas(self, alertas):
        self.alertas_list.clear()
        
        for alerta in alertas:
            item = QListWidgetItem(f"🚨 {alerta['ip']} - {alerta['mensagem']}")
            if alerta['severidade'] == 'ALTA':
                item.setBackground(QColor(255, 200, 200))
            self.alertas_list.addItem(item)
            
    def exportar_csv(self):
        arquivo, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar relatório CSV",
            f"relatorio_melt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "Arquivos CSV (*.csv)"
        )
        
        if arquivo:
            self.melt.gerar_relatorio_csv(
                self.resultados['contagem_total'],
                self.resultados['port_scans'],
                self.resultados['portas_por_ip'],
                arquivo
            )
            self.log(f"Relatório CSV exportado: {arquivo}")
            
    def exportar_json(self):
        arquivo, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar relatório JSON",
            f"relatorio_melt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "Arquivos JSON (*.json)"
        )
        
        if arquivo:
            dados = {
                'contagem_total': self.resultados['contagem_total'],
                'port_scans': self.resultados['port_scans'],
                'portas_por_ip': self.resultados['portas_por_ip']
            }
            self.melt.gerar_relatorio_json(dados, arquivo)
            self.log(f"Relatório JSON exportado: {arquivo}")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("MeltTrafego")
    app.setApplicationVersion("1.0")
    
    # Verificar se PyQt5 está disponível
    try:
        window = MeltTrafegoGUI()
        window.show()
        sys.exit(app.exec_())
    except ImportError:
        print("❌ PyQt5 não encontrado. Instale com: pip install PyQt5")
        sys.exit(1)

if __name__ == "__main__":
    main()