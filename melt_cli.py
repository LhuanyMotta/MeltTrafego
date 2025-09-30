#!/usr/bin/env python3
"""
MeltTrafego - Analisador de Tráfego de Rede Multiplataforma
Versão CLI Melhorada com Análise de Arquivos
"""

import os
import sys
import time
import json
import threading
import argparse
from datetime import datetime
import platform
import re

# Configuração multiplataforma
SISTEMA = platform.system()

if SISTEMA == "Linux":
    os.environ['PATH'] = '/usr/sbin:/sbin:' + os.environ.get('PATH', '')

try:
    import psutil
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    import pandas as pd
except ImportError as e:
    print(f"❌ Erro: Dependências não encontradas: {e}")
    print("💡 Instale com: pip install scapy psutil pandas")
    sys.exit(1)

class MeltTrafegoCLI:
    def __init__(self):
        self.dados_captura = []
        self.estatisticas = {}
        self.interface_atual = None
        self.captura_ativa = False
        self.arquivo_captura = None
        self.sistema = platform.system()
        self.arquivo_analisado = None
        self.relatorios_dir = "relatorios"
        self._criar_diretorios()
        
    def _criar_diretorios(self):
        """Cria os diretórios necessários"""
        os.makedirs(self.relatorios_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        
    def limpar_tela(self):
        if self.sistema == "Windows":
            os.system('cls')
        else:
            os.system('clear')
    
    def cabecalho(self):
        sistema_text = "WINDOWS" if self.sistema == "Windows" else "LINUX"
        print("\n" + "="*70)
        print(f"🚀  MELTTRÁFEGO - ANALISADOR DE REDE {sistema_text}  🌐")
        print("="*70)
    
    def menu_interativo(self):
        """Modo interativo com menu completo"""
        while True:
            self.limpar_tela()
            self.cabecalho()
            print(f"\n💻 Plataforma: {self.sistema}")
            print("📍 Diretório atual:", os.getcwd())
            
            # Status rápido
            if self.dados_captura:
                status_captura = f"📦 {len(self.dados_captura)} pacotes"
            else:
                status_captura = "📭 Sem dados"
                
            if self.arquivo_analisado:
                status_analise = f"📁 {os.path.basename(self.arquivo_analisado)}"
            else:
                status_analise = "📭 Sem análise"
                
            print(f"📊 Status: Captura: {status_captura} | Análise: {status_analise}")
            print("\n1️⃣  Listar interfaces disponíveis")
            print("2️⃣  Capturar tráfego (configurável)")
            print("3️⃣  Monitorar tráfego em tempo real (30s)")
            print("4️⃣  Analisar arquivo de captura")
            print("5️⃣  Estatísticas da última captura")
            print("6️⃣  Estatísticas do último arquivo analisado")
            print("7️⃣  Exportar relatórios")
            print("8️⃣  Status do sistema")
            print("9️⃣  Informações da plataforma")
            print("🔟  Limpar dados")
            print("0️⃣  Sair")
            
            opcao = input("\n📋 Digite o número da opção (0-10): ").strip()
            
            if opcao == "1":
                self.listar_interfaces()
            elif opcao == "2":
                self.capturar_trafego_interativo()
            elif opcao == "3":
                self.monitorar_tempo_real()
            elif opcao == "4":
                self.analisar_arquivo_interativo()
            elif opcao == "5":
                self.mostrar_estatisticas_captura()
            elif opcao == "6":
                self.mostrar_estatisticas_analise()
            elif opcao == "7":
                self.exportar_relatorio_interativo()
            elif opcao == "8":
                self.mostrar_status()
            elif opcao == "9":
                self.mostrar_info_plataforma()
            elif opcao == "10":
                self.limpar_dados_interativo()
            elif opcao == "0":
                print("\n👋 Saindo do MeltTrafego... Até logo!")
                break
            else:
                print("\n❌ Opção inválida! Tente novamente.")
                time.sleep(2)
    
    def listar_interfaces(self):
        """Lista todas as interfaces de rede disponíveis - Multiplataforma"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📡 INTERFACES DE REDE DISPONÍVEIS:\n")
        
        try:
            if self.sistema == "Linux":
                # Usar ip command para listar interfaces
                import subprocess
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                
                interfaces = {}
                current_interface = None
                
                for line in result.stdout.split('\n'):
                    if line and not line.startswith(' '):
                        # Nova interface
                        parts = line.split(':')
                        if len(parts) >= 2:
                            current_interface = parts[1].strip()
                            interfaces[current_interface] = {'ips': [], 'state': 'DOWN'}
                    elif current_interface and 'inet ' in line:
                        # Endereço IP
                        ip_parts = line.split()
                        if len(ip_parts) >= 2:
                            interfaces[current_interface]['ips'].append(ip_parts[1])
                    elif current_interface and 'state' in line:
                        # Estado da interface
                        if 'UP' in line:
                            interfaces[current_interface]['state'] = 'UP'
                
                # Mostrar interfaces
                for i, (interface, info) in enumerate(interfaces.items(), 1):
                    status = "✅ ATIVA" if info['state'] == 'UP' else "❌ INATIVA"
                    print(f"{i}. {interface} - {status}")
                    
                    for ip in info['ips']:
                        print(f"   📍 IP: {ip}")
                    print()
                    
            elif self.sistema == "Windows":
                print("🪟 Interfaces Windows:\n")
                try:
                    from scapy.all import get_windows_if_list
                    interfaces = get_windows_if_list()
                    
                    for i, interface in enumerate(interfaces, 1):
                        name = interface.get('name', 'N/A')
                        desc = interface.get('description', 'Sem descrição')
                        ips = interface.get('ips', ['Sem IP'])
                        ip = ips[0] if ips else 'Sem IP'
                        
                        print(f"{i}. {name}")
                        print(f"   📝 {desc}")
                        print(f"   📍 IP: {ip}")
                        print()
                        
                except Exception as e:
                    print(f"❌ Erro ao listar interfaces Windows: {e}")
                    # Fallback para psutil
                    interfaces = psutil.net_if_addrs()
                    stats = psutil.net_if_stats()
                    
                    for i, (interface, addrs) in enumerate(interfaces.items(), 1):
                        status = "✅ ATIVA" if interface in stats and stats[interface].isup else "❌ INATIVA"
                        print(f"{i}. {interface} - {status}")
                        
                        for addr in addrs:
                            if addr.family == 2:  # IPv4
                                print(f"   📍 IPv4: {addr.address}/{addr.netmask}")
                        print()
    
        except Exception as e:
            print(f"❌ Erro ao listar interfaces: {e}")
            # Fallback universal
            try:
                interfaces = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                
                for i, (interface, addrs) in enumerate(interfaces.items(), 1):
                    status = "✅ ATIVA" if interface in stats and stats[interface].isup else "❌ INATIVA"
                    print(f"{i}. {interface} - {status}")
                    
                    for addr in addrs:
                        if addr.family == 2:  # IPv4
                            print(f"   📍 IPv4: {addr.address}/{addr.netmask}")
                        elif addr.family == 10:  # IPv6
                            print(f"   📍 IPv6: {addr.address}")
                    print()
            except Exception as e2:
                print(f"❌ Erro no fallback: {e2}")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def capturar_trafego_interativo(self):
        """Captura tráfego com configuração interativa"""
        self.limpar_tela()
        self.cabecalho()
        print("\n🎯 CONFIGURAÇÃO DE CAPTURA\n")
        
        # Listar interfaces rapidamente
        interfaces = self.obter_interfaces()
        if not interfaces:
            print("❌ Nenhuma interface disponível.")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        print("📡 Interfaces disponíveis:")
        for i, interface in enumerate(interfaces, 1):
            print(f"   {i}. {interface}")
        
        try:
            # Selecionar interface
            escolha = input(f"\n🔢 Selecione a interface (1-{len(interfaces)}): ").strip()
            if not escolha.isdigit() or int(escolha) < 1 or int(escolha) > len(interfaces):
                print("❌ Seleção inválida. Usando primeira interface.")
                interface = interfaces[0]
            else:
                interface = interfaces[int(escolha) - 1]
            
            # Configurar tempo
            tempo = input("⏰ Tempo de captura em segundos [30]: ").strip()
            if not tempo.isdigit():
                tempo = 30
            else:
                tempo = int(tempo)
                if tempo < 5:
                    tempo = 5
                elif tempo > 3600:
                    tempo = 3600
            
            # Configurar mostrar em tempo real
            tempo_real = input("👀 Mostrar pacotes em tempo real? (s/N): ").strip().lower()
            mostrar_tempo_real = tempo_real in ['s', 'sim', 'y', 'yes']
            
            print(f"\n🚀 Iniciando captura na interface '{interface}' por {tempo} segundos...")
            
            if mostrar_tempo_real:
                print("📊 Mostrando pacotes em tempo real...")
                print("   Legenda: T=TCP, U=UDP, I=ICMP, O=Outro\n")
                self.mostrar_tempo_real = True
            else:
                self.mostrar_tempo_real = False
                print("⏳ Capturando (sem exibição em tempo real)...")
            
            self.capturar_trafego(tempo, interface)
            
            if self.dados_captura:
                self.estatisticas = self.analisar_dados()
                print(f"\n✅ Captura concluída! {len(self.dados_captura)} pacotes capturados.")
                
                # Mostrar estatísticas rápidas
                if self.estatisticas:
                    total = self.estatisticas['total_pacotes']
                    bytes_total = self.estatisticas['tamanho_pacotes']['total_bytes']
                    print(f"📊 Resumo: {total} pacotes, {bytes_total:,} bytes")
            else:
                print("\n❌ Nenhum pacote capturado.")
                
        except KeyboardInterrupt:
            print("\n⏹️ Captura interrompida pelo usuário.")
        except Exception as e:
            print(f"❌ Erro na captura: {e}")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def analisar_arquivo_interativo(self):
        """Analisa arquivo de captura interativamente - Busca em relatorios"""
        self.limpar_tela()
        self.cabecalho()
        print("\n🔍 ANÁLISE DE ARQUIVO DE CAPTURA\n")
        
        # Buscar arquivos na pasta relatorios
        arquivos_relatorios = []
        if os.path.exists(self.relatorios_dir):
            for arquivo in os.listdir(self.relatorios_dir):
                caminho_completo = os.path.join(self.relatorios_dir, arquivo)
                if os.path.isfile(caminho_completo):
                    arquivos_relatorios.append(caminho_completo)
        
        # Buscar arquivos no diretório atual também
        arquivos_atual = [f for f in os.listdir('.') if os.path.isfile(f)]
        
        print("📁 ARQUIVOS NA PASTA 'relatorios':")
        if arquivos_relatorios:
            for i, arquivo in enumerate(arquivos_relatorios[:15], 1):  # Mostrar apenas primeiros 15
                nome_arquivo = os.path.basename(arquivo)
                tamanho = os.path.getsize(arquivo)
                print(f"   {i:2d}. {nome_arquivo} ({tamanho:,} bytes)")
            
            if len(arquivos_relatorios) > 15:
                print(f"   ... e mais {len(arquivos_relatorios) - 15} arquivos")
        else:
            print("   📭 Nenhum arquivo encontrado na pasta 'relatorios'")
        
        print(f"\n📁 ARQUIVOS NO DIRETÓRIO ATUAL:")
        if arquivos_atual:
            for i, arquivo in enumerate(arquivos_atual[:10], len(arquivos_relatorios) + 1):  # Continuar numeração
                tamanho = os.path.getsize(arquivo)
                print(f"   {i:2d}. {arquivo} ({tamanho:,} bytes)")
            
            if len(arquivos_atual) > 10:
                print(f"   ... e mais {len(arquivos_atual) - 10} arquivos")
        else:
            print("   📭 Nenhum arquivo no diretório atual")
        
        total_arquivos = len(arquivos_relatorios) + len(arquivos_atual)
        if total_arquivos == 0:
            print("\n❌ Nenhum arquivo encontrado para análise.")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        opcao = input(f"\n🔢 Selecione o número do arquivo (1-{total_arquivos}) ou digite o caminho: ").strip()
        
        # Verificar se é um número da lista
        if opcao.isdigit() and 1 <= int(opcao) <= total_arquivos:
            if int(opcao) <= len(arquivos_relatorios):
                arquivo = arquivos_relatorios[int(opcao) - 1]
            else:
                arquivo = arquivos_atual[int(opcao) - len(arquivos_relatorios) - 1]
        else:
            arquivo = opcao
        
        if not os.path.exists(arquivo):
            print(f"❌ Arquivo não encontrado: {arquivo}")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        print(f"\n🔍 Analisando arquivo: {os.path.basename(arquivo)}")
        print("⏳ Isso pode levar alguns segundos...")
        
        try:
            resultado = self.analisar_arquivo(arquivo)
            if resultado:
                self.arquivo_analisado = arquivo
                self.mostrar_resultado_analise(resultado)
            else:
                print("❌ Não foi possível analisar o arquivo.")
                
        except Exception as e:
            print(f"❌ Erro na análise: {e}")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def analisar_arquivo(self, arquivo):
        """Analisa um arquivo de captura"""
        try:
            # Verificar se o arquivo existe
            if not os.path.exists(arquivo):
                return None
            
            # Ler e analisar o arquivo
            with open(arquivo, 'r', encoding='utf-8', errors='ignore') as f:
                linhas = f.readlines()
            
            if not linhas:
                return None
            
            # Análise básica do arquivo
            total_linhas = len(linhas)
            tipos_linhas = {}
            ips_unicos = set()
            portas = set()
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                # Classificar tipo de linha
                linha_upper = linha.upper()
                if 'TCP' in linha_upper:
                    tipo = 'TCP'
                elif 'UDP' in linha_upper:
                    tipo = 'UDP'
                elif 'ICMP' in linha_upper:
                    tipo = 'ICMP'
                elif 'IP' in linha_upper:
                    tipo = 'IP'
                else:
                    tipo = 'Outro'
                
                tipos_linhas[tipo] = tipos_linhas.get(tipo, 0) + 1
                
                # Extrair IPs
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', linha)
                ips_unicos.update(ips)
                
                # Extrair portas
                portas_encontradas = re.findall(r':(\d+)\s', linha)
                portas.update(portas_encontradas)
            
            resultado = {
                'arquivo': arquivo,
                'total_linhas': total_linhas,
                'tipos_linhas': tipos_linhas,
                'ips_unicos': len(ips_unicos),
                'portas_unicas': len(portas),
                'timestamp_analise': datetime.now().isoformat(),
                'tamanho_arquivo': os.path.getsize(arquivo),
                'lista_ips': list(ips_unicos)[:10]  # Primeiros 10 IPs
            }
            
            return resultado
            
        except Exception as e:
            print(f"Erro na análise: {e}")
            return None
    
    def mostrar_resultado_analise(self, resultado):
        """Mostra resultado da análise de arquivo"""
        print(f"\n✅ ANÁLISE CONCLUÍDA!")
        print("="*50)
        print(f"📁 Arquivo: {resultado['arquivo']}")
        print(f"📊 Tamanho: {resultado['tamanho_arquivo']:,} bytes")
        print(f"📈 Total de linhas: {resultado['total_linhas']:,}")
        print(f"🌐 IPs únicos encontrados: {resultado['ips_unicos']}")
        print(f"🔢 Portas únicas: {resultado['portas_unicas']}")
        print(f"⏰ Análise: {resultado['timestamp_analise']}")
        
        print(f"\n📋 DISTRIBUIÇÃO POR TIPO:")
        for tipo, quantidade in resultado['tipos_linhas'].items():
            percentual = (quantidade / resultado['total_linhas']) * 100
            print(f"   • {tipo}: {quantidade} linhas ({percentual:.1f}%)")
        
        if resultado['lista_ips']:
            print(f"\n🌐 PRIMEIROS IPs ENCONTRADOS:")
            for ip in resultado['lista_ips']:
                print(f"   • {ip}")
        
        print(f"\n💡 DICAS DE ANÁLISE:")
        if resultado['ips_unicos'] > 100:
            print("   ⚠️  Muitos IPs únicos - possível varredura de rede")
        if resultado['tipos_linhas'].get('TCP', 0) > resultado['total_linhas'] * 0.7:
            print("   📡 Alto volume TCP - muitas conexões estabelecidas")
        if resultado['tipos_linhas'].get('UDP', 0) > resultado['total_linhas'] * 0.5:
            print("   🎯 Alto volume UDP - comum em DNS/streaming")
    
    def processar_pacote(self, pacote):
        """Processa cada pacote capturado"""
        if not self.captura_ativa:
            return
            
        timestamp = datetime.now()
        info = {
            'timestamp': timestamp,
            'tamanho': len(pacote)
        }
        
        # Análise de camadas
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
        
        self.dados_captura.append(info)
        
        # Mostrar pacote em tempo real se estiver no modo monitoramento
        if hasattr(self, 'mostrar_tempo_real') and self.mostrar_tempo_real:
            proto_char = 'T' if info['tipo'] == 'TCP' else 'U' if info['tipo'] == 'UDP' else 'I' if info['tipo'] == 'ICMP' else 'O'
            origem = f"{info.get('ip_origem', 'N/A')}:{info.get('porta_origem', '')}"
            destino = f"{info.get('ip_destino', 'N/A')}:{info.get('porta_destino', '')}"
            print(f"📦 {timestamp.strftime('%H:%M:%S')} | {proto_char} | {origem:25} → {destino:25} | {info['tamanho']:4}B")
    
    def capturar_trafego(self, duracao, interface=None):
        """Captura tráfego por um período determinado - Multiplataforma"""
        self.dados_captura = []
        self.captura_ativa = True
        
        # Configurar interface para Windows
        if self.sistema == "Windows" and interface == "any":
            interface_captura = None  # Scapy detecta automaticamente
        else:
            interface_captura = interface
        
        # Thread para parar captura após o tempo
        def parar_captura():
            time.sleep(duracao)
            self.captura_ativa = False
        
        thread_parada = threading.Thread(target=parar_captura)
        thread_parada.start()
        
        try:
            # Configurações de filtro
            filter_str = "ip or ip6"
            
            # Captura pacotes
            sniff(prn=self.processar_pacote, timeout=duracao, 
                  iface=interface_captura, filter=filter_str)
                
        except PermissionError:
            if self.sistema == "Linux":
                print("❌ Erro de permissão. Execute com sudo ou configure permissões:")
                print("   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
            else:
                print("❌ Erro de permissão no Windows.")
                print("💡 Execute como Administrador ou verifique a instalação do Npcap.")
            self.captura_ativa = False
        except Exception as e:
            print(f"❌ Erro na captura: {e}")
            self.captura_ativa = False
        
        thread_parada.join()
    
    def analisar_dados(self):
        """Analisa os dados capturados e gera estatísticas"""
        if not self.dados_captura:
            return None
        
        df = pd.DataFrame(self.dados_captura)
        
        estatisticas = {
            'total_pacotes': len(df),
            'periodo_captura': {
                'inicio': df['timestamp'].min(),
                'fim': df['timestamp'].max(),
                'duracao': (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            },
            'tamanho_pacotes': {
                'total_bytes': df['tamanho'].sum(),
                'media_bytes': df['tamanho'].mean(),
                'maior_pacote': df['tamanho'].max(),
                'menor_pacote': df['tamanho'].min()
            },
            'tipos_trafego': df['tipo'].value_counts().to_dict(),
            'top_ips_origem': df['ip_origem'].value_counts().head(5).to_dict() if 'ip_origem' in df.columns else {},
            'top_ips_destino': df['ip_destino'].value_counts().head(5).to_dict() if 'ip_destino' in df.columns else {},
            'top_portas_origem': {},
            'top_portas_destino': {}
        }
        
        # Estatísticas de portas se disponíveis
        if 'porta_origem' in df.columns:
            estatisticas['top_portas_origem'] = df['porta_origem'].value_counts().head(5).to_dict()
        if 'porta_destino' in df.columns:
            estatisticas['top_portas_destino'] = df['porta_destino'].value_counts().head(5).to_dict()
        
        return estatisticas
    
    def monitorar_tempo_real(self):
        """Monitora tráfego em tempo real por 30 segundos"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📊 MODO MONITORAMENTO TEMPO REAL (30s)\n")
        print("📦 Mostrando pacotes em tempo real...")
        print("   Legenda: T=TCP, U=UDP, I=ICMP, O=Outro\n")
        
        # Ativar modo tempo real
        self.mostrar_tempo_real = True
        
        try:
            self.capturar_trafego(30)
            self.mostrar_tempo_real = False
            self.estatisticas = self.analisar_dados()
            
            if self.estatisticas:
                print(f"\n✅ Captura concluída! {self.estatisticas['total_pacotes']} pacotes capturados.")
            else:
                print("\n❌ Nenhum dado foi capturado.")
                
        except Exception as e:
            print(f"❌ Erro no monitoramento: {e}")
            self.mostrar_tempo_real = False
        
        input("\n📝 Pressione Enter para continuar...")
    
    def mostrar_estatisticas_captura(self):
        """Mostra estatísticas da última captura"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📈 ESTATÍSTICAS DA ÚLTIMA CAPTURA\n")
        
        if not self.estatisticas:
            print("❌ Nenhuma captura disponível. Execute uma captura primeiro.")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        stats = self.estatisticas
        
        print(f"📦 TOTAL DE PACOTES: {stats['total_pacotes']:,}")
        print(f"⏰ DURAÇÃO: {stats['periodo_captura']['duracao']:.1f}s")
        print(f"📊 TOTAL DE BYTES: {stats['tamanho_pacotes']['total_bytes']:,}")
        print(f"📏 MÉDIA POR PACOTE: {stats['tamanho_pacotes']['media_bytes']:.1f} bytes")
        print(f"📈 MAIOR PACOTE: {stats['tamanho_pacotes']['maior_pacote']} bytes")
        print(f"📉 MENOR PACOTE: {stats['tamanho_pacotes']['menor_pacote']} bytes")
        
        print("\n🚦 TIPOS DE TRÁFEGO:")
        for tipo, quantidade in stats['tipos_trafego'].items():
            print(f"   • {tipo}: {quantidade}")
        
        if stats['top_ips_origem']:
            print("\n🌐 TOP IPs DE ORIGEM:")
            for ip, count in stats['top_ips_origem'].items():
                print(f"   • {ip}: {count} pacotes")
        
        if stats['top_ips_destino']:
            print("\n🎯 TOP IPs DE DESTINO:")
            for ip, count in stats['top_ips_destino'].items():
                print(f"   • {ip}: {count} pacotes")
                
        if stats.get('top_portas_origem'):
            print("\n🔢 TOP PORTAS DE ORIGEM:")
            for porta, count in stats['top_portas_origem'].items():
                print(f"   • {porta}: {count} conexões")
                
        if stats.get('top_portas_destino'):
            print("\n🎯 TOP PORTAS DE DESTINO:")
            for porta, count in stats['top_portas_destino'].items():
                print(f"   • {porta}: {count} conexões")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def mostrar_estatisticas_analise(self):
        """Mostra estatísticas do último arquivo analisado"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📊 ESTATÍSTICAS DO ÚLTIMO ARQUIVO ANALISADO\n")
        
        if not self.arquivo_analisado:
            print("❌ Nenhum arquivo analisado. Use a opção 4 para analisar um arquivo.")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        if not os.path.exists(self.arquivo_analisado):
            print(f"❌ Arquivo não encontrado: {self.arquivo_analisado}")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        print(f"🔍 Analisando novamente: {self.arquivo_analisado}")
        resultado = self.analisar_arquivo(self.arquivo_analisado)
        
        if resultado:
            self.mostrar_resultado_analise(resultado)
        else:
            print("❌ Não foi possível analisar o arquivo.")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def exportar_relatorio_interativo(self):
        """Exporta relatórios igual ao GUI"""
        self.limpar_tela()
        self.cabecalho()
        print("\n💾 EXPORTAR RELATÓRIOS\n")
        
        tem_captura = bool(self.estatisticas)
        tem_analise = bool(self.arquivo_analisado)
        
        if not tem_captura and not tem_analise:
            print("❌ Nenhum dado disponível para exportar.")
            print("💡 Execute uma captura ou análise primeiro.")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        print("📤 Formatos de exportação disponíveis:")
        if tem_captura:
            print("1. 💾 JSON - Dados completos da captura")
            print("2. 📊 CSV - Tabela formatada da captura")
        
        opcao = input("\n🔢 Selecione o formato: ").strip()
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if opcao == "1" and tem_captura:
                filename = f"{self.relatorios_dir}/relatorio_captura_{timestamp}.json"
                self.exportar_json_captura(filename)
                
            elif opcao == "2" and tem_captura:
                filename = f"{self.relatorios_dir}/relatorio_captura_{timestamp}.csv"
                self.exportar_csv_captura(filename)
                
            elif opcao == "3" and tem_analise:
                filename = f"{self.relatorios_dir}/relatorio_analise_{timestamp}.txt"
                self.exportar_txt_analise(filename)
                
            else:
                print("❌ Opção inválida ou dados não disponíveis.")
                return
                
            print(f"✅ Relatório exportado com sucesso!")
            print(f"📁 Arquivo: {filename}")
            
        except Exception as e:
            print(f"❌ Erro ao exportar: {e}")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def exportar_json_captura(self, filename):
        """Exporta captura em JSON igual ao GUI"""
        if not self.dados_captura:
            return
        
        # Converter dados para formato serializável
        dados_serializaveis = []
        for dado in self.dados_captura:
            dado_serial = dado.copy()
            dado_serial['timestamp'] = dado['timestamp'].isoformat()
            dados_serializaveis.append(dado_serial)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(dados_serializaveis, f, indent=2, ensure_ascii=False)
    
    def exportar_csv_captura(self, filename):
        """Exporta captura em CSV igual ao GUI"""
        if not self.dados_captura:
            return
        
        df = pd.DataFrame(self.dados_captura)
        df.to_csv(filename, index=False, encoding='utf-8')
    
    def exportar_txt_analise(self, filename):
        """Exporta análise em TXT igual ao GUI"""
        if not self.arquivo_analisado:
            return
        
        resultado = self.analisar_arquivo(self.arquivo_analisado)
        if not resultado:
            return
        
        relatorio = f"""🚀 MELTTRÁFEGO - RELATÓRIO DE ANÁLISE
📅 Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
💻 Plataforma: {self.sistema}

📁 ARQUIVO ANALISADO:
   • Nome: {os.path.basename(resultado['arquivo'])}
   • Caminho: {resultado['arquivo']}
   • Tamanho: {resultado['tamanho_arquivo']:,} bytes
   • Linhas totais: {resultado['total_linhas']:,}

📊 ESTATÍSTICAS:
   • IPs únicos: {resultado['ips_unicos']}
   • Portas únicas: {resultado['portas_unicas']}

📈 DISTRIBUIÇÃO POR TIPO:
"""
        
        for tipo, quantidade in resultado['tipos_linhas'].items():
            percentual = (quantidade / resultado['total_linhas']) * 100
            relatorio += f"   • {tipo}: {quantidade} linhas ({percentual:.1f}%)\n"
        
        if resultado['lista_ips']:
            relatorio += f"\n🌐 PRIMEIROS {len(resultado['lista_ips'])} IPs ENCONTRADOS:\n"
            for ip in resultado['lista_ips']:
                relatorio += f"   • {ip}\n"
        
        relatorio += f"\n💡 OBSERVAÇÕES:\n"
        if resultado['ips_unicos'] > 100:
            relatorio += "   • ⚠️  Muitos IPs únicos podem indicar varredura de rede\n"
        if resultado['tipos_linhas'].get('TCP', 0) > resultado['total_linhas'] * 0.7:
            relatorio += "   • 📡 Alto volume TCP sugere muitas conexões estabelecidas\n"
        if resultado['tipos_linhas'].get('UDP', 0) > resultado['total_linhas'] * 0.5:
            relatorio += "   • 🎯 Alto volume UDP comum em DNS e streaming\n"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(relatorio)
    
    def obter_interfaces(self):
        """Obtém lista de interfaces disponíveis"""
        try:
            if self.sistema == "Windows":
                try:
                    from scapy.all import get_windows_if_list
                    interfaces = get_windows_if_list()
                    return [iface.get('name', '') for iface in interfaces if iface.get('name')]
                except:
                    return list(psutil.net_if_addrs().keys())
            else:
                return ["any"] + list(psutil.net_if_addrs().keys())
        except:
            return ["any"]
    
    def mostrar_status(self):
        """Mostra status do sistema"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📊 STATUS DO SISTEMA\n")
        
        try:
            # Informações da rede
            interfaces = psutil.net_io_counters(pernic=True)
            print("📡 ESTATÍSTICAS DE INTERFACES:")
            for interface, stats in interfaces.items():
                print(f"   • {interface}:")
                print(f"     ↑ Enviados: {stats.bytes_sent:,} bytes")
                print(f"     ↓ Recebidos: {stats.bytes_recv:,} bytes")
                print(f"     📦 Pacotes enviados: {stats.packets_sent:,}")
                print(f"     📦 Pacotes recebidos: {stats.packets_recv:,}")
            
            # Memória
            memoria = psutil.virtual_memory()
            print(f"\n💾 MEMÓRIA: {memoria.percent}% utilizada ({memoria.used//1024//1024}MB / {memoria.total//1024//1024}MB)")
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            print(f"⚡ CPU: {cpu_percent}% utilizada")
            
            # Load average (apenas Linux/Unix)
            if self.sistema != "Windows":
                load_avg = os.getloadavg()
                print(f"📊 Load Average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}")
            
            # Verificar permissões de captura
            if self.sistema == "Linux":
                import subprocess
                result = subprocess.run(['getcap', '$(which python3)'], capture_output=True, text=True, shell=True)
                if 'cap_net_raw' in result.stdout:
                    print("🔓 Permissões de captura: ✅ Configuradas")
                else:
                    print("🔓 Permissões de captura: ⚠️  Necessário sudo")
            elif self.sistema == "Windows":
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
                    winreg.CloseKey(key)
                    print("🔓 Npcap: ✅ Instalado")
                except:
                    print("🔓 Npcap: ❌ Não encontrado")
            
        except Exception as e:
            print(f"❌ Erro ao obter status: {e}")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def mostrar_info_plataforma(self):
        """Mostra informações da plataforma"""
        self.limpar_tela()
        self.cabecalho()
        print("\n💻 INFORMAÇÕES DA PLATAFORMA\n")
        
        print(f"Sistema: {platform.system()} {platform.release()}")
        print(f"Arquitetura: {platform.architecture()[0]}")
        print(f"Python: {platform.python_version()}")
        
        print(f"\n📦 DEPENDÊNCIAS:")
        print(f"Scapy: {'✅' if 'scapy' in sys.modules else '❌'}")
        print(f"Psutil: {'✅' if 'psutil' in sys.modules else '❌'}")
        print(f"Pandas: {'✅' if 'pandas' in sys.modules else '❌'}")
        
        print(f"\n💡 CONFIGURAÇÃO {self.sistema.upper()}:")
        if self.sistema == "Linux":
            print("• Requer tcpdump instalado")
            print("• Configure permissões: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3")
            print("• Ou execute com sudo")
        elif self.sistema == "Windows":
            print("• Requer Npcap instalado")
            print("• Download: https://npcap.com/#download")
            print("• Instale com opção 'WinPcap API-compatible Mode'")
            print("• Execute como Administrador se tiver problemas")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def limpar_dados_interativo(self):
        """Limpa dados com confirmação"""
        self.limpar_tela()
        self.cabecalho()
        print("\n🗑️ LIMPAR DADOS\n")
        
        tem_captura = bool(self.dados_captura)
        tem_analise = bool(self.arquivo_analisado)
        
        if not tem_captura and not tem_analise:
            print("✅ Nenhum dado para limpar.")
            input("\n📝 Pressione Enter para continuar...")
            return
        
        print("⚠️  Dados que serão removidos:")
        if tem_captura:
            print(f"   • 📦 Captura: {len(self.dados_captura)} pacotes")
        if tem_analise:
            print(f"   • 📁 Análise: {self.arquivo_analisado}")
        
        confirmacao = input("\n❓ Confirmar limpeza? (s/N): ").strip().lower()
        
        if confirmacao in ['s', 'sim', 'y', 'yes']:
            self.dados_captura = []
            self.estatisticas = {}
            self.arquivo_analisado = None
            print("✅ Todos os dados foram limpos!")
        else:
            print("ℹ️  Limpeza cancelada.")
        
        input("\n📝 Pressione Enter para continuar...")
    
    def modo_captura(self, interface, tempo, output=None):
        """Modo de captura via linha de comando"""
        print(f"🎯 Capturando tráfego na interface {interface} por {tempo}s...")
        
        if output:
            self.arquivo_captura = output
        
        self.capturar_trafego(tempo, interface)
        
        if self.dados_captura:
            self.estatisticas = self.analisar_dados()
            print(f"✅ Captura concluída! {len(self.dados_captura)} pacotes capturados.")
            
            # Salvar automaticamente igual ao GUI
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_json = f"{self.relatorios_dir}/relatorio_captura_{timestamp}.json"
            filename_csv = f"{self.relatorios_dir}/relatorio_captura_{timestamp}.csv"
            
            self.exportar_json_captura(filename_json)
            self.exportar_csv_captura(filename_csv)
            
            print(f"💾 Relatórios exportados:")
            print(f"   📄 {filename_json}")
            print(f"   📊 {filename_csv}")
        else:
            print("❌ Nenhum pacote capturado.")

def main():
    parser = argparse.ArgumentParser(
        description='MeltTrafego - Análise de Tráfego de Rede Multiplataforma',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Exemplos:
{sys.argv[0]} --interativo          # Modo menu interativo (RECOMENDADO)
{sys.argv[0]} --capturar eth0 -t 30 # Capturar 30s na eth0 (Linux)
{sys.argv[0]} --capturar "Ethernet" -t 30 # Capturar 30s no Windows
{sys.argv[0]} --analisar arquivo.log # Analisar arquivo específico
{sys.argv[0]} --interfaces          # Listar interfaces
{sys.argv[0]} --status              # Status do sistema

Desenvolvido para Windows e Linux
        '''
    )

    parser.add_argument('--interativo', action='store_true', help='Modo menu interativo (RECOMENDADO)')
    parser.add_argument('--capturar', type=str, help='Interface para captura')
    parser.add_argument('-t', '--tempo', type=int, default=30, help='Tempo de captura em segundos')
    parser.add_argument('-o', '--output', type=str, help='Arquivo de saída para captura')
    parser.add_argument('--analisar', type=str, help='Arquivo para análise')
    parser.add_argument('--interfaces', action='store_true', help='Listar interfaces')
    parser.add_argument('--status', action='store_true', help='Status do sistema')
    parser.add_argument('--plataforma', action='store_true', help='Informações da plataforma')

    args = parser.parse_args()

    analisador = MeltTrafegoCLI()

    try:
        if args.interativo:
            analisador.menu_interativo()
        elif args.capturar:
            analisador.modo_captura(args.capturar, args.tempo, args.output)
        elif args.analisar:
            resultado = analisador.analisar_arquivo(args.analisar)
            if resultado:
                analisador.mostrar_resultado_analise(resultado)
        elif args.interfaces:
            analisador.listar_interfaces()
        elif args.status:
            analisador.mostrar_status()
        elif args.plataforma:
            analisador.mostrar_info_plataforma()
        else:
            # Se nenhum argumento, mostrar ajuda
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n\n👋 Programa interrompido pelo usuário.")
    except Exception as e:
        print(f"❌ Erro: {e}")

if __name__ == "__main__":
    main()