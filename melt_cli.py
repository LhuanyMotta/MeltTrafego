#!/usr/bin/env python3
"""
MeltTrafego - Analisador de Tráfego de Rede Multiplataforma
Versão CLI Melhorada (adaptada para Linux)
"""

import os
import sys
import time
import json
import threading
import argparse
import socket
from datetime import datetime
import psutil

# scapy imports
try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP, ICMP
except Exception:
    # Import error will be raised at runtime if scapy not installed
    sniff = None
    IP = TCP = UDP = ICMP = None

import pandas as pd

# Corrigir encoding no Windows (mantido, mas não relevante para Linux)
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)


class MeltTrafegoCLI:
    def __init__(self):
        self.dados_captura = []
        self.estatisticas = {}
        self.interface_atual = None
        self.captura_ativa = False
        self.arquivo_captura = None
        self.mostrar_tempo_real = False

    def limpar_tela(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def cabecalho(self):
        print("\n" + "=" * 50)
        print("🚀  MELTTRÁFEGO - ANALISADOR DE REDE  🌐")
        print("=" * 50)

    def menu_interativo(self):
        """Modo interativo com menu"""
        while True:
            self.limpar_tela()
            self.cabecalho()
            print("\n1️⃣  Listar interfaces disponíveis")
            print("2️⃣  Monitorar tráfego (30s) - Tempo Real")
            print("3️⃣  Análise completa (60s captura + relatório)")
            print("4️⃣  Estatísticas do último relatório")
            print("5️⃣  Exportar relatório completo")
            print("6️⃣  Sair")

            opcao = input("\n📋 Digite o número da opção (1-6): ").strip()

            if opcao == "1":
                self.listar_interfaces()
            elif opcao == "2":
                self.monitorar_tempo_real()
            elif opcao == "3":
                self.analise_completa()
            elif opcao == "4":
                self.mostrar_estatisticas()
            elif opcao == "5":
                self.exportar_relatorio()
            elif opcao == "6":
                print("\n👋 Saindo do MeltTrafego... Até logo!")
                break
            else:
                print("\n❌ Opção inválida! Tente novamente.")
                time.sleep(2)

    def listar_interfaces(self):
        """Lista todas as interfaces de rede disponíveis"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📡 INTERFACES DE REDE DISPONÍVEIS:\n")

        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for i, (interface, addrs) in enumerate(interfaces.items(), 1):
                status = "✅ ATIVA" if interface in stats and stats[interface].isup else "❌ INATIVA"
                print(f"{i}. {interface} - {status}")

                # Mostrar endereços IP
                for addr in addrs:
                    if addr.family == socket.AF_INET:  # IPv4
                        print(f"   📍 IPv4: {addr.address}")
                    elif addr.family == socket.AF_INET6:  # IPv6
                        print(f"   📍 IPv6: {addr.address}")
                print()

        except Exception as e:
            print(f"❌ Erro ao listar interfaces: {e}")

        input("\n📝 Pressione Enter para continuar...")

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
        if IP and pacote.haslayer(IP):
            info['ip_origem'] = pacote[IP].src
            info['ip_destino'] = pacote[IP].dst
            info['protocolo'] = pacote[IP].proto

            if pacote.haslayer(TCP):
                info['porta_origem'] = int(pacote[TCP].sport)
                info['porta_destino'] = int(pacote[TCP].dport)
                info['tipo'] = 'TCP'
            elif pacote.haslayer(UDP):
                info['porta_origem'] = int(pacote[UDP].sport)
                info['porta_destino'] = int(pacote[UDP].dport)
                info['tipo'] = 'UDP'
            elif pacote.haslayer(ICMP):
                info['tipo'] = 'ICMP'
            else:
                info['tipo'] = 'Outro'
        else:
            info['tipo'] = 'Não-IP'

        self.dados_captura.append(info)

        # Mostrar pacote em tempo real se estiver no modo monitoramento
        if self.mostrar_tempo_real:
            print(f"📦 {timestamp.strftime('%H:%M:%S')} | {info['tipo']} | {info.get('ip_origem', 'N/A')} → {info.get('ip_destino', 'N/A')} | {info['tamanho']} bytes")

    def capturar_trafego(self, duracao, interface=None):
        """Captura tráfego por um período determinado"""
        if sniff is None:
            print("❌ Scapy não disponível. Instale com: pip install scapy")
            return

        self.dados_captura = []
        self.captura_ativa = True

        print(f"\n🎯 Capturando tráfego por {duracao} segundos...")

        # Thread para parar captura após o tempo
        def parar_captura():
            time.sleep(duracao)
            self.captura_ativa = False

        thread_parada = threading.Thread(target=parar_captura)
        thread_parada.start()

        try:
            # Captura pacotes
            if interface:
                sniff(prn=self.processar_pacote, timeout=duracao, iface=interface)
            else:
                sniff(prn=self.processar_pacote, timeout=duracao)

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
            'total_pacotes': int(len(df)),
            'periodo_captura': {
                'inicio': df['timestamp'].min(),
                'fim': df['timestamp'].max(),
                'duracao': (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            },
            'tamanho_pacotes': {
                'total_bytes': int(df['tamanho'].sum()),
                'media_bytes': float(df['tamanho'].mean()),
                'maior_pacote': int(df['tamanho'].max()),
                'menor_pacote': int(df['tamanho'].min())
            },
            'tipos_trafego': df['tipo'].value_counts().to_dict(),
            'top_ips_origem': df['ip_origem'].value_counts().head(5).to_dict() if 'ip_origem' in df.columns else {},
            'top_ips_destino': df['ip_destino'].value_counts().head(5).to_dict() if 'ip_destino' in df.columns else {},
            'top_portas': {}
        }

        # Estatísticas de portas se disponíveis
        if 'porta_origem' in df.columns:
            estatisticas['top_portas']['origem'] = df['porta_origem'].value_counts().head(5).to_dict()
        if 'porta_destino' in df.columns:
            estatisticas['top_portas']['destino'] = df['porta_destino'].value_counts().head(5).to_dict()

        return estatisticas

    def monitorar_tempo_real(self):
        """Monitora tráfego em tempo real por 30 segundos"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📊 MODO MONITORAMENTO TEMPO REAL (30s)\n")
        print("📦 Mostrando pacotes em tempo real...\n")

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

    def analise_completa(self):
        """Realiza análise completa por 60 segundos"""
        self.limpar_tela()
        self.cabecalho()
        print("\n🔍 ANÁLISE COMPLETA (60s)\n")

        try:
            print("⏳ Iniciando captura de 60 segundos...")
            self.capturar_trafego(60)
            print("📈 Analisando dados capturados...")
            self.estatisticas = self.analisar_dados()

            if self.estatisticas:
                print("\n✅ Análise concluída!")
                self.mostrar_estatisticas(aguardar=False)
            else:
                print("\n❌ Nenhum dado foi capturado durante a análise.")

        except Exception as e:
            print(f"❌ Erro na análise completa: {e}")

        input("\n📝 Pressione Enter para continuar...")

    def mostrar_estatisticas(self, aguardar=True):
        """Mostra estatísticas do último relatório"""
        self.limpar_tela()
        self.cabecalho()
        print("\n📈 ESTATÍSTICAS DO ÚLTIMO RELATÓRIO\n")

        if not self.estatisticas:
            print("❌ Nenhum relatório disponível. Execute uma captura primeiro.")
            if aguardar:
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

        if aguardar:
            input("\n📝 Pressione Enter para continuar...")

    def exportar_relatorio(self):
        """Exporta relatório completo para arquivo"""
        self.limpar_tela()
        self.cabecalho()
        print("\n💾 EXPORTAR RELATÓRIO\n")

        if not self.estatisticas:
            print("❌ Nenhum relatório disponível para exportar.")
            input("\n📝 Pressione Enter para continuar...")
            return

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"relatorio_trafego_{timestamp}"

            # Exportar como JSON
            with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                json.dump(self.estatisticas, f, indent=2, default=str)

            # Exportar como CSV se houver dados
            if self.dados_captura:
                df = pd.DataFrame(self.dados_captura)
                df.to_csv(f"{filename}.csv", index=False, encoding='utf-8')

            print(f"✅ Relatório exportado com sucesso!")
            print(f"📁 Arquivos criados:")
            print(f"   • {filename}.json")
            if self.dados_captura:
                print(f"   • {filename}.csv")

        except Exception as e:
            print(f"❌ Erro ao exportar relatório: {e}")

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

            # Salvar automaticamente
            if not output:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output = f"captura_{interface}_{timestamp}"

            self.salvar_captura(output)
        else:
            print("❌ Nenhum pacote capturado.")

    def salvar_captura(self, filename):
        """Salva a captura atual"""
        try:
            # Salvar dados brutos
            with open(f"{filename}_dados.json", 'w', encoding='utf-8') as f:
                # Converter timestamps para string
                dados_serializaveis = []
                for dado in self.dados_captura:
                    dado_serial = dado.copy()
                    dado_serial['timestamp'] = dado['timestamp'].isoformat()
                    dados_serializaveis.append(dado_serial)
                json.dump(dados_serializaveis, f, indent=2)

            # Salvar estatísticas
            with open(f"{filename}_estatisticas.json", 'w', encoding='utf-8') as f:
                json.dump(self.estatisticas, f, indent=2, default=str)

            print(f"💾 Captura salva como: {filename}_dados.json e {filename}_estatisticas.json")

        except Exception as e:
            print(f"❌ Erro ao salvar captura: {e}")

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
            print(f"\n💾 MEMÓRIA: {memoria.percent}% utilizada")

            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            print(f"⚡ CPU: {cpu_percent}% utilizada")

        except Exception as e:
            print(f"❌ Erro ao obter status: {e}")

        input("\n📝 Pressione Enter para continuar...")


def main():
    parser = argparse.ArgumentParser(
        description='MeltTrafego - Análise de Tráfego de Rede Multiblataforma',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Exemplos:
{sys.argv[0]} --interativo          # Modo menu interativo
{sys.argv[0]} --capturar eth0 -t 30 # Capturar 30s na eth0
{sys.argv[0]} --interfaces          # Listar interfaces
{sys.argv[0]} --status              # Status do sistema
{sys.argv[0]} --capturar wlan0 -t 60 -o minha_captura

Desenvolvido para Windows, Linux e macOS
        '''
    )

    parser.add_argument('--interativo', action='store_true', help='Modo menu interativo')
    parser.add_argument('--capturar', type=str, help='Interface para captura')
    parser.add_argument('-t', '--tempo', type=int, default=30, help='Tempo de captura em segundos')
    parser.add_argument('-o', '--output', type=str, help='Arquivo de saída para captura')
    parser.add_argument('--interfaces', action='store_true', help='Listar interfaces')
    parser.add_argument('--status', action='store_true', help='Status do sistema')

    args = parser.parse_args()

    analisador = MeltTrafegoCLI()

    try:
        if args.interativo:
            analisador.menu_interativo()
        elif args.capturar:
            analisador.modo_captura(args.capturar, args.tempo, args.output)
        elif args.interfaces:
            analisador.listar_interfaces()
        elif args.status:
            analisador.mostrar_status()
        else:
            # Se nenhum argumento, mostrar ajuda
            parser.print_help()

    except KeyboardInterrupt:
        print("\n\n👋 Programa interrompido pelo usuário.")
    except Exception as e:
        print(f"❌ Erro: {e}")


if __name__ == "__main__":
    main()
