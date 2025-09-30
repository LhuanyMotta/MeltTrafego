#!/usr/bin/env python3
"""
MeltTrafego - Núcleo do Sistema Linux
Análise de tráfego de rede com detecção de port scans
"""

import re
import csv
import json
import platform
import subprocess
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
import time

class MeltTrafegoCore:
    def __init__(self, janela_tempo=60, limite_portas=10):
        self.janela_tempo = janela_tempo
        self.limite_portas = limite_portas
        self.padrao_tcpdump = re.compile(
            r'^\s*(\d+\.\d+)\s+IP\s+([\d\.]+)\.(\d+)\s+>\s+[\d\.]+\.(\d+):'
        )
        self.sistema = platform.system()
        self._criar_diretorios()
        
    def _criar_diretorios(self):
        """Cria os diretórios necessários"""
        os.makedirs("relatorios", exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        os.makedirs("exemplos", exist_ok=True)
    
    def detectar_plataforma(self):
        """Detecta e retorna informações da plataforma"""
        return {
            'sistema': self.sistema,
            'arquitetura': platform.architecture()[0],
            'python_version': platform.python_version(),
            'kernel': platform.release()
        }
    
    def verificar_dependencias(self):
        """Verifica se as dependências estão instaladas"""
        dependencias = {
            'tcpdump': False,
            'python': True,
            'scapy': False,
            'psutil': False
        }
        
        try:
            # Verificar tcpdump
            resultado = subprocess.run(['which', 'tcpdump'], 
                                     capture_output=True, text=True)
            dependencias['tcpdump'] = resultado.returncode == 0
            
            # Verificar módulos Python
            import importlib
            dependencias['scapy'] = importlib.util.find_spec("scapy") is not None
            dependencias['psutil'] = importlib.util.find_spec("psutil") is not None
                
        except Exception:
            dependencias['tcpdump'] = False
            
        return dependencias
    
    def listar_interfaces(self):
        """Lista interfaces de rede disponíveis no Linux"""
        interfaces = []
        try:
            # Usar ip command para listar interfaces
            resultado = subprocess.run(['ip', 'addr', 'show'], 
                                     capture_output=True, text=True)
            
            if resultado.returncode == 0:
                linhas = resultado.stdout.split('\n')
                current_interface = None
                
                for linha in linhas:
                    linha = linha.strip()
                    if linha and not linha.startswith(' '):
                        # Nova interface
                        partes = linha.split(':')
                        if len(partes) >= 2:
                            current_interface = partes[1].strip()
                            interfaces.append(current_interface)
            
            # Fallback para ifconfig
            if not interfaces:
                resultado = subprocess.run(['ifconfig', '-a'], 
                                         capture_output=True, text=True)
                if resultado.returncode == 0:
                    for linha in resultado.stdout.split('\n'):
                        if linha and not linha.startswith(' '):
                            partes = linha.split(':')
                            if partes:
                                interface = partes[0].strip()
                                if interface and interface not in interfaces:
                                    interfaces.append(interface)
            
        except Exception as e:
            print(f"Erro ao listar interfaces: {e}")
            
        return interfaces
    
    def capturar_trafego(self, interface="any", tempo=60):
        """Captura tráfego usando tcpdump no Linux"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        arquivo_saida = f"relatorios/trafego_{interface}_{timestamp}.txt"
        
        try:
            comando = [
                'timeout', str(tempo),
                'tcpdump', '-i', interface, 
                '-nn', '-ttt', '-s0', 'ip'
            ]
            
            print(f"🎯 Capturando tráfego na interface {interface} por {tempo}s...")
            
            with open(arquivo_saida, 'w') as arquivo:
                processo = subprocess.Popen(comando, stdout=arquivo, stderr=subprocess.PIPE)
                _, stderr = processo.communicate()
                
            if processo.returncode != 0 and processo.returncode != 124:  # 124 é timeout
                print(f"⚠️  Aviso tcpdump: {stderr.decode()}")
            
            # Verificar se o arquivo foi criado e tem conteúdo
            if os.path.exists(arquivo_saida) and os.path.getsize(arquivo_saida) > 0:
                print(f"✅ Captura concluída: {arquivo_saida}")
                return arquivo_saida
            else:
                print("❌ Nenhum tráfego capturado.")
                return None
                
        except FileNotFoundError:
            print("❌ Erro: tcpdump não encontrado. Instale com:")
            print("   Ubuntu/Debian: sudo apt install tcpdump")
            print("   CentOS/RHEL: sudo yum install tcpdump")
            return None
        except Exception as e:
            print(f"❌ Erro na captura: {e}")
            return None
    
    def analisar_captura(self, arquivo_captura):
        """Analisa o arquivo de captura e detecta atividades suspeitas"""
        if not arquivo_captura or not os.path.exists(arquivo_captura):
            return None
        
        try:
            with open(arquivo_captura, 'r') as arquivo:
                linhas = arquivo.readlines()
            
            if not linhas:
                return None
            
            conexoes = []
            port_scan_candidates = defaultdict(lambda: defaultdict(set))
            
            for linha in linhas:
                linha = linha.strip()
                if not linha:
                    continue
                
                # Parse da linha do tcpdump
                match = self.padrao_tcpdump.match(linha)
                if match:
                    timestamp, ip_origem, porta_origem, porta_destino = match.groups()
                    
                    conexao = {
                        'timestamp': float(timestamp),
                        'ip_origem': ip_origem,
                        'porta_origem': int(porta_origem),
                        'porta_destino': int(porta_destino)
                    }
                    conexoes.append(conexao)
                    
                    # Agrupar por IP de origem e janela de tempo
                    janela = int(float(timestamp) / self.janela_tempo)
                    port_scan_candidates[ip_origem][janela].add(porta_destino)
            
            # Detectar port scans
            port_scans = []
            for ip_origem, janelas in port_scan_candidates.items():
                for janela, portas in janelas.items():
                    if len(portas) >= self.limite_portas:
                        port_scans.append({
                            'ip_origem': ip_origem,
                            'timestamp': janela * self.janela_tempo,
                            'portas_unicas': len(portas),
                            'portas': list(portas)[:20]  # Mostrar apenas as primeiras 20
                        })
            
            # Estatísticas gerais
            total_conexoes = len(conexoes)
            ips_unicos = len(set(c['ip_origem'] for c in conexoes))
            portas_unicas = len(set(c['porta_destino'] for c in conexoes))
            
            estatisticas = {
                'total_conexoes': total_conexoes,
                'ips_unicos': ips_unicos,
                'portas_unicas': portas_unicas,
                'port_scans_detectados': len(port_scans),
                'periodo_analise': self.janela_tempo,
                'limite_port_scan': self.limite_portas
            }
            
            resultado = {
                'estatisticas': estatisticas,
                'port_scans': port_scans,
                'conexoes_amostra': conexoes[:100],  # Amostra das primeiras conexões
                'timestamp_analise': datetime.now().isoformat()
            }
            
            return resultado
            
        except Exception as e:
            print(f"❌ Erro na análise: {e}")
            return None
    
    def gerar_relatorio(self, resultado_analise, formato='json'):
        """Gera relatório da análise"""
        if not resultado_analise:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if formato == 'json':
            arquivo_relatorio = f"relatorios/relatorio_{timestamp}.json"
            with open(arquivo_relatorio, 'w', encoding='utf-8') as f:
                json.dump(resultado_analise, f, indent=2, ensure_ascii=False)
        
        elif formato == 'csv':
            arquivo_relatorio = f"relatorios/relatorio_{timestamp}.csv"
            with open(arquivo_relatorio, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP Origem', 'Portas Únicas', 'Timestamp'])
                
                for scan in resultado_analise.get('port_scans', []):
                    writer.writerow([
                        scan['ip_origem'],
                        scan['portas_unicas'],
                        datetime.fromtimestamp(scan['timestamp']).isoformat()
                    ])
        
        return arquivo_relatorio
    
    def monitorar_tempo_real(self, interface="any", duracao=30):
        """Monitora tráfego em tempo real"""
        print(f"🔍 Monitorando {interface} por {duracao}s...")
        print("Pressione Ctrl+C para parar\n")
        
        try:
            comando = ['tcpdump', '-i', interface, '-nn', '-ttt', '-c', '50', 'ip']
            processo = subprocess.Popen(comando, stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE, text=True)
            
            inicio = time.time()
            contador = 0
            
            while time.time() - inicio < duracao:
                linha = processo.stdout.readline()
                if not linha:
                    break
                
                contador += 1
                print(f"{contador:3d}. {linha.strip()}")
                
                # Detectar padrões suspeitos em tempo real
                if 'S' in linha and 'F' not in linha:  # SYN sem FIN
                    print("   ⚠️  Possível SYN scan detectado")
                
            processo.terminate()
            print(f"\n✅ Monitoramento concluído. {contador} pacotes analisados.")
            
        except KeyboardInterrupt:
            print("\n⏹️  Monitoramento interrompido pelo usuário")
        except Exception as e:
            print(f"❌ Erro no monitoramento: {e}")

def main():
    """Função principal para testes"""
    analisador = MeltTrafegoCore()
    
    print("🔍 MeltTrafego Core - Teste de Funcionalidades")
    print("=" * 50)
    
    # Verificar plataforma
    plataforma = analisador.detectar_plataforma()
    print(f"📋 Plataforma: {plataforma['sistema']} {plataforma['kernel']}")
    
    # Verificar dependências
    dependencias = analisador.verificar_dependencias()
    print("📦 Dependências:")
    for dep, status in dependencias.items():
        print(f"   {dep}: {'✅' if status else '❌'}")
    
    # Listar interfaces
    interfaces = analisador.listar_interfaces()
    print(f"📡 Interfaces disponíveis: {interfaces}")
    
    if interfaces:
        # Capturar tráfego por 10 segundos
        arquivo = analisador.capturar_trafego(interfaces[0], 10)
        
        if arquivo:
            # Analisar captura
            resultado = analisador.analisar_captura(arquivo)
            
            if resultado:
                print(f"📊 Estatísticas:")
                print(f"   Total conexões: {resultado['estatisticas']['total_conexoes']}")
                print(f"   IPs únicos: {resultado['estatisticas']['ips_unicos']}")
                print(f"   Port scans detectados: {resultado['estatisticas']['port_scans_detectados']}")
                
                # Gerar relatório
                relatorio = analisador.gerar_relatorio(resultado)
                if relatorio:
                    print(f"📄 Relatório gerado: {relatorio}")
            else:
                print("❌ Nenhum dado para analisar")
    
    print("\n✅ Teste concluído!")

if __name__ == "__main__":
    main()