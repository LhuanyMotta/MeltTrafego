#!/usr/bin/env python3
"""
MeltTrafego - Núcleo Multiplataforma
"""

import platform
import subprocess
import os
import re
import csv
import json
from collections import defaultdict
from datetime import datetime

class MeltTrafegoCore:
    def __init__(self, janela_tempo=60, limite_portas=10):
        self.janela_tempo = janela_tempo
        self.limite_portas = limite_portas
        self.padrao_tcpdump = re.compile(
            r'^\s*(\d+\.\d+)\s+([\d\.]+)\.(\d+)\s+>\s+[\d\.]+\.(\d+):'
        )
        self.sistema = platform.system()
        
    def detectar_plataforma(self):
        """Detecta e retorna informações da plataforma"""
        return {
            'sistema': self.sistema,
            'arquitetura': platform.architecture()[0],
            'python_version': platform.python_version()
        }
    
    def verificar_dependencias(self):
        """Verifica se as dependências estão instaladas"""
        dependencias = {
            'tcpdump': False,
            'python': True
        }
        
        try:
            if self.sistema == "Windows":
                resultado = subprocess.run(['where', 'tcpdump'], 
                                         capture_output=True, text=True)
                dependencias['tcpdump'] = resultado.returncode == 0
            else:
                resultado = subprocess.run(['which', 'tcpdump'], 
                                         capture_output=True, text=True)
                dependencias['tcpdump'] = resultado.returncode == 0
                
        except Exception:
            dependencias['tcpdump'] = False
            
        return dependencias
    
    def listar_interfaces(self):
        """Lista interfaces de rede disponíveis"""
        if self.sistema == "Windows":
            return self._listar_interfaces_windows()
        else:
            return self._listar_interfaces_unix()
    
    def _listar_interfaces_windows(self):
        """Lista interfaces no Windows"""
        interfaces = []
        try:
            # Tentar usar PowerShell para listar interfaces
            comando = [
                'powershell', 
                '-Command', 
                'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, InterfaceDescription'
            ]
            resultado = subprocess.run(comando, capture_output=True, text=True, timeout=10)
            
            if resultado.returncode == 0:
                linhas = resultado.stdout.strip().split('\n')
                for i, linha in enumerate(linhas[3:]):  # Pular cabeçalho
                    if linha.strip():
                        partes = linha.split(' ', 1)
                        if partes and partes[0].strip():
                            nome = partes[0].strip()
                            interfaces.append({
                                'index': i,
                                'nome': nome,
                                'descricao': partes[1].strip() if len(partes) > 1 else nome
                            })
        except Exception as e:
            print(f"Erro ao listar interfaces Windows: {e}")
        
        # Fallback para interfaces comuns
        if not interfaces:
            interfaces = [
                {'index': 0, 'nome': 'Ethernet', 'descricao': 'Interface Ethernet'},
                {'index': 1, 'nome': 'Wi-Fi', 'descricao': 'Interface Wireless'},
                {'index': 2, 'nome': 'any', 'descricao': 'Todas as interfaces'}
            ]
            
        return interfaces
    
    def _listar_interfaces_unix(self):
        """Lista interfaces no Linux/macOS"""
        interfaces = []
        try:
            # Usar ip command (Linux moderno)
            resultado = subprocess.run(['ip', 'link', 'show'], 
                                     capture_output=True, text=True)
            if resultado.returncode == 0:
                linhas = resultado.stdout.split('\n')
                for linha in linhas:
                    if ':' in linha and 'LOOPBACK' not in linha:
                        partes = linha.split(':')
                        if len(partes) >= 2:
                            nome = partes[1].strip()
                            if nome and nome != 'lo':
                                interfaces.append({
                                    'index': len(interfaces),
                                    'nome': nome,
                                    'descricao': f'Interface {nome}'
                                })
            else:
                # Fallback para ifconfig
                resultado = subprocess.run(['ifconfig'], 
                                         capture_output=True, text=True)
                if resultado.returncode == 0:
                    linhas = resultado.stdout.split('\n')
                    for linha in linhas:
                        if 'flags=' in linha and 'LOOPBACK' not in linha:
                            partes = linha.split(':')
                            if partes:
                                nome = partes[0].strip()
                                interfaces.append({
                                    'index': len(interfaces),
                                    'nome': nome,
                                    'descricao': f'Interface {nome}'
                                })
        except Exception as e:
            print(f"Erro ao listar interfaces Unix: {e}")
        
        # Sempre incluir 'any'
        interfaces.append({'index': 999, 'nome': 'any', 'descricao': 'Todas as interfaces'})
        
        return interfaces
    
    def capturar_trafego(self, interface="any", tempo=60, arquivo_saida=None):
        """Captura tráfego de rede - Multiplataforma"""
        if not arquivo_saida:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            arquivo_saida = f"trafego_captura_{timestamp}.txt"
        
        if self.sistema == "Windows":
            return self._capturar_windows(interface, tempo, arquivo_saida)
        else:
            return self._capturar_unix(interface, tempo, arquivo_saida)
    
    def _capturar_windows(self, interface, tempo, arquivo_saida):
        """Captura tráfego no Windows"""
        try:
            # Verificar se tcpdump está disponível
            dependencias = self.verificar_dependencias()
            
            if dependencias['tcpdump']:
                # Usar tcpdump do Npcap
                comando = f'tcpdump -i {interface} -W 1 -G {tempo} -w "{arquivo_saida}.pcap"'
                processo = subprocess.Popen(comando, shell=True)
                
                try:
                    processo.wait(timeout=tempo + 5)
                    
                    # Converter para texto
                    if os.path.exists(f"{arquivo_saida}.pcap"):
                        comando_convert = f'tcpdump -nn -ttt -r "{arquivo_saida}.pcap" ip > "{arquivo_saida}"'
                        subprocess.run(comando_convert, shell=True, timeout=30)
                        os.remove(f"{arquivo_saida}.pcap")
                        
                        if os.path.exists(arquivo_saida):
                            return arquivo_saida, True, "Captura concluída com sucesso"
                
                except subprocess.TimeoutExpired:
                    processo.kill()
                    return arquivo_saida, False, "Timeout na captura"
            
            # Fallback para dados de exemplo
            return self._gerar_dados_exemplo(arquivo_saida)
            
        except Exception as e:
            return arquivo_saida, False, f"Erro na captura Windows: {e}"
    
    def _capturar_unix(self, interface, tempo, arquivo_saida):
        """Captura tráfego no Linux/macOS"""
        try:
            comando = f"timeout {tempo} tcpdump -i {interface} -nn -ttt ip"
            
            with open(arquivo_saida, 'w') as f:
                processo = subprocess.Popen(
                    comando.split(),
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )
                processo.wait()
            
            # Verificar se o arquivo foi criado e tem conteúdo
            if os.path.exists(arquivo_saida) and os.path.getsize(arquivo_saida) > 0:
                return arquivo_saida, True, "Captura concluída com sucesso"
            else:
                return arquivo_saida, False, "Nenhum dado capturado"
                
        except FileNotFoundError:
            return arquivo_saida, False, "tcpdump não encontrado. Instale com: sudo apt install tcpdump"
        except Exception as e:
            return arquivo_saida, False, f"Erro na captura: {e}"
    
    def _gerar_dados_exemplo(self, arquivo_saida):
        """Gera dados de exemplo para demonstração"""
        try:
            exemplos = [
                "0.000000 192.168.1.100.54321 > 8.8.8.8.53: UDP",
                "1.234567 192.168.1.100.54322 > 1.1.1.1.53: UDP", 
                "2.345678 192.168.1.101.443 > 192.168.1.1.80: TCP",
                "3.456789 10.0.0.15.12345 > 192.168.1.1.22: TCP",
                "4.567890 10.0.0.15.12346 > 192.168.1.1.443: TCP",
                "5.678901 10.0.0.15.12347 > 192.168.1.1.80: TCP",
                "6.789012 10.0.0.15.12348 > 192.168.1.1.21: TCP",
                "7.890123 10.0.0.15.12349 > 192.168.1.1.23: TCP",
                "8.901234 10.0.0.15.12350 > 192.168.1.1.25: TCP",
                "9.012345 10.0.0.15.12351 > 192.168.1.1.110: TCP",
                "10.123456 10.0.0.15.12352 > 192.168.1.1.143: TCP",
                "11.234567 10.0.0.15.12353 > 192.168.1.1.993: TCP",
                "12.345678 203.0.113.45.45678 > 192.168.1.1.3389: TCP"
            ]
            
            with open(arquivo_saida, 'w') as f:
                f.write("\n".join(exemplos))
            
            return arquivo_saida, True, "Dados de exemplo gerados (modo demonstração)"
            
        except Exception as e:
            return arquivo_saida, False, f"Erro ao gerar dados exemplo: {e}"
    
    def parse_trafego(self, arquivo_entrada):
        """Parseia arquivo de tráfego do tcpdump"""
        eventos = []
        estatisticas = {
            'linhas_processadas': 0,
            'linhas_invalidas': 0,
            'ips_unicos': set(),
            'portas_unicas': set(),
            'erro': None
        }
        
        try:
            with open(arquivo_entrada, 'r', encoding='utf-8', errors='ignore') as file:
                for linha in file:
                    linha = linha.strip()
                    if not linha:
                        continue
                    
                    match = self.padrao_tcpdump.match(linha)
                    if match:
                        timestamp = float(match.group(1))
                        ip_origem = match.group(2)
                        porta_destino = int(match.group(4))
                        
                        eventos.append((timestamp, ip_origem, porta_destino))
                        estatisticas['linhas_processadas'] += 1
                        estatisticas['ips_unicos'].add(ip_origem)
                        estatisticas['portas_unicas'].add(porta_destino)
                    else:
                        estatisticas['linhas_invalidas'] += 1
            
            estatisticas['total_ips'] = len(estatisticas['ips_unicos'])
            estatisticas['total_portas'] = len(estatisticas['portas_unicas'])
            
        except FileNotFoundError:
            estatisticas['erro'] = f"Arquivo não encontrado: {arquivo_entrada}"
        except Exception as e:
            estatisticas['erro'] = f"Erro ao processar arquivo: {e}"
        
        return eventos, estatisticas
    
    def analisar_comportamento(self, eventos):
        """Analisa comportamento de rede e detecta port scans"""
        contagem_total = defaultdict(int)
        portas_por_ip = defaultdict(set)
        eventos_por_ip = defaultdict(list)
        alertas = []
        
        # Coletar dados básicos
        for timestamp, ip, porta in eventos:
            contagem_total[ip] += 1
            portas_por_ip[ip].add(porta)
            eventos_por_ip[ip].append((timestamp, porta))
        
        # Detectar port scans
        port_scans = {}
        
        for ip, portas in portas_por_ip.items():
            total_portas = len(portas)
            
            # Detecção baseada em total de portas
            if total_portas > self.limite_portas:
                port_scans[ip] = True
                alertas.append({
                    'ip': ip,
                    'tipo': 'PORT_SCAN',
                    'severidade': 'ALTA',
                    'mensagem': f'IP conectou a {total_portas} portas diferentes',
                    'timestamp': datetime.now()
                })
                continue
            
            # Detecção temporal
            eventos_ip = eventos_por_ip[ip]
            if len(eventos_ip) > 1:
                eventos_ip.sort()
                port_scans[ip] = False
                
                for i in range(len(eventos_ip)):
                    portas_janela = set()
                    timestamp_inicio = eventos_ip[i][0]
                    
                    for j in range(i, len(eventos_ip)):
                        if eventos_ip[j][0] - timestamp_inicio <= self.janela_tempo:
                            portas_janela.add(eventos_ip[j][1])
                        else:
                            break
                        
                        if len(portas_janela) > self.limite_portas:
                            port_scans[ip] = True
                            alertas.append({
                                'ip': ip,
                                'tipo': 'PORT_SCAN_TEMPORAL',
                                'severidade': 'MEDIA',
                                'mensagem': f'IP conectou a {len(portas_janela)} portas em {self.janela_tempo}s',
                                'timestamp': datetime.now()
                            })
                            break
                    
                    if port_scans[ip]:
                        break
                
                if not port_scans[ip]:
                    port_scans[ip] = False
            else:
                port_scans[ip] = False
        
        return contagem_total, port_scans, portas_por_ip, alertas
    
    def gerar_relatorio_csv(self, contagem_total, port_scans, portas_por_ip, arquivo_saida):
        """Gera relatório em formato CSV"""
        try:
            with open(arquivo_saida, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['IP', 'Total_Eventos', 'Portas_Unicas', 'Detectado_PortScan', 'Severidade'])
                
                for ip in sorted(contagem_total.keys()):
                    total = contagem_total[ip]
                    portas_unicas = len(portas_por_ip.get(ip, set()))
                    portscan = 'Sim' if port_scans.get(ip, False) else 'Não'
                    severidade = 'ALTA' if portscan == 'Sim' else 'BAIXA'
                    writer.writerow([ip, total, portas_unicas, portscan, severidade])
            
            return True, f"Relatório CSV gerado: {arquivo_saida}"
        except Exception as e:
            return False, f"Erro ao gerar CSV: {e}"
    
    def gerar_relatorio_json(self, dados, arquivo_saida):
        """Gera relatório em formato JSON"""
        try:
            relatorio = {
                'metadata': {
                    'gerado_em': datetime.now().isoformat(),
                    'sistema': 'MeltTrafego',
                    'versao': '1.0',
                    'plataforma': self.sistema
                },
                'estatisticas': {
                    'total_ips': len(dados['contagem_total']),
                    'total_eventos': sum(dados['contagem_total'].values()),
                    'port_scans_detectados': sum(1 for ip in dados['port_scans'] if dados['port_scans'][ip])
                },
                'detalhes': []
            }
            
            for ip in sorted(dados['contagem_total'].keys()):
                relatorio['detalhes'].append({
                    'ip': ip,
                    'total_eventos': dados['contagem_total'][ip],
                    'portas_unicas': len(dados['portas_por_ip'].get(ip, set())),
                    'port_scan_detectado': dados['port_scans'].get(ip, False),
                    'severidade': 'ALTA' if dados['port_scans'].get(ip, False) else 'BAIXA'
                })
            
            with open(arquivo_saida, 'w', encoding='utf-8') as f:
                json.dump(relatorio, f, indent=2, ensure_ascii=False)
            
            return True, f"Relatório JSON gerado: {arquivo_saida}"
        except Exception as e:
            return False, f"Erro ao gerar JSON: {e}"
    
    def obter_estatisticas(self, eventos, contagem_total, port_scans):
        """Retorna estatísticas completas da análise"""
        total_eventos = len(eventos)
        total_ips = len(contagem_total)
        port_scans_count = sum(1 for ip in port_scans if port_scans[ip])
        
        top_ips = sorted(contagem_total.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_eventos': total_eventos,
            'total_ips': total_ips,
            'port_scans_detectados': port_scans_count,
            'ips_normais': total_ips - port_scans_count,
            'top_ips': top_ips,
            'timestamp_analise': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'plataforma': self.sistema
        }