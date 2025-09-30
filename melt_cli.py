#!/usr/bin/env python3
"""
MeltTrafego - Analisador de Tráfego Linux (Sem necessidade de sudo)
"""

import os
import sys
import time
import platform

# Adicionar ambiente virtual ao path
venv_path = os.path.join(os.path.dirname(__file__), 'melt_venv')
if os.path.exists(venv_path):
    sys.path.insert(0, os.path.join(venv_path, 'lib', f'python{sys.version_info.major}.{sys.version_info.minor}', 'site-packages'))

# Tentar importar dependências
try:
    import psutil
    import pandas as pd
except ImportError as e:
    print(f"❌ Erro: {e}")
    print("💡 Execute: pip install psutil pandas")
    sys.exit(1)

# Scapy é opcional
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy não disponível. Modo de demonstração ativado.")

class MeltTrafegoCLI:
    def __init__(self):
        self.dados_captura = []
        self.scapy_disponivel = SCAPY_AVAILABLE
        
    def cabecalho(self):
        print("\n" + "="*50)
        print("🚀  MELTTRÁFEGO - ANALISADOR DE REDE LINUX")
        print("🔒  Versão sem necessidade de sudo")
        print("="*50)
        
        if not self.scapy_disponivel:
            print("🎭  MODO DEMONSTRAÇÃO ATIVADO")
            print("💡  Para captura real: pip install scapy")
    
    def menu_principal(self):
        """Menu principal simplificado"""
        while True:
            self.cabecalho()
            print("\n1️⃣  Listar interfaces de rede")
            print("2️⃣  Monitorar tráfego (modo demo)")
            print("3️⃣  Estatísticas do sistema")
            print("4️⃣  Verificar dependências")
            print("5️⃣  Sair")
            
            opcao = input("\n📋 Escolha uma opção (1-5): ").strip()
            
            if opcao == "1":
                self.listar_interfaces()
            elif opcao == "2":
                self.monitorar_demo()
            elif opcao == "3":
                self.estatisticas_sistema()
            elif opcao == "4":
                self.verificar_dependencias()
            elif opcao == "5":
                print("\n👋 Saindo...")
                break
            else:
                print("\n❌ Opção inválida!")
                time.sleep(1)
    
    def listar_interfaces(self):
        """Lista interfaces de rede"""
        print("\n📡 INTERFACES DE REDE:\n")
        try:
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                print(f"🔹 {interface}:")
                for addr in addrs:
                    if addr.family == 2:  # IPv4
                        print(f"   📍 IPv4: {addr.address}")
                    elif addr.family == 10:  # IPv6
                        print(f"   📍 IPv6: {addr.address}")
                print()
        except Exception as e:
            print(f"❌ Erro: {e}")
        
        input("📝 Enter para continuar...")
    
    def monitorar_demo(self):
        """Monitoramento com dados de demonstração"""
        print("\n🎭 INICIANDO MODO DEMONSTRAÇÃO (30s)")
        print("📦 Gerando tráfego de exemplo...\n")
        
        import random
        from datetime import datetime
        
        contadores = {'total': 0, 'tcp': 0, 'udp': 0}
        inicio = time.time()
        
        try:
            while time.time() - inicio < 30:
                # Gerar pacote fake
                tipos = ['TCP', 'UDP', 'ICMP']
                tipo = random.choice(tipos)
                contadores['total'] += 1
                contadores[tipo.lower()] += 1
                
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"{timestamp} | {tipo} | 192.168.1.{random.randint(1,100)} → 8.8.8.8 | {random.randint(64,1500)}B")
                
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print("\n⏹️  Interrompido pelo usuário")
        
        print(f"\n📊 RESUMO:")
        print(f"   📦 Total: {contadores['total']} pacotes")
        print(f"   🔗 TCP: {contadores['tcp']}")
        print(f"   📨 UDP: {contadores['udp']}")
        print(f"   🎭 Modo demonstração")
        
        input("\n📝 Enter para continuar...")
    
    def estatisticas_sistema(self):
        """Mostra estatísticas do sistema"""
        print("\n💻 ESTATÍSTICAS DO SISTEMA:\n")
        
        try:
            # Rede
            io = psutil.net_io_counters()
            print(f"📡 REDE:")
            print(f"   ↑ Enviados: {io.bytes_sent:,} bytes")
            print(f"   ↓ Recebidos: {io.bytes_recv:,} bytes")
            
            # Memória
            mem = psutil.virtual_memory()
            print(f"\n💾 MEMÓRIA: {mem.percent}%")
            print(f"   Usada: {mem.used//1024//1024}MB")
            print(f"   Total: {mem.total//1024//1024}MB")
            
            # CPU
            cpu = psutil.cpu_percent(interval=1)
            print(f"\n⚡ CPU: {cpu}%")
            
            # Load average
            load = os.getloadavg()
            print(f"📊 Load: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}")
            
        except Exception as e:
            print(f"❌ Erro: {e}")
        
        input("\n📝 Enter para continuar...")
    
    def verificar_dependencias(self):
        """Verifica dependências instaladas"""
        print("\n📦 VERIFICAÇÃO DE DEPENDÊNCIAS:\n")
        
        dependencias = {
            'psutil': False,
            'pandas': False,
            'scapy': False
        }
        
        try:
            import psutil
            dependencias['psutil'] = True
        except ImportError:
            pass
            
        try:
            import pandas
            dependencias['pandas'] = True
        except ImportError:
            pass
            
        try:
            import scapy
            dependencias['scapy'] = True
        except ImportError:
            pass
        
        for dep, status in dependencias.items():
            print(f"   {dep}: {'✅' if status else '❌'}")
        
        print(f"\n🔧 Scapy: {'Captura real disponível' if dependencias['scapy'] else 'Modo demonstração'}")
        
        input("\n📝 Enter para continuar...")

def main():
    """Função principal"""
    if platform.system() != "Linux":
        print("❌ Este software foi desenvolvido para Linux")
        return
    
    # Verificar se não está sendo executado como root
    if os.geteuid() == 0:
        print("❌ Não execute como root/sudo!")
        print("💡 Execute como usuário normal")
        return
    
    app = MeltTrafegoCLI()
    app.menu_principal()

if __name__ == "__main__":
    main()