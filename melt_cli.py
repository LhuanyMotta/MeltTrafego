#!/usr/bin/env python3
"""
MeltTrafego - Interface de Linha de Comando Multiplataforma
"""

import argparse
import sys
import os
from datetime import datetime
from melt_platform import MeltTrafegoCore

def main():
    parser = argparse.ArgumentParser(
        description='MeltTrafego - Análise de Tráfego de Rede Multiplataforma',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Exemplos:
  {sys.argv[0]} capturar -i eth0 -t 30
  {sys.argv[0]} analisar trafego.txt -o relatorio.csv
  {sys.argv[0]} completo -i any -t 60 --formato json
  {sys.argv[0]} interfaces
  {sys.argv[0]} status
        '''
    )
    
    subparsers = parser.add_subparsers(dest='comando', help='Comando a executar')
    
    # Parser para captura
    captura_parser = subparsers.add_parser('capturar', help='Capturar tráfego de rede')
    captura_parser.add_argument('-i', '--interface', default='any', help='Interface de rede')
    captura_parser.add_argument('-t', '--tempo', type=int, default=60, help='Tempo de captura em segundos')
    captura_parser.add_argument('-o', '--output', help='Arquivo de saída')
    
    # Parser para análise
    analise_parser = subparsers.add_parser('analisar', help='Analisar arquivo de tráfego')
    analise_parser.add_argument('arquivo', help='Arquivo de tráfego para analisar')
    analise_parser.add_argument('-o', '--output', help='Arquivo de saída')
    analise_parser.add_argument('-f', '--formato', choices=['csv', 'json'], default='csv', help='Formato do relatório')
    analise_parser.add_argument('--janela-tempo', type=int, default=60, help='Janela temporal para análise')
    analise_parser.add_argument('--limite-portas', type=int, default=10, help='Limite de portas para detecção')
    
    # Parser para modo completo
    completo_parser = subparsers.add_parser('completo', help='Capturar e analisar automaticamente')
    completo_parser.add_argument('-i', '--interface', default='any', help='Interface de rede')
    completo_parser.add_argument('-t', '--tempo', type=int, default=60, help='Tempo de captura em segundos')
    completo_parser.add_argument('-o', '--output', help='Arquivo de saída')
    completo_parser.add_argument('-f', '--formato', choices=['csv', 'json'], default='csv', help='Formato do relatório')
    
    # Parser para listar interfaces
    subparsers.add_parser('interfaces', help='Listar interfaces de rede disponíveis')
    
    # Parser para status do sistema
    subparsers.add_parser('status', help='Verificar status e dependências do sistema')
    
    args = parser.parse_args()
    
    if not args.comando:
        parser.print_help()
        sys.exit(1)
    
    # Inicializar núcleo
    melt = MeltTrafegoCore()
    
    try:
        if args.comando == 'capturar':
            print("🔍 MeltTrafego - Iniciando captura...")
            print(f"📡 Plataforma: {melt.sistema}")
            print(f"🔧 Interface: {args.interface}")
            print(f"⏱️  Tempo: {args.tempo} segundos")
            
            arquivo, sucesso, mensagem = melt.capturar_trafego(
                args.interface, 
                args.tempo, 
                args.output
            )
            
            if sucesso:
                print(f"✅ {mensagem}")
                print(f"📁 Arquivo: {arquivo}")
            else:
                print(f"❌ {mensagem}")
                sys.exit(1)
                
        elif args.comando == 'analisar':
            print(f"📊 MeltTrafego - Analisando {args.arquivo}...")
            print(f"📡 Plataforma: {melt.sistema}")
            
            # Configurar parâmetros
            melt.janela_tempo = args.janela_tempo
            melt.limite_portas = args.limite_portas
            
            # Parsear e analisar
            eventos, stats = melt.parse_trafego(args.arquivo)
            
            if stats.get('erro'):
                print(f"❌ {stats['erro']}")
                sys.exit(1)
                
            if not eventos:
                print(f"❌ Nenhum evento válido encontrado em {args.arquivo}")
                sys.exit(1)
            
            print(f"✅ {stats['linhas_processadas']} eventos processados")
            print(f"🌐 {stats['total_ips']} IPs únicos encontrados")
            print(f"🔢 {stats['total_portas']} portas únicas detectadas")
            
            contagem_total, port_scans, portas_por_ip, alertas = melt.analisar_comportamento(eventos)
            
            # Gerar relatório
            if not args.output:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                args.output = f"relatorio_melt_{timestamp}.{args.formato}"
            
            if args.formato == 'csv':
                sucesso, mensagem = melt.gerar_relatorio_csv(contagem_total, port_scans, portas_por_ip, args.output)
            else:
                dados = {
                    'contagem_total': contagem_total,
                    'port_scans': port_scans,
                    'portas_por_ip': portas_por_ip
                }
                sucesso, mensagem = melt.gerar_relatorio_json(dados, args.output)
            
            if not sucesso:
                print(f"❌ {mensagem}")
                sys.exit(1)
            
            # Estatísticas
            stats_finais = melt.obter_estatisticas(eventos, contagem_total, port_scans)
            
            print(f"\n📈 RELATÓRIO FINAL:")
            print(f"📄 {mensagem}")
            print(f"🔢 Total de eventos: {stats_finais['total_eventos']}")
            print(f"🌐 IPs analisados: {stats_finais['total_ips']}")
            print(f"⚠️  Port scans detectados: {stats_finais['port_scans_detectados']}")
            print(f"✅ IPs normais: {stats_finais['ips_normais']}")
            
            if alertas:
                print(f"\n🚨 ALERTAS DETECTADOS:")
                for alerta in alertas:
                    print(f"   • {alerta['ip']}: {alerta['mensagem']}")
                    
        elif args.comando == 'completo':
            print("🚀 MeltTrafego - Modo Completo (Captura + Análise)")
            print(f"📡 Plataforma: {melt.sistema}")
            
            # Capturar
            arquivo_captura, sucesso, mensagem = melt.capturar_trafego(
                args.interface, 
                args.tempo
            )
            
            if not sucesso:
                print(f"❌ {mensagem}")
                sys.exit(1)
            
            print(f"✅ {mensagem}")
            print(f"📁 Captura: {arquivo_captura}")
            
            # Analisar
            eventos, stats = melt.parse_trafego(arquivo_captura)
            
            if stats.get('erro'):
                print(f"❌ {stats['erro']}")
                sys.exit(1)
                
            if not eventos:
                print("❌ Nenhum evento válido capturado")
                sys.exit(1)
            
            contagem_total, port_scans, portas_por_ip, alertas = melt.analisar_comportamento(eventos)
            
            # Gerar relatório
            if not args.output:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                args.output = f"relatorio_completo_{timestamp}.{args.formato}"
            
            if args.formato == 'csv':
                sucesso, mensagem = melt.gerar_relatorio_csv(contagem_total, port_scans, portas_por_ip, args.output)
            else:
                dados = {
                    'contagem_total': contagem_total,
                    'port_scans': port_scans,
                    'portas_por_ip': portas_por_ip
                }
                sucesso, mensagem = melt.gerar_relatorio_json(dados, args.output)
            
            if not sucesso:
                print(f"❌ {mensagem}")
                sys.exit(1)
            
            # Resultados
            stats_finais = melt.obter_estatisticas(eventos, contagem_total, port_scans)
            
            print(f"\n🎯 PROCESSO CONCLUÍDO:")
            print(f"📁 Captura: {arquivo_captura}")
            print(f"📊 {mensagem}")
            print(f"📈 Estatísticas: {stats_finais['total_eventos']} eventos, {stats_finais['port_scans_detectados']} alertas")
            
        elif args.comando == 'interfaces':
            print("🔍 MeltTrafego - Interfaces de Rede Disponíveis")
            print(f"📡 Plataforma: {melt.sistema}")
            print("\n" + "="*50)
            
            interfaces = melt.listar_interfaces()
            for interface in interfaces:
                print(f"📡 {interface['nome']} - {interface['descricao']}")
                
            print(f"\n💡 Use: {sys.argv[0]} capturar -i NOME_DA_INTERFACE")
            
        elif args.comando == 'status':
            print("🔍 MeltTrafego - Status do Sistema")
            print("="*50)
            
            # Informações da plataforma
            plataforma = melt.detectar_plataforma()
            print(f"🖥️  Sistema: {plataforma['sistema']}")
            print(f"🏗️  Arquitetura: {plataforma['arquitetura']}")
            print(f"🐍 Python: {plataforma['python_version']}")
            
            # Dependências
            dependencias = melt.verificar_dependencias()
            print(f"\n📦 Dependências:")
            print(f"   tcpdump: {'✅ Disponível' if dependencias['tcpdump'] else '❌ Não encontrado'}")
            print(f"   Python: ✅ Disponível")
            
            if not dependencias['tcpdump']:
                print(f"\n💡 Recomendações:")
                if melt.sistema == "Windows":
                    print("   • Instale o Npcap: https://npcap.com/#download")
                    print("   • Execute como Administrador para captura real")
                else:
                    print("   • Instale tcpdump: sudo apt install tcpdump")
                    print("   • Configure permissões: sudo usermod -aG wireshark $USER")
                    
    except KeyboardInterrupt:
        print("\n⏹️  Operação interrompida pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()