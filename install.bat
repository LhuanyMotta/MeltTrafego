@echo off
chcp 65001 >nul
echo 🔧 Instalando MeltTrafego no Windows...
echo.

:: Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python não encontrado.
    echo 📥 Instale Python 3.6+ em: https://python.org
    echo 💡 Marque a opção "Add Python to PATH" durante a instalação
    pause
    exit /b 1
)

echo ✅ Python encontrado: 
python --version

:: Criar diretórios
if not exist logs mkdir logs
if not exist relatorios mkdir relatorios
if not exist exemplos mkdir exemplos
if not exist assets mkdir assets

:: Instalar dependências Python
echo 📦 Instalando dependências Python...
pip install -r requirements.txt

:: Verificar Npcap/tcpdump
echo 🔍 Verificando Npcap...
where tcpdump >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Npcap não encontrado ou tcpdump não está no PATH
    echo.
    echo 📥 RECOMENDAÇÕES:
    echo   1. Baixe e instale o Npcap em: https://npcap.com/#download
    echo   2. Marque a opção "Install Npcap in WinPcap API-compatible Mode"
    echo   3. Execute como Administrador para captura real
    echo.
    echo 💡 Sem o Npcap, o sistema funcionará em modo demonstração
) else (
    echo ✅ tcpdump/Npcap encontrado
)

echo.
echo ✅ MeltTrafego instalado com sucesso!
echo.
echo 🚀 COMO USAR:
echo    Interface Gráfica: python melt_gui.py
echo    Linha de Comando:  python melt_cli.py [comando]
echo.
echo 📖 EXEMPLOS:
echo    python melt_cli.py status
echo    python melt_cli.py interfaces
echo    python melt_cli.py capturar -i 0 -t 30
echo    python melt_cli.py analisar trafego.txt -o relatorio.csv
echo.
echo 💡 DICA: Execute como Administrador para captura de rede real
pause