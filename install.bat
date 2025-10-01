@echo off
chcp 65001 >nul
echo 🔧 Instalando MeltTrafego no Windows...

cd /d "%~dp0"

:: Verificar se Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python não encontrado. Instale o Python 3.6+ primeiro.
    echo 📥 Download: https://python.org/downloads/
    pause
    exit /b 1
)

:: Verificar se pip está disponível
pip --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pip não encontrado. Reinstale o Python marcando "Add Python to PATH"
    pause
    exit /b 1
)

:: Verificar e avisar sobre Npcap
echo 📦 Verificando Npcap...
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Npcap não encontrado. É necessário para captura de pacotes.
    echo 📥 Download: https://npcap.com/#download
    echo 💡 Instale com opção "Install Npcap in WinPcap API-compatible Mode"
    echo.
)

:: Criar diretórios necessários
echo 📁 Criando estrutura de pastas...
mkdir relatorios 2>nul
mkdir assets 2>nul

:: Rodar setup.py
echo 🐍 Configurando ambiente Python...
python setup.py

echo.
echo 🎉 INSTALAÇÃO CONCLUÍDA!
echo.
echo 🚀 COMO USAR:
echo   - melt_gui.bat para interface gráfica
echo   - melt_cli.bat para linha de comando interativa
echo.
pause
