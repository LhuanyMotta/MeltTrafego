@echo off
chcp 65001 >nul
echo 🔧 Instalando MeltTrafego no Windows...

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

:: Verificar e instalar Npcap
echo 📦 Verificando Npcap...
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Npcap não encontrado. É necessário para captura de pacotes.
    echo 📥 Download: https://npcap.com/#download
    echo 💡 Instale com opção "Install Npcap in WinPcap API-compatible Mode"
    echo.
    choice /C SN /M "Pausar para instalação do Npcap? (S=Sim, N=Não)"
    if errorlevel 2 (
        echo ⚠️  Continuando sem Npcap - algumas funcionalidades não funcionarão.
    )
)

:: Criar ambiente virtual
echo 🐍 Configurando ambiente Python...
python -m venv melt_venv
if errorlevel 1 (
    echo ❌ Erro ao criar ambiente virtual.
    echo 💡 Tente: python -m pip install --user virtualenv
    pause
    exit /b 1
)

:: Ativar ambiente virtual e instalar dependências
echo 📦 Instalando dependências Python...
call melt_venv\Scripts\activate.bat
pip install --upgrade pip

if exist "requirements.txt" (
    pip install -r requirements.txt
) else (
    echo 📋 Instalando dependências manualmente...
    pip install scapy psutil pandas PyQt5
)

:: Criar diretórios necessários
echo 📁 Criando estrutura de pastas...
mkdir relatorios 2>nul
mkdir logs 2>nul
mkdir exemplos 2>nul
mkdir assets 2>nul

:: Criar script de ativação
echo 🚀 Criando scripts de execução...

:: Script de ativação do ambiente
echo @echo off > activate_melt.bat
echo chcp 65001 >nul >> activate_melt.bat
echo cd /d "%~dp0" >> activate_melt.bat
echo call melt_venv\Scripts\activate.bat >> activate_melt.bat
echo echo 🚀 Ambiente MeltTrafego ativado! >> activate_melt.bat
echo echo 💡 Use: python melt_cli.py --interativo >> activate_melt.bat
echo echo 🖥️  Ou: python melt_gui.py >> activate_melt.bat
echo cmd /k >> activate_melt.bat

:: Script para executar GUI
echo @echo off > melt_gui.bat
echo chcp 65001 >nul >> melt_gui.bat
echo cd /d "%~dp0" >> melt_gui.bat
echo call melt_venv\Scripts\activate.bat >> melt_gui.bat
echo python melt_gui.py >> melt_gui.bat
echo pause >> melt_gui.bat

:: Script para CLI interativo
echo @echo off > melt_cli.bat
echo chcp 65001 >nul >> melt_cli.bat
echo cd /d "%~dp0" >> melt_cli.bat
echo call melt_venv\Scripts\activate.bat >> melt_cli.bat
echo python melt_cli.py --interativo >> melt_cli.bat
echo pause >> melt_cli.bat

echo.
echo 🎉 INSTALAÇÃO CONCLUÍDA!
echo.
echo 🚀 COMO USAR:
echo   1. Execute activate_melt.bat para ativar o ambiente
echo   2. Ou use os atalhos:
echo      - melt_gui.bat para interface gráfica
echo      - melt_cli.bat para linha de comando interativa
echo.
echo 📝 Notas Windows:
echo   - Npcap é necessário para captura de pacotes
echo   - Execute como Administrador se tiver problemas de permissão
echo.
pause