@echo off
echo 🔧 Instalando MeltTrafego no Windows...

:: Verificar se Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python não encontrado. Instale o Python primeiro.
    pause
    exit /b 1
)

:: Instalar dependências
echo 🐍 Instalando dependências Python...
pip install -r requirements.txt

echo ✅ Instalação concluída!
echo 🚀 Modo interativo: python melt_cli.py --interativo
echo 📊 Captura direta: python melt_cli.py --capturar Ethernet -t 30
pause