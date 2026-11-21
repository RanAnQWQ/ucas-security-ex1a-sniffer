@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m venv .venv
if errorlevel 1 exit /b 1
.venv\Scripts\python.exe -m pip install pyinstaller==6.22.3
if errorlevel 1 exit /b 1
for /f "delims=" %%P in ('.venv\Scripts\python.exe -c "import sys; print(sys.base_prefix)"') do set "SNIFFER_PY_BASE=%%P"
set "PATH=%SNIFFER_PY_BASE%\Library\bin;%SNIFFER_PY_BASE%\DLLs;%PATH%"
.venv\Scripts\python.exe -m PyInstaller --clean --noconfirm --windowed --onedir --name 网络嗅探器 main.py
if errorlevel 1 exit /b 1
echo 程序位于 dist\网络嗅探器\网络嗅探器.exe，需保留整个目录。
pause
