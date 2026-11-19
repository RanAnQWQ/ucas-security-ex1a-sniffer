@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m venv .venv
if errorlevel 1 exit /b 1
.venv\Scripts\python.exe -m pip install pyinstaller==6.22.3
if errorlevel 1 exit /b 1
.venv\Scripts\python.exe -m PyInstaller --noconfirm --windowed --onedir --name ChengLiu main.py
if errorlevel 1 exit /b 1
echo 程序位于 dist\ChengLiu\ChengLiu.exe，需保留整个目录。
pause
