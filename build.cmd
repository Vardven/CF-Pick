@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   CF-Pick 重新打包
echo ============================================
where python >nul 2>nul || (echo [x] 没找到 python，请先安装并加入 PATH & pause & exit /b 1)
python -m PyInstaller --version >nul 2>nul || (echo [*] 安装 pyinstaller... & python -m pip install -q pyinstaller)
if not exist cf-domains.txt copy /y ..\cf-domains.txt . >nul
if not exist splash.png python gen_splash.py
set SPLASH=
python -c "import tkinter" >nul 2>nul && set SPLASH=--splash "splash.png"
python -m PyInstaller --noconfirm --onefile --noconsole --name "CF-Pick" ^
  --icon "icon.ico" %SPLASH% --add-data "ui.html;." --add-data "cf-domains.txt;." cfpick.py
if errorlevel 1 (echo [x] 打包失败 & pause & exit /b 1)
copy /y dist\CF-Pick.exe ..\CF-Pick.exe >nul
echo.
echo [ok] 已输出 ..\CF-Pick.exe
pause
