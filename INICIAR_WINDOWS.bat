@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo FiscalIA PFG 0.7.2 - Acesse http://127.0.0.1:8765 (ou a porta configurada)
echo.
python FiscalIA_PFG_Moderno_Seguro.py
if errorlevel 1 pause
