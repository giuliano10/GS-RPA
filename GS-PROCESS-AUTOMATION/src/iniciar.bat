@echo off
rem Liga o Caminho Livre: servidor + robo agendado (1 ciclo por minuto).
cd /d "%~dp0"
where py >nul 2>nul && (py servidor_caminho_livre.py) || (python servidor_caminho_livre.py)
pause
