@rem 80PWNER launcher (Windows) — by Anas Mahfouz (The 80)
@echo off
setlocal
set "DIR=%~dp0"

if exist "%DIR%.venv\Scripts\python.exe" (
    set "PY=%DIR%.venv\Scripts\python.exe"
) else (
    set "PY=python"
)

"%PY%" -m eightypwner %*
