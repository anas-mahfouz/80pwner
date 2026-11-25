@echo off
rem 80PWNER launcher (Windows CMD) - by Anas Mahfouz (The 80)
rem
rem   Usage: 80pwner.bat [--version] [--no-splash] [--theme dark^|light^|system]
rem
rem First run bootstraps a local .venv and installs the engine extras, so a
rem fresh clone only needs Python 3.11+ on PATH:
rem
rem   git clone https://github.com/the80/80pwner
rem   cd 80pwner
rem   80pwner.bat
rem
rem Environment:
rem   EIGHTYPWNER_NO_BOOTSTRAP=1   never create/install, just run what exists
rem   EIGHTYPWNER_PYTHON=path      interpreter used to create the venv
rem   EIGHTYPWNER_EXTRAS=all       extras to install (default: analysis)
setlocal EnableExtensions

set "DIR=%~dp0"
if "%DIR:~-1%"=="\" set "DIR=%DIR:~0,-1%"
set "VENV=%DIR%\.venv"
set "PYEXE=%VENV%\Scripts\python.exe"
if "%EIGHTYPWNER_EXTRAS%"=="" set "EIGHTYPWNER_EXTRAS=analysis"

"%PYEXE%" -c "import eightypwner, PySide6" >nul 2>&1
if not errorlevel 1 goto run

if "%EIGHTYPWNER_NO_BOOTSTRAP%"=="1" (
  echo [80PWNER] .venv is missing or incomplete and EIGHTYPWNER_NO_BOOTSTRAP=1. 1>&2
  exit /b 1
)

set "LAUNCHER="
if not "%EIGHTYPWNER_PYTHON%"=="" (
  set "LAUNCHER=%EIGHTYPWNER_PYTHON%"
) else (
  where py >nul 2>&1 && set "LAUNCHER=py -3"
)
if not defined LAUNCHER (
  where python >nul 2>&1 || (
    echo [80PWNER] Python 3.11+ is required: https://www.python.org/downloads/windows/ 1>&2
    exit /b 1
  )
  set "LAUNCHER=python"
)

if not exist "%PYEXE%" (
  echo [80PWNER] First run: creating .venv ...
  %LAUNCHER% -m venv "%VENV%"
  if errorlevel 1 (
    echo [80PWNER] Could not create the virtualenv. 1>&2
    exit /b 1
  )
)

echo [80PWNER] Installing 80PWNER and engine dependencies ^(one-time, needs network^)...
"%PYEXE%" -m pip install --upgrade pip >nul 2>&1
"%PYEXE%" -m pip install --disable-pip-version-check -e "%DIR%[%EIGHTYPWNER_EXTRAS%]"
if errorlevel 1 (
  echo [80PWNER] Full install failed; retrying core-only...
  "%PYEXE%" -m pip install --disable-pip-version-check -e "%DIR%"
  if errorlevel 1 (
    echo [80PWNER] Dependency installation failed. Check your network/proxy and retry. 1>&2
    exit /b 1
  )
)

:run
set "PYTHONPATH=%DIR%\src;%PYTHONPATH%"
"%PYEXE%" -m eightypwner %*
exit /b %ERRORLEVEL%
