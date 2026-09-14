@echo off
REM NETRA - Cyber Crime OSINT & Intelligence System
REM Jaipur Police Cyber Crime Dept | Rohit Khatana
REM Double-click this file to run Netra. No PowerShell commands needed.

cd /d "%~dp0"

if not exist venv (
    echo First-time setup: creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Installing dependencies, this may take a minute...
    pip install -r requirements.txt --quiet
) else (
    call venv\Scripts\activate.bat
)

python launch.py

echo.
pause
