@echo off
REM Embers launcher: run from an elevated (Administrator) prompt.
net session >nul 2>&1 || (echo Please run this as Administrator ^(raw volume access^). & pause & exit /b 1)
set /p DRIVE=Drive letter of the mounted image (e.g. F): 
set /p CASE=Case name (e.g. victim01): 
pip install -q -r "%~dp0requirements.txt"
start "" http://127.0.0.1:8766
python "%~dp0app.py" \\.\%DRIVE%: --db "%~dp0case-%CASE%.db"
pause
