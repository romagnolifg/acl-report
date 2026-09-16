@echo off
rem Serve the acl-report database for browsing at http://127.0.0.1:8000
rem Usage: run.bat [DATABASE]  (default: report.db beside this script)
setlocal
set "SCRIPT_DIR=%~dp0"
set "DB=%~1"
if "%DB%"=="" set "DB=%SCRIPT_DIR%report.db"
python "%SCRIPT_DIR%server.py" --database "%DB%"
