@echo off
echo Starting QWED Backend API...
echo.

REM Navigate to src directory
cd /d "%~dp0src"

REM Start FastAPI server
python -m uvicorn qwed_new.api.main:app --reload --port 8000

pause
