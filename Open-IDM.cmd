@echo off
setlocal
title IDM Trial Forever
set PYTHONUTF8=1
py -3 --version >nul 2>&1
if not errorlevel 1 (
    py -3 "%~dp0src\idm_trial_forever.py" --menu %*
    goto :done
)
python --version >nul 2>&1
if not errorlevel 1 (
    python "%~dp0src\idm_trial_forever.py" --menu %*
    goto :done
)
echo Python 3.10 or newer is required. Install Python from https://www.python.org/downloads/windows/
pause
exit /b 1
:done
if errorlevel 1 (
    pause
    exit /b 1
)
exit /b 0
