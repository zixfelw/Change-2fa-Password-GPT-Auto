@echo off
title Tool change Password vs 2FA GPT - Infinity AI Store
setlocal EnableExtensions
cd /d "%~dp0"
set "APP_DIR=%CD%"
set "PYTHON="

:: 1. Uu tien .venv ngay trong thu muc hien tai
if exist "%APP_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON=%APP_DIR%\.venv\Scripts\python.exe"
    goto check_running
)

:: 2. Neu khong co, dung .venv o thu muc cha (monorepo / dev)
if exist "%APP_DIR%\..\.venv\Scripts\python.exe" (
    set "PYTHON=%APP_DIR%\..\.venv\Scripts\python.exe"
    goto check_running
)

:: 3. Neu chua co .venv nao, goi setup.bat de tao
if exist "%APP_DIR%\setup.bat" (
    echo [Tool Password vs 2FA GPT] Phat hien chua cai dat runtime. Dang chay setup...
    call "%APP_DIR%\setup.bat"
    if errorlevel 1 (
        echo.
        echo [ERROR] Cai dat that bai.
        pause
        exit /b 1
    )
    if exist "%APP_DIR%\.venv\Scripts\python.exe" (
        set "PYTHON=%APP_DIR%\.venv\Scripts\python.exe"
        goto check_running
    )
)

echo [ERROR] Khong tim thay Python runtime (.venv).
echo Vui long chay setup.bat truoc.
pause
exit /b 1

:check_running
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo ============================================================
echo   Tool change Password vs 2FA GPT - Infinity AI Store
echo ============================================================
echo.

:: Kiem tra neu server da dang chay san tren port 5033
powershell -NoProfile -Command "try { $r = (Invoke-RestMethod -Uri 'http://127.0.0.1:5033/api/health' -TimeoutSec 1).ok; if ($r) { Start-Process 'http://127.0.0.1:5033'; exit 42 } } catch {}"
if errorlevel 42 (
    echo [OK] Server da dang chay san tai: http://127.0.0.1:5033
    echo [OK] Da mo Dashboard tren trinh duyet!
    echo.
    echo Nhan phim bat ky de thoat cua so nay...
    pause >nul
    exit /b 0
)

echo   Dang khoi dong server tai: http://127.0.0.1:5033 ...
echo   (Trinh duyet se tu dong mo len sau vai giay)
echo.

"%PYTHON%" server.py --host 127.0.0.1 --port 5033

if errorlevel 1 (
    echo.
    echo [ERROR] Server da dung hoac gap su co.
    pause
)

endlocal
