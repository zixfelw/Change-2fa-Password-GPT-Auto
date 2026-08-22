@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "ROOT_DIR=%CD%"
set "PYTHON=.venv\Scripts\python.exe"
set "WIN_PD_OVERRIDE_LOCAL_APPDATA=%ROOT_DIR%\runtime\camoufox-cache"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo ============================================================
echo   Tool change Password vs 2FA GPT
echo   Cai dat lan dau tai: %ROOT_DIR%
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Khong tim thay Python trong PATH.
    echo Cai Python 3.11, 3.12 hoac 3.13 roi chay lai khoidongoday.bat.
    exit /b 1
)

if not exist "%PYTHON%" (
    echo [1/5] Dang tao .venv...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Khong the tao .venv.
        exit /b 1
    )
) else (
    echo [1/5] Da co .venv.
)

"%PYTHON%" "scripts\check_python_runtime.py"
if errorlevel 1 exit /b 1

echo [2/5] Dang cai dependencies...
"%PYTHON%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1
"%PYTHON%" -m pip install --upgrade -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Cai dependencies that bai.
    exit /b 1
)
"%PYTHON%" -m pip check
if errorlevel 1 (
    echo [ERROR] Dependency consistency check that bai.
    exit /b 1
)

echo [3/5] Dang cai Playwright Chromium fallback...
"%PYTHON%" -m playwright install chromium
if errorlevel 1 (
    echo [ERROR] Cai Playwright Chromium that bai.
    exit /b 1
)

if not exist "camoufox-browser-spec.txt" (
    echo [ERROR] Thieu camoufox-browser-spec.txt.
    exit /b 1
)
set "CAMOUFOX_BROWSER_SPEC="
set /p "CAMOUFOX_BROWSER_SPEC="<"camoufox-browser-spec.txt"
if not defined CAMOUFOX_BROWSER_SPEC (
    echo [ERROR] Camoufox browser spec rong.
    exit /b 1
)

echo [4/5] Dang dong bo Camoufox catalog...
"%PYTHON%" -m camoufox sync
if errorlevel 1 (
    echo [ERROR] Camoufox catalog sync that bai.
    exit /b 1
)
"%PYTHON%" -m camoufox set "%CAMOUFOX_BROWSER_SPEC%"
if errorlevel 1 (
    echo [ERROR] Khong the chon Camoufox %CAMOUFOX_BROWSER_SPEC%.
    exit /b 1
)
"%PYTHON%" -m camoufox fetch
if errorlevel 1 (
    echo [ERROR] Tai Camoufox that bai. Kiem tra Internet roi thu lai.
    exit /b 1
)

echo [5/5] Dang kiem tra Camoufox...
"%PYTHON%" "scripts\verify_camoufox_install.py" --spec-file "camoufox-browser-spec.txt"
if errorlevel 1 exit /b 1

> ".setup-complete" echo Change 2FA setup completed

echo.
echo [OK] Cai dat hoan tat. Dashboard se tu mo.
exit /b 0
