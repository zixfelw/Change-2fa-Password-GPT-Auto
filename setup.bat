@echo off
REM gpt_signup_hybrid — 1 lệnh setup + start web UI (Windows)
REM Coi thư mục này là project root: .venv, runtime, .env đều nằm
REM trong gpt_signup_hybrid/, không leak ra parent.
REM
REM Usage: double-click setup.bat hoặc chạy trong cmd/powershell.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "ROOT_DIR=%CD%"
set "PKG_NAME=gpt_signup_hybrid"
REM Camoufox 0.5.x dùng platformdirs; override này cô lập active browser theo project.
set "WIN_PD_OVERRIDE_LOCAL_APPDATA=%ROOT_DIR%\runtime\camoufox-cache"

echo ═══════════════════════════════════════════════════════════
echo   gpt_signup_hybrid — auto setup + start (Windows)
echo   root:   %ROOT_DIR%
echo ═══════════════════════════════════════════════════════════
echo.

REM 1. Python venv trong chính package
if not exist ".venv" (
    echo [1/6] Creating .venv...
    python -m venv .venv
) else (
    echo [1/6] .venv exists √
)

.venv\Scripts\python.exe scripts\check_python_runtime.py
if errorlevel 1 (
    echo   ERROR: Python runtime version is unsupported.
    exit /b 1
)

REM 2. Install the canonical, pinned dependency set
echo [2/6] Installing dependencies from requirements.txt...
.venv\Scripts\python.exe -m pip install -q --upgrade pip
if errorlevel 1 (
    echo   ERROR: khong the upgrade pip.
    exit /b 1
)
.venv\Scripts\python.exe -m pip install -q --upgrade -r requirements.txt
if errorlevel 1 (
    echo   ERROR: dependency install failed. Camoufox GeoIP is required when Proxy is enabled.
    exit /b 1
)
.venv\Scripts\python.exe -m pip check
if errorlevel 1 (
    echo   ERROR: dependency consistency check failed.
    exit /b 1
)

REM 3. Shim dir + junction + .pth để import package bất kể tên folder
echo [3/6] Wiring package import via shim junction...
for /f "delims=" %%i in ('.venv\Scripts\python.exe -c "import site; print(site.getsitepackages()[0])" 2^>nul') do set "SITE_PKG=%%i"
if defined SITE_PKG (
    set "SHIM_DIR=%SITE_PKG%\_gpt_signup_hybrid_shim"
    if not exist "!SHIM_DIR!" mkdir "!SHIM_DIR!"
    set "SHIM_LINK=!SHIM_DIR!\%PKG_NAME%"
    if exist "!SHIM_LINK!" rmdir "!SHIM_LINK!" 2>nul
    mklink /J "!SHIM_LINK!" "%ROOT_DIR%" >nul
    echo !SHIM_DIR!> "%SITE_PKG%\_gpt_signup_hybrid_root.pth"
    echo   √ junction !SHIM_LINK! → %ROOT_DIR%
    echo   √ pth      %SITE_PKG%\_gpt_signup_hybrid_root.pth
) else (
    echo   ERROR: không xác định được site-packages.
    exit /b 1
)

REM 4. Playwright Chromium (fallback engine)
echo [4/6] Installing Playwright Chromium...
.venv\Scripts\python.exe -m playwright install chromium
if errorlevel 1 (
    echo   ERROR: Playwright Chromium install failed.
    exit /b 1
)

REM 5. Sync, select, fetch and verify the pinned Camoufox binary
if not exist "camoufox-browser-spec.txt" (
    echo   ERROR: camoufox-browser-spec.txt is missing.
    exit /b 1
)
set "CAMOUFOX_BROWSER_SPEC="
set /p "CAMOUFOX_BROWSER_SPEC="<"camoufox-browser-spec.txt"
if not defined CAMOUFOX_BROWSER_SPEC (
    echo   ERROR: Camoufox browser spec is empty.
    exit /b 1
)
echo [5/6] Syncing Camoufox catalog...
.venv\Scripts\python.exe -m camoufox sync
if errorlevel 1 (
    echo   ERROR: Camoufox catalog sync failed.
    exit /b 1
)
echo Fetching pinned Camoufox binary...
.venv\Scripts\python.exe -m camoufox set "%CAMOUFOX_BROWSER_SPEC%"
if errorlevel 1 (
    echo   ERROR: cannot select Camoufox browser %CAMOUFOX_BROWSER_SPEC%.
    exit /b 1
)
.venv\Scripts\python.exe -m camoufox fetch
if errorlevel 1 (
    echo   ERROR: Camoufox binary fetch failed.
    exit /b 1
)
.venv\Scripts\python.exe scripts\verify_camoufox_install.py --spec-file camoufox-browser-spec.txt
if errorlevel 1 (
    echo   ERROR: Camoufox binary postcondition failed.
    exit /b 1
)

REM 6. .env
if not exist ".env" (
    echo [6/6] Creating .env...
    (
        echo BROWSER_ENGINE=camoufox
        echo BROWSER_CHANNEL=chrome
        echo RUNTIME_DIR=runtime
        echo BROWSER_VIEWPORT_WIDTH=1440
        echo BROWSER_VIEWPORT_HEIGHT=800
        echo BROWSER_USE_PROFILE_TEMPLATE=true
        echo BROWSER_PROFILE_TEMPLATE_DIR=runtime/profiles/template
        echo BROWSER_CAMOUFOX_PROFILE_DIR=runtime/profiles/camoufox_template
        echo HYBRID_MAX_CONCURRENT=2
        echo HYBRID_OUTLOOK_PROXY=
        echo HYBRID_JOB_TIMEOUT=240
    ) > .env
    echo   √ .env created
) else (
    echo [6/6] .env exists √
)

REM Tạo runtime dirs
if not exist "runtime\profiles\template" mkdir "runtime\profiles\template"
if not exist "runtime\profiles\camoufox_template" mkdir "runtime\profiles\camoufox_template"
if not exist "runtime\sessions" mkdir "runtime\sessions"
if not exist "runtime\outlook_state" mkdir "runtime\outlook_state"
if not exist "runtime\outlook_pool" mkdir "runtime\outlook_pool"
if not exist "runtime\har_hybrid" mkdir "runtime\har_hybrid"

echo.
echo ═══════════════════════════════════════════════════════════
echo   √ Setup done. Starting web UI...
echo   URL web se duoc in ngay ben duoi.
echo.
echo   Paste combo vao textarea + bam Run.
echo   Format: email^|password^|refresh_token^|client_id
echo ═══════════════════════════════════════════════════════════
echo.

.venv\Scripts\python -m gpt_signup_hybrid web --host 127.0.0.1 --port 8083

pause
