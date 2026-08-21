@echo off
setlocal EnableExtensions
set "APP_DIR=%~dp0"
set "ROOT_DIR=%APP_DIR%"
set "PYTHONW=%APP_DIR%.venv\Scripts\pythonw.exe"

REM Standalone release: setup is complete only after every dependency and
REM pinned browser verification succeeds.
if exist "%APP_DIR%.setup-complete" if exist "%PYTHONW%" goto runtime_ready

REM Monorepo development layout: reuse the parent virtual environment only when
REM core modules are not bundled beside this launcher.
if not exist "%APP_DIR%_camoufox_runtime.py" if exist "%APP_DIR%..\.venv\Scripts\pythonw.exe" (
  set "ROOT_DIR=%APP_DIR%.."
  set "PYTHONW=%APP_DIR%..\.venv\Scripts\pythonw.exe"
  goto runtime_ready
)

REM First standalone launch: install Python dependencies and browser runtime.
if not exist "%APP_DIR%setup.bat" (
  echo [Change 2FA] Khong tim thay setup.bat trong:
  echo %APP_DIR%
  pause
  exit /b 1
)
call "%APP_DIR%setup.bat"
if errorlevel 1 (
  echo.
  echo [Change 2FA] Setup that bai. Kiem tra loi phia tren roi thu lai.
  pause
  exit /b 1
)
set "ROOT_DIR=%APP_DIR%"
set "PYTHONW=%APP_DIR%.venv\Scripts\pythonw.exe"
if not exist "%PYTHONW%" (
  echo [Change 2FA] Setup xong nhung khong tim thay pythonw.exe.
  pause
  exit /b 1
)

:runtime_ready
set "SOURCE_CA=%ROOT_DIR%\.venv\Lib\site-packages\certifi\cacert.pem"
set "ASCII_CA_DIR=%LOCALAPPDATA%\InfinityAIStore\Change2FA"
set "ASCII_CA=%ASCII_CA_DIR%\cacert.pem"

if not exist "%SOURCE_CA%" (
  echo [Change 2FA] Khong tim thay CA certificate:
  echo %SOURCE_CA%
  pause
  exit /b 1
)
if not exist "%ASCII_CA_DIR%" mkdir "%ASCII_CA_DIR%"
copy /Y "%SOURCE_CA%" "%ASCII_CA%" >nul
if errorlevel 1 (
  echo [Change 2FA] Khong the chuan bi CA certificate.
  pause
  exit /b 1
)

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
set "CURL_CA_BUNDLE=%ASCII_CA%"
set "SSL_CERT_FILE=%ASCII_CA%"
set "REQUESTS_CA_BUNDLE=%ASCII_CA%"

powershell -NoProfile -WindowStyle Hidden -Command ^
  "$health='http://127.0.0.1:5033/api/health';" ^
  "$alive=$false; try { $alive=(Invoke-RestMethod -Uri $health -TimeoutSec 1).ok } catch {};" ^
  "if (-not $alive) { Start-Process -WindowStyle Hidden -FilePath '%PYTHONW%' -ArgumentList @('%APP_DIR%server.py','--host','127.0.0.1','--port','5033') -WorkingDirectory '%ROOT_DIR%' };" ^
  "for ($i=0; $i -lt 720; $i++) { try { if ((Invoke-RestMethod -Uri $health -TimeoutSec 1).ok) { Start-Process 'http://127.0.0.1:5033'; exit 0 } } catch {}; Start-Sleep -Milliseconds 250 };" ^
  "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Server khong phan hoi sau 3 phut. Lan dau co the can tai Camoufox browser — thu lai hoac kiem tra log.','Change 2FA Password GPT') | Out-Null; exit 1"

endlocal
