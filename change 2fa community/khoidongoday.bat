@echo off
setlocal
set "APP_DIR=%~dp0"
set "ROOT_DIR=%APP_DIR%.."
set "PYTHONW=%ROOT_DIR%\.venv\Scripts\pythonw.exe"
set "SOURCE_CA=%ROOT_DIR%\.venv\Lib\site-packages\certifi\cacert.pem"
set "ASCII_CA_DIR=%LOCALAPPDATA%\InfinityAIStore\Change2FA"
set "ASCII_CA=%ASCII_CA_DIR%\cacert.pem"

if not exist "%PYTHONW%" (
  echo [Infinity AI Store] Khong tim thay moi truong Python tai:
  echo %PYTHONW%
  echo.
  echo Hay khoi tao .venv cua project truoc khi chay.
  pause
  exit /b 1
)
if not exist "%SOURCE_CA%" (
  echo [Infinity AI Store] Khong tim thay CA certificate:
  echo %SOURCE_CA%
  pause
  exit /b 1
)
if not exist "%ASCII_CA_DIR%" mkdir "%ASCII_CA_DIR%"
copy /Y "%SOURCE_CA%" "%ASCII_CA%" >nul
if errorlevel 1 (
  echo [Infinity AI Store] Khong the chuan bi CA certificate.
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
