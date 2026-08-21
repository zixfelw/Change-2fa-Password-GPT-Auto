"""Local FastAPI control plane for Change 2FA Community."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import certifi
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


APP_DIR = Path(__file__).resolve().parent
ROOT = APP_DIR.parent
STATIC_DIR = APP_DIR / "static"
LEGACY_RUNTIME_DIR = APP_DIR / "runtime"


def resolve_runtime_dir(
    platform: str | None = None,
    environ: dict[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Return the native per-user data directory for the current platform."""
    platform_name = platform or sys.platform
    environment = os.environ if environ is None else environ
    user_home = Path.home() if home is None else home
    if platform_name.startswith("win"):
        base = Path(environment.get("LOCALAPPDATA", user_home / "AppData" / "Local"))
    elif platform_name == "darwin":
        base = user_home / "Library" / "Application Support"
    else:
        base = Path(environment.get("XDG_DATA_HOME", user_home / ".local" / "share"))
    return base / "InfinityAIStore" / "Change2FA"


RUNTIME_DIR = resolve_runtime_dir()
DB_PATH = RUNTIME_DIR / "twofa.db"
RUNTIME_PORT = 5033


def _migrate_legacy_database() -> None:
    """Copy the source-mode database once; never bundle it into a release."""
    legacy = LEGACY_RUNTIME_DIR / "twofa.db"
    if DB_PATH.exists() or not legacy.is_file() or legacy.resolve() == DB_PATH.resolve():
        return
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(f"file:{legacy.as_posix()}?mode=ro", uri=True)
    target = sqlite3.connect(DB_PATH)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def _prepare_runtime() -> None:
    """Keep Python I/O and TLS certificate paths safe in frozen builds."""
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    source = Path(certifi.where())
    if not source.is_file():
        raise RuntimeError(f"Không tìm thấy CA bundle: {source}")
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    target = RUNTIME_DIR / "cacert.pem"
    if not target.exists() or source.read_bytes() != target.read_bytes():
        shutil.copy2(source, target)
    for key in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        os.environ[key] = str(target)


_prepare_runtime()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from _camoufox_runtime import configure_camoufox_cache  # noqa: E402

configure_camoufox_cache(ROOT)

from db import get_engine, get_repos, get_settings_repo  # noqa: E402
from jobs import TwoFAJobManager  # noqa: E402


RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
_migrate_legacy_database()


class BatchRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=500)
    mode: str = Field(pattern="^(check_only|change_2fa|change_password|change_password_and_2fa)$")


class SettingsRequest(BaseModel):
    max_concurrent: int = Field(ge=1, le=10)
    job_timeout: float = Field(ge=30, le=600)
    auto_retry: bool
    auto_retry_max: int = Field(ge=0, le=5)
    auto_retry_delay: float = Field(ge=0, le=60)
    change_enabled: bool
    input_draft: str = Field(max_length=1_000_000)


engine = get_engine(str(DB_PATH))
_, job_repo, _ = get_repos(engine)
settings_repo = get_settings_repo(engine)
auth_token = settings_repo.get("web.auth_token")
if not isinstance(auth_token, str) or len(auth_token) < 32:
    auth_token = secrets.token_urlsafe(32)
    settings_repo.set("web.auth_token", auth_token)
manager = TwoFAJobManager(job_repo, settings_repo)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    manager.start()
    yield
    await manager.shutdown()
    engine.close()


app = FastAPI(
    title="Infinity AI Store — Change 2FA Community",
    description="Local-only TOTP rotation control plane",
    version="1.0.0",
    lifespan=lifespan,
)


def require_token(x_auth_token: str | None = Header(default=None)) -> None:
    if not x_auth_token or not secrets.compare_digest(x_auth_token, auth_token):
        raise HTTPException(status_code=401, detail="Token không hợp lệ")


@app.get("/api/bootstrap")
def bootstrap() -> dict[str, Any]:
    return {
        "brand": "Infinity AI Store",
        "product": "Change 2FA Community",
        "token": auth_token,
        "jobs": manager.snapshots(),
        "settings": manager.settings,
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "port": RUNTIME_PORT}


@app.post("/api/jobs", dependencies=[Depends(require_token)])
def add_jobs(request: BatchRequest) -> dict[str, Any]:
    try:
        return {"jobs": manager.add(request.lines, request.mode)}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/jobs/{job_id}/retry", dependencies=[Depends(require_token)])
def retry_job(job_id: str) -> dict[str, Any]:
    try:
        return {"job": manager.retry(job_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/jobs/{job_id}/stop", dependencies=[Depends(require_token)])
def stop_job(job_id: str) -> dict[str, Any]:
    try:
        return {"job": manager.stop(job_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc


@app.delete("/api/jobs/{job_id}", dependencies=[Depends(require_token)])
def delete_job(job_id: str) -> dict[str, bool]:
    try:
        manager.delete(job_id)
        return {"ok": True}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/jobs/stop-all", dependencies=[Depends(require_token)])
def stop_all() -> dict[str, bool]:
    manager.stop_all()
    return {"ok": True}


@app.delete("/api/jobs", dependencies=[Depends(require_token)])
def clear_jobs() -> dict[str, int]:
    try:
        return {"deleted": manager.clear()}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/jobs/{job_id}/logs", dependencies=[Depends(require_token)])
def job_logs(job_id: str) -> dict[str, Any]:
    try:
        return {"logs": manager.logs(job_id)}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Không tìm thấy job") from exc


@app.get("/api/output", dependencies=[Depends(require_token)])
def output_file() -> PlainTextResponse:
    body = "\n".join(manager.output())
    if body:
        body += "\n"
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": "attachment; filename=twofa-success.txt"},
    )


@app.put("/api/settings", dependencies=[Depends(require_token)])
async def update_settings(request: SettingsRequest) -> dict[str, Any]:
    try:
        return {"settings": await manager.update_settings({
            "twofa.max_concurrent": request.max_concurrent,
            "twofa.job_timeout": request.job_timeout,
            "twofa.auto_retry": request.auto_retry,
            "twofa.auto_retry_max": request.auto_retry_max,
            "twofa.auto_retry_delay": request.auto_retry_delay,
            "twofa.change_enabled": request.change_enabled,
            "twofa.input_draft": request.input_draft,
        })}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/events")
async def events(token: str):
    if not secrets.compare_digest(token, auth_token):
        raise HTTPException(status_code=401, detail="Token không hợp lệ")
    queue = manager.subscribe()

    async def stream():
        try:
            yield f"data: {json.dumps({'type': 'snapshot', 'jobs': manager.snapshots()})}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            manager.unsubscribe(queue)

    return StreamingResponse(stream(), media_type="text/event-stream")


app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _open_browser_when_ready(host: str, port: int) -> None:
    url = f"http://{host if host != '::1' else '127.0.0.1'}:{port}/"

    def worker() -> None:
        health = f"{url}api/health"
        for _ in range(50):
            try:
                from urllib.request import urlopen

                with urlopen(health, timeout=0.5) as response:
                    if response.status == 200:
                        webbrowser.open(url)
                        return
            except Exception:
                time.sleep(0.2)

    threading.Thread(target=worker, name="twofa-browser", daemon=True).start()


def main() -> None:
    global RUNTIME_PORT
    parser = argparse.ArgumentParser(description="Change 2FA Community localhost")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5033)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--check-runtime-dependencies", action="store_true")
    args = parser.parse_args()
    if args.check_runtime_dependencies:
        import request_phase
        import sentinel_pow
        import sentinel_quickjs

        script = sentinel_quickjs._quickjs_script_path()
        required = (
            request_phase._get_sentinel_token,
            sentinel_pow.get_sentinel_token,
            sentinel_quickjs.get_sentinel_token_via_quickjs,
        )
        if not all(callable(item) for item in required):
            raise RuntimeError("Pure-request login dependency contract is incomplete")
        if not script.is_file():
            raise FileNotFoundError(f"Sentinel runtime asset missing: {script}")
        print("PASS: pure-request login dependencies and Sentinel runtime asset")
        return
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("Server chỉ được bind localhost")
    if not 1 <= args.port <= 65535:
        parser.error("Port phải nằm trong khoảng 1..65535")
    RUNTIME_PORT = args.port
    import uvicorn

    if not args.no_browser:
        _open_browser_when_ready(args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
