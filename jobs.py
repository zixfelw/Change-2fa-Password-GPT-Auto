"""Batch jobs and SQLite persistence for Change 2FA Community."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from service import TwoFAService


JOB_TYPE = "twofa_community"
TERMINAL = {"success", "error", "cancelled"}
VALID_MODES = {"check_only", "change_2fa", "change_password", "change_password_and_2fa"}


@dataclass(slots=True)
class TwoFAJob:
    id: str
    email: str
    password: str
    secret: str
    mode: str = "change_2fa"
    status: str = "queued"
    error: str | None = None
    error_kind: str | None = None
    account_state: str = "unknown"
    plan: str | None = None
    plan_source: str | None = None
    plan_expires: str | None = None
    rotated_pending_verify: bool = False
    password_changed: bool = False   # password đã được đổi thành công
    login_verified: bool = False
    retry_count: int = 0
    new_password: str = ""           # password mới sau khi đổi (nếu mode có đổi pass)
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)

    @property
    def retryable(self) -> bool:
        return self.error_kind not in {"account_die", "invalid_credentials"}

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "mode": self.mode,
            "status": self.status,
            "error": self.error,
            "error_kind": self.error_kind,
            "account_state": self.account_state,
            "plan": self.plan,
            "plan_source": self.plan_source,
            "plan_expires": self.plan_expires,
            "retryable": self.retryable,
            "rotated_pending_verify": self.rotated_pending_verify,
            "password_changed": self.password_changed,
            "login_verified": self.login_verified,
            "retry_count": self.retry_count,
            "has_new_password": bool(self.new_password),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "log_tail": self.logs[-3:],
            "logs": self.logs,
        }


class TwoFAJobManager:
    DEFAULTS = {
        "twofa.max_concurrent": 3,
        "twofa.job_timeout": 180,
        "twofa.auto_retry": False,
        "twofa.auto_retry_max": 1,
        "twofa.auto_retry_delay": 3,
        "twofa.change_enabled": False,
        "twofa.input_draft": "",
    }

    def __init__(self, job_repo, settings_repo, service: TwoFAService | None = None) -> None:
        self.job_repo = job_repo
        self.settings_repo = settings_repo
        self.service = service or TwoFAService()
        self.jobs: dict[str, TwoFAJob] = {}
        self.order: list[str] = []
        self._queue: asyncio.Queue[str | None] = asyncio.Queue()
        self._workers: list[asyncio.Task] = []
        self._tasks: dict[str, asyncio.Task] = {}
        self._retire_lock = asyncio.Lock()
        self._subscribers: set[asyncio.Queue] = set()
        self.settings = dict(self.DEFAULTS)
        self._load_settings()
        self._recover()

    @staticmethod
    def _legacy_error_metadata(error: Any) -> tuple[str | None, str]:
        if not isinstance(error, str) or not error.strip():
            return None, "unknown"
        from session_phase import classify_account_check_error, is_fatal_login_error

        if classify_account_check_error(error) == "deactivated":
            return "account_die", "die"
        if is_fatal_login_error(error):
            return "invalid_credentials", "unknown"
        return "technical_error", "unknown"

    def _load_settings(self) -> None:
        stored = self.settings_repo.list("twofa")
        self.settings.update({key: value for key, value in stored.items() if key in self.DEFAULTS})

    @staticmethod
    def parse_combo(line: str) -> tuple[str, str, str]:
        parts = [part.strip() for part in line.strip().split("|")]
        if len(parts) != 3 or not all(parts):
            raise ValueError("Định dạng phải là email|password|2FA_cũ")
        email, password, secret = parts
        if "@" not in email:
            raise ValueError("Email không hợp lệ")
        return email.casefold(), password, secret.replace(" ", "").upper()

    def _recover(self) -> None:
        for row in self.job_repo.list_all():
            if row.get("job_type") != JOB_TYPE:
                continue
            state = self._decode_state(row.get("account_check"))
            status = str(row.get("status") or "error")
            if status in {"running", "queued"}:
                status = "queued"
            legacy_kind, legacy_account_state = self._legacy_error_metadata(row.get("error"))
            job = TwoFAJob(
                id=str(row["id"]),
                email=str(row["email"]),
                password=str(row.get("password") or ""),
                secret=str(row.get("secret") or ""),
                mode=str(state.get("mode") or "change_2fa"),
                status=status,
                error=row.get("error"),
                error_kind=state.get("error_kind") or legacy_kind,
                account_state=str(state.get("account_state") or legacy_account_state),
                plan=state.get("plan"),
                plan_source=state.get("plan_source"),
                plan_expires=state.get("plan_expires"),
                rotated_pending_verify=bool(state.get("rotated_pending_verify")),
                password_changed=bool(state.get("password_changed")),
                login_verified=bool(state.get("login_verified")),
                retry_count=int(state.get("retry_count") or 0),
                new_password=str(state.get("new_password") or ""),
                created_at=float(row.get("created_at") or time.time()),
                started_at=row.get("started_at"),
                finished_at=row.get("finished_at"),
                logs=[str(item.get("line") or "") for item in self.job_repo.get_logs(str(row["id"]))],
            )
            self.jobs[job.id] = job
            self.order.append(job.id)

    @staticmethod
    def _decode_state(raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw:
            try:
                value = json.loads(raw)
                return value if isinstance(value, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    def _state(self, job: TwoFAJob) -> str:
        return json.dumps({
            "rotated_pending_verify": job.rotated_pending_verify,
            "password_changed": job.password_changed,
            "login_verified": job.login_verified,
            "retry_count": job.retry_count,
            "mode": job.mode,
            "error_kind": job.error_kind,
            "account_state": job.account_state,
            "plan": job.plan,
            "plan_source": job.plan_source,
            "plan_expires": job.plan_expires,
            "new_password": job.new_password,
        }, ensure_ascii=False)

    def start(self) -> None:
        self._spawn_workers(int(self.settings["twofa.max_concurrent"]))
        for job in self.jobs.values():
            if job.status == "queued":
                self._queue.put_nowait(job.id)

    def _active_workers(self) -> list[asyncio.Task]:
        self._workers[:] = [task for task in self._workers if not task.done()]
        return self._workers

    def _spawn_workers(self, target: int) -> None:
        workers = self._active_workers()
        while len(workers) < target:
            task = asyncio.create_task(self._worker())
            workers.append(task)

    async def _claim_retirement(self) -> bool:
        async with self._retire_lock:
            workers = self._active_workers()
            target = int(self.settings["twofa.max_concurrent"])
            current = asyncio.current_task()
            if len(workers) <= target or current not in workers:
                return False
            workers.remove(current)
            return True

    async def _resize_workers(self, previous: int, target: int) -> None:
        workers = self._active_workers()
        if target > len(workers):
            self._spawn_workers(target)
            return
        for _ in range(max(0, previous - target)):
            self._queue.put_nowait(None)

    async def shutdown(self) -> None:
        for task in list(self._tasks.values()) + self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    def add(self, lines: list[str], mode: str = "change_2fa") -> list[dict[str, Any]]:
        if mode not in VALID_MODES:
            raise ValueError(f"Chế độ phải là một trong: {', '.join(sorted(VALID_MODES))}")
        created: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in lines:
            email, password, secret = self.parse_combo(line)
            if email in seen:
                continue
            seen.add(email)
            job = TwoFAJob(
                id=uuid.uuid4().hex,
                email=email,
                password=password,
                secret=secret,
                mode=mode,
            )
            self.jobs[job.id] = job
            self.order.append(job.id)
            self.job_repo.create({
                "id": job.id,
                "email": email,
                "combo": "[redacted]",
                "mail_mode": "none",
                "status": "queued",
                "password": password,
                "secret": secret,
                "account_check": self._state(job),
                "created_at": job.created_at,
                "job_type": JOB_TYPE,
            })
            self._queue.put_nowait(job.id)
            created.append(job.snapshot())
            self._broadcast(job)
        return created

    async def _worker(self) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                if job_id is None:
                    if await self._claim_retirement():
                        return
                    continue
                job = self.jobs.get(job_id)
                if job and job.status == "queued":
                    task = asyncio.create_task(self._run(job))
                    self._tasks[job.id] = task
                    await task
            finally:
                if job_id is not None:
                    self._tasks.pop(job_id, None)
                self._queue.task_done()

    async def _run(self, job: TwoFAJob) -> None:
        job.status = "running"
        job.error = None
        job.started_at = time.time()
        self.job_repo.update_status(job.id, "running", account_check=self._state(job))
        self._broadcast(job)

        def log(message: str) -> None:
            safe = str(message).replace(job.password, "***").replace(job.secret, "***")
            stamped = f"{time.strftime('%H:%M:%S')}  {safe[:500]}"
            job.logs.append(stamped)
            job.logs[:] = job.logs[-300:]
            self.job_repo.append_log(job.id, stamped)
            self._broadcast(job)

        async def checkpoint(new_secret: str) -> None:
            job.secret = new_secret
            job.rotated_pending_verify = True
            job.login_verified = False
            self.job_repo.update_status(
                job.id,
                "running",
                secret=new_secret,
                password=job.password,
                account_check=self._state(job),
            )
            self._broadcast(job)

        async def password_checkpoint(new_pass: str, new_secret: str) -> None:
            """Checkpoint sau khi đổi password (và có thể cả secret)."""
            effective_pass = new_pass or job.password
            effective_secret = new_secret or job.secret
            job.new_password = effective_pass
            job.password_changed = True
            if new_secret and new_secret != job.secret:
                job.secret = effective_secret
                job.rotated_pending_verify = True
            self.job_repo.update_status(
                job.id,
                "running",
                secret=effective_secret,
                password=effective_pass,
                account_check=self._state(job),
            )
            self._broadcast(job)

        try:
            timeout = float(self.settings["twofa.job_timeout"])
            # --- Quyết định flow dựa trên mode và checkpoint state ---
            if job.mode == "check_only":
                result = await self.service.check(
                    email=job.email,
                    password=job.password,
                    secret=job.secret,
                    timeout=timeout,
                    log=log,
                )
            elif job.mode == "change_password":
                result = await self.service.change_password(
                    email=job.email,
                    password=job.new_password or job.password,
                    secret=job.secret,
                    timeout=timeout,
                    checkpoint=password_checkpoint,
                    log=log,
                )
            elif job.mode == "change_password_and_2fa":
                if job.rotated_pending_verify and job.password_changed:
                    # Password đã đổi và secret mới đã luưu — chỉ cần verify
                    result = await self.service.verify(
                        email=job.email,
                        password=job.new_password or job.password,
                        new_secret=job.secret,
                        timeout=timeout,
                        log=log,
                    )
                else:
                    result = await self.service.rotate_with_password(
                        email=job.email,
                        password=job.new_password or job.password,
                        old_secret=job.secret,
                        timeout=timeout,
                        checkpoint=password_checkpoint,
                        log=log,
                    )
            elif job.rotated_pending_verify:
                result = await self.service.verify(
                    email=job.email,
                    password=job.password,
                    new_secret=job.secret,
                    timeout=timeout,
                    log=log,
                )
            else:
                result = await self.service.rotate(
                    email=job.email,
                    password=job.password,
                    old_secret=job.secret,
                    timeout=timeout,
                    checkpoint=checkpoint,
                    log=log,
                )
            # --- Ghi kết quả ---
            job.secret = result.secret
            if job.mode in {"change_password", "change_password_and_2fa"} and job.new_password:
                job.password = job.new_password
            job.login_verified = result.login_verified
            job.account_state = result.account_state
            job.plan = result.plan
            job.plan_source = result.plan_source
            job.plan_expires = result.plan_expires
            job.error_kind = None
            job.rotated_pending_verify = False
            job.status = "success"
            job.finished_at = time.time()
            self.job_repo.update_status(
                job.id, "success", secret=job.secret,
                password=job.password, account_check=self._state(job),
            )
        except asyncio.CancelledError:
            job.status = "cancelled"
            job.error = "Đã dừng bởi người dùng"
            job.finished_at = time.time()
            self.job_repo.update_status(
                job.id, "cancelled", error=job.error,
                secret=job.secret, account_check=self._state(job),
            )
        except Exception as exc:
            job.status = "error"
            raw_err = (str(exc).strip() or type(exc).__name__)
            # Bỏ bớt prefix rườm rà nếu có
            clean_err = raw_err
            for prefix in ("TwoFAFlowError: ", "SessionError: ", "LoginError: ", "Exception: "):
                if clean_err.startswith(prefix):
                    clean_err = clean_err[len(prefix):]
            clean_err = clean_err[:240]
            job.error = clean_err
            job.error_kind = str(getattr(exc, "error_kind", "technical_error"))
            job.account_state = str(getattr(exc, "account_state", job.account_state))
            job.finished_at = time.time()
            log(f"❌ [LỖI] {clean_err}")
            self.job_repo.update_status(
                job.id, "error", error=job.error,
                secret=job.secret, account_check=self._state(job),
            )
            if self._should_auto_retry(job):
                delay = float(self.settings["twofa.auto_retry_delay"])
                max_retry = int(self.settings["twofa.auto_retry_max"])
                log(f"⏳ [TỰ ĐỘNG THỬ LẠI] Phát hiện lỗi tạm thời — Đang chuẩn bị thử lại lần {job.retry_count + 1}/{max_retry} sau {delay:.0f}s...")
                asyncio.create_task(self._delayed_retry(job.id, delay))
        finally:
            self._broadcast(job)

    def _should_auto_retry(self, job: TwoFAJob) -> bool:
        return (
            job.retryable
            and bool(self.settings["twofa.auto_retry"])
            and job.retry_count < int(self.settings["twofa.auto_retry_max"])
        )

    async def _delayed_retry(self, job_id: str, delay: float) -> None:
        await asyncio.sleep(delay)
        if job_id in self.jobs and self.jobs[job_id].status == "error":
            try:
                self.retry(job_id)
            except Exception:
                pass

    def retry(self, job_id: str) -> dict[str, Any]:
        job = self._require(job_id)
        if job.status not in TERMINAL:
            raise ValueError("Job đang chạy hoặc đang chờ")
        if not job.retryable:
            label = "tài khoản die" if job.error_kind == "account_die" else "sai thông tin đăng nhập/2FA"
            raise ValueError(f"Không retry tự động: {label}")
        job.retry_count += 1
        job.status = "queued"
        job.error = None
        job.error_kind = None
        job.finished_at = None
        retry_msg = f"🔄 [THỬ LẠI] Bắt đầu lượt thử lại lần {job.retry_count}..."
        job.logs.append(retry_msg)
        try:
            self.job_repo.add_log(job.id, retry_msg)
        except Exception:
            pass
        self.job_repo.update_status(
            job.id, "queued", secret=job.secret,
            password=job.password, account_check=self._state(job),
        )
        self._queue.put_nowait(job.id)
        self._broadcast(job)
        return job.snapshot()

    def stop(self, job_id: str) -> dict[str, Any]:
        job = self._require(job_id)
        task = self._tasks.get(job_id)
        if task:
            task.cancel()
        elif job.status == "queued":
            job.status = "cancelled"
            job.error = "Đã dừng bởi người dùng"
            self.job_repo.update_status(job.id, "cancelled", error=job.error)
            self._broadcast(job)
        return job.snapshot()

    def stop_all(self) -> None:
        for job in list(self.jobs.values()):
            if job.status in {"queued", "running"}:
                self.stop(job.id)

    def delete(self, job_id: str) -> None:
        job = self._require(job_id)
        if job.status not in TERMINAL:
            raise ValueError("Không thể xóa job đang chạy")
        self.job_repo.delete(job_id)
        self.jobs.pop(job_id, None)
        self.order = [item for item in self.order if item != job_id]
        self._broadcast_raw({"type": "removed", "id": job_id})

    def clear(self) -> int:
        if any(job.status not in TERMINAL for job in self.jobs.values()):
            raise ValueError("Hãy dừng toàn bộ job trước khi dọn danh sách")
        count = self.job_repo.delete_all(JOB_TYPE)
        self.jobs.clear()
        self.order.clear()
        self._broadcast_raw({"type": "snapshot", "jobs": []})
        return count

    def output(self) -> list[str]:
        lines = []
        for job in self.jobs.values():
            if job.status != "success" or not job.login_verified:
                continue
            if job.mode == "check_only":
                continue  # check_only không đưa vào output
            effective_pass = job.new_password if (job.new_password and job.mode in {
                "change_password", "change_password_and_2fa"
            }) else job.password
            lines.append("|".join((job.email, effective_pass, job.secret)))
        return lines

    def snapshots(self) -> list[dict[str, Any]]:
        return [self.jobs[job_id].snapshot() for job_id in self.order if job_id in self.jobs]

    def logs(self, job_id: str) -> list[str]:
        return list(self._require(job_id).logs)

    async def update_settings(self, values: dict[str, Any]) -> dict[str, Any]:
        previous = int(self.settings["twofa.max_concurrent"])
        for key, value in values.items():
            if key not in self.DEFAULTS:
                raise ValueError(f"Setting không hỗ trợ: {key}")
            self.settings_repo.set(key, value)
            self.settings[key] = value
        target = int(self.settings["twofa.max_concurrent"])
        if target != previous:
            await self._resize_workers(previous, target)
        return dict(self.settings)

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    def _broadcast(self, job: TwoFAJob) -> None:
        self._broadcast_raw({"type": "job", "job": job.snapshot()})

    def _broadcast_raw(self, payload: dict[str, Any]) -> None:
        for queue in list(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(payload)

    def _require(self, job_id: str) -> TwoFAJob:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        return job
