"""Core orchestration for Infinity AI Store Change 2FA Community."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable


LogFn = Callable[[str], None]
CheckpointFn = Callable[[str], Awaitable[None]]
PasswordCheckpointFn = Callable[[str, str], Awaitable[None]]  # (new_password, new_secret)
LoginFn = Callable[..., Awaitable[dict[str, Any]]]
RotateFn = Callable[..., Awaitable[dict[str, Any]]]
EntitlementFn = Callable[..., Awaitable[dict[str, Any]]]
ChangePasswordFn = Callable[..., Awaitable[None]]


class TwoFAFlowError(RuntimeError):
    """A fail-fast error safe to display in the local control plane."""

    def __init__(
        self,
        message: str,
        *,
        error_kind: str = "technical_error",
        account_state: str = "unknown",
    ) -> None:
        super().__init__(message)
        self.error_kind = error_kind
        self.account_state = account_state


@dataclass(frozen=True, slots=True)
class RotationResult:
    secret: str
    login_verified: bool
    account_state: str = "live"
    plan: str | None = None
    plan_source: str | None = None
    plan_expires: str | None = None
    is_trial: bool | None = None
    usage_summary: str | None = None
    usage_info: dict[str, Any] | None = None


class TwoFAService:
    """Run the smallest safe 2FA rotation flow using the existing core APIs."""

    def __init__(
        self,
        *,
        login_fn: LoginFn | None = None,
        rotate_fn: RotateFn | None = None,
        entitlement_fn: EntitlementFn | None = None,
        change_password_fn: ChangePasswordFn | None = None,
        login_attempts: int = 3,
        retry_delay: float = 3.0,
    ) -> None:
        self._login_fn = login_fn
        self._rotate_fn = rotate_fn
        self._entitlement_fn = entitlement_fn
        self._change_password_fn = change_password_fn
        self._login_attempts = login_attempts
        self._retry_delay = retry_delay

    @staticmethod
    def _resolve_dependencies() -> tuple[LoginFn, RotateFn]:
        from mfa_phase import rotate_2fa
        from session_phase import get_session_pure_request

        return get_session_pure_request, rotate_2fa

    @staticmethod
    def _resolve_password_fn() -> ChangePasswordFn:
        from session_phase import change_password_with_session

        return change_password_with_session

    @staticmethod
    def _generate_new_password(current_password: str) -> str:
        from session_phase import generate_random_password

        return generate_random_password(previous_password=current_password)

    @staticmethod
    def _clean_error_message(exc: BaseException | str | None) -> str:
        if exc is None:
            return "Lỗi không xác định"
        msg = str(exc).strip()
        msg_lower = msg.lower()
        if "account deactivated" in msg_lower or "deactivated" in msg_lower or "banned" in msg_lower:
            return "Tài khoản bị vô hiệu hóa hoặc xóa (Account Deactivated)"
        if "invalid_password" in msg_lower or "sai mật khẩu" in msg_lower or "invalid credential" in msg_lower or "invalid password" in msg_lower:
            return "Sai mật khẩu tài khoản"
        if "push_auth_required" in msg_lower or "push auth" in msg_lower:
            return "Tài khoản yêu cầu phê duyệt trên điện thoại (Push Auth)"
        if "2fa_failed" in msg_lower or "mã 2fa" in msg_lower or "incorrect_code" in msg_lower:
            return "Mã 2FA (OTP) không đúng hoặc Secret cũ không khớp"
        if "không có secret" in msg_lower or "thiếu secret" in msg_lower:
            return "Tài khoản yêu cầu 2FA nhưng không có mã Secret"
        if "cloudflare challenge" in msg_lower or "http 403" in msg_lower:
            return "Cloudflare chặn kết nối (HTTP 403)"
        if "timeout" in msg_lower:
            return "Quá thời gian chờ phản hồi từ OpenAI (Timeout)"
        if "too many redirect" in msg_lower:
            return "Lỗi vòng lặp chuyển hướng kết nối"
        if "network" in msg_lower or "transport" in msg_lower:
            return "Lỗi kết nối mạng tới OpenAI"
        # Làm sạch các prefix exception
        clean = msg.splitlines()[0] if msg else "Lỗi không xác định"
        for prefix in ("SessionError: ", "TwoFAFlowError: ", "LoginError: ", "Exception: "):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        return clean[:140]

    async def _login(
        self,
        *,
        email: str,
        password: str,
        secret: str,
        timeout: float,
        log: LogFn,
    ) -> dict[str, Any]:
        from session_phase import (
            classify_account_check_error,
            is_fatal_login_error,
        )

        default_login, _ = self._resolve_dependencies()
        login_fn = self._login_fn or default_login
        last_error: BaseException | None = None
        for attempt in range(1, self._login_attempts + 1):
            try:
                session = await asyncio.wait_for(
                    login_fn(
                        email=email,
                        password=password,
                        secret=secret,
                        proxy=None,
                        log=log,
                    ),
                    timeout=timeout,
                )
                token = session.get("accessToken")
                if not isinstance(token, str) or not token.strip():
                    raise TwoFAFlowError("Đăng nhập không trả về access token", error_kind="technical_error")
                return session
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_error = exc
                fatal = is_fatal_login_error(exc)
                if fatal or attempt >= self._login_attempts:
                    break
                clean_err = self._clean_error_message(exc)
                log(f"   ⚠️ [Thử lại {attempt}/{self._login_attempts}] Kết nối tạm thời gián đoạn ({clean_err}). Đang kết nối lại sau {self._retry_delay:.0f}s...")
                await asyncio.sleep(self._retry_delay)

        account_state = (
            "die"
            if classify_account_check_error(last_error) == "deactivated"
            else "unknown"
        )
        is_fatal = last_error is not None and is_fatal_login_error(last_error)
        error_kind = (
            "account_die"
            if account_state == "die"
            else "invalid_credentials"
            if is_fatal
            else "technical_error"
        )
        clean_msg = self._clean_error_message(last_error)
        raise TwoFAFlowError(
            clean_msg,
            error_kind=error_kind,
            account_state=account_state,
        ) from last_error

    @staticmethod
    def _normalize_plan_label(value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        s = value.strip().casefold()
        if s.startswith("chatgpt"):
            s = s[len("chatgpt"):]
        if s.endswith("plan"):
            s = s[:-len("plan")]
        return s or None

    @classmethod
    def _session_plan(cls, session: dict[str, Any]) -> str | None:
        if not isinstance(session, dict):
            return None
        account = session.get("account")
        if isinstance(account, dict):
            pt = account.get("planType")
            normalized = cls._normalize_plan_label(pt)
            if normalized:
                return normalized
        top = session.get("accountPlan")
        normalized = cls._normalize_plan_label(top)
        if normalized:
            return normalized
        return None

    async def _check_plan(
        self,
        *,
        session: dict[str, Any],
        timeout: float,
        log: LogFn,
    ) -> tuple[str | None, str | None, str | None, bool | None, str | None, dict[str, Any] | None]:
        from session_phase import fetch_account_entitlement, fetch_account_usage

        fallback = self._session_plan(session)
        entitlement_fn = self._entitlement_fn or fetch_account_entitlement
        token = str(session["accessToken"])
        cookies = session.get("__cookies")
        account_id = None
        if isinstance(session.get("account"), dict):
            account_id = session["account"].get("id")

        async def _do_entitlement():
            return await entitlement_fn(
                access_token=token,
                cookies=cookies,
                proxy=None,
                timeout=min(timeout, 20.0),
            )

        async def _do_usage():
            return await fetch_account_usage(
                access_token=token,
                account_id=account_id,
                cookies=cookies,
                proxy=None,
                timeout=min(timeout, 15.0),
            )

        ent_res, usage_res = await asyncio.gather(
            asyncio.wait_for(_do_entitlement(), timeout=min(timeout, 25.0)),
            asyncio.wait_for(_do_usage(), timeout=min(timeout, 18.0)),
            return_exceptions=True,
        )

        usage_summary = None
        usage_info = None
        if isinstance(usage_res, dict):
            usage_info = usage_res
            usage_summary = usage_res.get("status_text")
        elif isinstance(usage_res, Exception) and not isinstance(usage_res, asyncio.CancelledError):
            pass

        if isinstance(ent_res, Exception):
            if isinstance(ent_res, asyncio.CancelledError):
                raise ent_res
            if fallback:
                log(f"[account] Entitlement chưa đọc được; dùng session plan {fallback.upper()}")
                return fallback, "session", None, False, usage_summary, usage_info
            log(f"[account] Chưa xác định được gói: {type(ent_res).__name__}")
            return None, None, None, None, usage_summary, usage_info

        payload = ent_res
        has_active = bool(payload.get("has_active_subscription"))
        is_plus = bool(payload.get("is_plus"))
        is_trial = bool(payload.get("is_trial"))
        ent_plan = payload.get("plan")
        raw_expires = payload.get("expires")
        plan_expires = str(raw_expires) if raw_expires else None

        trial_suffix = " · TRIAL" if is_trial else ""
        quota_suffix = f" · Quota: {usage_summary}" if usage_summary else ""

        if is_plus:
            plan = "plus"
            date_str = plan_expires[:10] if plan_expires else ""
            date_msg = f" (Hết hạn: {date_str})" if date_str else ""
            log(f"[account] Tài khoản live · gói PLUS{date_msg}{trial_suffix}{quota_suffix}")
        elif has_active and ent_plan:
            plan = str(ent_plan).strip().casefold()
            date_str = plan_expires[:10] if plan_expires else ""
            date_msg = f" (Hết hạn: {date_str})" if date_str else ""
            log(f"[account] Tài khoản live · gói {plan.upper()}{date_msg}{trial_suffix}{quota_suffix}")
        else:
            plan = "free"
            plan_expires = None
            log(f"[account] Tài khoản live · gói FREE{trial_suffix}{quota_suffix}")

        return plan, "entitlement", plan_expires, is_trial, usage_summary, usage_info

    async def check(
        self,
        *,
        email: str,
        password: str,
        secret: str,
        timeout: float,
        log: LogFn,
    ) -> RotationResult:
        """Authenticate and classify the account without changing its TOTP secret."""
        log("[1/2] 🔑 Đang đăng nhập kiểm tra tài khoản...")
        session = await self._login(
            email=email,
            password=password,
            secret=secret,
            timeout=timeout,
            log=log,
        )
        log("[2/2] 📋 Đang kiểm tra gói dịch vụ (Free/Plus), Trial & Quota...")
        plan, plan_source, plan_expires, is_trial, usage_summary, usage_info = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )
        plan_str = (plan or "free").upper()
        trial_str = " · TRIAL" if is_trial else ""
        quota_str = f" · Quota: {usage_summary}" if usage_summary else ""
        if plan == "plus" and plan_expires:
            date_short = plan_expires[:10]
            log(f"[HOÀN TẤT] Kiểm tra thành công — Gói: PLUS (Hết hạn: {date_short}){trial_str}{quota_str} (Không thay đổi 2FA)")
        else:
            log(f"[HOÀN TẤT] Kiểm tra thành công — Gói: {plan_str}{trial_str}{quota_str} (Không thay đổi 2FA)")
        return RotationResult(
            secret=secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
            plan_expires=plan_expires,
            is_trial=is_trial,
            usage_summary=usage_summary,
            usage_info=usage_info,
        )

    async def rotate(
        self,
        *,
        email: str,
        password: str,
        old_secret: str,
        timeout: float,
        checkpoint: CheckpointFn,
        log: LogFn,
    ) -> RotationResult:
        """Rotate once and persist the new secret before fresh-login verification."""
        log("[1/3] 🔑 Đang đăng nhập bằng 2FA hiện tại...")
        session = await self._login(
            email=email,
            password=password,
            secret=old_secret,
            timeout=timeout,
            log=log,
        )
        access_token = str(session["accessToken"])
        plan, plan_source, plan_expires, is_trial, usage_summary, usage_info = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )

        log("[2/3] 🔄 Đang đổi mã 2FA an toàn (Safe-Lock)...")
        _, default_rotate = self._resolve_dependencies()
        rotate_fn = self._rotate_fn or default_rotate

        async def _early_checkpoint(data: dict[str, Any]) -> None:
            sec = str(data.get("secret") or "").strip()
            if sec:
                await checkpoint(sec)
                masked = f"{sec[:6]}...{sec[-4:]}" if len(sec) > 10 else sec
                log(f"   ↳ [Safe-Lock] Đã lưu mã Secret mới vào hệ thống ({masked})")

        try:
            # Cho phép tối thiểu 60s để các vòng retry Safe-Lock hoàn thành mà không bị cancel
            rotate_timeout = max(timeout, 60.0)
            payload = await asyncio.wait_for(
                rotate_fn(
                    access_token=access_token,
                    cookies=session.get("__cookies"),
                    proxy=None,
                    on_enroll=_early_checkpoint,
                    log=log,
                ),
                timeout=rotate_timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            partial = getattr(exc, "partial_state", None)
            if isinstance(partial, dict) and partial.get("secret"):
                try:
                    await checkpoint(str(partial["secret"]))
                    log("   ↳ [Cứu hộ Safe-Lock] Đã lưu emergency secret vào hệ thống trước khi báo lỗi!")
                except Exception:
                    pass
            detail = self._clean_error_message(exc)
            raise TwoFAFlowError(f"Đổi 2FA thất bại: {detail}", error_kind="technical_error") from exc

        new_secret = str(payload.get("secret") or "").strip()
        if payload.get("activated") is not True or not new_secret:
            raise TwoFAFlowError("Secret mới chưa được kích hoạt thành công trên OpenAI", error_kind="technical_error")

        await checkpoint(new_secret)
        await self.verify(
            email=email,
            password=password,
            new_secret=new_secret,
            timeout=timeout,
            log=log,
        )
        log(f"[THÀNH CÔNG] Đổi 2FA hoàn tất an toàn! Khóa mới: {new_secret}")
        return RotationResult(
            secret=new_secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
            plan_expires=plan_expires,
            is_trial=is_trial,
            usage_summary=usage_summary,
            usage_info=usage_info,
        )

    async def verify(
        self,
        *,
        email: str,
        password: str,
        new_secret: str,
        timeout: float,
        log: LogFn,
    ) -> RotationResult:
        """Verify an already-checkpointed secret without rotating again."""
        log("[3/3] 🛡️ Đang đăng nhập xác minh bằng 2FA mới...")
        session = await self._login(
            email=email,
            password=password,
            secret=new_secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source, plan_expires, is_trial, usage_summary, usage_info = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )
        log("   ↳ [Xác minh] Đăng nhập thành công với mã 2FA mới!")
        return RotationResult(
            secret=new_secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
            plan_expires=plan_expires,
            is_trial=is_trial,
            usage_summary=usage_summary,
            usage_info=usage_info,
        )

    async def change_password(
        self,
        *,
        email: str,
        password: str,
        secret: str,
        timeout: float,
        checkpoint: PasswordCheckpointFn,
        log: LogFn,
    ) -> RotationResult:
        """Đổi mật khẩu — giữ nguyên 2FA. Checkpoint ngay sau khi đổi xong."""
        log("[1/3] 🔑 Đang đăng nhập tài khoản để đổi mật khẩu...")
        session = await self._login(
            email=email,
            password=password,
            secret=secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source, plan_expires, is_trial, usage_summary, usage_info = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )

        log("[2/3] 🔐 Đang tạo và đổi mật khẩu mới...")
        new_password = self._generate_new_password(password)

        change_fn = self._change_password_fn or self._resolve_password_fn()
        try:
            await asyncio.wait_for(
                change_fn(
                    session_data=session,
                    current_password=password,
                    new_password=new_password,
                    secret=secret,
                    headless=True,
                    log=log,
                ),
                timeout=timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            detail = self._clean_error_message(exc)
            raise TwoFAFlowError(f"Đổi mật khẩu thất bại: {detail}", error_kind="technical_error") from exc

        await checkpoint(new_password, secret)
        log(f"   ↳ [Safe-Lock] Mật khẩu mới đã được lưu an toàn: {new_password}")

        log("[3/3] 🛡️ Đang đăng nhập kiểm tra lại bằng mật khẩu mới...")
        session2 = await self._login(
            email=email,
            password=new_password,
            secret=secret,
            timeout=timeout,
            log=log,
        )
        plan2, plan_source2, plan_expires2, is_trial2, usage_summary2, usage_info2 = await self._check_plan(
            session=session2,
            timeout=timeout,
            log=log,
        )
        log("[THÀNH CÔNG] Đổi mật khẩu hoàn tất an toàn!")
        return RotationResult(
            secret=secret,
            login_verified=True,
            account_state="live",
            plan=plan2 or plan,
            plan_source=plan_source2 or plan_source,
            plan_expires=plan_expires2 or plan_expires,
            is_trial=is_trial2 if is_trial2 is not None else is_trial,
            usage_summary=usage_summary2 or usage_summary,
            usage_info=usage_info2 or usage_info,
        )

    async def rotate_with_password(
        self,
        *,
        email: str,
        password: str,
        old_secret: str,
        timeout: float,
        checkpoint: PasswordCheckpointFn,
        log: LogFn,
    ) -> RotationResult:
        """Đổi password rồi đổi 2FA. Checkpoint sau mỗi bước."""
        log("[1/4] 🔑 Đang đăng nhập với thông tin hiện tại...")
        session = await self._login(
            email=email,
            password=password,
            secret=old_secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source, plan_expires, is_trial, usage_summary, usage_info = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )

        log("[2/4] 🔐 Đang tạo và đổi mật khẩu mới...")
        new_password = self._generate_new_password(password)
        change_fn = self._change_password_fn or self._resolve_password_fn()
        try:
            await asyncio.wait_for(
                change_fn(
                    session_data=session,
                    current_password=password,
                    new_password=new_password,
                    secret=old_secret,
                    headless=True,
                    log=log,
                ),
                timeout=timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            detail = self._clean_error_message(exc)
            raise TwoFAFlowError(f"Đổi mật khẩu thất bại: {detail}", error_kind="technical_error") from exc

        # Checkpoint password mới, secret chưa đổi
        await checkpoint(new_password, old_secret)
        log(f"   ↳ [Safe-Lock] Mật khẩu mới đã được lưu an toàn: {new_password}")

        # Đăng nhập lại với password mới để lấy session mới
        log("[3/4] 🔄 Đang đổi mã 2FA an toàn (Safe-Lock)...")
        session2 = await self._login(
            email=email,
            password=new_password,
            secret=old_secret,
            timeout=timeout,
            log=log,
        )
        access_token = str(session2["accessToken"])

        _, default_rotate = self._resolve_dependencies()
        rotate_fn = self._rotate_fn or default_rotate

        async def _early_checkpoint_pwd(data: dict[str, Any]) -> None:
            sec = str(data.get("secret") or "").strip()
            if sec:
                await checkpoint(new_password, sec)
                masked = f"{sec[:6]}...{sec[-4:]}" if len(sec) > 10 else sec
                log(f"   ↳ [Safe-Lock] Password và Secret mới đã được lưu an toàn ({masked})")

        try:
            rotate_timeout = max(timeout, 60.0)
            payload = await asyncio.wait_for(
                rotate_fn(
                    access_token=access_token,
                    cookies=session2.get("__cookies"),
                    proxy=None,
                    on_enroll=_early_checkpoint_pwd,
                    log=log,
                ),
                timeout=rotate_timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            partial = getattr(exc, "partial_state", None)
            if isinstance(partial, dict) and partial.get("secret"):
                try:
                    await checkpoint(new_password, str(partial["secret"]))
                    log("   ↳ [Cứu hộ Safe-Lock] Đã lưu emergency password + secret vào hệ thống!")
                except Exception:
                    pass
            detail = self._clean_error_message(exc)
            raise TwoFAFlowError(f"Đổi 2FA thất bại: {detail}", error_kind="technical_error") from exc

        new_secret = str(payload.get("secret") or "").strip()
        if payload.get("activated") is not True or not new_secret:
            raise TwoFAFlowError("Secret mới chưa được kích hoạt thành công trên OpenAI", error_kind="technical_error")

        # Checkpoint cả password mới + secret mới
        await checkpoint(new_password, new_secret)

        log("[4/4] 🛡️ Xác minh đăng nhập với password và 2FA mới...")
        await self.verify(
            email=email,
            password=new_password,
            new_secret=new_secret,
            timeout=timeout,
            log=log,
        )
        log(f"[THÀNH CÔNG] Đổi mật khẩu và 2FA hoàn tất an toàn! Khóa mới: {new_secret}")
        return RotationResult(
            secret=new_secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
            plan_expires=plan_expires,
            is_trial=is_trial,
            usage_summary=usage_summary,
            usage_info=usage_info,
        )
