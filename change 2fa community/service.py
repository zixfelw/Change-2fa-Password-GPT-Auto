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
                    raise TwoFAFlowError("Đăng nhập không trả về access token")
                return session
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                last_error = exc
                if is_fatal_login_error(exc) or attempt >= self._login_attempts:
                    break
                log(f"[login] lần {attempt}/{self._login_attempts} chưa thành công — thử lại...")
                await asyncio.sleep(self._retry_delay)
        detail = str(last_error).strip() if last_error else "unknown login error"
        account_state = (
            "die"
            if classify_account_check_error(last_error) == "deactivated"
            else "unknown"
        )
        error_kind = (
            "account_die"
            if account_state == "die"
            else "invalid_credentials"
            if last_error is not None and is_fatal_login_error(last_error)
            else "technical_error"
        )
        label = "Tài khoản die" if account_state == "die" else "Đăng nhập thất bại"
        raise TwoFAFlowError(
            f"{label}: {detail[:220]}",
            error_kind=error_kind,
            account_state=account_state,
        ) from last_error

    @staticmethod
    def _session_plan(session: dict[str, Any]) -> str | None:
        top = session.get("accountPlan")
        if isinstance(top, str) and top.strip():
            return top.strip().casefold()
        account = session.get("account")
        nested = account.get("planType") if isinstance(account, dict) else None
        return nested.strip().casefold() if isinstance(nested, str) and nested.strip() else None

    async def _check_plan(
        self,
        *,
        session: dict[str, Any],
        timeout: float,
        log: LogFn,
    ) -> tuple[str | None, str | None]:
        from session_phase import fetch_account_entitlement

        fallback = self._session_plan(session)
        entitlement_fn = self._entitlement_fn or fetch_account_entitlement
        try:
            payload = await asyncio.wait_for(
                entitlement_fn(
                    access_token=str(session["accessToken"]),
                    cookies=session.get("__cookies"),
                    proxy=None,
                    timeout=min(timeout, 20.0),
                ),
                timeout=min(timeout, 25.0),
            )
            plan = str(payload.get("plan") or "").strip().casefold()
            if not plan:
                plan = "plus" if payload.get("is_plus") is True else fallback or "free"
            log(f"[account] Tài khoản live · gói {plan.upper()}")
            return plan, "entitlement"
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if fallback:
                log(f"[account] Entitlement chưa đọc được; dùng session plan {fallback.upper()}")
                return fallback, "session"
            log(f"[account] Chưa xác định được gói: {type(exc).__name__}")
            return None, None

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
        log("[1/2] Đang xác thực tài khoản — chế độ chỉ kiểm tra...")
        session = await self._login(
            email=email,
            password=password,
            secret=secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )
        log("[done] Đã kiểm tra tài khoản; không thay đổi 2FA")
        return RotationResult(
            secret=secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
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
        log("[1/3] Đang xác thực tài khoản với 2FA hiện tại...")
        session = await self._login(
            email=email,
            password=password,
            secret=old_secret,
            timeout=timeout,
            log=log,
        )
        access_token = str(session["accessToken"])
        plan, plan_source = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )

        log("[2/3] Đang thay thế khóa TOTP...")
        _, default_rotate = self._resolve_dependencies()
        rotate_fn = self._rotate_fn or default_rotate
        try:
            payload = await asyncio.wait_for(
                rotate_fn(
                    access_token=access_token,
                    cookies=session.get("__cookies"),
                    proxy=None,
                    log=log,
                ),
                timeout=timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            detail = str(exc).strip() or type(exc).__name__
            raise TwoFAFlowError(f"Đổi 2FA thất bại: {detail[:220]}") from exc

        new_secret = str(payload.get("secret") or "").strip()
        if payload.get("activated") is not True or not new_secret:
            raise TwoFAFlowError("Secret mới chưa được kích hoạt")

        await checkpoint(new_secret)
        log("[checkpoint] Secret mới đã được lưu an toàn")
        await self.verify(
            email=email,
            password=password,
            new_secret=new_secret,
            timeout=timeout,
            log=log,
        )
        return RotationResult(
            secret=new_secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
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
        log("[3/3] Đang đăng nhập lại bằng 2FA mới...")
        session = await self._login(
            email=email,
            password=password,
            secret=new_secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )
        log("[done] 2FA mới đã được xác minh thành công")
        return RotationResult(
            secret=new_secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
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
        log("[1/3] Đang đăng nhập để đổi mật khẩu...")
        session = await self._login(
            email=email,
            password=password,
            secret=secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )

        log("[2/3] Đang tạo mật khẩu mới...")
        new_password = self._generate_new_password(password)

        log("[2/3] Đang đổi mật khẩu qua Account UI...")
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
            detail = str(exc).strip() or type(exc).__name__
            raise TwoFAFlowError(f"Đổi mật khẩu thất bại: {detail[:220]}") from exc

        await checkpoint(new_password, secret)
        log("[checkpoint] Mật khẩu mới đã được lưu an toàn")

        log("[3/3] Đang xác minh đăng nhập với mật khẩu mới...")
        session2 = await self._login(
            email=email,
            password=new_password,
            secret=secret,
            timeout=timeout,
            log=log,
        )
        plan2, plan_source2 = await self._check_plan(
            session=session2,
            timeout=timeout,
            log=log,
        )
        log("[done] Mật khẩu mới đã được xác minh thành công")
        return RotationResult(
            secret=secret,
            login_verified=True,
            account_state="live",
            plan=plan2 or plan,
            plan_source=plan_source2 or plan_source,
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
        log("[1/4] Đang đăng nhập với thông tin hiện tại...")
        session = await self._login(
            email=email,
            password=password,
            secret=old_secret,
            timeout=timeout,
            log=log,
        )
        plan, plan_source = await self._check_plan(
            session=session,
            timeout=timeout,
            log=log,
        )

        log("[2/4] Đang tạo và đổi mật khẩu mới...")
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
            detail = str(exc).strip() or type(exc).__name__
            raise TwoFAFlowError(f"Đổi mật khẩu thất bại: {detail[:220]}") from exc

        # Checkpoint password mới, secret chưa đổi
        await checkpoint(new_password, old_secret)
        log("[checkpoint] Mật khẩu mới đã được lưu — bắt đầu đổi 2FA")

        # Đăng nhập lại với password mới để lấy session mới
        log("[3/4] Đăng nhập lại với mật khẩu mới để đổi 2FA...")
        session2 = await self._login(
            email=email,
            password=new_password,
            secret=old_secret,
            timeout=timeout,
            log=log,
        )
        access_token = str(session2["accessToken"])

        log("[3/4] Đang thay thế khóa TOTP...")
        _, default_rotate = self._resolve_dependencies()
        rotate_fn = self._rotate_fn or default_rotate
        try:
            payload = await asyncio.wait_for(
                rotate_fn(
                    access_token=access_token,
                    cookies=session2.get("__cookies"),
                    proxy=None,
                    log=log,
                ),
                timeout=timeout,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            detail = str(exc).strip() or type(exc).__name__
            raise TwoFAFlowError(f"Đổi 2FA thất bại: {detail[:220]}") from exc

        new_secret = str(payload.get("secret") or "").strip()
        if payload.get("activated") is not True or not new_secret:
            raise TwoFAFlowError("Secret mới chưa được kích hoạt")

        # Checkpoint cả password mới + secret mới
        await checkpoint(new_password, new_secret)
        log("[checkpoint] Password + Secret mới đã được lưu an toàn")

        log("[4/4] Đang xác minh với password + 2FA mới...")
        await self.verify(
            email=email,
            password=new_password,
            new_secret=new_secret,
            timeout=timeout,
            log=log,
        )
        log("[done] Password và 2FA mới đã được xác minh thành công")
        return RotationResult(
            secret=new_secret,
            login_verified=True,
            account_state="live",
            plan=plan,
            plan_source=plan_source,
        )
