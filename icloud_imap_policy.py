"""Safety policy for high-volume iCloud Hide My Email polling."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ICloudImapPolicy:
    """Validated limits shared by Settings, scheduler, and IMAP cleanup."""

    daily_attempt_limit: int = 200
    min_start_interval_seconds: float = 30.0
    cleanup_after_hours: float = 24.0

    DAILY_MIN = 1
    INTERVAL_MIN = 5.0
    INTERVAL_MAX = 300.0
    CLEANUP_MIN = 1.0
    CLEANUP_MAX = 720.0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "ICloudImapPolicy":
        data = value or {}
        raw_daily = data.get("daily_attempt_limit", cls.daily_attempt_limit)
        raw_interval = data.get(
            "min_start_interval_seconds",
            cls.min_start_interval_seconds,
        )
        raw_cleanup = data.get("cleanup_after_hours", cls.cleanup_after_hours)
        if any(isinstance(item, bool) for item in (raw_daily, raw_interval, raw_cleanup)):
            raise ValueError("iCloud IMAP safety policy values must be numeric")
        if isinstance(raw_daily, float) and not raw_daily.is_integer():
            raise ValueError("daily_attempt_limit must be an integer")
        try:
            daily = int(raw_daily)
            interval = float(raw_interval)
            cleanup = float(raw_cleanup)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid iCloud IMAP safety policy value") from exc

        if daily < cls.DAILY_MIN:
            raise ValueError(f"daily_attempt_limit must be >= {cls.DAILY_MIN}")
        if not cls.INTERVAL_MIN <= interval <= cls.INTERVAL_MAX:
            raise ValueError(
                "min_start_interval_seconds must be "
                f"{cls.INTERVAL_MIN:g}..{cls.INTERVAL_MAX:g}"
            )
        if not cls.CLEANUP_MIN <= cleanup <= cls.CLEANUP_MAX:
            raise ValueError(
                f"cleanup_after_hours must be {cls.CLEANUP_MIN:g}..{cls.CLEANUP_MAX:g}"
            )
        return cls(
            daily_attempt_limit=daily,
            min_start_interval_seconds=interval,
            cleanup_after_hours=cleanup,
        )

    def to_config(self) -> dict[str, int | float]:
        return {
            "daily_attempt_limit": self.daily_attempt_limit,
            "min_start_interval_seconds": self.min_start_interval_seconds,
            "cleanup_after_hours": self.cleanup_after_hours,
        }
