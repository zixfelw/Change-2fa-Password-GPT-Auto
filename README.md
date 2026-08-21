# Change 2fa Password GPT - Auto

Tự động kiểm tra, đổi mật khẩu và xoay TOTP 2FA cho tài khoản ChatGPT — điều khiển qua giao diện web cục bộ.

> **Runtime:** Python 3.11–3.13 · **UI:** FastAPI + vanilla JS · **DB:** SQLite · **Browser:** Camoufox (Firefox anti-detect)

---

## Tính năng

| Chế độ | Mô tả |
|--------|-------|
| **Kiểm tra** | Login → xác minh trạng thái tài khoản (live/die) + gói (Free/Plus). |
| **Đổi 2FA** | Login → xoay TOTP secret → xác minh login lại bằng secret mới. |
| **Đổi mật khẩu** | Login → tạo mật khẩu mới ngẫu nhiên → xác minh login bằng mật khẩu mới. |
| **Đổi mật khẩu + 2FA** | Login → đổi mật khẩu → xoay TOTP → xác minh toàn bộ. |

**Cơ chế chung:**
- Multi-job song song (1–10 workers).
- Realtime log + trạng thái qua SSE.
- Auto-retry khi lỗi transient.
- SQLite Settings Store — cấu hình runtime duy nhất.
- Browser Camoufox tự tải và cô lập cache theo project.

---

## Cài đặt (Windows)

**Yêu cầu:** Python 3.11–3.13, internet (tải dependencies + Camoufox browser lần đầu).

```
setup.bat
```

Script tự động:
1. Tạo `.venv/` + cài dependencies.
2. Wiring package import.
3. Cài Playwright Chromium (fallback).
4. Tải Camoufox browser build ghim.
5. Tạo `.env` mặc định + runtime directories.

---

## Khởi động

**Double-click:**
```
change 2fa community\khoidongoday.bat
```

Launcher sẽ:
- Khởi động server ẩn trên `127.0.0.1:5033`.
- Lần đầu có thể mất 1–3 phút để tải Camoufox browser.
- Tự mở trình duyệt khi server sẵn sàng.

**Hoặc chạy thủ công:**
```
.venv\Scripts\python "change 2fa community\server.py" --host 127.0.0.1 --port 5033
```

---

## Sử dụng

1. Mở `http://127.0.0.1:5033` trong trình duyệt.
2. Paste danh sách tài khoản theo format: `email|password|totp_secret` (mỗi dòng 1 tài khoản).
3. Chọn chế độ (Kiểm tra / Đổi 2FA / Đổi mật khẩu / Đổi cả hai).
4. Nhấn **Bắt đầu**.
5. Theo dõi trạng thái realtime. Click vào dòng tài khoản để xem log chi tiết.
6. Kết quả thành công xuất ở panel Output (copy hoặc download).

---

## Cấu trúc

```
change 2fa community/
├── server.py          — FastAPI control plane
├── jobs.py            — Job manager + SQLite persistence
├── service.py         — Core orchestration (login → rotate → verify)
├── khoidongoday.bat   — Windows launcher
└── static/            — Frontend (HTML/CSS/JS)

session_phase.py       — Login + password change
mfa_phase.py           — TOTP 2FA rotation
request_phase.py       — Pure HTTP request engine
config.py              — Settings + env parsing
db/                    — SQLite persistence layer
_camoufox_runtime.py   — Browser cache isolation
```

---

## Dữ liệu

- Database SQLite lưu tại `%LOCALAPPDATA%\InfinityAIStore\Change2FA\twofa.db`.
- Browser cache tại `runtime\camoufox-cache\` (trong project folder).
- Không gửi dữ liệu ra ngoài — toàn bộ chạy local trên `127.0.0.1`.

---

## License

MIT — xem [LICENSE](LICENSE).
