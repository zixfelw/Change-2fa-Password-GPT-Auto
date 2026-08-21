# Change 2fa Password GPT - Auto

Tự động kiểm tra, đổi mật khẩu và xoay TOTP 2FA cho tài khoản ChatGPT qua
giao diện web chạy cục bộ.

> **Runtime:** Python 3.11–3.13 · **UI:** FastAPI + vanilla JS ·
> **DB:** SQLite · **Browser:** Camoufox

## Demo

[Xem video demo](demo.mp4)

<video src="demo.mp4" controls width="100%"></video>

---

## Chạy nhanh trên Windows

### 1. Giải nén source

Sau khi tải ZIP hoặc clone repo, mở thư mục chứa `khoidongoday.bat`:

```text
Change-2fa-Password-GPT-Auto\
```

### 2. Double-click `khoidongoday.bat`

Không cần chạy file nào khác.

- **Lần đầu:** launcher tự tạo `.venv`, cài dependencies, tải và kiểm tra
  Camoufox. Có thể mất vài phút tùy tốc độ mạng.
- **Những lần sau:** launcher khởi động server ẩn và tự mở dashboard tại
  `http://127.0.0.1:5033`.
- Nếu setup lỗi, cửa sổ sẽ giữ lại thông báo để sửa đúng nguyên nhân rồi chạy lại.

**Yêu cầu:** Python 3.11, 3.12 hoặc 3.13 đã được thêm vào `PATH` và có Internet
ở lần cài đầu tiên.

---

## Tính năng

| Chế độ | Mô tả |
|---|---|
| **Kiểm tra** | Login, kiểm tra live/die và gói Free/Plus. |
| **Đổi 2FA** | Xoay TOTP secret và xác minh đăng nhập bằng secret mới. |
| **Đổi mật khẩu** | Tạo mật khẩu mới và xác minh đăng nhập lại. |
| **Đổi mật khẩu + 2FA** | Đổi cả mật khẩu lẫn TOTP rồi xác minh toàn bộ. |

- Chạy song song 1–10 workers.
- Realtime log và trạng thái qua SSE.
- Auto-retry lỗi transient.
- SQLite Settings Store là nguồn cấu hình runtime duy nhất.
- Camoufox cache cô lập theo folder source.

---

## Sử dụng

1. Mở dashboard do `khoidongoday.bat` tự bật.
2. Paste mỗi tài khoản trên một dòng theo format
   `email|password|totp_secret`.
3. Chọn chế độ cần chạy.
4. Nhấn **Bắt đầu**.
5. Click một dòng tài khoản để mở/đóng log chi tiết bên phải.
6. Copy hoặc tải kết quả ở panel Output.

---

## Cấu trúc release

Toàn bộ chương trình nằm trong **một folder duy nhất**:

```text
change 2fa community/
├── khoidongoday.bat       # Double-click file này
├── setup.bat              # Được launcher tự gọi ở lần đầu
├── server.py
├── jobs.py
├── service.py
├── session_phase.py
├── mfa_phase.py
├── request_phase.py
├── _camoufox_runtime.py
├── camoufox-browser-spec.txt
├── requirements.txt
├── db/
├── scripts/
└── static/
```

Không di chuyển riêng `khoidongoday.bat` ra ngoài folder vì launcher cần các file
đi kèm tại đúng vị trí này.

---

## Dữ liệu local

- SQLite: `%LOCALAPPDATA%\InfinityAIStore\Change2FA\twofa.db`.
- Camoufox cache: `change 2fa community\runtime\camoufox-cache\`.
- `.venv`, runtime, database, cache và dữ liệu tài khoản đều bị loại khỏi Git/ZIP.
- Web server chỉ bind `127.0.0.1:5033`.

---

## Chạy thủ công

Sau khi setup hoàn tất:

```bat
.venv\Scripts\python.exe server.py --host 127.0.0.1 --port 5033
```

Lệnh được chạy từ bên trong folder `change 2fa community`.

---

## License

MIT — xem [LICENSE](LICENSE).
