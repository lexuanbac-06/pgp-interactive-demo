# PGP Demo (mô phỏng học tập)

Ứng dụng Python với giao diện web chạy cục bộ và CLI tương tác để minh họa
keyring, ASCII armor, ký RSA-PSS, mã hóa lai RSA-OAEP + AES-256-GCM, xác minh
chữ ký và thử sửa gói tin.

> Đây là định dạng mô phỏng, không tương thích OpenPGP và không dành cho dữ liệu
> thật. Không chia sẻ gói tin nhạy cảm hoặc dùng thay phần mềm PGP đã được kiểm
> chứng.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên.

```powershell
python -m pip install -r requirements.txt
python -m pgp_demo.web
```

Mở `http://127.0.0.1:8000` trong trình duyệt. Máy chủ chỉ lắng nghe trên máy
cục bộ. Có thể đổi cổng hoặc thư mục lưu dữ liệu:

```powershell
python -m pgp_demo.web --port 8080 --data-dir .\data
```

Để dùng menu terminal:

```powershell
python -m pgp_demo.cli
```

Tùy chọn chỉ định nơi lưu người dùng và keyring:

```powershell
python -m pgp_demo.cli --data-dir .\data
```

Chọn Alice, Bob hoặc Eve để mở menu. Mỗi người có thể tự tạo khóa RSA 2048/4096,
export/import khóa công khai, soạn tin có ký và/hoặc mã hóa, rồi giải mã và xác
minh. Muốn xác minh chữ ký, người nhận cần import khóa công khai của người ký.
Chế độ tấn công có thể sửa payload hoặc thử mở gói tin bằng Eve.

Khóa riêng lưu cục bộ trong thư mục người dùng và được mã hóa bằng passphrase.
Mỗi gói tin sử dụng khóa AES ngẫu nhiên; khóa phiên được bọc bằng RSA-OAEP,
nội dung nén bằng zlib và tùy chọn ký bằng RSA-PSS/SHA-256.

## Kiểm thử

```powershell
python -m pytest
```
