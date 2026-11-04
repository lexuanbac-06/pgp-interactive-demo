# PGP Demo (mô phỏng học tập)

Ứng dụng Python với giao diện web chạy cục bộ và CLI tương tác để minh họa
keyring, ASCII armor, ký RSA-PSS, mã hóa lai RSA-OAEP + AES-256-GCM, xác minh
chữ ký và thử sửa gói tin.

> Đây là định dạng mô phỏng, không tương thích OpenPGP và không dành cho dữ liệu
> thật. Không chia sẻ gói tin nhạy cảm hoặc dùng thay phần mềm PGP đã được kiểm
> chứng.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên và Node.js 20.19 trở lên để build giao diện React.

```powershell
python -m pip install -r requirements.txt
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build
python -m pgp_demo.web
```

Mở `http://127.0.0.1:8000` trong trình duyệt. Máy chủ chỉ lắng nghe trên máy
cục bộ. Có thể đổi cổng hoặc thư mục lưu dữ liệu:

```powershell
python -m pgp_demo.web --port 8080 --data-dir .\data
```

Khi chỉnh sửa giao diện React/TypeScript, build lại bằng
`npm.cmd --prefix frontend run build`. Để phát triển với Vite hot reload, chạy
backend bằng `python -m pgp_demo.web` ở một terminal và
`npm.cmd --prefix frontend run dev` ở terminal khác, rồi mở
`http://127.0.0.1:5173`.

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

Giao diện web được xây dựng bằng React và TypeScript. Mỗi lần bấm “Tiếp theo”
mới thực thi bước gửi/nhận tương ứng; backend chỉ trả kết quả của bước vừa chạy.
Vì vậy lỗi định dạng, mở khóa, giải mã hoặc xác minh chỉ xuất hiện khi quy trình
chạm đến bước đó. Phiên xử lý tạm thời được lưu trong bộ nhớ máy chủ và hết hạn
sau 15 phút. Luồng gửi được gộp thành: tạo chữ ký số, nén dữ liệu, sinh khóa
phiên, mã hóa lai và đóng gói ASCII armor. Luồng nhận được gộp thành: tách armor,
mở khóa phiên, giải mã/giải nén và xác minh chữ ký. Armor của demo không có
CRC-24. Chữ ký RSA-PSS được xác minh trực tiếp trên plaintext; không thể giải
mã chữ ký để trích H1 như một số mô tả RSA khác. Giá trị khóa phiên AES được
ẩn. Đây chỉ là mô phỏng quy trình mật mã kiểu PGP; định dạng không tương thích
chuẩn OpenPGP.

## Kiểm thử

```powershell
python -m pytest
```
