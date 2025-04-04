# Wireguard VPN Dashboard

Một máy chủ Wireguard VPN được container hóa với bảng điều khiển web để cấu hình và quản lý dễ dàng.

## Tính năng

- Bảng điều khiển web dễ sử dụng để quản lý Wireguard VPN
- Cấu hình máy khách thông qua mã QR
- Giao diện quản lý người dùng
- Thống kê và giám sát lưu lượng

## Yêu cầu

- Ubuntu/Debian (khuyến nghị) hoặc các bản phân phối Linux khác
- Các cổng mở: 51820/udp (Wireguard) và 10086/tcp (Bảng điều khiển)
- Python 3.8 trở lên
- pip (Python package manager)

## Hướng dẫn nhanh

### 1. Clone kho lưu trữ

```bash
git clone https://github.com/hepham/wireguard.git
cd wireguard-dashboard/src
```

### 2. Tạo và kích hoạt môi trường ảo

```bash
# Tạo môi trường ảo
python3 -m venv venv

# Kích hoạt môi trường ảo
# Trên Linux/Mac:
source venv/bin/activate
# Trên Windows:
.\venv\Scripts\activate
```

### 3. Cài đặt các yêu cầu

```bash
pip install -r requirements.txt
```

### 4. Cài đặt wireguard
```bash
sudo chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```
Đặt cổng 51820 và các cấu hình mặc định khác.

### 5. Cài đặt WGDashboard

```bash
sudo chmod u+x wgd.sh
sudo ./wgd.sh install
```

### 6. Cấu hình quyền cho WireGuard

Cấp quyền đọc và thực thi cho thư mục gốc của cấu hình WireGuard. Bạn có thể thay đổi đường dẫn nếu các file cấu hình của bạn không được lưu trong `/etc/wireguard`.

```bash
sudo chmod -R 755 /etc/wireguard
```

### 7. Chạy WGDashboard

```bash
./wgd.sh start
```

Mở trình duyệt và truy cập:
```
http://địa-chỉ-ip-máy-chủ:10086
```

Thông tin đăng nhập mặc định:
- Tên đăng nhập: admin
- Mật khẩu: admin

**Quan trọng:** Hãy thay đổi thông tin đăng nhập mặc định ngay sau khi đăng nhập lần đầu.

## Cấu trúc dự án

```
wireguard/
├── docker-compose.yml     # Cấu hình Docker
├── env.sh                 # Script thiết lập môi trường
├── img/                   # Hình ảnh cho bảng điều khiển
└── src/
    ├── dashboard.py       # Ứng dụng bảng điều khiển chính
    ├── db/                # Các file cơ sở dữ liệu
    ├── static/            # Tài nguyên tĩnh cho giao diện web
    ├── templates/         # Các template HTML
    ├── wgd.sh             # Script điều khiển bảng điều khiển wireguard
    └── requirements.txt   # Các phụ thuộc Python
```

## Thiết lập máy khách

1. Truy cập bảng điều khiển tại http://ip:10086
2. Điều hướng đến phần "Clients"
3. Nhấp "Add Client" và điền thông tin cần thiết
4. Tải file cấu hình hoặc quét mã QR bằng ứng dụng máy khách Wireguard

## Quản lý máy chủ

### Tích hợp với OpenVPN Manager

Để quản lý server thông qua OpenVPN Manager, bạn cần call API endpoint:


API_ENDPOINT=http://openvpn_manager_ip/server/list METHOD =["POST"]

[
    {
        "IP": "http://3.139.103.95:10086",
        "category": "Videos",
        "description": "Telemundo",
        "flag": "https://flagcdn.com/w320/us.png",
        "isFree": true
    }
]

Sau khi cấu hình, WGDashboard sẽ tự động đồng bộ danh sách server với OpenVPN Manager.

### Dừng máy chủ

```bash
./wgd.sh stop
```

## Xử lý sự cố

### Vấn đề kết nối

- Đảm bảo các cổng 51820/udp và 10086/tcp đã được mở trong tường lửa

### Vấn đề truy cập bảng điều khiển

- Kiểm tra địa chỉ IP máy chủ có chính xác không
- Kiểm tra xem mạng của bạn có cho phép truy cập cổng 10086 không
- Đảm bảo container đang chạy đúng cách

## Khuyến nghị bảo mật

- Thay đổi thông tin đăng nhập bảng điều khiển mặc định ngay lập tức
- Sử dụng proxy ngược với HTTPS để truy cập bảng điều khiển
- Cấu hình quy tắc tường lửa để giới hạn quyền truy cập vào bảng điều khiển

