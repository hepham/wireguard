# Hướng dẫn sử dụng API Dashboard WireGuard

## Tổng quan

Dashboard WireGuard cung cấp giao diện web để quản lý các kết nối WireGuard VPN. Tài liệu này sẽ hướng dẫn cách sử dụng các API để tương tác với hệ thống.

![WireGuard Logo](https://www.wireguard.com/img/wireguard.svg)

## Cài đặt và Khởi động

### Yêu cầu hệ thống
- Python 3.7+ 
- WireGuard đã được cài đặt
- Redis server
- Các thư viện Python: Flask, tinydb, ifcfg, flask_qrcode, icmplib, redis, ping3, configparser, qrcode

### Cài đặt Redis
Redis là bắt buộc cho Dashboard WireGuard phiên bản mới. Cài đặt Redis theo hệ điều hành của bạn:

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

#### CentOS/RHEL
```bash
sudo yum install epel-release
sudo yum install redis
sudo systemctl enable redis
sudo systemctl start redis
```

#### Arch Linux
```bash
sudo pacman -S redis
sudo systemctl enable redis
sudo systemctl start redis
```

#### Windows
Tải Redis từ [GitHub](https://github.com/microsoftarchive/redis/releases) hoặc cài đặt thông qua Chocolatey:
```
choco install redis-64
```

### Cách chạy
1. Clone mã nguồn:
```
git clone [repository-url]
cd wireGuard
```

2. Cài đặt các thư viện phụ thuộc:
```
pip install -r src/requirements.txt
```

3. Chạy ứng dụng:
```
python src/dashboard.py
```

Mặc định, ứng dụng chạy trên cổng 10086 và có thể truy cập thông qua: `http://localhost:10086`

![Giao diện Dashboard](https://i.imgur.com/example.jpg)

## Luồng hoạt động

1. **Khởi tạo**: Khi bắt đầu, hệ thống sẽ tạo file cấu hình `wg-dashboard.ini` nếu chưa tồn tại
2. **Xác thực**: Người dùng đăng nhập với thông tin mặc định (tên người dùng: admin, mật khẩu: admin)
3. **Quản lý cấu hình**: Hiển thị và quản lý các cấu hình WireGuard
4. **Quản lý peer**: Thêm, xóa, sửa các peer trong mỗi cấu hình

## Các API chính

### Authentication

#### Đăng nhập
- **Endpoint**: `/auth`
- **Method**: POST
- **Dữ liệu**: username, password
- **Mô tả**: Xác thực người dùng

#### Đăng xuất
- **Endpoint**: `/signout`
- **Method**: GET
- **Mô tả**: Đăng xuất người dùng hiện tại

### Quản lý cấu hình

#### Danh sách cấu hình
- **Endpoint**: `/`
- **Method**: GET
- **Mô tả**: Hiển thị danh sách tất cả cấu hình

#### Xem chi tiết cấu hình
- **Endpoint**: `/configuration/<config_name>`
- **Method**: GET
- **Mô tả**: Hiển thị chi tiết của một cấu hình cụ thể

#### Lấy thông tin cấu hình
- **Endpoint**: `/get_conf/<config_name>`
- **Method**: GET
- **Tham số**: search (tùy chọn để tìm kiếm peer)
- **Mô tả**: Lấy thông tin chi tiết về cấu hình và các peer

#### Bật/tắt cấu hình
- **Endpoint**: `/switch/<config_name>`
- **Method**: GET
- **Mô tả**: Bật hoặc tắt một cấu hình WireGuard

### Quản lý peer

#### Thêm peer
- **Endpoint**: `/add_peer/<config_name>`
- **Method**: POST
- **Dữ liệu JSON**:
  ```json
  {
    "public_key": "công khai key của peer",
    "allowed_ips": "IP được phép (VD: 10.66.66.2/32)",
    "endpoint_allowed_ip": "IP endpoint được phép (VD: 0.0.0.0/0)",
    "DNS": "DNS server (VD: 1.1.1.1)",
    "name": "tên peer",
    "private_key": "khóa riêng tư (tùy chọn)",
    "MTU": "1420",
    "keep_alive": "21"
  }
  ```
- **Mô tả**: Thêm một peer mới vào cấu hình

#### Xóa peer
- **Endpoint**: `/remove_peer/<config_name>`
- **Method**: POST
- **Dữ liệu JSON**:
  ```json
  {
    "peer_id": "khóa công khai của peer"
  }
  ```
- **Mô tả**: Xóa một peer khỏi cấu hình

#### Cập nhật thiết lập peer
- **Endpoint**: `/save_peer_setting/<config_name>`
- **Method**: POST
- **Dữ liệu JSON**:
  ```json
  {
    "id": "khóa công khai của peer",
    "name": "tên mới",
    "private_key": "khóa riêng tư",
    "DNS": "DNS mới",
    "allowed_ip": "IP được phép mới",
    "endpoint_allowed_ip": "IP endpoint được phép mới",
    "MTU": "MTU mới",
    "keep_alive": "giá trị keepalive mới"
  }
  ```
- **Mô tả**: Cập nhật thiết lập của một peer

#### Lấy dữ liệu peer
- **Endpoint**: `/get_peer_data/<config_name>`
- **Method**: POST
- **Dữ liệu JSON**:
  ```json
  {
    "id": "khóa công khai của peer"
  }
  ```
- **Mô tả**: Lấy thông tin chi tiết của một peer

#### Tạo client mới
- **Endpoint**: `/create_client/<config_name>`
- **Method**: POST
- **Dữ liệu JSON**:
  ```json
  {
    "name": "tên client",
    "keep_alive": 21
  }
  ```
- **Mô tả**: Tạo và cấu hình client mới, trả về file cấu hình

### Công cụ

#### Tạo khóa
- **Endpoint**: `/generate_peer`
- **Method**: GET
- **Mô tả**: Tạo cặp khóa private/public mới

#### Tạo khóa công khai từ khóa riêng tư
- **Endpoint**: `/generate_public_key`
- **Method**: POST
- **Dữ liệu JSON**:
  ```json
  {
    "private_key": "khóa riêng tư"
  }
  ```
- **Mô tả**: Tạo khóa công khai từ khóa riêng tư

#### Ping IP
- **Endpoint**: `/ping_ip`
- **Method**: POST
- **Dữ liệu**: ip, count
- **Mô tả**: Kiểm tra kết nối tới một IP

#### Traceroute IP
- **Endpoint**: `/traceroute_ip`
- **Method**: POST
- **Dữ liệu**: ip
- **Mô tả**: Theo dõi đường đi của gói tin tới một IP

## Cải tiến mới

### Cơ chế khóa tập tin
Hệ thống hiện sử dụng cơ chế khóa tập tin để ngăn chặn xung đột khi nhiều người dùng cập nhật cấu hình WireGuard cùng lúc.

### Lưu trữ Redis
Thông tin peer bây giờ được lưu trữ trong Redis thay vì TinyDB để cải thiện hiệu suất và độ tin cậy.

### Cấu trúc mô-đun
Mã nguồn đã được tái cấu trúc thành các mô-đun riêng biệt để dễ bảo trì và mở rộng.

## Tính năng tự động

### Dọn dẹp peer không hoạt động
Hệ thống tự động dọn dẹp các peer không hoạt động sau một khoảng thời gian (mặc định là 180 phút hoặc 3 ngày).

## Ví dụ

### Tạo client WireGuard mới
```bash
curl -X POST http://localhost:10086/create_client/wg0 \
  -H "Content-Type: application/json" \
  -d '{"name":"test_client","keep_alive":25}'
```

Lệnh này sẽ:
1. Tạo client mới với tên "test_client"
2. Tự động tạo khóa
3. Gán địa chỉ IP trong dải mạng 10.66.66.x
4. Trả về file cấu hình WireGuard

### Kiểm tra kết nối
```bash
curl -X POST http://localhost:10086/ping_ip \
  -d "ip=10.66.66.2&count=4"
```

## Cấu trúc dữ liệu Redis

Dữ liệu của peer được lưu trong Redis với các khóa có định dạng `{config_name}_peer:{peer_id}`:
- private_key: Khóa riêng tư (tùy chọn)
- name: Tên peer
- allowed_ip: Địa chỉ IP được cấp 
- DNS: Máy chủ DNS
- endpoint_allowed_ip: Địa chỉ IP được phép kết nối
- mtu: MTU cho peer
- keepalive: Giá trị persistent keepalive
- created_at: Thời gian tạo peer

## Lỗi thường gặp và cách khắc phục

### 1. Lỗi Redis không kết nối được

**Lỗi:**
```
Warning: Could not configure Redis persistence - connection failed
```

**Nguyên nhân:** Redis không chạy hoặc không thể kết nối

**Giải pháp:**
- Kiểm tra nếu Redis đã được cài đặt: `redis-cli ping`
- Đảm bảo Redis đang chạy: `sudo systemctl start redis`
- Kiểm tra cấu hình Redis: `redis-cli CONFIG GET bind`

### 2. Lỗi không thể kết nối tới WireGuard

**Lỗi:**
```
Command failed: wg show wg0 dump
```

**Nguyên nhân:** Interface WireGuard không tồn tại hoặc không được khởi động

**Giải pháp:**
- Kiểm tra xem WireGuard đã được cài đặt: `wg --version`
- Khởi động interface: `wg-quick up wg0`

### 3. Lỗi không thể lưu cấu hình

**Lỗi:**
```
error sync: error opening '/etc/wireguard/wg0.conf.tmp': No such file or directory
```

**Nguyên nhân:** Thư mục WireGuard không tồn tại hoặc không có quyền ghi

**Giải pháp:**
- Tạo thư mục: `sudo mkdir -p /etc/wireguard`
- Đặt quyền thích hợp: `sudo chmod 700 /etc/wireguard`
- Thay đổi quyền sở hữu: `sudo chown user:user /etc/wireguard`

## Ghi chú

- Mặc định, API chạy trên cổng 10086 và địa chỉ 0.0.0.0
- Tài khoản mặc định: admin/admin
- File cấu hình WireGuard được lưu tại /etc/wireguard
- File cấu hình dashboard được lưu tại /etc/wireguard-dashboard/wg-dashboard.ini
- IP được gán tự động trong dải 10.66.66.x 