# LAN Vulnerability Service

Service Python nhận yêu cầu đánh giá thiết bị/dịch vụ LAN qua RabbitMQ, chuẩn hóa thông tin phần mềm thành CPE và đối
chiếu CVE từ NVD. Kết quả và cache NVD được lưu trong PostgreSQL; API Flask cung cấp health check và truy vấn findings
theo `scan_id`.

Pipeline gồm CVE matching, kiểm tra cấu hình và chấm điểm rủi ro. Hiện hai bước cuối mới có khung xử lý, chưa triển khai
logic đánh giá.

## Chạy trên local

Yêu cầu: [uv](https://docs.astral.sh/uv/getting-started/installation/), PostgreSQL, RabbitMQ và kết nối Internet để tra cứu
NVD. Dự án dùng Python 3.12 (khai báo trong `.python-version`); uv có thể tự tải Python nếu máy chưa có.
Chạy các lệnh từ thư mục gốc dự án.

### 1. Cài đặt thư viện

```powershell
uv sync --locked
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Lệnh này tạo `.venv` và cài các phiên bản trong `uv.lock`, bao gồm pytest cho phát triển. Dùng `uv run --locked` để chạy
lệnh trong môi trường này, không cần kích hoạt thủ công. Chỉ cài thư viện runtime: `uv sync --locked --no-dev`.

Thêm thư viện bằng `uv add <package>`, thêm công cụ phát triển bằng `uv add --dev <package>`. Commit cả
`pyproject.toml` và `uv.lock`. `requirements.txt` là bản export tương thích với pip; sau khi đổi dependencies, tạo lại bằng:

```powershell
uv export --locked --no-hashes --output-file requirements.txt
```

### 2. Cấu hình

Sao chép `.env.example` thành `.env` (nếu chưa có), rồi cập nhật cấu hình phù hợp. File mẫu liệt kê cả các tùy chọn
RabbitMQ, NVD và database pool:

```dotenv
DATABASE_URL=postgresql+psycopg://vuln:vuln_password@localhost:5432/lan_vuln
RABBITMQ_URL=amqp://vuln:vuln_password@localhost:5672/%2F
SCOPE_CHECK_URL=http://localhost:8080/api/v1/scope/check
NVD_API_KEY=
FLASK_HOST=127.0.0.1
FLASK_PORT=8082
```

Tạo database `lan_vuln`, user PostgreSQL và user RabbitMQ tương ứng trước khi chạy. User RabbitMQ cần quyền
configure/read/write trên vhost `/`. `SCOPE_CHECK_URL` là cấu hình bắt buộc khi khởi tạo client NVD; thay bằng URL của
hệ thống tích hợp (hiện chưa được gọi trong luồng xử lý). `NVD_API_KEY` có thể để trống.

Mặc định service đọc `.env` ở thư mục gốc. Để dùng file khác, sao chép `.env.example` thành `.env.debug` và đặt
`LAN_VULN_ENV_FILE` trước khi chạy. Đường dẫn tương đối được tính từ thư mục gốc dự án; đường dẫn tuyệt đối cũng được hỗ trợ.
File được chọn thay thế `.env`, không trộn hai file; biến môi trường của process được ưu tiên. Nếu chỉ định file không tồn
tại, service báo lỗi ngay. `.gitignore` có quy tắc bỏ qua các file `.env` và `.env.*` chưa được track
(ngoại trừ `.env.example`).

PowerShell:

```powershell
$env:LAN_VULN_ENV_FILE = ".env.debug"
uv run --locked python -m app.run_service
```

Linux/macOS:

```bash
LAN_VULN_ENV_FILE=.env.debug uv run --locked python -m app.run_service
```

Khởi tạo bảng bằng `psql` (URL này dùng dạng PostgreSQL thông thường, không có `+psycopg`):

```powershell
psql "postgresql://vuln:vuln_password@localhost:5432/lan_vuln" -v ON_ERROR_STOP=1 -f sql/schema.sql
```

### 3. Khởi chạy

Khởi tạo exchange/queue RabbitMQ, sau đó chạy worker:

```powershell
uv run --locked python -m app.common.messaging.setup
uv run --locked python -m app.run_service
```

Worker chờ sự kiện `platform.assessment.stage.requested` và phát sự kiện hoàn thành từng bước/giai đoạn. Để truy vấn kết
quả, mở terminal khác và chạy API (đặt lại `LAN_VULN_ENV_FILE` nếu dùng file riêng):

```powershell
uv run --locked python -m app.api
```

- Health check: `http://localhost:8082/health` (trả HTTP 503 nếu không kết nối được database).
- Findings: `http://localhost:8082/api/v1/findings/<scan_id>`.

### 4. Debug trong VS Code

1. Chạy `uv sync --locked`, cài các extension **Python** và **Python Debugger** được workspace đề xuất.
2. Chọn interpreter `.venv` qua **Python: Select Interpreter** nếu VS Code chưa chọn tự động.
3. Mở **Run and Debug**, chọn profile **LAN Vuln: Worker**, **LAN Vuln: API** hoặc **LAN Vuln: RabbitMQ setup** rồi nhấn F5.
   Profile **LAN Vuln: Worker + API** chạy cả hai process; dừng debug sẽ dừng cả hai.
4. Nhập đường dẫn file cấu hình tính từ workspace khi được hỏi, ví dụ `.env` (mặc định), `.env.debug` hoặc `config/local.env`.
   Chuẩn bị file này từ `.env.example` và sửa giá trị trước khi debug.

Các profile trong [`.vscode/launch.json`](.vscode/launch.json) dùng module entry point và thư mục gốc làm working directory.
Có thể đổi giá trị `default` của input `envFile` để nhớ file cấu hình thường dùng, hoặc thêm biến vào `env` của từng profile
để ghi đè giá trị trong file. VS Code nạp `envFile` vào process trước khi ứng dụng chạy; các giá trị này ưu tiên hơn biến
môi trường kế thừa từ terminal. RabbitMQ setup chỉ chạy khi chọn profile tương ứng; hãy khởi tạo topology trước khi chạy worker.

### 5. Kiểm tra

```powershell
uv run --locked pytest
```

Một số test hiện có cần PostgreSQL và dữ liệu CPE phù hợp trong database. Các test cấu hình không cần dịch vụ ngoài:
`uv run --locked pytest test/test_config.py`.

## Chạy bằng Docker

Yêu cầu Docker đang hoạt động, PostgreSQL và RabbitMQ đã sẵn sàng; khởi tạo database bằng `sql/schema.sql` như trên.
Image chỉ chứa service, các dịch vụ phụ thuộc chạy riêng.
Docker build dùng `uv sync --locked --no-dev` để cài runtime dependencies từ cùng `uv.lock` với local.

### 1. Build image

```powershell
docker build -t lan-vuln-service .
```

### 2. Cấu hình kết nối

Tạo file `.env.docker` với các biến như `.env`. Nếu PostgreSQL/RabbitMQ chạy trên máy host và dùng Docker Desktop, đổi
`localhost` thành `host.docker.internal` trong các URL:

```dotenv
DATABASE_URL=postgresql+psycopg://vuln:vuln_password@host.docker.internal:5432/lan_vuln
RABBITMQ_URL=amqp://vuln:vuln_password@host.docker.internal:5672/%2F
SCOPE_CHECK_URL=http://host.docker.internal:8080/api/v1/scope/check
NVD_API_KEY=
FLASK_HOST=0.0.0.0
FLASK_PORT=8082
```

Nếu các dịch vụ phụ thuộc chạy trong container cùng Docker network, dùng tên container làm hostname và thêm
`--network <ten-network>` vào các lệnh `docker run`. Trên Linux Docker Engine, khi kết nối về host, thêm
`--add-host host.docker.internal:host-gateway`; các dịch vụ trên host cần lắng nghe trên địa chỉ mà container truy cập
được.

### 3. Chạy worker

```powershell
docker run -d --name lan-vuln-worker --env-file .env.docker lan-vuln-service
```

Chạy API bằng cùng image, ghi đè lệnh mặc định, chưa cần chạy thì thôi:

```powershell
docker run -d --name lan-vuln-api --env-file .env.docker -e FLASK_HOST=0.0.0.0 -e FLASK_PORT=8082 -p 127.0.0.1:8082:8082 lan-vuln-service python -m app.api
```

Truy cập API tại `http://localhost:8082/health`. API dùng Flask development server, phù hợp để chạy thử local.

Xem log và dừng/xóa container:

```powershell
docker logs -f lan-vuln-worker
docker stop lan-vuln-worker lan-vuln-api
docker rm lan-vuln-worker lan-vuln-api
```
