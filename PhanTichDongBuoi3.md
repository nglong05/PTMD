## Phân tích động mẫu Lab3-2.dll trong 'sample buoi 3.zip' pass infected. Bạn hãy trả lời các câu hỏi sau:
1. Cách cài đặt mã độc?
2. Mã độc đạt được persistence như thế nào?
3. Cách chạy mã độc sau khi cài đặt?
4. Xác định PID của tiến trình đang chạy mã độc.
5. Dấu hiệu host-based(file, process, registry, service) trên máy bị nhiễm mã độc?
6. Dấu hiệu về network trên máy bị nhiễm mã độc?
## Solution
Sử dụng `rundll32 Lab3-2.dll`, system infomer không phát hiện thấy chương trình gì.

![image](https://github.com/user-attachments/assets/7ff378c3-370a-4dbe-98c9-1a4b87b39640)

Thử với entrypoint `Install`, ta thấy file `rundll32.exe`

![image](https://github.com/user-attachments/assets/dccfb03e-6b44-4e12-8778-aa718870f276)
#### Phân tích hàm `Install`
- Đầu tiên, hàm mở regiskey `HKEY_LOCAL_MACHINE`
- Sau đó hàm sẽ lấy giá trị của registry key và lưu vào `Data`
- Hàm sẽ kiểm tra xem trong Data có giá trị String2 hay không, có thể là một chuỗi dịch vụ
- Kết nối đến SCM và tạo dịch vụ, cấu hình vào Registry sao cho file dll được thực thi mỗi khi máy chạy
- Như vậy, hàm Install có thể cài đặt một dịch vụ lên máy khi được thực thi 

#### Phân tích hàm `ServiceMain`
