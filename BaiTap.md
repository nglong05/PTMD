# Phân tích tĩnh mã độc
### Instructions: Phân tích tĩnh mã độc brbbot.exe trong thư mục sample buoi 2.zip ( pass giải nén: infected). Xác định:
1. Mã độc có bị virustotal gán nhãn độc hại hay không?
2. Mã độc có đạt kỹ thuật persistence?
3. Strings của file mã độc gợi ý điều gì?
4. Dấu hiệu file của mã độc xuất hiện trên máy nạn nhân?
5. Dấu hiệu về network của mã độc?
6. Mã độc sử dụng thuật toán gì để giải mã config?
7. Mã độc thuộc loại mã độc nào?

## Solution
### 1. Mã độc có bị virustotal gán nhãn độc hại hay không?
![Screenshot 2024-10-08 211148](https://github.com/user-attachments/assets/60eac2fd-1f33-4bb9-ac9f-0458d30454f4)

Sau khi upload file lên [VirusTotal](https://www.virustotal.com/gui/home/upload) website đưa ra kết quả rằng 63/73 nhà cung cấp bảo mật gán nhãn tệp này là độc hại.

### 2. Mã độc có đạt kỹ thuật persistence?
“Persistent Techniques” là các kỹ thuật giúp mã độc tạo được sự tồn tại và duy trì hoạt động trong hệ thống mục tiêu.
Em sẽ trình bày sơ lược về cái nhìn tổng quan đầu tiên đối với file mã độc này.

Hàm `wWinMain` đầu tiên khởi tạo Winsock (WSAStartup), giao tiếp với C&C Server

- Hàm `sub_140001150()`, có thể tìm config của máy? hoặc là tài nguyên nào đó rồi lưu vào file tạm thời `brbconfig.tmp`

- Hàm `sub_140002230()` lấy tên tệp, kiểm tra xem tệp có đang ở APPDATA hay không, sau đó tạo một bản sao của tệp ở một vị trí cố định. Đặc biệt, hàm đã mở khóa Registry, sau đó thêm file `brbbot` sẽ được thực thi mỗi lần máy chạy. Đồng thời hàm cũng di chuyển hay xóa tệp `brbconfig.tmp`
```cpp
v11 = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        0x20006u,
        &hKey);
```

- Hàm `sub_1400012E0(&unk_140014560)` trích xuất các tham số (uri, exec, conf, file, exit, ...) là các tham số config, có thể sử dụng những dữ liệu này để mã độc hoạt động
- Hàm `sub_140001C10(&unk_140014560, &v9, &hInternet)` có thể tạo ra một url, sau đó mã hóa trước khi gửi request. Phần dữ liệu này có thể là thông tin của máy bị mã độc tấn công.
```cpp
strcpy(Format, "%s?i=%s&c=%s&p=%s");
```
- Hàm `sub_140002550()`, hàm ở cuối của chương trình, có nhiệm vụ xóa file tạm `brbconfig.tmp`, sau đó mở khóa Registry và xóa file mã độc `brbbot`, sau đó đóng Registry.
- Bên cạnh đó, mã độc cũng sử dụng một số API như InternetCloseHandle, sau đó dọn dẹp tài nguyên bằng WSACleanup...

Một điểm đáng chú ý là, các hàm kể trên quản lí bộ nhớ khá kĩ lưỡng, đều giải phóng bộ nhớ trước khi kết thúc hàm (HeapFree...). Ví dụ như ở hàm `sub_140002230()`:
```cpp
if ( hKey )
    RegCloseKey(hKey);
if ( v0 < 0 && v2 )
    DeleteFileA(v1);
if ( v1 )
{
    v13 = GetProcessHeap();
    HeapFree(v13, 0, v1);
}
```
hay ở hàm `wWinMain`
```cpp
if ( lpMem )
{
  ProcessHeap = GetProcessHeap();
  HeapFree(ProcessHeap, 0, lpMem);
}

```
đặc biệt, hàm `sub_140002550()`:
```cpp
{
  RegDeleteValueA(hKey, "brbbot");
  RegFlushKey(hKey);
  v2 = 0;
}
```

Như vậy, có thể nói rằng mã độc đã đạt được kỹ thuật persistence như: Registry Keys, Startup Programs.
