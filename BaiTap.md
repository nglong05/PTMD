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

Như vậy, có thể nói rằng mã độc đã đạt được kỹ thuật persistence như: Registry Keys, Startup Programs. Mã độc này đã lưu các tệp nguy hiểm vào trong `Appdata` của người dùng, đồng thời xóa dấu vết để người dùng không phát hiện.

### 3. Strings của file mã độc gợi ý điều gì?
Sau khi strings file mã độc, em có thế thấy được một số điều như:
- các API liên quan tới việc quản lí file hay registry: RegSetValueExA
RegOpenKeyExA
RegDeleteValueA
RegFlushKey
RegCloseKey
- Các hàm mã hóa: CryptAcquireContextW
CryptDeriveKey
CryptReleaseContext
CryptEncrypt
CryptCreateHash
CryptDestroyKey
CryptDecrypt
CryptDestroyHash
CryptHashData
- các hàm liên quan tới mạng, truyền tải dữ liệu: InternetQueryDataAvailable
InternetReadFile
InternetCloseHandle
HttpQueryInfoA
InternetConnectA
InternetSetOptionA
HttpOpenRequestA
HttpSendRequestA
InternetOpenA
- các hàm quản lí dữ liệu: 
CreateFileA
FindResourceA
LoadResource
HeapAlloc
HeapFree
GetProcessHeap
WriteFile
SizeofResource
GetLastError
LockResource
GetModuleHandleA
CloseHandle
GetComputerNameA
HeapReAlloc
MoveFileExA

Bên cạnh đó, có một số dữ kiện đặc biệt khác như:
- `Software\Microsoft\Windows\CurrentVersion\Run`, như phần phân tích sơ lược ở trên, đây là một register key. có thể mã độc sử dụng các kỹ thuật liên quan.
- `brbconfig.tmp`, `brbbot` là tên các tệp được file mã độc tạo ra.
- `HTTP/1.1 Connection: close`, `%s?i=%s&c=%s&p=%s`, `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` là request, url với các params, và một User-agent giả. Có thể khẳng định rằng mã độc này liên quan tới việc truyền thông tin, dữ liệu mạng internet

### 4. Dấu hiệu file của mã độc xuất hiện trên máy nạn nhân?
Tuy rằng các file có thể được xóa sau khi mã độc thực hiện(?), em có thể sẽ kiểm tra file `brbconfig.tmp` hay `brbbot` trong `\AppData\Local\Temp\` chẳng hạn.

Còn có thể kiểm tra Register key xem liệu có mã độc xuất hiện ở đấy không.

### 5. Dấu hiệu về network của mã độc?
Như đã trình bày ở các phần trên, sau khi phân tích file mã độc thì phát hiện được rất nhiều dấu hiệu về Network.

Em sẽ trình bày lại quá trình từ đầu về network:
- Đầu tiên, WSAStartup khởi tạo winsock
- Sau khi lấy được config của người dùng (?),hàm `sub_140001C10` khởi tạo url với param (param có thể chứa config người dùng (?) `%s?i=%s&c=%s&p=%s`), đồng thời lấy IP của người dùng, khởi tạo 1 user-agent và request.
- Mã độc cũng đã nhận dữ liệu từ CCsever, sau đó tạo file brb là mã độc và mã hóa. Sau đó có thể gây ảnh hưởng tới máy bị nhiễm mã độc (?).
- Hàm cũng sử dụng API `InternetCloseHandle` và `WaitForSingleObject`.

