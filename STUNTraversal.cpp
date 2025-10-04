#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <random>
#include <optional>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <atomic>
#include <mutex>
#include <future>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <mstcpip.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winreg.h>

#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h>
#include <winrt/Windows.Foundation.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "windowsapp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")

// 全局定义和辅助工具
// 【新】用于存储连接对的数据结构
struct ConnectionPair {
    SOCKET client_socket; // 来自公网的连接
    SOCKET local_socket;  // 连接到本地P2P软件的连接
};

std::atomic<bool> g_tcp_reconnect_flag{false};
std::atomic<bool> g_udp_reconnect_flag{false};
std::atomic<bool> g_tcp_ready{false};
std::atomic<bool> g_udp_ready{false};
std::atomic<bool> g_run_executed_this_cycle{false};
std::mutex g_cout_mutex;
std::mutex g_run_mutex;

HWND g_hMessageWindow = NULL;
UINT const WM_APP_EXECUTE_RUN = WM_APP + 1;
UINT const WM_APP_SHOW_NOTIFICATION = WM_APP + 2;

bool g_is_hidden = false;
std::string g_public_ip, g_tcp_port_str, g_udp_port_str;
std::wstring g_app_name;

enum class StunRfc { RFC3489, RFC5780 };

enum ConsoleColor { DARKBLUE = 1, GREEN = 2, CYAN = 3, RED = 4, MAGENTA = 5, YELLOW = 6, WHITE = 7, GRAY = 8, LIGHT_GREEN = 10 };
void SetColor(ConsoleColor color) {
    if (g_is_hidden) return;
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

template<typename... Args>
void Print(ConsoleColor color, Args&&... args) {
    if (g_is_hidden) return;
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    (std::cout << ... << args) << std::endl;
}

// ... (trim, trim_w, WstringToString, StringToWstring 函数保持不变) ...
std::string trim(const std::string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (std::string::npos == first) return "";
    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, (last - first + 1));
}

std::wstring trim_w(const std::wstring& s) {
    size_t first = s.find_first_not_of(L" \t\r\n");
    if (std::wstring::npos == first) return L"";
    size_t last = s.find_last_not_of(L" \t\r\n");
    return s.substr(first, (last - first + 1));
}

std::string WstringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

std::wstring StringToWstring(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// 配置管理
struct Config {
    std::vector<std::string> stun_servers;
    std::optional<int> tcp_listen_port;
    std::optional<std::string> tcp_forward_host;
    std::optional<int> tcp_forward_port;
    std::optional<int> udp_listen_port;
    std::optional<std::string> udp_forward_host;
    std::optional<int> udp_forward_port;
    int punch_timeout_ms = 3000;
    int keep_alive_ms = 2300;
    int retry_interval_ms = 3000;
    bool auto_retry = true;
    int stun_retry = 3;
    int stun_retry_delay_ms = 200;
    int udp_session_timeout_ms = 30000;
    int udp_max_chunk_length = 1500;
    std::optional<std::string> run_path;
    std::optional<std::string> run_cmd;
    std::optional<std::string> keep_alive_host;
    int monitor_interval_sec = 300;
    int keep_alive_retry = 3; // 【新】保活服务器连接重试次数
};

Config ReadIniConfig(const std::wstring& filePath) {
    Config config;
    // ... (文件读取和编码转换部分保持不变) ...
    FILE* fp = _wfopen(filePath.c_str(), L"rb");
    if (!fp) return config;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    std::vector<char> buffer(file_size);
    fread(buffer.data(), 1, file_size, fp);
    fclose(fp);

    std::wstring wcontent;
    if (file_size >= 3 && buffer[0] == (char)0xEF && buffer[1] == (char)0xBB && buffer[2] == (char)0xBF) {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &buffer[3], file_size - 3, NULL, 0);
        wcontent.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, &buffer[3], file_size - 3, &wcontent[0], size_needed);
    } else {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, buffer.data(), file_size, NULL, 0);
        wcontent.resize(size_needed);
        MultiByteToWideChar(CP_UTF8, 0, buffer.data(), file_size, &wcontent[0], size_needed);
    }

    std::wstringstream wss(wcontent);
    std::wstring wline, current_section;

    while (std::getline(wss, wline)) {
        wline = trim_w(wline);
        if (wline.empty() || wline[0] == L';' || wline[0] == L'#') continue;

        if (wline[0] == L'[' && wline.back() == L']') {
            current_section = trim_w(wline.substr(1, wline.length() - 2));
            std::transform(current_section.begin(), current_section.end(), current_section.begin(), ::tolower);
        } else if (current_section == L"stun") {
            if(!wline.empty()) config.stun_servers.push_back(WstringToString(wline));
        } else if (current_section == L"settings") {
            size_t eq_pos = wline.find(L'=');
            if (eq_pos != std::wstring::npos) {
                std::wstring key_w = trim_w(wline.substr(0, eq_pos));
                std::wstring value_w = trim_w(wline.substr(eq_pos + 1));
                std::transform(key_w.begin(), key_w.end(), key_w.begin(), ::tolower);
                std::string value = WstringToString(value_w);

                try {
                    if (key_w == L"tcplistenport") config.tcp_listen_port = std::stoi(value);
                    else if (key_w == L"tcpforwardhost") config.tcp_forward_host = value;
                    else if (key_w == L"tcpforwardport") {
                        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                        if (value == "auto") config.tcp_forward_port = 0; else config.tcp_forward_port = std::stoi(value);
                    }
                    else if (key_w == L"udplistenport") config.udp_listen_port = std::stoi(value);
                    else if (key_w == L"udpforwardhost") config.udp_forward_host = value;
                    else if (key_w == L"udpforwardport") {
                        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                        if (value == "auto") config.udp_forward_port = 0; else config.udp_forward_port = std::stoi(value);
                    }
                    else if (key_w == L"punchtimeoutms") config.punch_timeout_ms = std::stoi(value);
                    else if (key_w == L"keepalivems") config.keep_alive_ms = std::stoi(value);
                    else if (key_w == L"retryintervalms") config.retry_interval_ms = std::stoi(value);
                    else if (key_w == L"autoretry") config.auto_retry = (std::stoi(value) == 1);
                    else if (key_w == L"stunretry") config.stun_retry = std::stoi(value);
                    else if (key_w == L"stunretrydelayms") config.stun_retry_delay_ms = std::stoi(value);
                    else if (key_w == L"udpsessiontimeoutms") config.udp_session_timeout_ms = std::stoi(value);
                    else if (key_w == L"udpmaxchunklength") config.udp_max_chunk_length = std::stoi(value);
                    else if (key_w == L"run") config.run_path = value;
                    else if (key_w == L"runcmd") config.run_cmd = value;
                    else if (key_w == L"keepalivehost") config.keep_alive_host = value;
                    else if (key_w == L"monitorintervalsec") config.monitor_interval_sec = std::stoi(value);
                    else if (key_w == L"keepaliveretry") config.keep_alive_retry = std::stoi(value);
                } catch (const std::exception&) { /* ignore bad values */ }
            }
        }
    }
    return config;
}

// ... (STUN, 通知, 外部程序调用等模块保持不变) ...
void BuildStunRequest(char* buffer, StunRfc rfc) {
    memset(buffer, 0, 20);
    *(unsigned short*)buffer = htons(0x0001);
    if (rfc == StunRfc::RFC5780) {
        *(unsigned int*)(buffer + 4) = htonl(0x2112A442);
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis;
    for (int i = 0; i < 3; ++i) {
        *(unsigned int*)(buffer + 8 + i * 4) = dis(gen);
    }
}

bool ParseStunResponse(char* response_buffer, int response_len, StunRfc rfc, std::string& out_ip, int& out_port) {
    const char* header_buffer = response_buffer;
    if (ntohs(*(unsigned short*)header_buffer) != 0x0101) return false;
    if (rfc == StunRfc::RFC5780 && *(unsigned int*)(header_buffer + 4) != htonl(0x2112A442)) return false;

    unsigned short msg_len = ntohs(*(unsigned short*)(header_buffer + 2));
    if (msg_len > response_len - 20) return false;

    const char* p = header_buffer + 20;
    const char* end = p + msg_len;
    while (p < end) {
        unsigned short type = ntohs(*(unsigned short*)p);
        unsigned short len = ntohs(*(unsigned short*)(p + 2));
        const char* attr_value = p + 4;
        bool found = false;

        if (rfc == StunRfc::RFC5780 && type == 0x0020) {
            unsigned short port_net = *(unsigned short*)(attr_value + 2);
            unsigned int ip_net = *(unsigned int*)(attr_value + 4);
            unsigned short real_port_net = port_net ^ htons(0x2112);
            unsigned int real_ip_net = ip_net ^ htonl(0x2112A442);
            out_port = ntohs(real_port_net);
            in_addr addr; addr.s_addr = real_ip_net;
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN) != NULL) {
                out_ip = ip_str; found = true;
            }
        } else if (rfc == StunRfc::RFC3489 && type == 0x0001) {
            out_port = ntohs(*(unsigned short*)(attr_value + 2));
            in_addr addr; addr.s_addr = *(unsigned int*)(attr_value + 4);
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN) != NULL) {
                out_ip = ip_str; found = true;
            }
        }
        if (found) return true;
        p += 4 + len;
        if (len % 4 != 0) p += (4 - (len % 4));
    }
    return false;
}

void ShowToastNotification(const std::wstring& aumid, const std::wstring& message, const std::wstring& title_override = L"") {
    if (!g_is_hidden && title_override.empty()) return;

    HKEY hKey;
    std::wstring regPath = L"Software\\Classes\\AppUserModelId\\" + aumid;

    if (RegCreateKeyExW(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"DisplayName", 0, REG_SZ, (const BYTE*)aumid.c_str(), (aumid.length() + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    try {
        winrt::Windows::UI::Notifications::ToastNotifier notifier = winrt::Windows::UI::Notifications::ToastNotificationManager::CreateToastNotifier(aumid);
        winrt::Windows::Data::Xml::Dom::XmlDocument toastXml;
        
        std::wstring title = title_override.empty() ? (L"公网地址变更") : title_override;
        std::wstring xml_content = L"<toast><visual><binding template='ToastGeneric'><text>" + title + L"</text><text>";
        xml_content += message;
        xml_content += L"</text></binding></visual></toast>";

        toastXml.LoadXml(xml_content);
        winrt::Windows::UI::Notifications::ToastNotification notification(toastXml);

        auto cleanup_callback = [aumid_copy = aumid](const auto&, const auto&) {
            std::wstring regPath_copy = L"Software\\Classes\\AppUserModelId\\" + aumid_copy;
            RegDeleteKeyW(HKEY_CURRENT_USER, regPath_copy.c_str());
        };

        notification.Dismissed(cleanup_callback);
        notification.Failed(cleanup_callback);

        notifier.Show(notification);

    } catch (const winrt::hresult_error& e) {
        std::wcerr << L"弹出通知错误: " << e.message().c_str() << std::endl;
        RegDeleteKeyW(HKEY_CURRENT_USER, regPath.c_str());
    }
}

bool IsProcessRunning(const std::wstring& processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32FirstW(snapshot, &entry) == TRUE) {
        while (Process32NextW(snapshot, &entry) == TRUE) {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return true;
            }
        }
    }
    CloseHandle(snapshot);
    return false;
}

void ExecuteRunCommand(const Config& config) {
    if (!config.run_path || config.run_path->empty()) return;

    std::wstring wide_run_path = StringToWstring(*config.run_path);
    wchar_t expanded_path[MAX_PATH];
    ExpandEnvironmentStringsW(wide_run_path.c_str(), expanded_path, MAX_PATH);

    wchar_t absolute_path[MAX_PATH];
    GetFullPathNameW(expanded_path, MAX_PATH, absolute_path, nullptr);

    wchar_t* file_part = PathFindFileNameW(absolute_path);
    std::wstring process_name(file_part);

    if (!IsProcessRunning(process_name)) {
        Print(YELLOW, "[RUN] 目标进程 ", WstringToString(process_name), " 未运行 跳过执行");
        return;
    }

    std::string cmd = config.run_cmd.value_or("");
    auto replace = [&](std::string& str, const std::string& from, const std::string& to) {
        size_t start_pos = 0;
        while((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
    };
    replace(cmd, "{PublicIP}", g_public_ip);
    replace(cmd, "{TCPPort}", g_tcp_port_str);
    replace(cmd, "{UDPPort}", g_udp_port_str);

    std::wstring wide_cmd = StringToWstring(cmd);
    std::wstring quoted_path = L"\"" + std::wstring(absolute_path) + L"\"";

    Print(GREEN, "[RUN] 正在执行: ", WstringToString(quoted_path), " ", cmd);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = absolute_path;
    sei.lpParameters = wide_cmd.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        Print(RED, "[RUN] ShellExecuteExW 失败 错误码: ", GetLastError());
    } else {
        CloseHandle(sei.hProcess);
    }
}

bool CheckAndExecuteRun(const Config& config, bool tcp_enabled, bool udp_enabled) {
    std::lock_guard<std::mutex> lock(g_run_mutex);
    if (g_run_executed_this_cycle) return true;

    bool tcp_ok = !tcp_enabled || g_tcp_ready;
    bool udp_ok = !udp_enabled || g_udp_ready;

    if (tcp_ok && udp_ok) {
        ExecuteRunCommand(config);
        if (g_is_hidden) {
            std::wstring msg = L"IP: " + StringToWstring(g_public_ip);
            if (tcp_enabled) msg += L"\nTCP: " + StringToWstring(g_tcp_port_str);
            if (udp_enabled) msg += L"\nUDP: " + StringToWstring(g_udp_port_str);
            ShowToastNotification(g_app_name, msg);
        }
        g_run_executed_this_cycle = true;
        return true;
    }
    return false;
}

void TriggerManualNotification() {
    Print(CYAN, "[IPC] 收到 -show 命令 正在发送通知...");
    std::wstring msg;
    if (g_public_ip.empty()) {
        msg = L"公网地址尚未确定";
    } else {
        msg = L"IP: " + StringToWstring(g_public_ip);
        if (g_tcp_ready && !g_tcp_port_str.empty()) {
            msg += L"\nTCP: " + StringToWstring(g_tcp_port_str);
        }
        if (g_udp_ready && !g_udp_port_str.empty()) {
            msg += L"\nUDP: " + StringToWstring(g_udp_port_str);
        }
    }
    
    std::thread([](const std::wstring& aumid, const std::wstring& message){
        winrt::init_apartment(); 
        ShowToastNotification(aumid, message, L"当前公网地址");
        winrt::uninit_apartment();
    }, g_app_name, msg).detach();
}

void TCP_Proxy(SOCKET s1, SOCKET s2, int keep_alive_ms) {
    tcp_keepalive ka; ka.onoff = (u_long)1; ka.keepalivetime = keep_alive_ms; ka.keepaliveinterval = 1000;
    DWORD bytes_returned;
    WSAIoctl(s1, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes_returned, NULL, NULL);
    char buffer[8192];
    while (true) {
        int bytes = recv(s1, buffer, sizeof(buffer), 0);
        if (bytes <= 0) break;
        if (send(s2, buffer, bytes, 0) <= 0) break;
    }
    closesocket(s1); closesocket(s2);
}

void TCP_HandleNewConnection(SOCKET peer_sock, Config config) {
    sockaddr_in peer_addr; int peer_addr_len = sizeof(peer_addr);
    getpeername(peer_sock, (sockaddr*)&peer_addr, &peer_addr_len);
    char peer_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
    Print(GREEN, "[TCP] 新连接来自 ", peer_ip_str, ":", ntohs(peer_addr.sin_port));
    
    SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addrinfo* fwd_res = nullptr;
    getaddrinfo(config.tcp_forward_host->c_str(), std::to_string(*config.tcp_forward_port).c_str(), nullptr, &fwd_res);
    if (connect(target_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == SOCKET_ERROR) {
        Print(RED, "[TCP] 无法连接本地目标 ", *config.tcp_forward_host, ":", *config.tcp_forward_port);
        closesocket(peer_sock);
    } else {
        Print(YELLOW, "[TCP] 开始转发 ", peer_ip_str, " <==> ", *config.tcp_forward_host, ":", *config.tcp_forward_port);
        std::thread(TCP_Proxy, peer_sock, target_sock, config.keep_alive_ms).detach();
        std::thread(TCP_Proxy, target_sock, peer_sock, config.keep_alive_ms).detach();
    }
    freeaddrinfo(fwd_res);
}

// 【重构】TCP 监控线程 - 实现“粘性”服务器和协议的智能逻辑
void TCP_StunCheckThread(std::string initial_ip, int initial_port, const Config& config, int local_port, 
                         int initial_server_index, std::map<std::string, StunRfc> initial_protocol_map) {
    
    // 内部状态 会随着时间更新
    int current_server_index = initial_server_index;
    auto protocol_map = initial_protocol_map;

    while (!g_tcp_reconnect_flag) {
        std::this_thread::sleep_for(std::chrono::seconds(config.monitor_interval_sec));
        if (g_tcp_reconnect_flag) break;

        Print(CYAN, "\n[TCP] 监控: 正在检查公网地址...");
        
        bool overall_check_success = false;
        std::string current_ip; 
        int current_port;

        // 【新】从上一个成功的服务器开始 循环遍历整个列表
        for (int i = 0; i < config.stun_servers.size(); ++i) {
            int server_index_to_try = (current_server_index + i) % config.stun_servers.size();
            const auto& server_str = config.stun_servers[server_index_to_try];

            size_t colon_pos = server_str.find(':');
            if (colon_pos == std::string::npos) continue;
            std::string host = server_str.substr(0, colon_pos);
            int port = std::stoi(server_str.substr(colon_pos + 1));

            // 定义一个可重用的尝试函数
            auto attempt_protocol = [&](StunRfc rfc) -> bool {
                SOCKET check_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (check_sock == INVALID_SOCKET) return false;
                // ... (省略与之前版本相同的socket创建和bind代码) ...
                BOOL reuse = TRUE; setsockopt(check_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                sockaddr_in local_addr = { AF_INET, htons(local_port), {INADDR_ANY} };
                if (bind(check_sock, (sockaddr*)&local_addr, sizeof(local_addr)) != 0) { closesocket(check_sock); return false; }

                bool success = false;
                addrinfo* stun_res = nullptr;
                if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
                    if (connect(check_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == 0) {
                        char req[20]; BuildStunRequest(req, rfc);
                        if (send(check_sock, req, sizeof(req), 0) != SOCKET_ERROR) {
                            char response_buffer[512];
                            int bytes = recv(check_sock, response_buffer, sizeof(response_buffer), 0);
                            if (bytes > 20 && ParseStunResponse(response_buffer, bytes, rfc, current_ip, current_port)) {
                                success = true;
                            }
                        }
                    }
                    freeaddrinfo(stun_res);
                }
                closesocket(check_sock);
                return success;
            };

            // 【新】智能协议选择逻辑
            if (protocol_map.count(server_str)) {
                // 如果有记录 只尝试记录过的协议
                StunRfc known_rfc = protocol_map.at(server_str);
                Print(CYAN, "[TCP] 监控: 尝试 ", host, " (已知协议 RFC", (known_rfc == StunRfc::RFC5780 ? "5780" : "3489"), ")");
                if (attempt_protocol(known_rfc)) {
                    overall_check_success = true;
                }
            } else {
                // 如果没有记录 先试5780 再试3489
                Print(CYAN, "[TCP] 监控: 尝试 ", host, " (RFC5780)");
                if (attempt_protocol(StunRfc::RFC5780)) {
                    overall_check_success = true;
                    protocol_map[server_str] = StunRfc::RFC5780; // 记录成功的协议
                } else {
                    Print(CYAN, "[TCP] 监控: 尝试 ", host, " (RFC3489)");
                    if (attempt_protocol(StunRfc::RFC3489)) {
                        overall_check_success = true;
                        protocol_map[server_str] = StunRfc::RFC3489; // 记录成功的协议
                    }
                }
            }

            if (overall_check_success) {
                current_server_index = server_index_to_try; // 更新“粘性”服务器索引
                break; // 检查成功 跳出服务器遍历循环
            }
        }

        if (overall_check_success) {
            if (current_ip != initial_ip || current_port != initial_port) {
                Print(YELLOW, "[TCP] 监控: 公网地址已变化！");
                Print(YELLOW, "       旧: ", initial_ip, ":", initial_port, " -> 新: ", current_ip, ":", current_port);
                g_tcp_reconnect_flag = true;
            }
        } else {
            Print(RED, "[TCP] 监控: 所有 STUN 服务器检查均失败");
            Print(YELLOW, "[TCP] 监控: 将维持当前连接 稍后重试...");
        }
    }
}

// 【重构】单线程代理循环 - 内部实现“软”恢复 (保活重连)
void TCP_SingleThreadProxyLoop(SOCKET listener_sock, const Config& config, int local_port) {
    std::map<SOCKET, ConnectionPair> connections;
    char buffer[8192];

    std::string ka_host = *config.keep_alive_host;
    std::string keep_alive_packet = "HEAD / HTTP/1.1\r\nHost: " + ka_host + "\r\nConnection: keep-alive\r\n\r\n";
    auto last_keepalive_time = std::chrono::steady_clock::now();
    
    SOCKET keep_alive_sock = INVALID_SOCKET;

    // 主循环 仅在需要“硬”重置 (公网IP变化) 时退出
    while (!g_tcp_reconnect_flag) {

        // --- 内部的保活连接管理 ---
        if (keep_alive_sock == INVALID_SOCKET) {
            Print(CYAN, "[TCP] 维持: 正在尝试连接保活服务器 ", *config.keep_alive_host, ":80...");
            bool ka_reconnected = false;
            for (int retry_count = 0; retry_count < config.keep_alive_retry; ++retry_count) {
                SOCKET new_ka_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (new_ka_sock == INVALID_SOCKET) continue;

                BOOL reuse = TRUE;
                setsockopt(new_ka_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                sockaddr_in local_addr = { AF_INET, htons(local_port), {INADDR_ANY} };
                if (bind(new_ka_sock, (sockaddr*)&local_addr, sizeof(local_addr)) != 0) {
                    closesocket(new_ka_sock);
                    continue;
                }

                addrinfo* ka_res = nullptr;
                if (getaddrinfo(config.keep_alive_host->c_str(), "80", nullptr, &ka_res) == 0) {
                    if (connect(new_ka_sock, ka_res->ai_addr, (int)ka_res->ai_addrlen) == 0) {
                        keep_alive_sock = new_ka_sock;
                        ka_reconnected = true;
                        freeaddrinfo(ka_res);
                        break;
                    }
                    freeaddrinfo(ka_res);
                }
                closesocket(new_ka_sock);
                
                if (retry_count < config.keep_alive_retry - 1) {
                    Print(YELLOW, "[TCP] 维持: 重连失败 3秒后重试 (", retry_count + 1, "/", config.keep_alive_retry, ")...");
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                }
            }

            if (!ka_reconnected) {
                Print(RED, "[TCP] 维持: 所有重连尝试均失败 触发完整重连...");
                g_tcp_reconnect_flag = true; // 软恢复失败 升级为硬恢复
                continue; // 跳出主循环
            }
            Print(LIGHT_GREEN, "[TCP] 维持: 成功连接保活服务器");
        }

        // --- 主 select 逻辑 ---
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listener_sock, &read_fds);
        FD_SET(keep_alive_sock, &read_fds);
        SOCKET max_sd = max(listener_sock, keep_alive_sock);

        for (const auto& pair : connections) {
            FD_SET(pair.second.client_socket, &read_fds);
            FD_SET(pair.second.local_socket, &read_fds);
            max_sd = max(max_sd, pair.second.client_socket);
            max_sd = max(max_sd, pair.second.local_socket);
        }

        timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int activity = select(max_sd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) { continue; }

        // ... (处理新连接和数据转发的逻辑与之前版本完全相同) ...
        if (FD_ISSET(listener_sock, &read_fds)) {
            sockaddr_in client_addr;
            int client_addr_len = sizeof(client_addr);
            SOCKET new_client_socket = accept(listener_sock, (sockaddr*)&client_addr, &client_addr_len);

            if (new_client_socket != INVALID_SOCKET) {
                char client_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
                
                if (config.tcp_forward_host && !config.tcp_forward_host->empty()) {
                    SOCKET new_local_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    addrinfo* fwd_res = nullptr;
                    getaddrinfo(config.tcp_forward_host->c_str(), std::to_string(*config.tcp_forward_port).c_str(), nullptr, &fwd_res);
                    if (connect(new_local_socket, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == 0) {
                        Print(YELLOW, "[TCP] 开始转发 ", client_ip_str, " <==> ", *config.tcp_forward_host, ":", *config.tcp_forward_port);
                        connections[new_client_socket] = { new_client_socket, new_local_socket };
                        connections[new_local_socket] = { new_client_socket, new_local_socket };
                    } else {
                        Print(RED, "[TCP] 无法连接本地目标 来自 ", client_ip_str, " 的连接已关闭");
                        closesocket(new_client_socket);
                        closesocket(new_local_socket);
                    }
                    freeaddrinfo(fwd_res);
                } else {
                    Print(CYAN, "[TCP] 仅打洞模式 来自 ", client_ip_str, " 的连接已接受并立即关闭");
                    closesocket(new_client_socket);
                }
            }
        }

        if (FD_ISSET(keep_alive_sock, &read_fds)) {
            int bytes = recv(keep_alive_sock, buffer, sizeof(buffer), 0);
            if (bytes <= 0) {
                Print(RED, "[TCP] 维持: 与保活服务器的连接已断开 将尝试自动重连...");
                closesocket(keep_alive_sock);
                keep_alive_sock = INVALID_SOCKET;
                continue; // 立即进入下一次循环 触发重连逻辑
            }
        }

        for (auto it = connections.begin(); it != connections.end(); ) {
            // ... (数据转发和连接清理逻辑与之前版本完全相同) ...
            bool connection_closed = false;
            SOCKET source_sock = it->first;
            
            if (FD_ISSET(source_sock, &read_fds)) {
                SOCKET target_sock = (source_sock == it->second.client_socket) ? it->second.local_socket : it->second.client_socket;
                int bytes = recv(source_sock, buffer, sizeof(buffer), 0);
                if (bytes > 0) {
                    if (send(target_sock, buffer, bytes, 0) <= 0) {
                        connection_closed = true;
                    }
                } else {
                    connection_closed = true;
                }
            }

            if (connection_closed) {
                // Print(YELLOW, "[TCP] 连接关闭 清理通道");
                closesocket(it->second.client_socket);
                closesocket(it->second.local_socket);
                SOCKET s1 = it->second.client_socket;
                SOCKET s2 = it->second.local_socket;
                connections.erase(s1);
                it = connections.find(s2);
                if (it != connections.end()) {
                    it = connections.erase(it);
                } else {
                    it = connections.begin();
                }
            } else {
                ++it;
            }
        }

        // --- 发送保活包 ---
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_keepalive_time).count() > config.keep_alive_ms) {
            if (send(keep_alive_sock, keep_alive_packet.c_str(), keep_alive_packet.length(), 0) == SOCKET_ERROR) {
                Print(RED, "[TCP] 维持: 发送保活包失败 连接已断开 将尝试自动重连...");
                closesocket(keep_alive_sock);
                keep_alive_sock = INVALID_SOCKET;
                continue; // 立即进入下一次循环 触发重连逻辑
            }
            last_keepalive_time = now;
        }
    }

    // 清理所有剩余的连接
    if (keep_alive_sock != INVALID_SOCKET) closesocket(keep_alive_sock);
    for (auto const& [key, val] : connections) {
        if (key == val.client_socket) {
            closesocket(val.client_socket);
            closesocket(val.local_socket);
        }
    }
}

// 【重构】TCP 主线程 - 负责找到初始状态并传递给监控线程
void TCP_PortForwardingThread(Config base_config) {
    winrt::init_apartment();

    if (!base_config.keep_alive_host.has_value() || base_config.keep_alive_host->empty()) {
        Print(RED, "[TCP] 错误: 未在配置文件中设置 'KeepAliveHost'TCP 线程无法启动");
        winrt::uninit_apartment();
        return;
    }

    do {
        g_tcp_reconnect_flag = false;
        g_tcp_ready = false;
        g_run_executed_this_cycle = false;
        Config config = base_config;
        SOCKET listener_sock = INVALID_SOCKET, stun_sock = INVALID_SOCKET;
        std::string public_ip; int public_port;
        bool stun_success = false;

        // 【新】用于记录成功状态的变量
        int last_successful_server_index = -1;
        std::map<std::string, StunRfc> protocol_map;

        Print(WHITE, "\n--- [TCP] 开始新一轮端口开启尝试 ---");

        // 阶段一: 使用 STUN 服务器发现端口
        for (int i = 0; i < config.stun_servers.size(); ++i) {
            if (stun_success) break;
            const auto& server_str = config.stun_servers[i];
            
            size_t colon_pos = server_str.find(':');
            if (colon_pos == std::string::npos) continue;
            std::string host = server_str.substr(0, colon_pos);
            int port = std::stoi(server_str.substr(colon_pos + 1));

            // 优先尝试 RFC5780
            for (int retry = 0; retry < config.stun_retry; ++retry) {
                Print(CYAN, "[TCP] 发现: 尝试 ", host, ":", port, " (RFC5780, 第 ", retry + 1, " 次)...");
                // ... (省略与之前版本相同的socket创建和bind代码) ...
                stun_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if(stun_sock == INVALID_SOCKET) continue;
                BOOL reuse = TRUE; setsockopt(stun_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                sockaddr_in local_addr = { AF_INET, htons(*config.tcp_listen_port), {INADDR_ANY} };
                if (bind(stun_sock, (sockaddr*)&local_addr, sizeof(local_addr)) != 0) { closesocket(stun_sock); continue; }
                
                addrinfo* stun_res = nullptr;
                if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
                    if (connect(stun_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == 0) {
                        char req[20]; BuildStunRequest(req, StunRfc::RFC5780);
                        if (send(stun_sock, req, sizeof(req), 0) != SOCKET_ERROR) {
                            char response_buffer[512];
                            int bytes = recv(stun_sock, response_buffer, sizeof(response_buffer), 0);
                            if (bytes > 20 && ParseStunResponse(response_buffer, bytes, StunRfc::RFC5780, public_ip, public_port)) {
                                stun_success = true;
                                last_successful_server_index = i;
                                protocol_map[server_str] = StunRfc::RFC5780;
                            }
                        }
                    }
                    freeaddrinfo(stun_res);
                }
                closesocket(stun_sock);
                if (stun_success) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(config.stun_retry_delay_ms));
            }
            if (stun_success) break;

            // 如果 RFC5780 失败 再尝试 RFC3489
            for (int retry = 0; retry < config.stun_retry; ++retry) {
                 Print(CYAN, "[TCP] 发现: 尝试 ", host, ":", port, " (RFC3489, 第 ", retry + 1, " 次)...");
                // ... (省略与之前版本相同的socket创建和bind代码) ...
                stun_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if(stun_sock == INVALID_SOCKET) continue;
                BOOL reuse = TRUE; setsockopt(stun_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                sockaddr_in local_addr = { AF_INET, htons(*config.tcp_listen_port), {INADDR_ANY} };
                if (bind(stun_sock, (sockaddr*)&local_addr, sizeof(local_addr)) != 0) { closesocket(stun_sock); continue; }

                addrinfo* stun_res = nullptr;
                if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
                    if (connect(stun_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == 0) {
                        char req[20]; BuildStunRequest(req, StunRfc::RFC3489);
                        if (send(stun_sock, req, sizeof(req), 0) != SOCKET_ERROR) {
                            char response_buffer[512];
                            int bytes = recv(stun_sock, response_buffer, sizeof(response_buffer), 0);
                            if (bytes > 20 && ParseStunResponse(response_buffer, bytes, StunRfc::RFC3489, public_ip, public_port)) {
                                stun_success = true;
                                last_successful_server_index = i;
                                protocol_map[server_str] = StunRfc::RFC3489;
                            }
                        }
                    }
                    freeaddrinfo(stun_res);
                }
                closesocket(stun_sock);
                if (stun_success) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(config.stun_retry_delay_ms));
            }
        }

        if (!stun_success) {
            Print(RED, "[TCP] 发现: 所有STUN服务器均尝试失败");
            if (config.auto_retry) {
                Print(YELLOW, "[TCP] 等待 ", config.retry_interval_ms / 1000, " 秒后重试...");
                std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
            }
            continue;
        }

        Print(LIGHT_GREEN, "[TCP] 发现: 成功获取公网端口 ", public_ip, ":", public_port);
        g_public_ip = public_ip;
        g_tcp_port_str = std::to_string(public_port);
        
        if (config.tcp_forward_port == 0) {
            config.tcp_forward_port = public_port;
            Print(CYAN, "[TCP] 动态转发端口已设置为公网端口: ", *config.tcp_forward_port);
        } else {
            Print(CYAN, "[TCP] 转发端口已设置为: ", *config.tcp_forward_port);
        }

        listener_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL reuse = TRUE;
        setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        sockaddr_in local_addr = { AF_INET, htons(*config.tcp_listen_port), {INADDR_ANY} };

        if (bind(listener_sock, (sockaddr*)&local_addr, sizeof(local_addr)) != 0 ||
            listen(listener_sock, SOMAXCONN) != 0) {
            Print(RED, "[TCP] 维持: 绑定或监听本地端口失败 重启流程...");
            if(listener_sock != INVALID_SOCKET) closesocket(listener_sock);
            if (config.auto_retry) std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
            continue;
        }
        
        Print(LIGHT_GREEN, "[TCP] 维持: 本地端口监听已就绪");
        g_tcp_ready = true;
        
        while (!CheckAndExecuteRun(base_config, base_config.tcp_listen_port.has_value(), base_config.udp_listen_port.has_value())) {
            if (g_tcp_reconnect_flag) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // 【新】将初始状态传递给监控线程
        std::thread(TCP_StunCheckThread, public_ip, public_port, config, *config.tcp_listen_port, last_successful_server_index, protocol_map).detach();

        TCP_SingleThreadProxyLoop(listener_sock, config, *config.tcp_listen_port);

        closesocket(listener_sock);
        if (g_tcp_reconnect_flag) {
            Print(YELLOW, "[TCP] 检测到公网地址变更 重启完整穿透流程...");
        }
    } while (base_config.auto_retry);

    winrt::uninit_apartment();
}

// ... (UDP 模块和主入口点模块保持不变) ...
struct UDPSession {
    SOCKET local_socket;
    sockaddr_in peer_addr;
    std::chrono::steady_clock::time_point last_activity;
};

void UDP_PortForwardingThread(Config base_config) {
    winrt::init_apartment();

    do {
        g_udp_reconnect_flag = false;
        g_udp_ready = false;
        g_run_executed_this_cycle = false;
        Config config = base_config;
        SOCKET public_sock = INVALID_SOCKET;
        std::string public_ip; int public_port;
        bool stun_success = false;
        std::map<std::string, UDPSession> sessions;
        sockaddr_in successful_stun_server_addr;

        Print(WHITE, "\n--- [UDP] 开始新一轮端口开启尝试 ---");

        public_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(public_sock == INVALID_SOCKET) {
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }
        sockaddr_in local_addr = { AF_INET, htons(*config.udp_listen_port), {INADDR_ANY} };
        if (bind(public_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            closesocket(public_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }

        for (const auto& server_str : config.stun_servers) {
            if (stun_success) break;
            size_t colon_pos = server_str.find(':');
            if (colon_pos == std::string::npos) continue;
            std::string host = server_str.substr(0, colon_pos);
            int port = std::stoi(server_str.substr(colon_pos + 1));

            auto attempt_stun = [&](StunRfc rfc) {
                for (int i = 0; i < config.stun_retry; ++i) {
                    Print(CYAN, "[UDP] 尝试 ", host, ":", port, " (RFC", (rfc == StunRfc::RFC5780 ? "5780" : "3489"), " 第 ", i + 1, " 次)...");
                    
                    addrinfo* stun_res = nullptr;
                    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
                        char req[20];
                        BuildStunRequest(req, rfc);
                        sendto(public_sock, req, sizeof(req), 0, stun_res->ai_addr, (int)stun_res->ai_addrlen);
                        
                        char response_buffer[512];
                        sockaddr_in from_addr; int from_len = sizeof(from_addr);
                        setsockopt(public_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&config.punch_timeout_ms, sizeof(config.punch_timeout_ms));
                        int bytes = recvfrom(public_sock, response_buffer, sizeof(response_buffer), 0, (sockaddr*)&from_addr, &from_len);

                        if (bytes > 20) {
                            if (ParseStunResponse(response_buffer, bytes, rfc, public_ip, public_port)) {
                                stun_success = true;
                                memcpy(&successful_stun_server_addr, stun_res->ai_addr, stun_res->ai_addrlen);
                            }
                        }
                        freeaddrinfo(stun_res);
                    }
                    if (stun_success) return;
                    std::this_thread::sleep_for(std::chrono::milliseconds(config.stun_retry_delay_ms));
                }
            };
            attempt_stun(StunRfc::RFC5780);
            if (stun_success) break;
            attempt_stun(StunRfc::RFC3489);
        }

        if (!stun_success) {
            Print(RED, "[UDP] 所有STUN服务器和协议均尝试失败");
            closesocket(public_sock);
            if (config.auto_retry) {
                Print(YELLOW, "[UDP] 等待 ", config.retry_interval_ms / 1000, " 秒后重试...");
                std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
            }
            continue;
        }

        g_public_ip = public_ip;
        g_udp_port_str = std::to_string(public_port);

        if (config.udp_forward_port == 0) {
            config.udp_forward_port = public_port;
            Print(CYAN, "[UDP] 动态转发端口已设置为公网端口: ", *config.udp_forward_port);
        } else {
            Print(CYAN, "[UDP] 转发端口已设置为: ", *config.udp_forward_port);
        }

        Print(LIGHT_GREEN, "[UDP] 成功！公网端口 ", public_ip, ":", public_port, " 已开启");
        
        g_udp_ready = true;
        while (!CheckAndExecuteRun(base_config, base_config.tcp_listen_port.has_value(), base_config.udp_listen_port.has_value())) {
            if (g_tcp_reconnect_flag || g_udp_reconnect_flag) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        auto last_cleanup_time = std::chrono::steady_clock::now();
        auto last_keepalive_time = std::chrono::steady_clock::now();

        while (!g_udp_reconnect_flag) {
            fd_set read_fds; FD_ZERO(&read_fds);
            FD_SET(public_sock, &read_fds);
            SOCKET max_sd = public_sock;

            for (const auto& pair : sessions) {
                FD_SET(pair.second.local_socket, &read_fds);
                if (pair.second.local_socket > max_sd) max_sd = pair.second.local_socket;
            }

            timeval timeout; timeout.tv_sec = 5; timeout.tv_usec = 0;
            int activity = select(max_sd + 1, &read_fds, NULL, NULL, &timeout);

            auto now = std::chrono::steady_clock::now();

            if (activity == SOCKET_ERROR) { g_udp_reconnect_flag = true; break; }
            if (activity > 0) {
                if (FD_ISSET(public_sock, &read_fds)) {
                    std::vector<char> buffer(config.udp_max_chunk_length);
                    sockaddr_in peer_addr; int peer_addr_len = sizeof(peer_addr);
                    int bytes = recvfrom(public_sock, buffer.data(), buffer.size(), 0, (sockaddr*)&peer_addr, &peer_addr_len);
                    if (bytes > 0) {
                        char peer_ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
                        std::string session_key = std::string(peer_ip_str) + ":" + std::to_string(ntohs(peer_addr.sin_port));

                        if (sessions.count(session_key)) {
                            sessions[session_key].last_activity = now;
                            send(sessions[session_key].local_socket, buffer.data(), bytes, 0);
                        } else {
                            if (config.udp_forward_host && !config.udp_forward_host->empty()) {
                                SOCKET local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                                addrinfo* fwd_res = nullptr;
                                getaddrinfo(config.udp_forward_host->c_str(), std::to_string(*config.udp_forward_port).c_str(), nullptr, &fwd_res);
                                connect(local_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen);
                                freeaddrinfo(fwd_res);
                                send(local_sock, buffer.data(), bytes, 0);
                                Print(GREEN, "[UDP] 新会话 ", session_key, " ==> ", *config.udp_forward_host, ":", *config.udp_forward_port);
                                sessions[session_key] = { local_sock, peer_addr, now };
                            } else {
                                Print(CYAN, "[UDP] 收到来自 ", session_key, " 的数据包 (仅打洞模式) 已丢弃");
                            }
                        }
                    }
                }
                for (auto it = sessions.begin(); it != sessions.end(); ++it) {
                    if (FD_ISSET(it->second.local_socket, &read_fds)) {
                        std::vector<char> buffer(config.udp_max_chunk_length);
                        int bytes = recv(it->second.local_socket, buffer.data(), buffer.size(), 0);
                        if (bytes > 0) {
                            it->second.last_activity = now;
                            sendto(public_sock, buffer.data(), bytes, 0, (sockaddr*)&it->second.peer_addr, sizeof(it->second.peer_addr));
                        }
                    }
                }
            }
            
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_keepalive_time).count() > config.keep_alive_ms) {
                char keepalive_req[20];
                BuildStunRequest(keepalive_req, StunRfc::RFC5780);
                sendto(public_sock, keepalive_req, sizeof(keepalive_req), 0, (sockaddr*)&successful_stun_server_addr, sizeof(successful_stun_server_addr));
                last_keepalive_time = now;
            }

            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup_time).count() >= 10) {
                for (auto it = sessions.begin(); it != sessions.end(); ) {
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_activity).count() > config.udp_session_timeout_ms) {
                        Print(YELLOW, "[UDP] 会话 ", it->first, " 超时 已清理");
                        closesocket(it->second.local_socket);
                        it = sessions.erase(it);
                    } else {
                        ++it;
                    }
                }
                last_cleanup_time = now;
            }
        }
        closesocket(public_sock);
        for(const auto& pair : sessions) closesocket(pair.second.local_socket);
        if (g_udp_reconnect_flag) {
            Print(YELLOW, "[UDP] 检测到重连信号 重启流程...");
        }
    } while (base_config.auto_retry);

    winrt::uninit_apartment();
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_APP_EXECUTE_RUN: {
            Print(CYAN, "[IPC] 收到 -run 命令 正在执行...");
            wchar_t exe_path_wchar[MAX_PATH];
            GetModuleFileNameW(NULL, exe_path_wchar, MAX_PATH);
            PathRemoveFileSpecW(exe_path_wchar);
            std::wstring iniPath = std::wstring(exe_path_wchar) + L"\\" + g_app_name + L".ini";
            Config config = ReadIniConfig(iniPath);
            ExecuteRunCommand(config);
            return 0;
        }
        case WM_APP_SHOW_NOTIFICATION: {
            TriggerManualNotification();
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void MainLogic(const Config& config);

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    bool run_command_only = false;
    bool show_command_only = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-hide") == 0) g_is_hidden = true;
        if (strcmp(argv[i], "-run") == 0) run_command_only = true;
        if (strcmp(argv[i], "-show") == 0) show_command_only = true;
    }

    wchar_t exe_path_wchar[MAX_PATH];
    GetModuleFileNameW(NULL, exe_path_wchar, MAX_PATH);
    std::wstring exe_path_str = exe_path_wchar;
    std::wstring exe_name = exe_path_str.substr(exe_path_str.find_last_of(L"/\\") + 1);
    g_app_name = exe_name.substr(0, exe_name.rfind(L'.'));

    HANDLE hMutex = CreateMutexW(NULL, TRUE, g_app_name.c_str());
    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND hExistingWnd = FindWindowW(g_app_name.c_str(), NULL);
        if (hExistingWnd) {
            if (run_command_only) {
                SendMessageW(hExistingWnd, WM_APP_EXECUTE_RUN, 0, 0);
            }
            if (show_command_only) {
                SendMessageW(hExistingWnd, WM_APP_SHOW_NOTIFICATION, 0, 0);
            }
        }
        CloseHandle(hMutex);
        WSACleanup();
        return 1;
    }

    if (g_is_hidden) {
        FreeConsole();
    } else {
        if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) {
            SetConsoleOutputCP(65001);
            SetConsoleTitleW(g_app_name.c_str());
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
            freopen_s(&fDummy, "CONIN$", "r", stdin);
            std::cout.clear(); std::cin.clear(); std::cerr.clear();
        }
    }

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = g_app_name.c_str();
    RegisterClassW(&wc);
    g_hMessageWindow = CreateWindowExW(0, g_app_name.c_str(), L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);

    PathRemoveFileSpecW(exe_path_wchar);
    std::wstring iniPath = std::wstring(exe_path_wchar) + L"\\" + g_app_name + L".ini";
    Config config = ReadIniConfig(iniPath);
    
    std::thread main_thread(MainLogic, config);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    main_thread.join();
    ReleaseMutex(hMutex);
    CloseHandle(hMutex);
    DestroyWindow(g_hMessageWindow);
    WSACleanup();
    return 0;
}

void MainLogic(const Config& config) {
    Print(YELLOW, "--- STUN Traversal ---");
	Print(YELLOW, "--- 隐藏运行 -hide ---");
	Print(YELLOW, "--- 显示通知 -show ---");
	Print(YELLOW, "--- 运行程序 -run ---");
    if (config.stun_servers.empty()) {
        Print(RED, "错误：配置文件中未找到任何 [STUN] 服务器");
        return;
    }

    std::vector<std::thread> threads;
    if (config.tcp_listen_port) {
        threads.emplace_back(TCP_PortForwardingThread, config);
    }
    if (config.udp_listen_port) {
        threads.emplace_back(UDP_PortForwardingThread, config);
    }

    if (threads.empty()) {
        Print(RED, "错误：配置文件中未启用任何监听端口");
        return;
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}