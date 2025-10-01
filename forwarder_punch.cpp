#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <random>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <mstcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

// --- 控制台颜色管理 ---
enum ConsoleColor { DARKBLUE = 1, GREEN = 2, CYAN = 3, RED = 4, MAGENTA = 5, YELLOW = 6, WHITE = 7, GRAY = 8, LIGHT_GREEN = 10 };
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
void SetColor(ConsoleColor color) { SetConsoleTextAttribute(hConsole, color); }

// --- 配置结构体 ---
struct Config {
    std::string stun_server_host;
    int stun_server_port;
    int local_punch_port;
    std::string forward_host;
    int forward_port;
    std::string priming_host;
    int keep_alive_ms;
    int retry_interval_ms;
    bool auto_retry;
};

// --- INI 文件解析 ---
Config ReadIniConfig(const std::string& filePath) {
    Config config;
    char buffer[1024];
    GetPrivateProfileStringA("STUN", "ServerHost", "stun.l.google.com", buffer, sizeof(buffer), filePath.c_str());
    config.stun_server_host = buffer;
    config.stun_server_port = GetPrivateProfileIntA("STUN", "ServerPort", 19302, filePath.c_str());
    config.local_punch_port = GetPrivateProfileIntA("TCP_HolePunch", "LocalListenPort", 8001, filePath.c_str());
    GetPrivateProfileStringA("TCP_HolePunch", "ForwardHost", "127.0.0.1", buffer, sizeof(buffer), filePath.c_str());
    config.forward_host = buffer;
    config.forward_port = GetPrivateProfileIntA("TCP_HolePunch", "ForwardPort", 9999, filePath.c_str());
    // *** 关键修改：使用一个不会响应的地址作为默认打洞目标 ***
    GetPrivateProfileStringA("TCP_HolePunch", "PrimingHost", "192.0.2.1", buffer, sizeof(buffer), filePath.c_str());
    config.priming_host = buffer;
    config.keep_alive_ms = GetPrivateProfileIntA("TCP_HolePunch", "KeepAliveMS", 2300, filePath.c_str());
    config.retry_interval_ms = GetPrivateProfileIntA("TCP_HolePunch", "RetryIntervalMS", 30000, filePath.c_str());
    config.auto_retry = GetPrivateProfileIntA("TCP_HolePunch", "AutoRetry", 1, filePath.c_str()) == 1;
    return config;
}

// --- STUN 客户端 (无需修改) ---
bool GetPublicEndpoint_TCP(const Config& config, std::string& out_ip, int& out_port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    addrinfo* stun_res = nullptr;
    if (getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_res) != 0 || !stun_res) {
        closesocket(sock); return false;
    }
    DWORD timeout_ms = 3000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    if (connect(sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == SOCKET_ERROR) {
        freeaddrinfo(stun_res); closesocket(sock); return false;
    }
    freeaddrinfo(stun_res);
    char req[20] = { 0 };
    *(unsigned short*)req = htons(0x0001); *(unsigned short*)(req + 2) = 0; *(unsigned int*)(req + 4) = htonl(0x2112A442);
    std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<unsigned int> dis;
    for (int i = 0; i < 3; ++i) { *(unsigned int*)(req + 8 + i * 4) = dis(gen); }
    if (send(sock, req, sizeof(req), 0) == SOCKET_ERROR) { closesocket(sock); return false; }
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    char header_buffer[20];
    if (!RecvAll(sock, header_buffer, 20)) { closesocket(sock); return false; }
    if (!((header_buffer[0] == 0x01) && (header_buffer[1] == 0x01))) { closesocket(sock); return false; }
    unsigned short msg_len = ntohs(*(unsigned short*)(header_buffer + 2));
    if (msg_len > 1400) { closesocket(sock); return false; }
    std::vector<char> attr_buffer(msg_len);
    if (msg_len > 0 && !RecvAll(sock, attr_buffer.data(), msg_len)) { closesocket(sock); return false; }
    closesocket(sock);
    const char* p = attr_buffer.data(); const char* end = p + msg_len;
    while (p < end) {
        unsigned short type = ntohs(*(unsigned short*)p); unsigned short len = ntohs(*(unsigned short*)(p + 2));
        const char* attr_value = p + 4;
        if (type == 0x0020) {
            unsigned short port_net = *(unsigned short*)(attr_value + 2); unsigned int ip_net = *(unsigned int*)(attr_value + 4);
            unsigned int magic_cookie_net = htonl(0x2112A442);
            unsigned short real_port_net = port_net ^ htons(0x2112); unsigned int real_ip_net = ip_net ^ magic_cookie_net;
            out_port = ntohs(real_port_net);
            in_addr addr; addr.s_addr = real_ip_net;
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN) != NULL) {
                out_ip = ip_str; return true;
            } else { return false; }
        }
        p += 4 + len; if (len % 4 != 0) p += (4 - (len % 4));
    }
    return false;
}

// --- TCP 代理 (无需修改) ---
void TcpProxy(SOCKET s1, SOCKET s2, int keep_alive_ms) {
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

// --- 连接处理 (无需修改) ---
void HandleNewConnection(SOCKET peer_sock, Config config) {
    sockaddr_in peer_addr; int peer_addr_len = sizeof(peer_addr);
    getpeername(peer_sock, (sockaddr*)&peer_addr, &peer_addr_len);
    char peer_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
    SetColor(GREEN);
    std::cout << "[新连接] 接受来自 " << peer_ip_str << ":" << ntohs(peer_addr.sin_port) << " 的连接。" << std::endl;
    SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addrinfo* fwd_res = nullptr;
    getaddrinfo(config.forward_host.c_str(), std::to_string(config.forward_port).c_str(), nullptr, &fwd_res);
    if (connect(target_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == SOCKET_ERROR) {
        SetColor(RED);
        std::cerr << "[错误] 无法连接到本地转发目标 " << config.forward_host << ":" << config.forward_port << std::endl;
        closesocket(peer_sock);
    } else {
        SetColor(YELLOW);
        std::cout << "[转发] 开始转发 " << peer_ip_str << " <==> " << config.forward_host << ":" << config.forward_port << std::endl;
        std::thread(TcpProxy, peer_sock, target_sock, config.keep_alive_ms).detach();
        std::thread(TcpProxy, target_sock, peer_sock, config.keep_alive_ms).detach();
    }
    freeaddrinfo(fwd_res);
}

// --- 单边打洞并监听的主逻辑 (已修复) ---
void PortForwardingThread(Config config) {
    do {
        SetColor(WHITE);
        std::cout << "\n--- 开始新一轮端口开启尝试 ---" << std::endl;

        std::string public_ip; int public_port;
        SetColor(CYAN);
        std::cout << "[步骤 1] 正在通过 STUN/TCP 发现公网地址..." << std::endl;
        if (!GetPublicEndpoint_TCP(config, public_ip, public_port)) {
            SetColor(RED); std::cerr << "[失败] STUN 请求失败。" << std::endl;
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }
        SetColor(LIGHT_GREEN);
        std::cout << "[成功] 当前公网端口为: " << public_ip << ":" << public_port << std::endl;

        SOCKET listener_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL reuse = TRUE;
        setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        sockaddr_in local_addr = { AF_INET, htons(config.local_punch_port), {INADDR_ANY} };
        if (bind(listener_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            SetColor(RED); std::cerr << "[错误] 无法绑定本地端口 " << config.local_punch_port << "。" << std::endl;
            closesocket(listener_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }
        SetColor(CYAN);
        std::cout << "[步骤 2] 套接字已成功绑定至本地端口 " << config.local_punch_port << "。" << std::endl;

        SetColor(CYAN);
        std::cout << "[步骤 3] 正在向 '" << config.priming_host << "' 发送打洞包..." << std::endl;
        addrinfo* prime_res = nullptr;
        getaddrinfo(config.priming_host.c_str(), "80", nullptr, &prime_res);
        if (prime_res) {
            // *** 关键修改：使用带超时的阻塞 connect ***
            // 1. 设置一个非常短的发送超时，确保 SYN 包能发出去
            DWORD timeout = 1000; // 1秒
            setsockopt(listener_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

            // 2. 这个 connect 注定会因为超时而失败，但这正是我们想要的！
            //    失败前，SYN 包已经被发出，NAT 映射已建立。
            connect(listener_sock, prime_res->ai_addr, (int)prime_res->ai_addrlen);
            freeaddrinfo(prime_res);

            // 3. connect 失败后，套接字仍处于可用状态，可以安全地调用 listen
            if (listen(listener_sock, SOMAXCONN) == SOCKET_ERROR) {
                 SetColor(RED);
                 std::cerr << "[错误] 套接字 listen() 失败。错误码: " << WSAGetLastError() << std::endl;
                 closesocket(listener_sock);
                 if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
            }
            
            SetColor(GREEN);
            std::cout << "[成功] 打洞完成！公网端口 " << public_port << " 已开启并监听。" << std::endl;
            SetColor(YELLOW);
            std::cout << "[服务] 所有传入连接将被转发到 " << config.forward_host << ":" << config.forward_port << std::endl;

            while (true) {
                SOCKET peer_sock = accept(listener_sock, NULL, NULL);
                if (peer_sock == INVALID_SOCKET) {
                    SetColor(RED); std::cerr << "[警告] accept() 失败，准备重试..." << std::endl;
                    break;
                }
                std::thread(HandleNewConnection, peer_sock, config).detach();
            }
        } else {
             SetColor(RED); std::cerr << "[错误] 无法解析预热主机 '" << config.priming_host << "'。" << std::endl;
        }
        closesocket(listener_sock);
        if (config.auto_retry) {
             SetColor(YELLOW); std::cout << "[准备重试] 等待 " << config.retry_interval_ms / 1000 << " 秒后将自动重试..." << std::endl;
             std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
        }
    } while (config.auto_retry);
}

// --- 主函数 (无需修改) ---
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(65001);
    SetConsoleTitleA("TCP NAT 端口转发器");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string iniPath = std::string(exePath) + "\\config.ini";
    Config config = ReadIniConfig(iniPath);
    SetColor(YELLOW);
    std::cout << "--- TCP NAT 端口转发器 (修复版) ---" << std::endl;
    std::cout << "本程序将尝试通过STUN在NAT上打开一个公网端口，" << std::endl;
    std::cout << "并将所有流量转发到本地的 " << config.forward_host << ":" << config.forward_port << std::endl;
    PortForwardingThread(config);
    WSACleanup();
    return 0;
}