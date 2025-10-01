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
    int tcp_local_listen_port;
    std::string tcp_forward_host;
    int tcp_forward_port;
    std::string tcp_priming_host;
    int tcp_punch_timeout_ms;
    int tcp_keep_alive_ms;
    int tcp_retry_interval_ms;
    bool tcp_auto_retry;
};

// --- INI 文件解析 ---
Config ReadIniConfig(const std::string& filePath) {
    Config config;
    char buffer[1024];
    GetPrivateProfileStringA("STUN", "ServerHost", "stun.l.google.com", buffer, sizeof(buffer), filePath.c_str());
    config.stun_server_host = buffer;
    config.stun_server_port = GetPrivateProfileIntA("STUN", "ServerPort", 19302, filePath.c_str());
    config.tcp_local_listen_port = GetPrivateProfileIntA("TCP_HolePunch", "LocalListenPort", 8001, filePath.c_str());
    GetPrivateProfileStringA("TCP_HolePunch", "ForwardHost", "127.0.0.1", buffer, sizeof(buffer), filePath.c_str());
    config.tcp_forward_host = buffer;
    config.tcp_forward_port = GetPrivateProfileIntA("TCP_HolePunch", "ForwardPort", 23000, filePath.c_str());
    GetPrivateProfileStringA("TCP_HolePunch", "PrimingHost", "qq.com", buffer, sizeof(buffer), filePath.c_str());
    config.tcp_priming_host = buffer;
    config.tcp_punch_timeout_ms = GetPrivateProfileIntA("TCP_HolePunch", "PunchTimeoutMS", 3000, filePath.c_str());
    config.tcp_keep_alive_ms = GetPrivateProfileIntA("TCP_HolePunch", "KeepAliveMS", 2300, filePath.c_str());
    config.tcp_retry_interval_ms = GetPrivateProfileIntA("TCP_HolePunch", "RetryIntervalMS", 3000, filePath.c_str());
    config.tcp_auto_retry = GetPrivateProfileIntA("TCP_HolePunch", "AutoRetry", 1, filePath.c_str()) == 1;
    return config;
}

// --- STUN 客户端 ---
bool GetPublicEndpoint(const Config& config, std::string& out_ip, int& out_port) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    addrinfo* stun_res = nullptr;
    getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_res);
    if (!stun_res) { closesocket(sock); return false; }
    sockaddr_in stun_addr = *(sockaddr_in*)stun_res->ai_addr;
    freeaddrinfo(stun_res);

    char req[20] = { 0 };
    *(unsigned short*)req = htons(0x0001);
    *(unsigned short*)(req + 2) = 0;
    *(unsigned int*)(req + 4) = htonl(0x2112A442);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis;
    for (int i = 0; i < 3; ++i) {
        *(unsigned int*)(req + 8 + i * 4) = dis(gen);
    }

    sendto(sock, req, sizeof(req), 0, (const sockaddr*)&stun_addr, sizeof(stun_addr));

    timeval timeout = { 3, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    char buffer[1500];
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    closesocket(sock);

    if (bytes <= 0) return false;

    if (!((buffer[0] == 0x01) && (buffer[1] == 0x01))) return false;
    const char* p = buffer + 20;
    while (p < buffer + bytes) {
        unsigned short type = ntohs(*(unsigned short*)p);
        unsigned short len = ntohs(*(unsigned short*)(p + 2));
        if (type == 0x0020) {
            unsigned short port = ntohs(*(unsigned short*)(p + 6));
            unsigned int ip = ntohl(*(unsigned int*)(p + 8));
            port ^= (ntohl(0x2112A442) >> 16);
            ip ^= ntohl(0x2112A442);
            
            in_addr addr = { htonl(ip) };
            out_ip = inet_ntoa(addr);
            out_port = port;
            return true;
        }
        p += (4 + len);
    }
    return false;
}

// --- TCP 代理和心跳 ---
void TcpProxy(SOCKET s1, SOCKET s2, int keep_alive_ms) {
    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = keep_alive_ms;
    ka.keepaliveinterval = 1000;
    DWORD bytes_returned;
    WSAIoctl(s1, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes_returned, NULL, NULL);
    
    char buffer[8192];
    while (true) {
        int bytes = recv(s1, buffer, sizeof(buffer), 0);
        if (bytes <= 0) break;
        if (send(s2, buffer, bytes, 0) <= 0) break;
    }
    closesocket(s1);
    closesocket(s2);
}

// --- TCP 打洞主逻辑 ---
void TcpHolePunchingThread(Config config, bool is_listener, const std::string& peer_addr_str) {
    do {
        SetColor(WHITE);
        std::cout << "\n--- 开始新一轮穿透尝试 ---" << std::endl;

        // 1. 获取公网地址
        SetColor(CYAN);
        std::cout << "[步骤 1] 正在通过 STUN 服务器发现公网地址..." << std::endl;
        std::string my_public_ip;
        int my_public_port;
        if (GetPublicEndpoint(config, my_public_ip, my_public_port)) {
            SetColor(LIGHT_GREEN);
            std::cout << "[成功] 我的公网地址是: " << my_public_ip << ":" << my_public_port << std::endl;
            if (is_listener) {
                SetColor(YELLOW);
                std::cout << "[操作] 请将此地址发送给连接方。" << std::endl;
            }
        } else {
            SetColor(RED);
            std::cerr << "[失败] STUN 请求超时或失败。请检查服务器地址或网络连接。" << std::endl;
            goto retry_logic;
        }

        // 2. 创建并绑定本地TCP套接字
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL reuse = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        
        sockaddr_in local_addr = { AF_INET, htons(config.tcp_local_listen_port), {INADDR_ANY} };
        if (bind(sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            SetColor(RED);
            std::cerr << "[错误] 无法绑定本地端口 " << config.tcp_local_listen_port << "。该端口可能已被占用。" << std::endl;
            closesocket(sock);
            goto retry_logic;
        }
        SetColor(CYAN);
        std::cout << "[步骤 2] 套接字已成功绑定至本地端口 " << config.tcp_local_listen_port << "。" << std::endl;

        // 3. "预热" NAT
        SetColor(CYAN);
        std::cout << "[步骤 3] 正在通过连接 '" << config.tcp_priming_host << "' 来预热 NAT..." << std::endl;
        addrinfo* prime_res = nullptr;
        getaddrinfo(config.tcp_priming_host.c_str(), "80", nullptr, &prime_res);
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        connect(sock, prime_res->ai_addr, (int)prime_res->ai_addrlen);
        freeaddrinfo(prime_res);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        SetColor(GREEN);
        