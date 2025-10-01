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

// --- 辅助函数：健壮地从TCP流中读取指定长度的数据 ---
bool RecvAll(SOCKET sock, char* buffer, int len) {
    int total_received = 0;
    while (total_received < len) {
        int bytes = recv(sock, buffer + total_received, len - total_received, 0);
        if (bytes <= 0) {
            return false; // 连接关闭或出错
        }
        total_received += bytes;
    }
    return true;
}

// --- STUN 客户端 (STUN over TCP 模式 - 已修复TCP流读取逻辑) ---
bool GetPublicEndpoint_TCP(const Config& config, std::string& out_ip, int& out_port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    addrinfo* stun_res = nullptr;
    getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_res);
    if (!stun_res) { closesocket(sock); return false; }
    
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, stun_res->ai_addr, (int)stun_res->ai_addrlen);
    
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    timeval timeout = { 3, 0 };
    
    bool connected = false;
    if (select(0, NULL, &write_set, NULL, &timeout) > 0) {
        int opt_val;
        int opt_len = sizeof(opt_val);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&opt_val, &opt_len) == 0 && opt_val == 0) {
            connected = true;
        }
    }
    
    freeaddrinfo(stun_res);
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);

    if (!connected) {
        closesocket(sock);
        return false;
    }

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

    if (send(sock, req, sizeof(req), 0) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    // --- FIX: Robust two-stage TCP stream reading ---
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Stage 1: Read exactly 20 bytes for the header
    char header_buffer[20];
    if (!RecvAll(sock, header_buffer, 20)) {
        closesocket(sock);
        return false;
    }

    // Stage 2: Parse message length and read the rest of the message
    unsigned short msg_len = ntohs(*(unsigned short*)(header_buffer + 2));
    if (msg_len > 1400) { // Sanity check
        closesocket(sock);
        return false;
    }

    std::vector<char> attr_buffer(msg_len);
    if (msg_len > 0 && !RecvAll(sock, attr_buffer.data(), msg_len)) {
        closesocket(sock);
        return false;
    }
    closesocket(sock); // We have the full message, close the socket

    // Combine header and attributes into one buffer for parsing
    std::vector<char> full_message(20 + msg_len);
    memcpy(full_message.data(), header_buffer, 20);
    if (msg_len > 0) {
        memcpy(full_message.data() + 20, attr_buffer.data(), msg_len);
    }

    // Parse the complete response
    if (!((full_message[0] == 0x01) && (full_message[1] == 0x01))) return false;
    const char* p = full_message.data() + 20;
    while (p < full_message.data() + full_message.size()) {
        unsigned short type = ntohs(*(unsigned short*)p);
        unsigned short len = ntohs(*(unsigned short*)(p + 2));
        if (type == 0x0020) { // XOR-MAPPED-ADDRESS
            unsigned short port = ntohs(*(unsigned short*)(p + 6));
            unsigned int ip = ntohl(*(unsigned int*)(p + 8));
            port ^= (ntohl(0x2112A442) >> 16);
            ip ^= ntohl(0x2112A442);
            
            in_addr addr = { htonl(ip) };
            out_ip = inet_ntoa(addr);
            out_port = port;
            return true;
        }
        p += (4 + (len % 4 == 0 ? len : len + (4 - len % 4))); // Attributes are 4-byte aligned
    }
    return false;
}

// --- TCP 代理和心跳 ---
void TcpProxy(SOCKET s1, SOCKET s2, int keep_alive_ms) {
    tcp_keepalive ka;
    ka.onoff = (u_long)1;
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

        SetColor(CYAN);
        std::cout << "[步骤 1] 正在通过 STUN/TCP 发现公网地址..." << std::endl;
        std::string my_public_ip;
        int my_public_port;
        if (!GetPublicEndpoint_TCP(config, my_public_ip, my_public_port)) {
            SetColor(RED);
            std::cerr << "[失败] STUN/TCP 请求超时或失败。请检查服务器地址或网络连接。" << std::endl;
            if (config.tcp_auto_retry) {
                SetColor(YELLOW);
                std::cout << "[准备重试] 等待 " << config.tcp_retry_interval_ms << " 毫秒后将自动重试..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(config.tcp_retry_interval_ms));
                continue;
            } else {
                break;
            }
        }
        
        SetColor(LIGHT_GREEN);
        std::cout << "[成功] 我的公网地址是: " << my_public_ip << ":" << my_public_port << std::endl;
        if (is_listener) {
            SetColor(YELLOW);
            std::cout << "[操作] 请将此地址发送给连接方。" << std::endl;
        }

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL reuse = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        
        sockaddr_in local_addr = { AF_INET, htons(config.tcp_local_listen_port), {INADDR_ANY} };
        if (bind(sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            SetColor(RED);
            std::cerr << "[错误] 无法绑定本地端口 " << config.tcp_local_listen_port << "。该端口可能已被占用。" << std::endl;
            closesocket(sock);
            if (config.tcp_auto_retry) {
                SetColor(YELLOW);
                std::cout << "[准备重试] 等待 " << config.tcp_retry_interval_ms << " 毫秒后将自动重试..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(config.tcp_retry_interval_ms));
                continue;
            } else {
                break;
            }
        }

        SetColor(CYAN);
        std::cout << "[步骤 2] 套接字已成功绑定至本地端口 " << config.tcp_local_listen_port << "。" << std::endl;

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
        std::cout << "[成功] NAT 预热包已发送。" << std::endl;

        SOCKET peer_sock = INVALID_SOCKET;
        if (is_listener) {
            SetColor(CYAN);
            std::cout << "[步骤 4] 正在监听等待对方连接..." << std::endl;
            listen(sock, 1);
            
            timeval timeout = { config.tcp_punch_timeout_ms / 1000, (config.tcp_punch_timeout_ms % 1000) * 1000 };
            fd_set read_set;
            FD_ZERO(&read_set);
            FD_SET(sock, &read_set);
            if (select(0, &read_set, NULL, NULL, &timeout) > 0) {
                peer_sock = accept(sock, NULL, NULL);
            }
        } else {
            SetColor(CYAN);
            std::cout << "[步骤 4] 正在连接对端地址 " << peer_addr_str << "..." << std::endl;
            size_t colon_pos = peer_addr_str.find(':');
            std::string peer_ip = peer_addr_str.substr(0, colon_pos);
            int peer_port = std::stoi(peer_addr_str.substr(colon_pos + 1));
            
            sockaddr_in peer_addr = { AF_INET, htons(peer_port) };
            inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);

            timeval timeout = { config.tcp_punch_timeout_ms / 1000, (config.tcp_punch_timeout_ms % 1000) * 1000 };
            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            
            mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            connect(sock, (sockaddr*)&peer_addr, sizeof(peer_addr));
            if (select(0, NULL, &write_set, NULL, &timeout) > 0) {
                peer_sock = sock;
            }
            mode = 0;
            ioctlsocket(sock, FIONBIO, &mode);
        }

        if (peer_sock != INVALID_SOCKET) {
            SetColor(LIGHT_GREEN);
            std::cout << "\n[穿透成功] TCP 打洞成功！P2P 直连已建立。" << std::endl;
            SetColor(YELLOW);
            std::cout << "[开始转发] 正在代理 P2P 连接与本地目标 " << config.tcp_forward_host << ":" << config.tcp_forward_port << " 之间的数据。" << std::endl;

            SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            addrinfo* fwd_res = nullptr;
            getaddrinfo(config.tcp_forward_host.c_str(), std::to_string(config.tcp_forward_port).c_str(), nullptr, &fwd_res);
            if (connect(target_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == SOCKET_ERROR) {
                SetColor(RED);
                std::cerr << "[错误] 无法连接到本地转发目标。" << std::endl;
            } else {
                std::thread(TcpProxy, peer_sock, target_sock, config.tcp_keep_alive_ms).detach();
                std::thread(TcpProxy, target_sock, peer_sock, config.tcp_keep_alive_ms).join();
            }
            freeaddrinfo(fwd_res);
            closesocket(target_sock);
            SetColor(WHITE);
            std::cout << "[连接关闭] P2P 连接已断开。" << std::endl;
        } else {
            SetColor(RED);
            std::cerr << "[穿透失败] TCP 打洞失败 (连接超时)。" << std::endl;
            closesocket(sock);
        }

        if (config.tcp_auto_retry) {
            SetColor(YELLOW);
            std::cout << "[准备重试] 等待 " << config.tcp_retry_interval_ms << " 毫秒后将自动重试..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(config.tcp_retry_interval_ms));
        }
    } while (config.tcp_auto_retry);
}

// --- 主函数 ---
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(65001);
    SetConsoleTitleA("TCP NAT 穿透转发器");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (argc < 2 || (strcmp(argv[1], "listen") != 0 && strcmp(argv[1], "connect") != 0)) {
        SetColor(YELLOW);
        std::cout << "用法说明:\n";
        std::cout << "  作为监听方:  forwarder.exe listen\n";
        std::cout << "  作为连接方:  forwarder.exe connect <监听方的公网IP:端口>\n";
        WSACleanup();
        return 1;
    }

    bool is_listener = (strcmp(argv[1], "listen") == 0);
    std::string peer_addr_str = "";
    if (!is_listener) {
        if (argc < 3) {
            SetColor(RED);
            std::cerr << "错误: 连接方模式需要提供对端的公网地址。" << std::endl;
            return 1;
        }
        peer_addr_str = argv[2];
    }

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string iniPath = std::string(exePath) + "\\config.ini";
    
    Config config = ReadIniConfig(iniPath);

    TcpHolePunchingThread(config, is_listener, peer_addr_str);

    WSACleanup();
    return 0;
}