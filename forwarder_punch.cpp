#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
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
    // STUN
    std::string stun_server_host;
    int stun_server_port;

    // TCP Hole Punching
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
std::string GetPublicEndpoint(const Config& config, std::string& out_ip, int& out_port) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    addrinfo* stun_res = nullptr;
    getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_res);
    sockaddr_in stun_addr = *(sockaddr_in*)stun_res->ai_addr;
    freeaddrinfo(stun_res);

    char req[20] = { 0 };
    *(unsigned short*)req = htons(0x0001); // STUN Binding Request
    *(unsigned int*)(req + 4) = htonl(0x2112A442); // Magic Cookie

    sendto(sock, req, sizeof(req), 0, (const sockaddr*)&stun_addr, sizeof(stun_addr));

    // 设置接收超时
    timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    char buffer[1500];
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    closesocket(sock);

    if (bytes <= 0) return "STUN request timed out or failed.";

    // 解析响应
    if (!((buffer[0] == 0x01) && (buffer[1] == 0x01))) return "Invalid STUN response.";
    const char* p = buffer + 20;
    while (p < buffer + bytes) {
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
            return out_ip + ":" + std::to_string(out_port);
        }
        p += (4 + len);
    }
    return "Could not find address attribute in STUN response.";
}

// --- TCP 代理和心跳 ---
void TcpProxy(SOCKET s1, SOCKET s2, int keep_alive_ms) {
    // 启用TCP Keep-Alive
    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = keep_alive_ms;
    ka.keepaliveinterval = 1000; // 1 second
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
        std::cout << "\n--- Starting new punch attempt ---" << std::endl;

        // 1. 获取公网地址
        SetColor(CYAN);
        std::cout << "[Step 1] Discovering public endpoint via STUN..." << std::endl;
        std::string my_public_ip;
        int my_public_port;
        std::string my_public_endpoint = GetPublicEndpoint(config, my_public_ip, my_public_port);
        SetColor(LIGHT_GREEN);
        std::cout << "[Success] My public endpoint is: " << my_public_endpoint << std::endl;
        if (is_listener) {
            SetColor(YELLOW);
            std::cout << "[Action] Please send this address to the connector peer." << std::endl;
        }

        // 2. 创建并绑定本地TCP套接字
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        BOOL reuse = TRUE;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        
        sockaddr_in local_addr = { AF_INET, htons(config.tcp_local_listen_port), {INADDR_ANY} };
        if (bind(sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            SetColor(RED);
            std::cerr << "[Error] Failed to bind local port " << config.tcp_local_listen_port << ". It might be in use." << std::endl;
            closesocket(sock);
            goto retry_logic;
        }
        SetColor(CYAN);
        std::cout << "[Step 2] Socket bound to local port " << config.tcp_local_listen_port << "." << std::endl;

        // 3. "预热" NAT
        SetColor(CYAN);
        std::cout << "[Step 3] Priming NAT by connecting to '" << config.tcp_priming_host << "'..." << std::endl;
        addrinfo* prime_res = nullptr;
        getaddrinfo(config.tcp_priming_host.c_str(), "80", nullptr, &prime_res);
        // 设置非阻塞模式以实现带超时的连接
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
        connect(sock, prime_res->ai_addr, (int)prime_res->ai_addrlen);
        freeaddrinfo(prime_res);
        // 等待一小段时间让包发出去
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        // 恢复阻塞模式
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        SetColor(GREEN);
        std::cout << "[Success] NAT priming packet sent." << std::endl;

        // 4. 打洞
        SOCKET peer_sock = INVALID_SOCKET;
        if (is_listener) {
            SetColor(CYAN);
            std::cout << "[Step 4] Listening for incoming connection..." << std::endl;
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
            std::cout << "[Step 4] Connecting to peer at " << peer_addr_str << "..." << std::endl;
            size_t colon_pos = peer_addr_str.find(':');
            std::string peer_ip = peer_addr_str.substr(0, colon_pos);
            int peer_port = std::stoi(peer_addr_str.substr(colon_pos + 1));
            
            sockaddr_in peer_addr = { AF_INET, htons(peer_port) };
            inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);

            // 使用带超时的连接
            timeval timeout = { config.tcp_punch_timeout_ms / 1000, (config.tcp_punch_timeout_ms % 1000) * 1000 };
            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);
            
            // 恢复非阻塞模式
            mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            connect(sock, (sockaddr*)&peer_addr, sizeof(peer_addr));
            if (select(0, NULL, &write_set, NULL, &timeout) > 0) {
                peer_sock = sock;
            }
            mode = 0;
            ioctlsocket(sock, FIONBIO, &mode);
        }

        // 5. 结果处理和转发
        if (peer_sock != INVALID_SOCKET) {
            SetColor(LIGHT_GREEN);
            std::cout << "\n[SUCCESS] TCP Hole Punching successful! P2P connection established." << std::endl;
            SetColor(YELLOW);
            std::cout << "[Forwarding] Now proxying data between P2P link and " << config.tcp_forward_host << ":" << config.tcp_forward_port << std::endl;

            SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            addrinfo* fwd_res = nullptr;
            getaddrinfo(config.tcp_forward_host.c_str(), std::to_string(config.tcp_forward_port).c_str(), nullptr, &fwd_res);
            if (connect(target_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == SOCKET_ERROR) {
                SetColor(RED);
                std::cerr << "[Error] Could not connect to local forward target." << std::endl;
            } else {
                std::thread(TcpProxy, peer_sock, target_sock, config.tcp_keep_alive_ms).detach();
                std::thread(TcpProxy, target_sock, peer_sock, config.tcp_keep_alive_ms).join(); // 等待转发结束
            }
            freeaddrinfo(fwd_res);
            closesocket(target_sock);
            SetColor(WHITE);
            std::cout << "[Info] P2P connection closed." << std::endl;
        } else {
            SetColor(RED);
            std::cerr << "[FAILURE] TCP Hole Punching failed (timeout)." << std::endl;
            closesocket(sock);
        }

    retry_logic:
        if (config.tcp_auto_retry) {
            SetColor(YELLOW);
            std::cout << "[Retry] Waiting for " << config.tcp_retry_interval_ms << "ms before retrying..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(config.tcp_retry_interval_ms));
        }
    } while (config.tcp_auto_retry);
}

// --- 主函数 ---
int main(int argc, char* argv[]) {
    SetConsoleTitleA("TCP Hole Punching Forwarder");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (argc < 2 || (strcmp(argv[1], "listen") != 0 && strcmp(argv[1], "connect") != 0)) {
        SetColor(YELLOW);
        std::cout << "Usage:\n";
        std::cout << "  As Listener:  forwarder.exe listen\n";
        std::cout << "  As Connector: forwarder.exe connect <listener_public_ip:port>\n";
        WSACleanup();
        return 1;
    }

    bool is_listener = (strcmp(argv[1], "listen") == 0);
    std::string peer_addr_str = "";
    if (!is_listener) {
        if (argc < 3) {
            SetColor(RED);
            std::cerr << "Error: Connector mode requires the peer's public address." << std::endl;
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