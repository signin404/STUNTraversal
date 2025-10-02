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
    config.keep_alive_ms = GetPrivateProfileIntA("TCP_HolePunch", "KeepAliveMS", 2300, filePath.c_str());
    config.retry_interval_ms = GetPrivateProfileIntA("TCP_HolePunch", "RetryIntervalMS", 30000, filePath.c_str());
    config.auto_retry = GetPrivateProfileIntA("TCP_HolePunch", "AutoRetry", 1, filePath.c_str()) == 1;
    return config;
}

// --- 辅助函数：健壮地从TCP流中读取指定长度的数据 ---
bool RecvAll(SOCKET sock, char* buffer, int len) {
    int total_received = 0;
    while (total_received < len) {
        int bytes = recv(sock, buffer + total_received, len - total_received, 0);
        if (bytes <= 0) return false;
        total_received += bytes;
    }
    return true;
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

        SOCKET listener_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        SOCKET stun_heartbeat_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        
        BOOL reuse = TRUE;
        setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
        setsockopt(stun_heartbeat_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

        sockaddr_in local_addr = { AF_INET, htons(config.local_punch_port), {INADDR_ANY} };

        if (bind(listener_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR ||
            bind(stun_heartbeat_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            SetColor(RED); std::cerr << "[错误] 无法绑定本地端口 " << config.local_punch_port << "。" << std::endl;
            closesocket(listener_sock); closesocket(stun_heartbeat_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }
        SetColor(CYAN);
        std::cout << "[步骤 1] 套接字已成功绑定至本地端口 " << config.local_punch_port << "。" << std::endl;

        if (listen(listener_sock, SOMAXCONN) == SOCKET_ERROR) {
            SetColor(RED); std::cerr << "[错误] 监听套接字 listen() 失败。" << std::endl;
            closesocket(listener_sock); closesocket(stun_heartbeat_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }

        SetColor(CYAN);
        std::cout << "[步骤 2] 正在连接 STUN 服务器 '" << config.stun_server_host << "' 以发现并保持端口..." << std::endl;
        addrinfo* stun_res = nullptr;
        if (getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_res) != 0 || !stun_res) {
            SetColor(RED); std::cerr << "[错误] 无法解析 STUN 服务器地址。" << std::endl;
            closesocket(listener_sock); closesocket(stun_heartbeat_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }
        
        if (connect(stun_heartbeat_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == SOCKET_ERROR) {
            SetColor(RED); std::cerr << "[失败] 无法连接到 STUN 服务器。" << std::endl;
            freeaddrinfo(stun_res);
            closesocket(listener_sock); closesocket(stun_heartbeat_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }
        freeaddrinfo(stun_res);

        char req[20] = { 0 };
        *(unsigned short*)req = htons(0x0001); *(unsigned short*)(req + 2) = 0; *(unsigned int*)(req + 4) = htonl(0x2112A442);
        
        // *** FIX: Correctly seed the random number engine ***
        std::random_device rd;
        unsigned int seed = rd(); // 1. Get a random number from the hardware device
        std::mt19937 gen(seed);   // 2. Seed the Mersenne Twister engine with that number
        std::uniform_int_distribution<unsigned int> dis;
        
        for (int i = 0; i < 3; ++i) { *(unsigned int*)(req + 8 + i * 4) = dis(gen); }
        if (send(stun_heartbeat_sock, req, sizeof(req), 0) == SOCKET_ERROR) {
            SetColor(RED); std::cerr << "[失败] 发送 STUN 请求失败。" << std::endl;
            closesocket(listener_sock); closesocket(stun_heartbeat_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }

        std::string public_ip; int public_port; bool stun_success = false;
        char header_buffer[20];
        if (RecvAll(stun_heartbeat_sock, header_buffer, 20)) {
            unsigned short msg_len = ntohs(*(unsigned short*)(header_buffer + 2));
            if (msg_len <= 1400) {
                std::vector<char> attr_buffer(msg_len);
                if (msg_len == 0 || RecvAll(stun_heartbeat_sock, attr_buffer.data(), msg_len)) {
                    const char* p = attr_buffer.data(); const char* end = p + msg_len;
                    while (p < end) {
                        unsigned short type = ntohs(*(unsigned short*)p); unsigned short len = ntohs(*(unsigned short*)(p + 2));
                        const char* attr_value = p + 4;
                        if (type == 0x0020) {
                            unsigned short port_net = *(unsigned short*)(attr_value + 2); unsigned int ip_net = *(unsigned int*)(attr_value + 4);
                            unsigned int magic_cookie_net = htonl(0x2112A442);
                            unsigned short real_port_net = port_net ^ htons(0x2112); unsigned int real_ip_net = ip_net ^ magic_cookie_net;
                            public_port = ntohs(real_port_net);
                            in_addr addr; addr.s_addr = real_ip_net;
                            char ip_str[INET_ADDRSTRLEN];
                            if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN) != NULL) {
                                public_ip = ip_str; stun_success = true; break;
                            }
                        }
                        p += 4 + len; if (len % 4 != 0) p += (4 - (len % 4));
                    }
                }
            }
        }

        if (!stun_success) {
            SetColor(RED); std::cerr << "[失败] 解析 STUN 响应失败。" << std::endl;
            closesocket(listener_sock); closesocket(stun_heartbeat_sock);
            if (config.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms)); continue; } else break;
        }

        tcp_keepalive ka; ka.onoff = (u_long)1; ka.keepalivetime = config.keep_alive_ms; ka.keepaliveinterval = 1000;
        DWORD bytes_returned;
        WSAIoctl(stun_heartbeat_sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes_returned, NULL, NULL);

        SetColor(LIGHT_GREEN);
        std::cout << "[成功] NAT映射已建立！公网端口 " << public_ip << ":" << public_port << " 已开启并监听。" << std::endl;
        SetColor(YELLOW);
        std::cout << "[服务] 所有传入连接将被转发到 " << config.forward_host << ":" << config.forward_port << std::endl;

        while (true) {
            SOCKET peer_sock = accept(listener_sock, NULL, NULL);
            if (peer_sock == INVALID_SOCKET) {
                SetColor(RED); std::cerr << "[警告] accept() 失败，可能心跳连接已断开，准备重试..." << std::endl;
                break; 
            }
            std::thread(HandleNewConnection, peer_sock, config).detach();
        }

        closesocket(listener_sock);
        closesocket(stun_heartbeat_sock);
        if (config.auto_retry) {
             SetColor(YELLOW); std::cout << "[准备重试] 等待 " << config.retry_interval_ms / 1000 << " 秒后将自动重试..." << std::endl;
             std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
        }
    } while (config.auto_retry);
}

// --- 主函数 ---
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
    std::cout << "--- TCP NAT 端口转发器 (最终版) ---" << std::endl;
    std::cout << "本程序将通过与STUN服务器保持长连接来稳定地打开NAT端口，" << std::endl;
    std::cout << "并将所有流量转发到本地的 " << config.forward_host << ":" << config.forward_port << std::endl;
    PortForwardingThread(config);
    WSACleanup();
    return 0;
}