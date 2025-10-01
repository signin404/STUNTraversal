#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

// --- 控制台颜色管理 ---
enum ConsoleColor {
    DARKBLUE = 1, BLUE, GREEN, CYAN, RED, MAGENTA, YELLOW, WHITE,
    GRAY, LIGHT_BLUE, LIGHT_GREEN, LIGHT_CYAN, LIGHT_RED, LIGHT_MAGENTA, LIGHT_YELLOW, BRIGHT_WHITE
};

HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

void SetColor(ConsoleColor color) {
    SetConsoleTextAttribute(hConsole, color);
}

// --- 配置结构体 ---
struct Config {
    bool enable_udp = true;
    bool enable_tcp = true;

    // UDP settings
    std::string stun_server_host;
    int stun_server_port;
    std::string udp_forward_host;
    int udp_forward_port;
    int keep_alive_interval;

    // TCP settings
    int tcp_listen_port;
    std::string tcp_forward_host;
    int tcp_forward_port;
};

// --- INI 文件解析 ---
Config ReadIniConfig(const std::string& filePath) {
    Config config;
    char buffer[1024];

    config.enable_udp = GetPrivateProfileIntA("General", "EnableUDP", 1, filePath.c_str()) == 1;
    config.enable_tcp = GetPrivateProfileIntA("General", "EnableTCP", 1, filePath.c_str()) == 1;

    GetPrivateProfileStringA("UDP", "StunServerHost", "stun.l.google.com", buffer, sizeof(buffer), filePath.c_str());
    config.stun_server_host = buffer;
    config.stun_server_port = GetPrivateProfileIntA("UDP", "StunServerPort", 19302, filePath.c_str());
    GetPrivateProfileStringA("UDP", "ForwardHost", "127.0.0.1", buffer, sizeof(buffer), filePath.c_str());
    config.udp_forward_host = buffer;
    config.udp_forward_port = GetPrivateProfileIntA("UDP", "ForwardPort", 6060, filePath.c_str());
    config.keep_alive_interval = GetPrivateProfileIntA("UDP", "KeepAliveInterval", 20, filePath.c_str());

    config.tcp_listen_port = GetPrivateProfileIntA("TCP", "ListenPort", 7070, filePath.c_str());
    GetPrivateProfileStringA("TCP", "ForwardHost", "127.0.0.1", buffer, sizeof(buffer), filePath.c_str());
    config.tcp_forward_host = buffer;
    config.tcp_forward_port = GetPrivateProfileIntA("TCP", "ForwardPort", 8080, filePath.c_str());

    return config;
}

// --- STUN 响应解析 ---
// 从STUN响应中解析出公网IP和端口
std::string ParseStunResponse(const char* buffer, int len) {
    if (len < 20) return ""; // 响应头都不够

    // 检查是否是成功的绑定响应
    if (!((buffer[0] == 0x01) && (buffer[1] == 0x01))) return "";

    const char* p = buffer + 20; // 跳过20字节的头
    while (p < buffer + len) {
        unsigned short attr_type = ntohs(*(unsigned short*)p);
        unsigned short attr_len = ntohs(*(unsigned short*)(p + 2));
        const char* attr_val = p + 4;

        // 我们只关心 XOR-MAPPED-ADDRESS (0x0020)
        if (attr_type == 0x0020) {
            if (attr_len < 8) break;
            unsigned short port = ntohs(*(unsigned short*)(attr_val + 2));
            unsigned int ip = ntohl(*(unsigned int*)(attr_val + 4));

            // Magic Cookie (0x2112A442)
            unsigned int magic_cookie = ntohl(0x2112A442);
            port ^= (magic_cookie >> 16);
            ip ^= magic_cookie;

            in_addr addr;
            addr.s_addr = htonl(ip);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);

            return std::string(ip_str) + ":" + std::to_string(port);
        }
        p += (4 + attr_len);
    }
    return "";
}


// --- UDP 模块 ---
void UdpKeepAliveThread(SOCKET sock, sockaddr_in stun_addr, int interval) {
    char keep_alive_packet[20] = { 0 };
    // STUN Binding Request
    *(unsigned short*)keep_alive_packet = htons(0x0001); // Message Type
    *(unsigned short*)(keep_alive_packet + 2) = 0; // Message Length
    *(unsigned int*)(keep_alive_packet + 4) = htonl(0x2112A442); // Magic Cookie

    while (true) {
        SetColor(GRAY);
        std::cout << "[UDP Keep-Alive] Sending heartbeat..." << std::endl;
        sendto(sock, keep_alive_packet, sizeof(keep_alive_packet), 0, (const sockaddr*)&stun_addr, sizeof(stun_addr));
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
}

void UdpForwarderThread(Config config) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in local_addr = { AF_INET, 0, {INADDR_ANY} };
    bind(sock, (sockaddr*)&local_addr, sizeof(local_addr));

    addrinfo* stun_res = nullptr;
    getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_res);
    sockaddr_in stun_addr = *(sockaddr_in*)stun_res->ai_addr;
    freeaddrinfo(stun_res);

    addrinfo* fwd_res = nullptr;
    getaddrinfo(config.udp_forward_host.c_str(), std::to_string(config.udp_forward_port).c_str(), nullptr, &fwd_res);
    sockaddr_in fwd_addr = *(sockaddr_in*)fwd_res->ai_addr;
    freeaddrinfo(fwd_res);

    // 发送初始STUN请求以获取公网地址
    char stun_req[20] = { 0 };
    *(unsigned short*)stun_req = htons(0x0001);
    *(unsigned int*)(stun_req + 4) = htonl(0x2112A442);
    sendto(sock, stun_req, sizeof(stun_req), 0, (const sockaddr*)&stun_addr, sizeof(stun_addr));

    char recv_buffer[1500];
    sockaddr_in sender_addr;
    int sender_len = sizeof(sender_addr);
    int bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (sockaddr*)&sender_addr, &sender_len);
    if (bytes_received > 0) {
        std::string public_addr = ParseStunResponse(recv_buffer, bytes_received);
        if (!public_addr.empty()) {
            SetColor(LIGHT_GREEN);
            std::cout << "[UDP Success] Public endpoint discovered: " << public_addr << std::endl;
        } else {
            SetColor(LIGHT_YELLOW);
            std::cout << "[UDP Warning] Could not determine public endpoint from STUN response." << std::endl;
        }
    }

    std::thread(UdpKeepAliveThread, sock, stun_addr, config.keep_alive_interval).detach();
    SetColor(CYAN);
    std::cout << "[UDP Info] Keep-alive thread started. Now forwarding traffic..." << std::endl;

    while (true) {
        bytes_received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0, (sockaddr*)&sender_addr, &sender_len);
        if (bytes_received > 0) {
            if (sender_addr.sin_addr.s_addr == stun_addr.sin_addr.s_addr && sender_addr.sin_port == stun_addr.sin_port) {
                continue; // 忽略来自STUN服务器的后续响应
            }
            SetColor(LIGHT_YELLOW);
            std::cout << "[UDP Forwarding] " << bytes_received << " bytes -> " << config.udp_forward_host << ":" << config.udp_forward_port << std::endl;
            sendto(sock, recv_buffer, bytes_received, 0, (const sockaddr*)&fwd_addr, sizeof(fwd_addr));
        }
    }
    closesocket(sock);
}

// --- TCP 模块 ---
void TcpProxy(SOCKET client, SOCKET target) {
    char buffer[4096];
    while (true) {
        int bytes = recv(client, buffer, sizeof(buffer), 0);
        if (bytes <= 0) break;
        if (send(target, buffer, bytes, 0) <= 0) break;
    }
    closesocket(client);
    closesocket(target);
}

void TcpForwarderThread(Config config) {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in listen_addr = { AF_INET, htons(config.tcp_listen_port), {INADDR_ANY} };
    
    if (bind(listen_sock, (sockaddr*)&listen_addr, sizeof(listen_addr)) == SOCKET_ERROR) {
        SetColor(LIGHT_RED);
        std::cerr << "[TCP Error] Bind failed on port " << config.tcp_listen_port << ". Error: " << WSAGetLastError() << std::endl;
        closesocket(listen_sock);
        return;
    }
    
    listen(listen_sock, SOMAXCONN);
    SetColor(CYAN);
    std::cout << "[TCP Info] Listening on 0.0.0.0:" << config.tcp_listen_port << ". Ready to forward connections..." << std::endl;

    while (true) {
        SOCKET client_sock = accept(listen_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) continue;

        SetColor(LIGHT_MAGENTA);
        std::cout << "[TCP Connection] Accepted connection. Attempting to forward to " << config.tcp_forward_host << ":" << config.tcp_forward_port << std::endl;

        SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        addrinfo* fwd_res = nullptr;
        getaddrinfo(config.tcp_forward_host.c_str(), std::to_string(config.tcp_forward_port).c_str(), nullptr, &fwd_res);
        
        if (connect(target_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == SOCKET_ERROR) {
            SetColor(LIGHT_RED);
            std::cerr << "[TCP Error] Failed to connect to forward target. Error: " << WSAGetLastError() << std::endl;
            closesocket(client_sock);
            closesocket(target_sock);
        } else {
            SetColor(LIGHT_YELLOW);
            std::cout << "[TCP Forwarding] Connection established. Proxying data..." << std::endl;
            std::thread(TcpProxy, client_sock, target_sock).detach();
            std::thread(TcpProxy, target_sock, client_sock).detach();
        }
        freeaddrinfo(fwd_res);
    }
    closesocket(listen_sock);
}


// --- 主函数 ---
int main() {
    SetConsoleTitleA("UDP/TCP Forwarder");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string iniPath = std::string(exePath) + "\\config.ini";

    SetColor(WHITE);
    std::cout << "Reading configuration from: " << iniPath << std::endl;
    Config config = ReadIniConfig(iniPath);
    
    std::vector<std::thread> threads;
    if (config.enable_udp) {
        threads.emplace_back(UdpForwarderThread, config);
    }
    if (config.enable_tcp) {
        threads.emplace_back(TcpForwarderThread, config);
    }

    if (threads.empty()) {
        SetColor(LIGHT_RED);
        std::cerr << "Both TCP and UDP forwarders are disabled in config.ini. Exiting." << std::endl;
    } else {
        SetColor(WHITE);
        std::cout << "--- All enabled modules started. Press Ctrl+C to exit. ---" << std::endl;
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    WSACleanup();
    return 0;
}