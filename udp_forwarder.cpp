#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h> // For PathRemoveFileSpecA

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

// 用于存储从INI文件读取的配置
struct Config {
    std::string stun_server_host;
    int stun_server_port = 3478;
    std::string local_forward_host = "127.0.0.1";
    int local_forward_port = 6060;
    int keep_alive_interval = 20;
};

// 简单的INI文件解析器
Config ReadIniConfig(const std::string& filePath) {
    Config config;
    char buffer[1024];

    GetPrivateProfileStringA("Forwarder", "StunServerHost", "stun.l.google.com", buffer, sizeof(buffer), filePath.c_str());
    config.stun_server_host = buffer;

    config.stun_server_port = GetPrivateProfileIntA("Forwarder", "StunServerPort", 3478, filePath.c_str());

    GetPrivateProfileStringA("Forwarder", "LocalForwardHost", "127.0.0.1", buffer, sizeof(buffer), filePath.c_str());
    config.local_forward_host = buffer;

    config.local_forward_port = GetPrivateProfileIntA("Forwarder", "LocalForwardPort", 6060, filePath.c_str());
    config.keep_alive_interval = GetPrivateProfileIntA("Forwarder", "KeepAliveInterval", 20, filePath.c_str());

    return config;
}

// 后台线程函数，用于发送UDP心跳包
void KeepAliveThread(SOCKET sock, const sockaddr_in& stun_addr, int interval) {
    char keep_alive_packet[] = { 0x01 }; // 一个简单的1字节数据包
    while (true) {
        std::cout << "[Keep-Alive] Sending heartbeat to maintain NAT mapping..." << std::endl;
        sendto(sock, keep_alive_packet, sizeof(keep_alive_packet), 0, (const sockaddr*)&stun_addr, sizeof(stun_addr));
        std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
}

int main() {
    // --- 1. 初始化 Winsock ---
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed. Error: " << WSAGetLastError() << std::endl;
        return 1;
    }

    // --- 2. 读取配置文件 ---
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath); // 移除文件名，只保留目录
    std::string iniPath = std::string(exePath) + "\\config.ini";
    
    std::cout << "Reading configuration from: " << iniPath << std::endl;
    Config config = ReadIniConfig(iniPath);

    std::cout << "--- Configuration ---" << std::endl;
    std::cout << "STUN Server: " << config.stun_server_host << ":" << config.stun_server_port << std::endl;
    std::cout << "Local Forward Target: " << config.local_forward_host << ":" << config.local_forward_port << std::endl;
    std::cout << "Keep-Alive Interval: " << config.keep_alive_interval << " seconds" << std::endl;
    std::cout << "---------------------" << std::endl;

    // --- 3. 创建并绑定UDP套接字 ---
    SOCKET forward_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (forward_socket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed. Error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY; // 监听所有本地接口
    local_addr.sin_port = 0; // 让系统自动选择一个可用端口

    if (bind(forward_socket, (const sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Error: " << WSAGetLastError() << std::endl;
        closesocket(forward_socket);
        WSACleanup();
        return 1;
    }

    // 获取系统分配的本地端口
    sockaddr_in bound_addr;
    int bound_addr_len = sizeof(bound_addr);
    getsockname(forward_socket, (sockaddr*)&bound_addr, &bound_addr_len);
    std::cout << "Socket bound to local port: " << ntohs(bound_addr.sin_port) << std::endl;

    // --- 4. 解析服务器地址 ---
    addrinfo* stun_result = nullptr;
    getaddrinfo(config.stun_server_host.c_str(), std::to_string(config.stun_server_port).c_str(), nullptr, &stun_result);
    if (stun_result == nullptr) {
        std::cerr << "Could not resolve STUN server address." << std::endl;
        closesocket(forward_socket);
        WSACleanup();
        return 1;
    }
    sockaddr_in stun_addr = *(sockaddr_in*)stun_result->ai_addr;
    freeaddrinfo(stun_result);

    addrinfo* forward_target_result = nullptr;
    getaddrinfo(config.local_forward_host.c_str(), std::to_string(config.local_forward_port).c_str(), nullptr, &forward_target_result);
    if (forward_target_result == nullptr) {
        std::cerr << "Could not resolve local forward target address." << std::endl;
        closesocket(forward_socket);
        WSACleanup();
        return 1;
    }
    sockaddr_in forward_target_addr = *(sockaddr_in*)forward_target_result->ai_addr;
    freeaddrinfo(forward_target_result);

    // --- 5. 启动心跳线程 ---
    std::thread(KeepAliveThread, forward_socket, stun_addr, config.keep_alive_interval).detach();
    std::cout << "Keep-alive thread started." << std::endl;

    // --- 6. 主循环：接收和转发数据 ---
    std::cout << "Waiting for incoming traffic to forward..." << std::endl;
    char recv_buffer[65535]; // UDP最大包大小
    sockaddr_in sender_addr;
    int sender_addr_len = sizeof(sender_addr);

    while (true) {
        int bytes_received = recvfrom(forward_socket, recv_buffer, sizeof(recv_buffer), 0, (sockaddr*)&sender_addr, &sender_addr_len);
        if (bytes_received > 0) {
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
            
            // 检查数据包是否来自STUN服务器，如果是，则忽略转发（因为那是心跳包的响应）
            if (sender_addr.sin_addr.s_addr == stun_addr.sin_addr.s_addr && sender_addr.sin_port == stun_addr.sin_port) {
                std::cout << "[Info] Received a response from STUN server. Ignoring." << std::endl;
                continue;
            }

            std::cout << "[Forwarding] Received " << bytes_received << " bytes from " << sender_ip << ":" << ntohs(sender_addr.sin_port) << ". Forwarding to " << config.local_forward_host << ":" << config.local_forward_port << std::endl;

            // 将收到的数据原封不动地转发到本地目标
            sendto(forward_socket, recv_buffer, bytes_received, 0, (const sockaddr*)&forward_target_addr, sizeof(forward_target_addr));
        }
    }

    // --- 7. 清理 ---
    closesocket(forward_socket);
    WSACleanup();
    return 0;
}