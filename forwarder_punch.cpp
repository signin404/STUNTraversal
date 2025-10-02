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
#include <atomic>
#include <algorithm>
#include <map>
#include <mutex>
#include <stdexcept>
#include <fstream>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

// --- 全局标志 ---
std::atomic<bool> g_tcp_reconnect_flag{false};
std::mutex g_console_mutex;

// --- 控制台颜色管理 ---
enum ConsoleColor { DARKBLUE = 1, GREEN = 2, CYAN = 3, RED = 4, MAGENTA = 5, YELLOW = 6, WHITE = 7, GRAY = 8, LIGHT_GREEN = 10 };
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
void SetColor(ConsoleColor color) {
    std::lock_guard<std::mutex> lock(g_console_mutex);
    SetConsoleTextAttribute(hConsole, color);
}

// --- 配置结构体 ---
struct Settings {
    int tcp_listen_port = 0;
    std::string tcp_forward_host;
    int tcp_forward_port = 0;
    int udp_listen_port = 0;
    std::string udp_forward_host;
    int udp_forward_port = 0;
    int udp_session_timeout_ms = 30000;
    int udp_max_chunk_length = 1500;
    int punch_timeout_ms = 3000;
    int keep_alive_ms = 2300;
    int retry_interval_ms = 3000;
    bool auto_retry = true;
    int stun_retry = 3;
    std::vector<std::string> stun_servers;
};

// --- 新增:字符串 Trim 函数 ---
std::string trim(const std::string& str) {
    const std::string whitespace = " \t\n\r\f\v";
    size_t first = str.find_first_not_of(whitespace);
    if (std::string::npos == first) {
        return "";
    }
    size_t last = str.find_last_not_of(whitespace);
    return str.substr(first, (last - first + 1));
}

// --- INI 文件解析 (修复版) ---
Settings ReadIniConfig(const std::string& filePath) {
    Settings settings;
    
    auto safe_stoi = [&](const std::string& s, int default_val) {
        if (s.empty()) return default_val;
        try {
            return std::stoi(s);
        } catch (...) {
            return default_val;
        }
    };

    // 读取基本配置
    char buffer[4096];
    settings.tcp_listen_port = GetPrivateProfileIntA("Settings", "TCPListenPort", 0, filePath.c_str());
    GetPrivateProfileStringA("Settings", "TCPForwardHost", "", buffer, sizeof(buffer), filePath.c_str());
    settings.tcp_forward_host = trim(buffer);
    
    GetPrivateProfileStringA("Settings", "TCPForwardPort", "0", buffer, sizeof(buffer), filePath.c_str());
    std::string tcp_fwd_port_str = trim(buffer);
    std::transform(tcp_fwd_port_str.begin(), tcp_fwd_port_str.end(), tcp_fwd_port_str.begin(), ::tolower);
    settings.tcp_forward_port = (tcp_fwd_port_str == "auto") ? -1 : safe_stoi(tcp_fwd_port_str, 0);

    settings.udp_listen_port = GetPrivateProfileIntA("Settings", "UDPListenPort", 0, filePath.c_str());
    GetPrivateProfileStringA("Settings", "UDPForwardHost", "", buffer, sizeof(buffer), filePath.c_str());
    settings.udp_forward_host = trim(buffer);
    
    GetPrivateProfileStringA("Settings", "UDPForwardPort", "0", buffer, sizeof(buffer), filePath.c_str());
    std::string udp_fwd_port_str = trim(buffer);
    std::transform(udp_fwd_port_str.begin(), udp_fwd_port_str.end(), udp_fwd_port_str.begin(), ::tolower);
    settings.udp_forward_port = (udp_fwd_port_str == "auto") ? -1 : safe_stoi(udp_fwd_port_str, 0);
    
    settings.udp_session_timeout_ms = GetPrivateProfileIntA("Settings", "UDPSessionTimeoutMS", 30000, filePath.c_str());
    settings.udp_max_chunk_length = GetPrivateProfileIntA("Settings", "UDPMaxChunkLength", 1500, filePath.c_str());
    settings.punch_timeout_ms = GetPrivateProfileIntA("Settings", "PunchTimeoutMS", 3000, filePath.c_str());
    settings.keep_alive_ms = GetPrivateProfileIntA("Settings", "KeepAliveMS", 2300, filePath.c_str());
    settings.retry_interval_ms = GetPrivateProfileIntA("Settings", "RetryIntervalMS", 3000, filePath.c_str());
    settings.auto_retry = GetPrivateProfileIntA("Settings", "AutoRetry", 1, filePath.c_str()) == 1;
    settings.stun_retry = GetPrivateProfileIntA("Settings", "STUNRetry", 3, filePath.c_str());

    // 读取 STUN 服务器列表 - 修复版
    // 直接读取文件内容解析 [STUN] 部分
    std::ifstream file(filePath);
    if (file.is_open()) {
        std::string line;
        bool in_stun_section = false;
        
        while (std::getline(file, line)) {
            line = trim(line);
            
            // 检查是否进入 [STUN] 部分
            if (line == "[STUN]") {
                in_stun_section = true;
                continue;
            }
            
            // 检查是否进入其他部分
            if (!line.empty() && line[0] == '[') {
                in_stun_section = false;
                continue;
            }
            
            // 如果在 STUN 部分,解析服务器地址
            if (in_stun_section && !line.empty() && line[0] != ';' && line[0] != '#') {
                // 移除注释部分
                size_t comment_pos = line.find(';');
                if (comment_pos != std::string::npos) {
                    line = line.substr(0, comment_pos);
                }
                comment_pos = line.find('#');
                if (comment_pos != std::string::npos) {
                    line = line.substr(0, comment_pos);
                }
                
                line = trim(line);
                
                // 如果有等号,取等号后的值(支持 key=value 格式)
                size_t equals_pos = line.find('=');
                if (equals_pos != std::string::npos) {
                    line = trim(line.substr(equals_pos + 1));
                }
                
                // 验证格式是否为 host:port
                if (!line.empty() && line.find(':') != std::string::npos) {
                    settings.stun_servers.push_back(line);
                }
            }
        }
        file.close();
    }

    return settings;
}

// --- 辅助函数:RecvAll ---
bool RecvAll(SOCKET sock, char* buffer, int len) {
    int total_received = 0;
    while (total_received < len) {
        int bytes = recv(sock, buffer + total_received, len - total_received, 0);
        if (bytes <= 0) return false;
        total_received += bytes;
    }
    return true;
}

// --- 通用 STUN 客户端 ---
bool GetPublicEndpoint(const std::string& server_str, bool is_tcp, bool use_rfc5780, int local_port,
                       std::string& out_ip, int& out_port, SOCKET& out_sock, int timeout_ms) {
    size_t colon_pos = server_str.find(':');
    if (colon_pos == std::string::npos) return false;
    std::string host = server_str.substr(0, colon_pos);
    std::string port = server_str.substr(colon_pos + 1);

    addrinfo* stun_res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), nullptr, &stun_res) != 0 || !stun_res) {
        if (stun_res) freeaddrinfo(stun_res);
        return false;
    }

    out_sock = socket(AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (out_sock == INVALID_SOCKET) {
        freeaddrinfo(stun_res);
        return false;
    }

    sockaddr_in local_addr = { AF_INET, htons(local_port), {INADDR_ANY} };
    if (bind(out_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(out_sock); freeaddrinfo(stun_res);
        return false;
    }

    DWORD timeout = timeout_ms;
    setsockopt(out_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(out_sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (is_tcp && connect(out_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == SOCKET_ERROR) {
        closesocket(out_sock); freeaddrinfo(stun_res);
        return false;
    }

    char req[20] = { 0 };
    *(unsigned short*)req = htons(0x0001);
    *(unsigned short*)(req + 2) = 0;
    
    std::random_device rd;
    unsigned int seed = rd();
    std::mt19937 gen(seed);
    std::uniform_int_distribution<unsigned int> dis;

    if (use_rfc5780) {
        *(unsigned int*)(req + 4) = htonl(0x2112A442);
        for (int i = 0; i < 3; ++i) *(unsigned int*)(req + 8 + i * 4) = dis(gen);
    } else {
        for (int i = 0; i < 4; ++i) *(unsigned int*)(req + 4 + i * 4) = dis(gen);
    }

    int sent_bytes = is_tcp ? send(out_sock, req, sizeof(req), 0) : sendto(out_sock, req, sizeof(req), 0, stun_res->ai_addr, (int)stun_res->ai_addrlen);
    freeaddrinfo(stun_res);

    if (sent_bytes == SOCKET_ERROR) {
        closesocket(out_sock);
        return false;
    }

    char resp[1500];
    int recv_bytes = is_tcp ? recv(out_sock, resp, sizeof(resp), 0) : recvfrom(out_sock, resp, sizeof(resp), 0, NULL, NULL);

    if (recv_bytes < 20) {
        if (!is_tcp) closesocket(out_sock);
        return false;
    }

    const char* p = resp + 20;
    const char* end = resp + recv_bytes;
    while (p < end) {
        unsigned short type = ntohs(*(unsigned short*)p);
        unsigned short len = ntohs(*(unsigned short*)(p + 2));
        const char* attr_value = p + 4;

        if (use_rfc5780 && type == 0x0020) {
            unsigned short port_net = *(unsigned short*)(attr_value + 2);
            unsigned int ip_net = *(unsigned int*)(attr_value + 4);
            port_net ^= htons(0x2112);
            ip_net ^= htonl(0x2112A442);
            out_port = ntohs(port_net);
            in_addr addr = { ip_net };
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            out_ip = ip_str;
            return true;
        }
        if (!use_rfc5780 && type == 0x0001) {
            out_port = ntohs(*(unsigned short*)(attr_value + 2));
            in_addr addr = { *(unsigned int*)(attr_value + 4) };
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
            out_ip = ip_str;
            return true;
        }
        p += 4 + len;
        if (len % 4 != 0) p += (4 - (len % 4));
    }

    if (!is_tcp) closesocket(out_sock);
    return false;
}

// --- TCP 代理 ---
void TcpProxy(SOCKET s1, SOCKET s2, int keep_alive_ms) {
    try {
        tcp_keepalive ka; ka.onoff = (u_long)1; ka.keepalivetime = keep_alive_ms; ka.keepaliveinterval = 1000;
        DWORD bytes_returned;
        WSAIoctl(s1, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes_returned, NULL, NULL);
        char buffer[8192];
        while (true) {
            int bytes = recv(s1, buffer, sizeof(buffer), 0);
            if (bytes <= 0) break;
            if (send(s2, buffer, bytes, 0) <= 0) break;
        }
    } catch (...) {}
    closesocket(s1); closesocket(s2);
}

// --- TCP 连接处理 ---
void HandleNewConnection(SOCKET peer_sock, Settings settings, int forward_port) {
    try {
        sockaddr_in peer_addr; int peer_addr_len = sizeof(peer_addr);
        getpeername(peer_sock, (sockaddr*)&peer_addr, &peer_addr_len);
        char peer_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
        
        {
            std::lock_guard<std::mutex> lock(g_console_mutex);
            SetColor(GREEN);
            std::cout << "[TCP] 接受来自 " << peer_ip_str << ":" << ntohs(peer_addr.sin_port) << " 的连接。" << std::endl;
        }

        if (settings.tcp_forward_host.empty()) {
            closesocket(peer_sock);
            return;
        }

        SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        addrinfo* fwd_res = nullptr;
        getaddrinfo(settings.tcp_forward_host.c_str(), std::to_string(forward_port).c_str(), nullptr, &fwd_res);
        if (!fwd_res || connect(target_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen) == SOCKET_ERROR) {
            {
                std::lock_guard<std::mutex> lock(g_console_mutex);
                SetColor(RED);
                std::cerr << "[TCP] 无法连接到本地转发目标 " << settings.tcp_forward_host << ":" << forward_port << std::endl;
            }
            closesocket(peer_sock);
        } else {
            {
                std::lock_guard<std::mutex> lock(g_console_mutex);
                SetColor(YELLOW);
                std::cout << "[TCP] 开始转发 " << peer_ip_str << " <==> " << settings.tcp_forward_host << ":" << forward_port << std::endl;
            }
            std::thread(TcpProxy, peer_sock, target_sock, settings.keep_alive_ms).detach();
            std::thread(TcpProxy, target_sock, peer_sock, settings.keep_alive_ms).detach();
        }
        if(fwd_res) freeaddrinfo(fwd_res);
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_console_mutex);
        SetColor(RED);
        std::cerr << "[TCP] HandleNewConnection 异常: " << e.what() << std::endl;
    } catch (...) {
        std::lock_guard<std::mutex> lock(g_console_mutex);
        SetColor(RED);
        std::cerr << "[TCP] HandleNewConnection 发生未知异常。" << std::endl;
    }
}

// --- TCP 打洞线程 ---
void TCPPunchingThread(Settings settings) {
    try {
        do {
            g_tcp_reconnect_flag = false;
            SOCKET listener_sock = INVALID_SOCKET, heartbeat_sock = INVALID_SOCKET;
            std::string public_ip; int public_port = 0;
            bool punch_success = false;

            for (const auto& server : settings.stun_servers) {
                if (punch_success) break;
                for (int i = 0; i < settings.stun_retry; ++i) {
                    {
                        std::lock_guard<std::mutex> lock(g_console_mutex);
                        SetColor(CYAN);
                        std::cout << "[TCP] 尝试 RFC5780 on " << server << " (第 " << i + 1 << " 次)" << std::endl;
                    }
                    if (GetPublicEndpoint(server, true, true, settings.tcp_listen_port, public_ip, public_port, heartbeat_sock, settings.punch_timeout_ms)) {
                        punch_success = true; break;
                    }
                }
                if (punch_success) break;
                for (int i = 0; i < settings.stun_retry; ++i) {
                    {
                        std::lock_guard<std::mutex> lock(g_console_mutex);
                        SetColor(CYAN);
                        std::cout << "[TCP] 尝试 RFC3489 on " << server << " (第 " << i + 1 << " 次)" << std::endl;
                    }
                    if (GetPublicEndpoint(server, true, false, settings.tcp_listen_port, public_ip, public_port, heartbeat_sock, settings.punch_timeout_ms)) {
                        punch_success = true; break;
                    }
                }
            }

            if (!punch_success) {
                {
                    std::lock_guard<std::mutex> lock(g_console_mutex);
                    SetColor(RED);
                    std::cerr << "[TCP] 所有 STUN 服务器和协议均失败。" << std::endl;
                }
                if (settings.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(settings.retry_interval_ms)); continue; } else break;
            }

            int final_forward_port = (settings.tcp_forward_port == -1) ? public_port : settings.tcp_forward_port;

            listener_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            BOOL reuse = TRUE;
            setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
            sockaddr_in local_addr = { AF_INET, htons(settings.tcp_listen_port), {INADDR_ANY} };
            bind(listener_sock, (sockaddr*)&local_addr, sizeof(local_addr));
            listen(listener_sock, SOMAXCONN);

            tcp_keepalive ka; ka.onoff = (u_long)1; ka.keepalivetime = settings.keep_alive_ms; ka.keepaliveinterval = 1000;
            DWORD bytes_returned;
            WSAIoctl(heartbeat_sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes_returned, NULL, NULL);

            {
                std::lock_guard<std::mutex> lock(g_console_mutex);
                SetColor(LIGHT_GREEN);
                std::cout << "[TCP] 打洞成功!公网端口 " << public_ip << ":" << public_port << " 已开启并监听。" << std::endl;
                if (!settings.tcp_forward_host.empty()) {
                    SetColor(YELLOW);
                    std::cout << "[TCP] 传入连接将被转发到 " << settings.tcp_forward_host << ":" << final_forward_port << std::endl;
                } else {
                    SetColor(YELLOW);
                    std::cout << "[TCP] 仅打洞模式:端口已开启,请在路由器/防火墙上手动配置转发。" << std::endl;
                }
            }

            while (!g_tcp_reconnect_flag) {
                fd_set read_fds; FD_ZERO(&read_fds); FD_SET(listener_sock, &read_fds);
                timeval timeout; timeout.tv_sec = 5; timeout.tv_usec = 0;
                int activity = select(0, &read_fds, NULL, NULL, &timeout);
                if (activity > 0) {
                    SOCKET peer_sock = accept(listener_sock, NULL, NULL);
                    if (peer_sock != INVALID_SOCKET) {
                        std::thread(HandleNewConnection, peer_sock, settings, final_forward_port).detach();
                    }
                }
            }
            closesocket(listener_sock);
            closesocket(heartbeat_sock);
        } while (settings.auto_retry);
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_console_mutex);
        SetColor(RED);
        std::cerr << "[TCP] 线程发生严重异常: " << e.what() << std::endl;
    } catch (...) {
        std::lock_guard<std::mutex> lock(g_console_mutex);
        SetColor(RED);
        std::cerr << "[TCP] 线程发生未知严重异常。" << std::endl;
    }
}

// --- UDP 打洞线程 ---
void UDPPunchingThread(Settings settings) {
    try {
        do {
            SOCKET punch_sock = INVALID_SOCKET;
            std::string public_ip; int public_port = 0;
            bool punch_success = false;

            for (const auto& server : settings.stun_servers) {
                if (punch_success) break;
                for (int i = 0; i < settings.stun_retry; ++i) {
                    {
                        std::lock_guard<std::mutex> lock(g_console_mutex);
                        SetColor(CYAN);
                        std::cout << "[UDP] 尝试 RFC5780 on " << server << " (第 " << i + 1 << " 次)" << std::endl;
                    }
                    if (GetPublicEndpoint(server, false, true, settings.udp_listen_port, public_ip, public_port, punch_sock, settings.punch_timeout_ms)) {
                        punch_success = true; break;
                    }
                }
                if (punch_success) break;
                for (int i = 0; i < settings.stun_retry; ++i) {
                    {
                        std::lock_guard<std::mutex> lock(g_console_mutex);
                        SetColor(CYAN);
                        std::cout << "[UDP] 尝试 RFC3489 on " << server << " (第 " << i + 1 << " 次)" << std::endl;
                    }
                    if (GetPublicEndpoint(server, false, false, settings.udp_listen_port, public_ip, public_port, punch_sock, settings.punch_timeout_ms)) {
                        punch_success = true; break;
                    }
                }
            }

            if (!punch_success) {
                {
                    std::lock_guard<std::mutex> lock(g_console_mutex);
                    SetColor(RED);
                    std::cerr << "[UDP] 所有 STUN 服务器和协议均失败。" << std::endl;
                }
                if (settings.auto_retry) { std::this_thread::sleep_for(std::chrono::milliseconds(settings.retry_interval_ms)); continue; } else break;
            }

            int final_forward_port = (settings.udp_forward_port == -1) ? public_port : settings.udp_forward_port;
            
            {
                std::lock_guard<std::mutex> lock(g_console_mutex);
                SetColor(LIGHT_GREEN);
                std::cout << "[UDP] 打洞成功!公网端口 " << public_ip << ":" << public_port << " 已开启。" << std::endl;
                if (!settings.udp_forward_host.empty()) {
                    SetColor(YELLOW);
                    std::cout << "[UDP] 传入数据包将被转发到 " << settings.udp_forward_host << ":" << final_forward_port << std::endl;
                } else {
                    SetColor(YELLOW);
                    std::cout << "[UDP] 仅打洞模式:端口已开启,请在路由器/防火墙上手动配置转发。" << std::endl;
                }
            }

            if (settings.udp_forward_host.empty()) {
                while(true) {
                    std::this_thread::sleep_for(std::chrono::seconds(15));
                    char dummy = 0;
                    send(punch_sock, &dummy, 1, 0);
                }
            }

            SOCKET forward_sock = socket(AF_INET, SOCK_DGRAM, 0);
            sockaddr_in fwd_local_addr = { AF_INET, 0, {INADDR_ANY} };
            bind(forward_sock, (sockaddr*)&fwd_local_addr, sizeof(fwd_local_addr));

            addrinfo* fwd_res = nullptr;
            getaddrinfo(settings.udp_forward_host.c_str(), std::to_string(final_forward_port).c_str(), nullptr, &fwd_res);

            struct Session { sockaddr_in public_addr; std::chrono::steady_clock::time_point last_seen; };
            std::map<std::string, Session> sessions;
            char* buffer = new char[settings.udp_max_chunk_length];

            while (true) {
                fd_set read_fds; FD_ZERO(&read_fds);
                FD_SET(punch_sock, &read_fds); FD_SET(forward_sock, &read_fds);
                timeval timeout; timeout.tv_sec = 5; timeout.tv_usec = 0;

                int activity = select(0, &read_fds, NULL, NULL, &timeout);
                if (activity > 0) {
                    if (FD_ISSET(punch_sock, &read_fds)) {
                        sockaddr_in public_client_addr; int addr_len = sizeof(public_client_addr);
                        int bytes = recvfrom(punch_sock, buffer, settings.udp_max_chunk_length, 0, (sockaddr*)&public_client_addr, &addr_len);
                        if (bytes > 0) {
                            sendto(forward_sock, buffer, bytes, 0, fwd_res->ai_addr, (int)fwd_res->ai_addrlen);
                            char client_ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &public_client_addr.sin_addr, client_ip, sizeof(client_ip));
                            std::string client_key = std::string(client_ip) + ":" + std::to_string(ntohs(public_client_addr.sin_port));
                            sessions[client_key] = { public_client_addr, std::chrono::steady_clock::now() };
                        }
                    }
                    if (FD_ISSET(forward_sock, &read_fds)) {
                        int bytes = recvfrom(forward_sock, buffer, settings.udp_max_chunk_length, 0, NULL, NULL);
                        if (bytes > 0 && !sessions.empty()) {
                            sendto(punch_sock, buffer, bytes, 0, (sockaddr*)&sessions.rbegin()->second.public_addr, sizeof(sockaddr_in));
                        }
                    }
                }
                auto now = std::chrono::steady_clock::now();
                for (auto it = sessions.begin(); it != sessions.end(); ) {
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_seen).count() > settings.udp_session_timeout_ms) {
                        it = sessions.erase(it);
                    } else { ++it; }
                }
            }
            delete[] buffer; freeaddrinfo(fwd_res);
            closesocket(punch_sock); closesocket(forward_sock);

        } while (settings.auto_retry);
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_console_mutex);
        SetColor(RED