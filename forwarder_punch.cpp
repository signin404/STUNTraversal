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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <mstcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

// =================================================================================
// 全局定义和辅助工具
// =================================================================================

std::atomic<bool> g_tcp_reconnect_flag{false};
std::atomic<bool> g_udp_reconnect_flag{false};
std::mutex g_cout_mutex;

enum class StunRfc { RFC3489, RFC5780 };

enum ConsoleColor { DARKBLUE = 1, GREEN = 2, CYAN = 3, RED = 4, MAGENTA = 5, YELLOW = 6, WHITE = 7, GRAY = 8, LIGHT_GREEN = 10 };
void SetColor(ConsoleColor color) { 
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); 
}

template<typename... Args>
void Print(ConsoleColor color, Args&&... args) {
    std::lock_guard<std::mutex> lock(g_cout_mutex);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    (std::cout << ... << args) << std::endl;
}

std::string trim(const std::string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (std::string::npos == first) return "";
    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, (last - first + 1));
}

bool RecvAll(SOCKET sock, char* buffer, int len, int timeout_ms) {
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    int total_received = 0;
    while (total_received < len) {
        int bytes = recv(sock, buffer + total_received, len - total_received, 0);
        if (bytes <= 0) return false;
        total_received += bytes;
    }
    return true;
}

// =================================================================================
// 配置管理
// =================================================================================

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
};

Config ReadIniConfig(const std::string& filePath) {
    Config config;
    std::ifstream file(filePath);
    std::string line, current_section;

    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[' && line.back() == ']') {
            current_section = trim(line.substr(1, line.length() - 2));
            std::transform(current_section.begin(), current_section.end(), current_section.begin(), ::tolower);
        } else if (current_section == "stun") {
            if(!line.empty()) config.stun_servers.push_back(line);
        } else if (current_section == "settings") {
            size_t eq_pos = line.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = trim(line.substr(0, eq_pos));
                std::string value = trim(line.substr(eq_pos + 1));
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);

                try {
                    if (key == "tcplistenport") config.tcp_listen_port = std::stoi(value);
                    else if (key == "tcpforwardhost") config.tcp_forward_host = value;
                    else if (key == "tcpforwardport") {
                        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                        if (value == "auto") config.tcp_forward_port = 0; else config.tcp_forward_port = std::stoi(value);
                    }
                    else if (key == "udplistenport") config.udp_listen_port = std::stoi(value);
                    else if (key == "udpforwardhost") config.udp_forward_host = value;
                    else if (key == "udpforwardport") {
                        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                        if (value == "auto") config.udp_forward_port = 0; else config.udp_forward_port = std::stoi(value);
                    }
                    else if (key == "punchtimeoutms") config.punch_timeout_ms = std::stoi(value);
                    else if (key == "keepalivems") config.keep_alive_ms = std::stoi(value);
                    else if (key == "retryintervalms") config.retry_interval_ms = std::stoi(value);
                    else if (key == "autoretry") config.auto_retry = (std::stoi(value) == 1);
                    else if (key == "stunretry") config.stun_retry = std::stoi(value);
                    else if (key == "stunretrydelayms") config.stun_retry_delay_ms = std::stoi(value);
                    else if (key == "udpsessiontimeoutms") config.udp_session_timeout_ms = std::stoi(value);
                    else if (key == "udpmaxchunklength") config.udp_max_chunk_length = std::stoi(value);
                } catch (const std::exception&) { /* ignore bad values */ }
            }
        }
    }
    return config;
}

// =================================================================================
// STUN 核心逻辑
// =================================================================================

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

// =================================================================================
// TCP 模块
// =================================================================================

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

void TCP_StunCheckThread(std::string initial_ip, int initial_port, const Config& config) {
    while (!g_tcp_reconnect_flag) {
        std::this_thread::sleep_for(std::chrono::minutes(5));
        if (g_tcp_reconnect_flag) break;

        Print(CYAN, "\n[TCP] 监控: 正在检查公网地址...");
        
        // 使用第一个 STUN 服务器进行检查
        const auto& server_str = config.stun_servers[0];
        size_t colon_pos = server_str.find(':');
        if (colon_pos == std::string::npos) { g_tcp_reconnect_flag = true; break; }
        std::string host = server_str.substr(0, colon_pos);
        int port = std::stoi(server_str.substr(colon_pos + 1));

        SOCKET check_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (check_sock == INVALID_SOCKET) { g_tcp_reconnect_flag = true; break; }

        addrinfo* stun_res = nullptr;
        bool check_success = false;
        std::string current_ip; int current_port;

        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
            if (connect(check_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == 0) {
                char req[20] = {0}; // Build RFC5780 request
                *(unsigned short*)req = htons(0x0001); *(unsigned int*)(req + 4) = htonl(0x2112A442);
                std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<unsigned int> dis;
                for (int i = 0; i < 3; ++i) *(unsigned int*)(req + 8 + i * 4) = dis(gen);
                
                if (send(check_sock, req, sizeof(req), 0) != SOCKET_ERROR) {
                    char response_buffer[512];
                    int bytes = recv(check_sock, response_buffer, sizeof(response_buffer), 0);
                    if (bytes > 20) {
                        if (ParseStunResponse(response_buffer, bytes, StunRfc::RFC5780, current_ip, current_port)) {
                            check_success = true;
                        }
                    }
                }
            }
            freeaddrinfo(stun_res);
        }
        closesocket(check_sock);

        if (check_success) {
            if (current_ip != initial_ip || current_port != initial_port) {
                Print(YELLOW, "[TCP] 监控: 公网地址已变化！");
                Print(YELLOW, "       旧: ", initial_ip, ":", initial_port, " -> 新: ", current_ip, ":", current_port);
                g_tcp_reconnect_flag = true;
            } else {
                Print(GREEN, "[TCP] 监控: 公网地址未变化。");
            }
        } else {
            Print(RED, "[TCP] 监控: STUN检查失败，连接可能已断开。");
            g_tcp_reconnect_flag = true;
        }
    }
}

void TCP_PortForwardingThread(Config base_config) {
    do {
        g_tcp_reconnect_flag = false;
        Config config = base_config;
        SOCKET listener_sock = INVALID_SOCKET, stun_heartbeat_sock = INVALID_SOCKET;
        std::string public_ip; int public_port;
        bool stun_success = false;

        Print(WHITE, "\n--- [TCP] 开始新一轮端口开启尝试 ---");

        for (const auto& server_str : config.stun_servers) {
            if (stun_success) break;
            size_t colon_pos = server_str.find(':');
            if (colon_pos == std::string::npos) continue;
            std::string host = server_str.substr(0, colon_pos);
            int port = std::stoi(server_str.substr(colon_pos + 1));

            auto attempt_stun = [&](StunRfc rfc) {
                for (int i = 0; i < config.stun_retry; ++i) {
                    Print(CYAN, "[TCP] 尝试 ", host, ":", port, " (RFC", (rfc == StunRfc::RFC5780 ? "5780" : "3489"), ", 第 ", i + 1, " 次)...");
                    
                    listener_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    stun_heartbeat_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if(listener_sock == INVALID_SOCKET || stun_heartbeat_sock == INVALID_SOCKET) continue;

                    BOOL reuse = TRUE;
                    setsockopt(listener_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                    setsockopt(stun_heartbeat_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
                    sockaddr_in local_addr = { AF_INET, htons(*config.tcp_listen_port), {INADDR_ANY} };

                    if (bind(listener_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR ||
                        bind(stun_heartbeat_sock, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR ||
                        listen(listener_sock, SOMAXCONN) == SOCKET_ERROR) {
                        // Bind or listen failed
                    } else {
                        addrinfo* stun_res = nullptr;
                        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
                            if (connect(stun_heartbeat_sock, stun_res->ai_addr, (int)stun_res->ai_addrlen) == 0) {
                                char req[20] = {0}; // Build request
                                *(unsigned short*)req = htons(0x0001);
                                if(rfc == StunRfc::RFC5780) *(unsigned int*)(req + 4) = htonl(0x2112A442);
                                std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<unsigned int> dis;
                                for (int k = 0; k < 3; ++k) *(unsigned int*)(req + 8 + k * 4) = dis(gen);
                                
                                if (send(stun_heartbeat_sock, req, sizeof(req), 0) != SOCKET_ERROR) {
                                    char response_buffer[512];
                                    int bytes = recv(stun_heartbeat_sock, response_buffer, sizeof(response_buffer), 0);
                                    if (bytes > 20) {
                                        if (ParseStunResponse(response_buffer, bytes, rfc, public_ip, public_port)) {
                                            stun_success = true;
                                        }
                                    }
                                }
                            }
                            freeaddrinfo(stun_res);
                        }
                    }
                    if (stun_success) return;
                    closesocket(listener_sock); closesocket(stun_heartbeat_sock);
                    std::this_thread::sleep_for(std::chrono::milliseconds(config.stun_retry_delay_ms));
                }
            };

            attempt_stun(StunRfc::RFC5780);
            if (stun_success) break;
            attempt_stun(StunRfc::RFC3489);
        }

        if (!stun_success) {
            Print(RED, "[TCP] 所有STUN服务器和协议均尝试失败。");
            if (config.auto_retry) {
                Print(YELLOW, "[TCP] 等待 ", config.retry_interval_ms / 1000, " 秒后重试...");
                std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
            }
            continue;
        }

        if (config.tcp_forward_port == 0) {
            config.tcp_forward_port = public_port;
            Print(CYAN, "[TCP] 动态转发端口已设置为: ", *config.tcp_forward_port);
        }

        tcp_keepalive ka; ka.onoff = (u_long)1; ka.keepalivetime = config.keep_alive_ms; ka.keepaliveinterval = 1000;
        DWORD bytes_returned;
        WSAIoctl(stun_heartbeat_sock, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &bytes_returned, NULL, NULL);
        Print(LIGHT_GREEN, "[TCP] 成功！公网端口 ", public_ip, ":", public_port, " 已开启并监听。");
        
        std::thread(TCP_StunCheckThread, public_ip, public_port, config).detach();

        while (!g_tcp_reconnect_flag) {
            fd_set read_fds; FD_ZERO(&read_fds); FD_SET(listener_sock, &read_fds);
            timeval timeout; timeout.tv_sec = 5; timeout.tv_usec = 0;
            int activity = select(0, &read_fds, NULL, NULL, &timeout);

            if (activity == SOCKET_ERROR) { g_tcp_reconnect_flag = true; break; }
            if (activity > 0 && FD_ISSET(listener_sock, &read_fds)) {
                SOCKET peer_sock = accept(listener_sock, NULL, NULL);
                if (peer_sock != INVALID_SOCKET) {
                    if (config.tcp_forward_host && !config.tcp_forward_host->empty()) {
                        std::thread(TCP_HandleNewConnection, peer_sock, config).detach();
                    } else {
                        Print(CYAN, "[TCP] 接受连接并立即关闭 (仅打洞模式)。");
                        closesocket(peer_sock);
                    }
                }
            }
        }
        closesocket(listener_sock); closesocket(stun_heartbeat_sock);
        if (g_tcp_reconnect_flag) {
            Print(YELLOW, "[TCP] 检测到重连信号，重启流程...");
        }
    } while (base_config.auto_retry);
}

// =================================================================================
// UDP 模块
// =================================================================================

struct UDPSession {
    SOCKET local_socket;
    sockaddr_in peer_addr;
    std::chrono::steady_clock::time_point last_activity;
};

void UDP_PortForwardingThread(Config base_config) {
    do {
        g_udp_reconnect_flag = false;
        Config config = base_config;
        SOCKET public_sock = INVALID_SOCKET;
        std::string public_ip; int public_port;
        bool stun_success = false;
        std::map<std::string, UDPSession> sessions;

        Print(WHITE, "\n--- [UDP] 开始新一轮端口开启尝试 ---");

        for (const auto& server_str : config.stun_servers) {
            if (stun_success) break;
            size_t colon_pos = server_str.find(':');
            if (colon_pos == std::string::npos) continue;
            std::string host = server_str.substr(0, colon_pos);
            int port = std::stoi(server_str.substr(colon_pos + 1));

            auto attempt_stun = [&](StunRfc rfc) {
                for (int i = 0; i < config.stun_retry; ++i) {
                    Print(CYAN, "[UDP] 尝试 ", host, ":", port, " (RFC", (rfc == StunRfc::RFC5780 ? "5780" : "3489"), ", 第 ", i + 1, " 次)...");
                    
                    public_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    if(public_sock == INVALID_SOCKET) continue;

                    sockaddr_in local_addr = { AF_INET, htons(*config.udp_listen_port), {INADDR_ANY} };
                    if (bind(public_sock, (sockaddr*)&local_addr, sizeof(local_addr)) != SOCKET_ERROR) {
                        addrinfo* stun_res = nullptr;
                        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), nullptr, &stun_res) == 0) {
                            char req[20] = {0};
                            *(unsigned short*)req = htons(0x0001);
                            if(rfc == StunRfc::RFC5780) *(unsigned int*)(req + 4) = htonl(0x2112A442);
                            std::random_device rd; std::mt19937 gen(rd()); std::uniform_int_distribution<unsigned int> dis;
                            for (int k = 0; k < 3; ++k) *(unsigned int*)(req + 8 + k * 4) = dis(gen);

                            sendto(public_sock, req, sizeof(req), 0, stun_res->ai_addr, (int)stun_res->ai_addrlen);
                            
                            char response_buffer[512];
                            sockaddr_in from_addr; int from_len = sizeof(from_addr);
                            setsockopt(public_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&config.punch_timeout_ms, sizeof(config.punch_timeout_ms));
                            int bytes = recvfrom(public_sock, response_buffer, sizeof(response_buffer), 0, (sockaddr*)&from_addr, &from_len);

                            if (bytes > 20) {
                                if (ParseStunResponse(response_buffer, bytes, rfc, public_ip, public_port)) {
                                    stun_success = true;
                                }
                            }
                            freeaddrinfo(stun_res);
                        }
                    }
                    if (stun_success) return;
                    closesocket(public_sock);
                    std::this_thread::sleep_for(std::chrono::milliseconds(config.stun_retry_delay_ms));
                }
            };
            attempt_stun(StunRfc::RFC5780);
            if (stun_success) break;
            attempt_stun(StunRfc::RFC3489);
        }

        if (!stun_success) {
            Print(RED, "[UDP] 所有STUN服务器和协议均尝试失败。");
            if (config.auto_retry) {
                Print(YELLOW, "[UDP] 等待 ", config.retry_interval_ms / 1000, " 秒后重试...");
                std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_interval_ms));
            }
            continue;
        }

        if (config.udp_forward_port == 0) {
            config.udp_forward_port = public_port;
            Print(CYAN, "[UDP] 动态转发端口已设置为: ", *config.udp_forward_port);
        }

        Print(LIGHT_GREEN, "[UDP] 成功！公网端口 ", public_ip, ":", public_port, " 已开启。");
        
        auto last_cleanup_time = std::chrono::steady_clock::now();

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
                            sessions[session_key].last_activity = std::chrono::steady_clock::now();
                            send(sessions[session_key].local_socket, buffer.data(), bytes, 0);
                        } else {
                            if (config.udp_forward_host && !config.udp_forward_host->empty()) {
                                Print(GREEN, "[UDP] 来自 ", session_key, " 的新会话。");
                                SOCKET local_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                                addrinfo* fwd_res = nullptr;
                                getaddrinfo(config.udp_forward_host->c_str(), std::to_string(*config.udp_forward_port).c_str(), nullptr, &fwd_res);
                                connect(local_sock, fwd_res->ai_addr, (int)fwd_res->ai_addrlen);
                                freeaddrinfo(fwd_res);
                                send(local_sock, buffer.data(), bytes, 0);
                                sessions[session_key] = { local_sock, peer_addr, std::chrono::steady_clock::now() };
                            }
                        }
                    }
                }
                for (auto it = sessions.begin(); it != sessions.end(); ++it) {
                    if (FD_ISSET(it->second.local_socket, &read_fds)) {
                        std::vector<char> buffer(config.udp_max_chunk_length);
                        int bytes = recv(it->second.local_socket, buffer.data(), buffer.size(), 0);
                        if (bytes > 0) {
                            it->second.last_activity = std::chrono::steady_clock::now();
                            sendto(public_sock, buffer.data(), bytes, 0, (sockaddr*)&it->second.peer_addr, sizeof(it->second.peer_addr));
                        }
                    }
                }
            }
            
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup_time).count() >= 10) {
                for (auto it = sessions.begin(); it != sessions.end(); ) {
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_activity).count() > config.udp_session_timeout_ms) {
                        Print(YELLOW, "[UDP] 会话 ", it->first, " 超时，已清理。");
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
            Print(YELLOW, "[UDP] 检测到重连信号，重启流程...");
        }
    } while (base_config.auto_retry);
}

// =================================================================================
// 主函数
// =================================================================================

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(65001);
    SetConsoleTitleA("TCP/UDP NAT 穿透转发器");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    std::string iniPath = std::string(exePath) + "\\config.ini";
    
    Config config = ReadIniConfig(iniPath);

    Print(YELLOW, "--- TCP/UDP NAT 端口转发器 (高级版) ---");
    Print(YELLOW, "配置文件 ", iniPath, " 已加载。");
    if (config.stun_servers.empty()) {
        Print(RED, "错误：配置文件中未找到任何 [STUN] 服务器。");
        return 1;
    }

    std::vector<std::thread> threads;
    if (config.tcp_listen_port) {
        threads.emplace_back(TCP_PortForwardingThread, config);
    }
    if (config.udp_listen_port) {
        threads.emplace_back(UDP_PortForwardingThread, config);
    }

    if (threads.empty()) {
        Print(RED, "错误：配置文件中未启用任何监听端口 (TCPListenPort 或 UDPListenPort)。");
        return 1;
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    WSACleanup();
    return 0;
}