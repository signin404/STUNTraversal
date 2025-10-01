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
enum ConsoleColor { GREEN = 2, CYAN = 3, RED = 4, YELLOW = 6, WHITE = 7, LIGHT_GREEN = 10 };
HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
void SetColor(ConsoleColor color) { SetConsoleTextAttribute(hConsole, color); }

// --- 主函数 ---
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(65001);
    SetConsoleTitleA("Proprietary Protocol Cloner");
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // --- 关键部分：用从 Wireshark 抓取到的十六进制数据替换这里 ---
    // 示例：如果抓到的是 01 02 03 04 ...
    // 注意：这是一个示例，你需要用你抓到的真实数据替换它！
    unsigned char SECRET_HANDSHAKE[] = {
        0x00, 0x01, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C
    };

    const char* SERVER_IP = "137.74.112.113";
    const int SERVER_PORT = 3478;

    SetColor(WHITE);
    std::cout << "正在尝试使用克隆的数据包进行连接..." << std::endl;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // 发送“秘密暗号”
    sendto(sock, (const char*)SECRET_HANDSHAKE, sizeof(SECRET_HANDSHAKE), 0, (const sockaddr*)&server_addr, sizeof(server_addr));
    SetColor(CYAN);
    std::cout << "克隆包已发送至 " << SERVER_IP << ":" << SERVER_PORT << std::endl;

    timeval timeout = { 3, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    char buffer[1500];
    sockaddr_in recv_addr;
    int recv_addr_len = sizeof(recv_addr);
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (sockaddr*)&recv_addr, &recv_addr_len);
    
    if (bytes > 0) {
        SetColor(LIGHT_GREEN);
        std::cout << "\n[成功] 收到了服务器的响应！ (" << bytes << " 字节)" << std::endl;
        
        // 尝试像旧版STUN一样解析 MAPPED-ADDRESS
        if (bytes >= 28 && buffer[0] == 0x01 && buffer[1] == 0x01) {
            const char* p = buffer + 20;
            while (p < buffer + bytes) {
                unsigned short type = ntohs(*(unsigned short*)p);
                unsigned short len = ntohs(*(unsigned short*)(p + 2));
                if (type == 0x0001) { // MAPPED-ADDRESS
                    unsigned short port = ntohs(*(unsigned short*)(p + 6));
                    in_addr addr;
                    addr.s_addr = *(unsigned int*)(p + 8);
                    SetColor(YELLOW);
                    std::cout << "[解析成功] 你的公网地址可能是: " << inet_ntoa(addr) << ":" << port << std::endl;
                    break;
                }
                p += (4 + len);
            }
        } else {
            SetColor(YELLOW);
            std::cout << "[信息] 响应格式未知，但连接已探通。" << std::endl;
        }

    } else {
        SetColor(RED);
        std::cerr << "\n[失败] 克隆包未收到响应，超时。" << std::endl;
    }

    closesocket(sock);
    WSACleanup();
    
    std::cout << "\n按任意键退出..." << std::endl;
    std::cin.get();
    return 0;
}