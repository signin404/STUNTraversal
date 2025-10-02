// main.cpp
// 最终验证方案：“阅后即焚”的托盘图标用法
// 点击窗口上的按钮，会临时创建一个托盘图标，发送一个通知，然后立即销毁图标。
// 通知本身会被系统接管并保留在通知中心，但将变得不可交互。

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <shellapi.h> // For Shell_NotifyIcon and NOTIFYICONDATA

// 自动链接所需的库
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

// 全局常量
const wchar_t CLASS_NAME[] = L"FireAndForgetTrayApp";
const int ID_BUTTON_SHOW_ZOMBIE_TOAST = 101; // 按钮的ID

// 函数原型
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void ShowFireAndForgetBalloon(HWND hwnd);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    // 1. 注册窗口类
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    // 2. 创建一个可见的窗口
    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"C++ 阅后即焚通知", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 350, 200, // 窗口大小
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL)
    {
        return 0;
    }

    // 3. 在窗口上创建一个按钮
    CreateWindow(
        L"BUTTON",
        L"发送一个“僵尸”通知", // 按钮文本
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 50, 230, 50, // 按钮位置和大小
        hwnd,
        (HMENU)ID_BUTTON_SHOW_ZOMBIE_TOAST,
        (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
        NULL
    );

    // 4. 显示窗口
    ShowWindow(hwnd, nCmdShow);

    // 5. 标准消息循环
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

// 窗口消息处理函数
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND: // 处理按钮点击
        if (LOWORD(wParam) == ID_BUTTON_SHOW_ZOMBIE_TOAST)
        {
            // 点击按钮时，执行“阅后即焚”操作
            ShowFireAndForgetBalloon(hwnd);
        }
        return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// “阅后即焚”核心函数
void ShowFireAndForgetBalloon(HWND hwnd)
{
    // 1. 准备 NOTIFYICONDATA 结构体
    NOTIFYICONDATA nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 200; // 使用一个唯一的ID，避免与可能存在的其他图标冲突
    nid.uFlags = NIF_ICON | NIF_INFO; // 我们只需要设置图标和气泡信息
    nid.dwInfoFlags = NIIF_INFO;
    nid.hIcon = LoadIcon(NULL, IDI_INFORMATION); // 使用一个信息图标
    lstrcpyW(nid.szInfoTitle, L"我是“僵尸”通知");
    lstrcpyW(nid.szInfo, L"我的发送者（托盘图标）已经消失了。你点击我不会有任何反应。");

    // 2. 【发射】添加图标并立即显示气泡
    // NIM_ADD 会创建图标并处理 NIF_INFO 标志来显示气泡
    Shell_NotifyIcon(NIM_ADD, &nid);

    // 3. 【遗忘】几乎立即发送删除图标的命令
    // 注意：这里的删除操作是异步的。你发出命令，Shell会在稍后处理。
    // 这给了Shell足够的时间来处理之前的NIM_ADD命令中的通知部分。
    Shell_NotifyIcon(NIM_DELETE, &nid);
}