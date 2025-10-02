// main.cpp
// 终极答案：“GUID + 隐藏图标”的阅后即焚法
// 这是在不显示可见托盘图标的情况下，发送可被存档到通知中心的Toast通知的正确Win32方法。

#ifndef UNICODE
#define UNICODE
#endif

#define NTDDI_VERSION NTDDI_WINVISTA // 需要Vista或更高版本的功能
#define _WIN32_WINNT _WIN32_WINNT_VISTA

#include <windows.h>
#include <shellapi.h>
#include <objbase.h> // For CoInitializeEx and CoCreateGuid
#include <guiddef.h> // For GUID definition

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

const wchar_t CLASS_NAME[] = L"GuidTrayApp";
const int ID_BUTTON_SHOW_PERSISTENT_TOAST = 101;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void ShowPersistentFireAndForgetBalloon(HWND hwnd);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    // 使用COM，需要初始化
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"C++ 可存档的“阅后即焚”通知", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    CreateWindow(
        L"BUTTON",
        L"发送一个可存档的通知",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 50, 280, 50,
        hwnd,
        (HMENU)ID_BUTTON_SHOW_PERSISTENT_TOAST,
        (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
        NULL
    );

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CoUninitialize();
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON_SHOW_PERSISTENT_TOAST) {
            ShowPersistentFireAndForgetBalloon(hwnd);
        }
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// “GUID + 隐藏图标”核心函数
void ShowPersistentFireAndForgetBalloon(HWND hwnd)
{
    NOTIFYICONDATA nid = {};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 100; // 窗口内的ID，可以固定

    // --- 关键步骤 1: 启用现代通知行为 ---
    // 设置版本为 NOTIFYICON_VERSION_4 (需要Vista或更高)
    // 这是使用GUID和新功能的“魔法开关”
    nid.uVersion = NOTIFYICON_VERSION_4;

    // --- 关键步骤 2: 赋予强身份标识 ---
    // 为这个临时的通知源创建一个唯一的GUID
    CoCreateGuid(&nid.guidItem);
    nid.uFlags = NIF_GUID;

    // 步骤 A: 【注册端点】添加一个隐藏的图标作为通知源
    nid.uFlags |= NIF_STATE;
    nid.dwState = NIS_HIDDEN;
    nid.dwStateMask = NIS_HIDDEN;
    Shell_NotifyIcon(NIM_ADD, &nid);

    // 设置版本，确保Shell使用新行为
    Shell_NotifyIcon(NIM_SETVERSION, &nid);

    // 步骤 B: 【发送通知】修改刚才注册的隐藏图标，让它显示气泡
    nid.uFlags = NIF_INFO | NIF_GUID; // 必须再次包含GUID来标识是哪个图标
    nid.dwInfoFlags = NIIF_INFO;
    lstrcpyW(nid.szInfoTitle, L"我能被存档！");
    lstrcpyW(nid.szInfo, L"我使用了GUID作为身份标识，即使我的发送者（隐藏图标）马上被删除，我也会被保留在通知中心。");

    Shell_NotifyIcon(NIM_MODIFY, &nid);

    // 步骤 C: 【注销端点】通知请求已发出，立即删除这个隐藏的图标
    // 再次需要GUID来标识删除谁
    nid.uFlags = NIF_GUID;
    Shell_NotifyIcon(NIM_DELETE, &nid);
}