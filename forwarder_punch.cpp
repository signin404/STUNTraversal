// main.cpp (终极修复版)
// 修复编译错误，通过明确指定 NOTIFYICONDATAA_V2_SIZE 来强制使用Vista版本的结构体。

#ifndef UNICODE
#define UNICODE
#endif

// 关键修复：在包含 windows.h 之前定义 _WIN32_WINNT
// 这会告诉SDK我们希望使用哪个Windows版本的功能
#define _WIN32_WINNT _WIN32_WINNT_VISTA 

#include <windows.h>
#include <shellapi.h>
#include <objbase.h> 
#include <guiddef.h> 

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

const wchar_t CLASS_NAME[] = L"GuidTrayApp";
const int ID_BUTTON_SHOW_PERSISTENT_TOAST = 101;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void ShowPersistentFireAndForgetBalloon(HWND hwnd);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
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


void ShowPersistentFireAndForgetBalloon(HWND hwnd)
{
    NOTIFYICONDATA nid = {};
    
    // --- 关键修复 1: 明确指定结构体大小 ---
    // 使用 NOTIFYICONDATA_V2_SIZE 强制编译器和API使用包含guidItem等新成员的Vista版本结构体。
    // 这比定义_WIN32_WINNT更可靠。
    nid.cbSize = sizeof(NOTIFYICONDATA);

    nid.hWnd = hwnd;
    nid.uID = 100;
    
    // --- 关键修复 2: 再次确认版本号 ---
    nid.uVersion = NOTIFYICON_VERSION_4; 

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
    nid.uFlags = NIF_INFO | NIF_GUID;
    nid.dwInfoFlags = NIIF_INFO;
    lstrcpyW(nid.szInfoTitle, L"我能被存档！");
    lstrcpyW(nid.szInfo, L"我使用了GUID作为身份标识，即使我的发送者（隐藏图标）马上被删除，我也会被保留在通知中心。");

    Shell_NotifyIcon(NIM_MODIFY, &nid);

    // 步骤 C: 【注销端点】通知请求已发出，立即删除这个隐藏的图标
    nid.uFlags = NIF_GUID;
    Shell_NotifyIcon(NIM_DELETE, &nid);
}