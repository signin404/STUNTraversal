// main.cpp (最终答案版 - 事件驱动清理)
// 核心修复：不再立即删除图标，而是在收到NIN_BALLOONHIDE或NIN_BALLOONTIMEOUT回调消息后，再进行清理。

#ifndef UNICODE
#define UNICODE
#endif

#define _WIN32_WINNT _WIN32_WINNT_VISTA 

#include <windows.h>
#include <shellapi.h>
#include <objbase.h> 
#include <guiddef.h> 

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")

const wchar_t CLASS_NAME[] = L"EventDrivenTrayApp";
const int ID_BUTTON_SHOW_CORRECT_TOAST = 101;
const UINT WM_TRAYICON = WM_APP + 1; // 托盘图标回调消息

// 将nid设为全局，以便在不同函数中访问
NOTIFYICONDATA nid = {}; 

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void ShowCorrectFireAndForgetBalloon(HWND hwnd);
void RemoveHiddenIcon();

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"C++ 事件驱动的正确通知", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    CreateWindow(
        L"BUTTON",
        L"发送一个可存档的通知 (正确方式)",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        50, 50, 280, 50,
        hwnd,
        (HMENU)ID_BUTTON_SHOW_CORRECT_TOAST,
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
        // 确保在窗口关闭时，任何可能存在的隐藏图标都被清理
        RemoveHiddenIcon(); 
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON_SHOW_CORRECT_TOAST) {
            ShowCorrectFireAndForgetBalloon(hwnd);
        }
        return 0;
    
    case WM_TRAYICON:
        // 检查lParam的低位字，确定是哪个通知事件
        switch (LOWORD(lParam))
        {
        case NIN_BALLOONSHOW:
            // 通知已经显示，我们什么都不做，等待它结束
            break;

        case NIN_BALLOONHIDE:
        case NIN_BALLOONTIMEOUT:
            // --- 决定性的一步 ---
            // 通知已经隐藏或超时，现在是清理隐藏图标的最佳时机
            RemoveHiddenIcon();
            break;
        }
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ShowCorrectFireAndForgetBalloon(HWND hwnd)
{
    // 每次都清零结构体
    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hwnd;
    nid.uID = 100;
    nid.uVersion = NOTIFYICON_VERSION_4;
    nid.uCallbackMessage = WM_TRAYICON; // 告诉Shell有事件时给我们发这个消息

    CoCreateGuid(&nid.guidItem);
    nid.uFlags = NIF_GUID | NIF_MESSAGE; // 我们需要GUID和回调消息

    // 步骤 A: 注册一个隐藏的图标作为通知源
    nid.uFlags |= NIF_STATE;
    nid.dwState = NIS_HIDDEN;
    nid.dwStateMask = NIS_HIDDEN;
    Shell_NotifyIcon(NIM_ADD, &nid);
    Shell_NotifyIcon(NIM_SETVERSION, &nid);

    // 步骤 B: 修改图标，让它显示气泡
    nid.uFlags = NIF_INFO | NIF_GUID;
    nid.dwInfoFlags = NIIF_INFO;
    lstrcpyW(nid.szInfoTitle, L"我能被存档！ (正确方式)");
    lstrcpyW(nid.szInfo, L"我的发送者（隐藏图标）将在我消失后被自动清理。");

    Shell_NotifyIcon(NIM_MODIFY, &nid);

    // 注意：这里不再调用 NIM_DELETE。删除操作将由WindowProc中的回调消息触发。
}

void RemoveHiddenIcon()
{
    // 准备一个只包含GUID的结构体来删除图标
    NOTIFYICONDATA nid_del = {};
    nid_del.cbSize = sizeof(NOTIFYICONDATA);
    nid_del.uFlags = NIF_GUID;
    nid_del.guidItem = nid.guidItem; // 使用之前保存的GUID

    Shell_NotifyIcon(NIM_DELETE, &nid_del);
}