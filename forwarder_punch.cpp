// main.cpp (已再次修复)
// 验证方案：通过 SHGetPropertyStoreForWindow 在内存中动态注册 AUMID
// 编译环境：Visual Studio, C++17 或更高, Windows SDK 10.0.17763.0 或更高
// 链接库会自动通过 #pragma comment 指令包含

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <shobjidl.h>   // For SHGetPropertyStoreForWindow
#include <propsys.h>    // For IPropertyStore and PKEYs
#include <propkey.h>    // For PKEY_AppUserModel_ID
#include <propvarutil.h> // For InitPropVariantFromString
#include <string>

// C++/WinRT headers for Toast Notifications
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h> // <--- 修复编译错误 C2653: 'Xml' is not a class or namespace name

// 自动链接所需的库
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "windowsapp.lib")

// --- 核心部分 ---
// 我们将在内存中动态应用的应用程序用户模型ID (AUMID)
const wchar_t* AUMID = L"MyCompany.MyInMemoryAumidApp.1";

// 函数原型
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool SetAumidForWindow(HWND hwnd, const wchar_t* aumid);
void SendToastNotification(const wchar_t* aumid);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    // 初始化 COM 和 WinRT
    winrt::init_apartment();
    CoInitialize(NULL);

    // 1. 创建一个标准的 Win32 窗口
    const wchar_t CLASS_NAME[] = L"InMemoryAumidSample";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"验证窗口", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL)
    {
        return 0;
    }

    // 2. 【核心验证】为刚刚创建的窗口句柄动态设置AUMID
    // 这一步完全在内存中进行，不涉及任何文件或注册表写入
    bool success = SetAumidForWindow(hwnd, AUMID);

    if (success)
    {
        // 3. 【证明有效】如果AUMID设置成功，立即尝试发送Toast通知
        // 如果通知能够出现，就证明了这个临时的、内存中的AUMID是有效的
        SendToastNotification(AUMID);
    }
    
    ShowWindow(hwnd, nCmdShow);

    // 标准消息循环
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0))
    {
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
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// 这就是魔法发生的地方
bool SetAumidForWindow(HWND hwnd, const wchar_t* aumid)
{
    // 使用 SHGetPropertyStoreForWindow API 获取与窗口句柄关联的属性存储区
    IPropertyStore* pps;
    HRESULT hr = SHGetPropertyStoreForWindow(hwnd, IID_PPV_ARGS(&pps));

    if (SUCCEEDED(hr))
    {
        // 将我们的AUMID字符串包装成一个PROPVARIANT类型
        PROPVARIANT pvAumid;
        hr = InitPropVariantFromString(aumid, &pvAumid);
        
        if (SUCCEEDED(hr))
        {
            // 将AUMID属性 (PKEY_AppUserModel_ID) 设置到属性存储区中
            hr = pps->SetValue(PKEY_AppUserModel_ID, pvAumid);
            
            // 清理PROPVARIANT
            PropVariantClear(&pvAumid);
        }

        // 释放COM接口
        pps->Release();
    }
    
    return SUCCEEDED(hr);
}

void SendToastNotification(const wchar_t* aumid)
{
    try
    {
        // 使用C++/WinRT发送通知
        auto notifier = winrt::Windows::UI::Notifications::ToastNotificationManager::CreateToastNotifier(aumid);
        winrt::Windows::Data::Xml::Dom::XmlDocument toastXml;

        std::wstring xml = L"<toast><visual><binding template='ToastGeneric'><text>验证成功！</text><text>";
        xml += L"此通知由一个临时的、仅存于内存的AUMID发送。";
        xml += L"</text></binding></visual></toast>";
        
        toastXml.LoadXml(xml);

        winrt::Windows::UI::Notifications::ToastNotification notification(toastXml);
        notifier.Show(notification);
    }
    catch (const winrt::hresult_error& e)
    {
        // 如果失败，显示错误信息
        MessageBox(NULL, e.message().c_str(), L"Toast 发送失败", MB_OK);
    }
}