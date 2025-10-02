// main.cpp (终极版)
// 验证方案：结合程序化创建的快捷方式 (注册契约) 和内存中的AUMID绑定 (身份认领)
// 编译环境：Visual Studio, C++17 或更高, Windows SDK 10.0.17763.0 或更高

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <shobjidl.h>
#include <propsys.h>
#include <propkey.h>
#include <propvarutil.h>
#include <string>
#include <shlobj.h>     // For SHGetKnownFolderPath
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "windowsapp.lib")

// --- 核心定义 ---
const wchar_t* AUMID = L"MyCompany.MyUltimateValidationApp.1";
const wchar_t* SHORTCUT_NAME = L"ValidationApp.lnk";

// 函数原型
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool SetAumidForWindow(HWND hwnd, const wchar_t* aumid);
void SendToastNotification(const wchar_t* aumid);
bool InstallShortcut(const wchar_t* shortcutName, const wchar_t* aumid);
void RemoveShortcut(const wchar_t* shortcutName);

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    winrt::init_apartment();
    CoInitialize(NULL);

    // 1. 【创建注册契约】在开始菜单中创建带有AUMID的快捷方式
    // 这是让通知中心“认识”我们的关键一步
    if (!InstallShortcut(SHORTCUT_NAME, AUMID)) {
        MessageBox(NULL, L"无法创建开始菜单快捷方式。\n请确保程序有权限写入 %APPDATA%", L"错误", MB_OK);
        return 0;
    }
    
    // 注册一个函数，确保程序退出时清理快捷方式
    atexit([] { RemoveShortcut(SHORTCUT_NAME); CoUninitialize(); });

    const wchar_t CLASS_NAME[] = L"UltimateValidationSample";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"终极验证窗口", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    // 2. 【运行时认领身份】将AUMID绑定到窗口句柄
    // 告诉系统，我这个进程就是那个快捷方式代表的应用
    SetAumidForWindow(hwnd, AUMID);

    // 显示窗口并确保其已激活
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // 3. 【发送通知】在“契约”和“认领”都完成后发送
    SendToastNotification(AUMID);
    
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// 内存绑定部分 (不变)
bool SetAumidForWindow(HWND hwnd, const wchar_t* aumid) {
    IPropertyStore* pps;
    if (SUCCEEDED(SHGetPropertyStoreForWindow(hwnd, IID_PPV_ARGS(&pps)))) {
        PROPVARIANT pvAumid;
        if (SUCCEEDED(InitPropVariantFromString(aumid, &pvAumid))) {
            pps->SetValue(PKEY_AppUserModel_ID, pvAumid);
            PropVariantClear(&pvAumid);
        }
        pps->Release();
        return true;
    }
    return false;
}

// 发送通知部分 (不变)
void SendToastNotification(const wchar_t* aumid) {
    try {
        auto notifier = winrt::Windows::UI::Notifications::ToastNotificationManager::CreateToastNotifier(aumid);
        winrt::Windows::Data::Xml::Dom::XmlDocument toastXml;
        std::wstring xml = L"<toast><visual><binding template='ToastGeneric'><text>终极验证成功！</text><text>此通知结合了快捷方式“契约”和内存“认领”。</text></binding></visual></toast>";
        toastXml.LoadXml(xml);
        winrt::Windows::UI::Notifications::ToastNotification notification(toastXml);
        notifier.Show(notification);
    }
    catch (const winrt::hresult_error& e) {
        MessageBox(NULL, e.message().c_str(), L"Toast 发送失败", MB_OK);
    }
}

// 【新函数】获取开始菜单程序文件夹的路径
std::wstring GetStartMenuProgramsPath() {
    PWSTR pszPath = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Programs, 0, NULL, &pszPath))) {
        std::wstring path = pszPath;
        CoTaskMemFree(pszPath);
        return path;
    }
    return L"";
}

// 【新函数】创建并注册快捷方式
bool InstallShortcut(const wchar_t* shortcutName, const wchar_t* aumid) {
    std::wstring shortcutPath = GetStartMenuProgramsPath();
    if (shortcutPath.empty()) return false;
    shortcutPath += L"\\" + std::wstring(shortcutName);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    IShellLink* psl = NULL;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);

    if (SUCCEEDED(hr)) {
        psl->SetPath(exePath);
        
        IPropertyStore* pps = NULL;
        hr = psl->QueryInterface(IID_IPropertyStore, (void**)&pps);
        if (SUCCEEDED(hr)) {
            PROPVARIANT pvAumid;
            hr = InitPropVariantFromString(aumid, &pvAumid);
            if (SUCCEEDED(hr)) {
                hr = pps->SetValue(PKEY_AppUserModel_ID, pvAumid);
                PropVariantClear(&pvAumid);
            }
            pps->Release();
        }

        IPersistFile* ppf = NULL;
        hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
        if (SUCCEEDED(hr)) {
            hr = ppf->Save(shortcutPath.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }
    return SUCCEEDED(hr);
}

// 【新函数】清理快捷方式
void RemoveShortcut(const wchar_t* shortcutName) {
    std::wstring shortcutPath = GetStartMenuProgramsPath();
    if (shortcutPath.empty()) return;
    shortcutPath += L"\\" + std::wstring(shortcutName);
    DeleteFileW(shortcutPath.c_str());
}