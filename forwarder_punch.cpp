// main.cpp (最终答案版)
// 核心修复：在单线程单元 (STA) 中初始化COM/WinRT环境

#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <shobjidl.h>
#include <propsys.h>
#include <propkey.h>
#include <propvarutil.h>
#include <string>
#include <shlobj.h>
#include <winrt/Windows.UI.Notifications.h>
#include <winrt/Windows.Data.Xml.Dom.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "windowsapp.lib")

const wchar_t* AUMID = L"MyCompany.TheFinalAnswerApp.1";
const wchar_t* SHORTCUT_NAME = L"FinalAnswer.lnk";

// 函数原型无需改变
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
bool SetAumidForWindow(HWND hwnd, const wchar_t* aumid);
void SendToastNotification(const wchar_t* aumid);
bool InstallShortcut(const wchar_t* shortcutName, const wchar_t* aumid);
void RemoveShortcut(const wchar_t* shortcutName);
std::wstring GetStartMenuProgramsPath();

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR pCmdLine, int nCmdShow)
{
    // --- 决定性的、唯一的修复 ---
    // 初始化一个单线程单元 (STA)。所有UI相关的COM/WinRT操作都必须在这里进行。
    winrt::init_apartment(winrt::apartment_type::single_threaded);
    
    // CoInitialize现在不再需要，因为winrt::init_apartment已经处理了
    // CoInitialize(NULL); 

    if (!InstallShortcut(SHORTCUT_NAME, AUMID)) {
        MessageBox(NULL, L"无法创建开始菜单快捷方式。", L"错误", MB_OK);
        return 0;
    }
    
    atexit([] { RemoveShortcut(SHORTCUT_NAME); });

    const wchar_t CLASS_NAME[] = L"FinalAnswerSample";
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, L"最终答案验证", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    SetAumidForWindow(hwnd, AUMID);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    SendToastNotification(AUMID);
    
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}

// WindowProc, SetAumidForWindow, SendToastNotification 
// GetStartMenuProgramsPath 函数保持不变
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
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
void SendToastNotification(const wchar_t* aumid) {
    try {
        auto notifier = winrt::Windows::UI::Notifications::ToastNotificationManager::CreateToastNotifier(aumid);
        winrt::Windows::Data::Xml::Dom::XmlDocument toastXml;
        std::wstring xml = L"<toast><visual><binding template='ToastGeneric'><text>终极验证成功！</text><text>COM线程模型 (STA) 是最后的关键。</text></binding></visual></toast>";
        toastXml.LoadXml(xml);
        winrt::Windows::UI::Notifications::ToastNotification notification(toastXml);
        notifier.Show(notification);
    }
    catch (const winrt::hresult_error& e) {
        MessageBox(NULL, e.message().c_str(), L"Toast 发送失败", MB_OK);
    }
}
std::wstring GetStartMenuProgramsPath() {
    PWSTR pszPath = NULL;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Programs, 0, NULL, &pszPath))) {
        std::wstring path = pszPath;
        CoTaskMemFree(pszPath);
        return path;
    }
    return L"";
}

// 包含SHChangeNotify的快捷方式函数 (不变)
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
    if (SUCCEEDED(hr)) {
        SHChangeNotify(SHCNE_CREATE, SHCNF_PATH, shortcutPath.c_str(), NULL);
        Sleep(100); 
    }
    return SUCCEEDED(hr);
}
void RemoveShortcut(const wchar_t* shortcutName) {
    std::wstring shortcutPath = GetStartMenuProgramsPath();
    if (shortcutPath.empty()) return;
    shortcutPath += L"\\" + std::wstring(shortcutName);
    if(DeleteFileW(shortcutPath.c_str())) {
        SHChangeNotify(SHCNE_DELETE, SHCNF_PATH, shortcutPath.c_str(), NULL);
    }
}