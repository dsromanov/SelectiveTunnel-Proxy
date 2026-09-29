#include "app/commands.h"
#include "app/settings.h"

#include "core/constants.h"
#include "core/control.h"
#include "core/ipc.h"
#include "core/json_io.h"
#include "core/paths.h"
#include "core/policy.h"
#include "core/profile.h"
#include "core/status.h"
#include "core/utf.h"
#include "core/util.h"
#include "core/win_service.h"

#ifdef _WIN32
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comdlg32.lib")

namespace {

constexpr int kIdStatus = 301;
constexpr int kIdDomains = 302;
constexpr int kIdConnect = 303;
constexpr int kIdBlock = 304;
constexpr int kIdSettings = 305;
constexpr int kIdVerify = 306;
constexpr int kIdImport = 307;
constexpr int kIdRefresh = 308;
constexpr int kIdDiagnose = 309;
constexpr int kIdMore = 311;
constexpr UINT kTrayMsg = WM_APP + 1;
constexpr UINT kTimerId = 1;

NOTIFYICONDATAW g_nid{};
HWND g_hwnd = nullptr;
HFONT g_font = nullptr;
HFONT g_title = nullptr;

void ShowError(HWND hwnd, const std::string& text) {
    MessageBoxW(hwnd, st::Utf8ToWide(text).c_str(), L"SelectiveTunnel", MB_OK | MB_ICONWARNING);
}

nlohmann::json Call(HWND hwnd, const nlohmann::json& request) {
    nlohmann::json response;
    if (auto err = st::SendIpc(request, response)) {
        st::StartWindowsService();
        st::SleepMs(800);
        err = st::SendIpc(request, response);
        if (err) {
            ShowError(hwnd, err.message);
            return {{"ok", false}, {"error", err.message}};
        }
    }
    if (!response.value("ok", false)) {
        ShowError(hwnd, response.value("error", "Unknown error"));
    } else if (response.contains("message")) {
        MessageBoxW(hwnd, st::Utf8ToWide(response["message"].get<std::string>()).c_str(), L"SelectiveTunnel",
                    MB_OK | MB_ICONINFORMATION);
    } else if (response.contains("verify")) {
        MessageBoxW(hwnd, st::Utf8ToWide(response["verify"].get<std::string>()).c_str(), L"Egress verification",
                    MB_OK | MB_ICONINFORMATION);
    }
    return response;
}

void RefreshStatus(HWND hwnd) {
    std::string text = "Запуск…";
    auto status = st::ReadStatus();
    if (status) {
        const bool stale = st::StatusIsStale(status.value);
        if (stale) {
            text = "Служба не отвечает";
        } else if (status.value.state == "running") {
            text = "Figma и ChatGPT — через прокси";
        } else if (status.value.state == "blocked") {
            text = "Figma и ChatGPT заблокированы";
        } else if (status.value.state == "error") {
            text = "Ошибка. Откройте «Ещё» → Диагностика";
        } else {
            text = status.value.state;
        }
        g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        const auto tip = st::Utf8ToWide(text.substr(0, 120));
        wcsncpy(g_nid.szTip, tip.c_str(), ARRAYSIZE(g_nid.szTip) - 1);
        g_nid.szTip[ARRAYSIZE(g_nid.szTip) - 1] = 0;
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    }
    SetWindowTextW(GetDlgItem(hwnd, kIdStatus), st::Utf8ToWide(text).c_str());
    auto policy = st::LoadBundledPolicy(st::PolicyPath());
    if (policy) {
        std::string domains = "Домены: ";
        for (std::size_t i = 0; i < policy.value.domains.size(); ++i) {
            if (i) {
                domains += ", ";
            }
            domains += policy.value.domains[i];
        }
        SetWindowTextW(GetDlgItem(hwnd, kIdDomains), st::Utf8ToWide(domains).c_str());
    }
}

void DoImport(HWND hwnd) {
    wchar_t file[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Domain policy (*.json)\0*.json\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) {
        return;
    }
    if (st::FileSize(file) > 65536) {
        ShowError(hwnd, "Policy is too large.");
        return;
    }
    auto json = st::ReadJsonFile(file);
    if (!json) {
        ShowError(hwnd, json.error.message);
        return;
    }
    Call(hwnd, {{"cmd", "import_policy"}, {"policy", json.value}});
}

void DoSettings(HWND hwnd) {
    auto current = st::ReadConnection(st::ConnectionPath());
    st::Profile* ptr = current ? &current.value : nullptr;
    auto edited = ShowProxySettings(hwnd, ptr);
    if (!edited) {
        return;
    }
    Call(hwnd, {{"cmd", "save_profile"}, {"profile", edited.value.ToJson()}});
}

void ShowTrayMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kIdConnect, L"Через прокси");
    AppendMenuW(menu, MF_STRING, kIdBlock, L"Заблокировать");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, 400, L"Открыть");
    AppendMenuW(menu, MF_STRING, 401, L"Выход");
    SetForegroundWindow(hwnd);
    const int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
    if (cmd == 400) {
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    } else if (cmd == 401) {
        DestroyWindow(hwnd);
    } else if (cmd) {
        SendMessageW(hwnd, WM_COMMAND, cmd, 0);
    }
}

LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_CREATE: {
            g_font = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
            g_title = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
            HWND title = CreateWindowW(L"STATIC", L"Figma / ChatGPT", WS_CHILD | WS_VISIBLE, 22, 16, 500, 34, hwnd,
                                       nullptr, nullptr, nullptr);
            SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(g_title), TRUE);
            HWND status = CreateWindowW(L"STATIC", L"Запуск…", WS_CHILD | WS_VISIBLE, 22, 58, 500, 28, hwnd,
                                        reinterpret_cast<HMENU>(kIdStatus), nullptr, nullptr);
            SendMessageW(status, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
            HWND domains = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 22, 92, 500, 40, hwnd,
                                         reinterpret_cast<HMENU>(kIdDomains), nullptr, nullptr);
            SendMessageW(domains, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
            struct Btn {
                const wchar_t* text;
                int id;
                DWORD style;
                int x;
                int y;
                int w;
            } buttons[] = {{L"Через прокси", kIdConnect, BS_DEFPUSHBUTTON, 22, 146, 236},
                           {L"Заблокировать", kIdBlock, 0, 270, 146, 236},
                           {L"Прокси", kIdSettings, 0, 22, 198, 156},
                           {L"Проверить IP", kIdVerify, 0, 186, 198, 156},
                           {L"Ещё", kIdMore, 0, 350, 198, 156}};
            for (const auto& btn : buttons) {
                HWND b = CreateWindowW(L"BUTTON", btn.text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | btn.style, btn.x,
                                       btn.y, btn.w, 38, hwnd, reinterpret_cast<HMENU>(btn.id), nullptr, nullptr);
                SendMessageW(b, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
            }
            SetTimer(hwnd, kTimerId, 1500, nullptr);
            g_nid.cbSize = sizeof(g_nid);
            g_nid.hWnd = hwnd;
            g_nid.uID = 1;
            g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            g_nid.uCallbackMessage = kTrayMsg;
            g_nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
            wcsncpy(g_nid.szTip, L"SelectiveTunnel", ARRAYSIZE(g_nid.szTip) - 1);
            g_nid.szTip[ARRAYSIZE(g_nid.szTip) - 1] = 0;
            Shell_NotifyIconW(NIM_ADD, &g_nid);
            RefreshStatus(hwnd);
            return 0;
        }
        case WM_TIMER:
            RefreshStatus(hwnd);
            return 0;
        case WM_COMMAND: {
            switch (LOWORD(wparam)) {
                case kIdConnect:
                    Call(hwnd, {{"cmd", "connect"}});
                    break;
                case kIdBlock:
                    Call(hwnd, {{"cmd", "block"}});
                    break;
                case kIdSettings:
                    DoSettings(hwnd);
                    break;
                case kIdVerify:
                    Call(hwnd, {{"cmd", "verify"}});
                    break;
                case kIdImport:
                    DoImport(hwnd);
                    break;
                case kIdRefresh:
                    Call(hwnd, {{"cmd", "refresh"}});
                    break;
                case kIdDiagnose:
                    st::RunDiagnose();
                    break;
                case kIdMore: {
                    RECT box{};
                    GetWindowRect(GetDlgItem(hwnd, kIdMore), &box);
                    HMENU menu = CreatePopupMenu();
                    AppendMenuW(menu, MF_STRING, kIdImport, L"Импорт списка");
                    AppendMenuW(menu, MF_STRING, kIdRefresh, L"Обновить список");
                    AppendMenuW(menu, MF_STRING, kIdDiagnose, L"Диагностика");
                    const int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_LEFTALIGN, box.left, box.bottom, 0, hwnd,
                                                   nullptr);
                    DestroyMenu(menu);
                    if (cmd) {
                        SendMessageW(hwnd, WM_COMMAND, cmd, 0);
                    }
                    break;
                }
            }
            RefreshStatus(hwnd);
            return 0;
        }
        case kTrayMsg:
            if (lparam == WM_LBUTTONDBLCLK || lparam == WM_LBUTTONUP) {
                ShowWindow(hwnd, SW_SHOW);
                SetForegroundWindow(hwnd);
            } else if (lparam == WM_RBUTTONUP) {
                ShowTrayMenu(hwnd);
            }
            return 0;
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            KillTimer(hwnd, kTimerId);
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

}  // namespace

namespace st {

int RunGui() {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES};
    InitCommonControlsEx(&icc);
    WNDCLASSW wc{};
    wc.lpfnWndProc = MainProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SelectiveTunnelMain";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassW(&wc);
    g_hwnd = CreateWindowW(wc.lpszClassName, Utf8ToWide(std::string("SelectiveTunnel ") + kVersion).c_str(),
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 540,
                           300, nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(g_hwnd, SW_SHOW);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

bool ElevateAndRerun(const std::wstring& args) {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei)) {
        return false;
    }
    if (sei.hProcess) {
        CloseHandle(sei.hProcess);
    }
    return true;
}

}  // namespace st

#else

namespace st {
int RunGui() { return 1; }
bool ElevateAndRerun(const std::wstring&) { return false; }
}  // namespace st

#endif
