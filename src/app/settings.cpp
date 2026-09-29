#include "app/settings.h"

#include "core/constants.h"
#include "core/utf.h"
#include "core/util.h"

#include <string>

#ifdef _WIN32
#include <commctrl.h>
#include <windowsx.h>

namespace {

constexpr int kIdProtocol = 201;
constexpr int kIdIp = 202;
constexpr int kIdPort = 203;
constexpr int kIdUser = 204;
constexpr int kIdPass = 205;
constexpr int kIdExpected = 206;
constexpr int kIdTls = 207;
constexpr int kIdSave = 208;
constexpr int kIdCancel = 209;
constexpr int kIdNote = 210;

struct SettingsState {
    st::Profile current;
    st::Profile result;
    bool accepted = false;
};

void AddLabel(HWND parent, const wchar_t* text, int x, int y, HFONT font) {
    HWND w = CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y, 235, 25, parent, nullptr, nullptr, nullptr);
    SendMessageW(w, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

HWND AddEdit(HWND parent, int id, int y, HFONT font, bool password) {
    HWND w = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | (password ? ES_PASSWORD : 0), 265, y,
                             280, 28, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
    SendMessageW(w, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return w;
}

std::string GetText(HWND parent, int id) {
    wchar_t buf[512]{};
    GetDlgItemTextW(parent, id, buf, 512);
    return st::WideToUtf8(buf);
}

LRESULT CALLBACK SettingsProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<SettingsState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
        case WM_CREATE: {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lparam);
            state = reinterpret_cast<SettingsState*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            HFONT font = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, 0, 0, L"Segoe UI");
            SetWindowFont(hwnd, font, TRUE);
            const wchar_t* labels[] = {L"Протокол", L"IP прокси", L"Порт", L"Логин прокси", L"Пароль прокси",
                                       L"Ожидаемый внешний IP", L"Имя в TLS-сертификате"};
            for (int i = 0; i < 7; ++i) {
                AddLabel(hwnd, labels[i], 20, 22 + 45 * i, font);
            }
            HWND combo = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST, 265, 20,
                                       280, 200, hwnd, reinterpret_cast<HMENU>(kIdProtocol), nullptr, nullptr);
            SendMessageW(combo, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"socks5"));
            SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"http"));
            SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"https"));
            const auto proto = st::Utf8ToWide(state->current.protocol);
            int sel = 0;
            if (proto == L"http") {
                sel = 1;
            } else if (proto == L"https") {
                sel = 2;
            }
            SendMessageW(combo, CB_SETCURSEL, sel, 0);
            SetWindowTextW(AddEdit(hwnd, kIdIp, 65, font, false), st::Utf8ToWide(state->current.server_ip).c_str());
            SetWindowTextW(AddEdit(hwnd, kIdPort, 110, font, false),
                           st::Utf8ToWide(std::to_string(state->current.server_port)).c_str());
            SetWindowTextW(AddEdit(hwnd, kIdUser, 155, font, false), st::Utf8ToWide(state->current.username).c_str());
            AddEdit(hwnd, kIdPass, 200, font, true);
            SetWindowTextW(AddEdit(hwnd, kIdExpected, 245, font, false),
                           st::Utf8ToWide(state->current.expected_exit_ip).c_str());
            SetWindowTextW(AddEdit(hwnd, kIdTls, 290, font, false),
                           st::Utf8ToWide(state->current.tls_server_name).c_str());
            HWND note = CreateWindowW(L"STATIC",
                                      L"Данные самого прокси. Пустой пароль — оставить текущий.",
                                      WS_CHILD | WS_VISIBLE, 20, 345, 525, 40, hwnd,
                                      reinterpret_cast<HMENU>(kIdNote), nullptr, nullptr);
            SendMessageW(note, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            HWND save = CreateWindowW(L"BUTTON", L"Сохранить", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 305,
                                      400, 115, 33, hwnd, reinterpret_cast<HMENU>(kIdSave), nullptr, nullptr);
            HWND cancel = CreateWindowW(L"BUTTON", L"Отмена", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 430, 400, 115, 33, hwnd,
                                        reinterpret_cast<HMENU>(kIdCancel), nullptr, nullptr);
            SendMessageW(save, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SendMessageW(cancel, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wparam) == kIdCancel || LOWORD(wparam) == IDCANCEL) {
                DestroyWindow(hwnd);
                return 0;
            }
            if (LOWORD(wparam) == kIdSave || LOWORD(wparam) == IDOK) {
                try {
                    wchar_t proto[32]{};
                    const int sel = static_cast<int>(SendMessageW(GetDlgItem(hwnd, kIdProtocol), CB_GETCURSEL, 0, 0));
                    SendMessageW(GetDlgItem(hwnd, kIdProtocol), CB_GETLBTEXT, sel, reinterpret_cast<LPARAM>(proto));
                    st::Profile candidate = state->current;
                    candidate.protocol = st::WideToUtf8(proto);
                    candidate.server_ip = GetText(hwnd, kIdIp);
                    candidate.server_port = std::stoi(GetText(hwnd, kIdPort));
                    candidate.username = GetText(hwnd, kIdUser);
                    candidate.password = GetText(hwnd, kIdPass);
                    candidate.expected_exit_ip = GetText(hwnd, kIdExpected);
                    candidate.tls_server_name = GetText(hwnd, kIdTls);
                    if (candidate.password.empty()) {
                        candidate.password = state->current.password;
                    }
                    if (auto err = st::AssertProfile(candidate)) {
                        MessageBoxW(hwnd, st::Utf8ToWide(err.message).c_str(), L"Проверьте настройки", MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    state->result = candidate;
                    state->accepted = true;
                    DestroyWindow(hwnd);
                } catch (...) {
                    MessageBoxW(hwnd, L"Проверьте настройки", L"SelectiveTunnel", MB_OK | MB_ICONWARNING);
                }
                return 0;
            }
            return 0;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

}  // namespace

st::Result<st::Profile> ShowProxySettings(HWND parent, const st::Profile* current) {
    SettingsState state;
    if (current) {
        state.current = *current;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = SettingsProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"SelectiveTunnelSettings";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, wc.lpszClassName, L"Прокси",
                                WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 586, 490, parent,
                                nullptr, wc.hInstance, &state);
    if (parent) {
        EnableWindow(parent, FALSE);
    }
    MSG msg;
    while (IsWindow(hwnd) && GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    if (parent) {
        EnableWindow(parent, TRUE);
        SetForegroundWindow(parent);
    }
    if (!state.accepted) {
        return st::Result<st::Profile>::fail("cancelled");
    }
    return st::Result<st::Profile>::ok(state.result);
}

#endif
