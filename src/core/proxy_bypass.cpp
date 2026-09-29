#include "proxy_bypass.h"

#include "constants.h"
#include "utf.h"
#include "util.h"

#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>
#include <wtsapi32.h>
#endif

namespace st {
namespace {

std::string TrimCopy(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return std::string(text);
}

std::vector<std::string> SplitList(const std::string& existing) {
    std::vector<std::string> parts;
    std::string cur;
    for (char ch : existing) {
        if (ch == ';' || ch == ',') {
            cur = TrimCopy(cur);
            if (!cur.empty()) {
                parts.push_back(cur);
            }
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    cur = TrimCopy(cur);
    if (!cur.empty()) {
        parts.push_back(cur);
    }
    return parts;
}

bool IsFakeIpBypass(const std::string& entry) {
    const auto lower = ToLowerAscii(entry);
    return lower == "100.82.*" || lower == kFakeV4 || lower == "100.82.0.*" || lower == "100.82.0.0/16";
}

bool IsOwnedBypass(const std::string& entry, const std::vector<std::string>& domains) {
    if (IsFakeIpBypass(entry)) {
        return true;
    }
    const auto lower = ToLowerAscii(entry);
    for (const auto& domain : domains) {
        const auto d = ToLowerAscii(domain);
        if (lower == d || lower == "*." + d || lower == "." + d) {
            return true;
        }
    }
    return false;
}

std::string JoinList(const std::vector<std::string>& parts, char sep) {
    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) {
            out << sep;
        }
        out << parts[i];
    }
    return out.str();
}

void PushUnique(std::vector<std::string>& out, std::vector<std::string>& seen, const std::string& entry) {
    const auto key = ToLowerAscii(entry);
    for (const auto& prev : seen) {
        if (prev == key) {
            return;
        }
    }
    seen.push_back(key);
    out.push_back(entry);
}

#ifdef _WIN32

const wchar_t* kInternetSettings = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const wchar_t* kUserEnvironment = L"Environment";
const wchar_t* kMachineEnvironment = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
const wchar_t* kNoProxyNames[] = {L"NO_PROXY", L"no_proxy"};

bool IsUserSidKey(const wchar_t* name) {
    if (!name || name[0] != L'S') {
        return false;
    }
    if (wcsstr(name, L"_Classes")) {
        return false;
    }
    if (wcscmp(name, L"S-1-5-18") == 0 || wcscmp(name, L"S-1-5-19") == 0 || wcscmp(name, L"S-1-5-20") == 0) {
        return false;
    }
    return wcsncmp(name, L"S-1-5-21-", 9) == 0;
}

std::string ReadRegString(HKEY key, const wchar_t* name) {
    wchar_t buf[4096]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) != ERROR_SUCCESS) {
        return {};
    }
    return WideToUtf8(buf);
}

void WriteRegString(HKEY key, const wchar_t* name, const std::string& value) {
    if (ReadRegString(key, name) == value) {
        return;
    }
    if (value.empty()) {
        RegDeleteValueW(key, name);
        return;
    }
    const auto wide = Utf8ToWide(value);
    RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(wide.c_str()),
                   static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t)));
}

void ApplyInternetSettings(HKEY hive, const Policy& policy, bool remove) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(hive, kInternetSettings, 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) {
        return;
    }
    const auto next = remove ? StripProxyBypass(ReadRegString(key, L"ProxyOverride"), policy.domains)
                             : MergeProxyBypass(ReadRegString(key, L"ProxyOverride"), policy.domains);
    WriteRegString(key, L"ProxyOverride", next);
    RegCloseKey(key);
}

void ApplyEnvKey(HKEY key, const Policy& policy, bool remove) {
    for (const wchar_t* name : kNoProxyNames) {
        const auto current = ReadRegString(key, name);
        const auto next =
            remove ? StripNoProxy(current, policy.domains) : MergeNoProxy(current, policy.domains);
        WriteRegString(key, name, next);
    }
}

void ApplyUserEnvironment(HKEY hive, const Policy& policy, bool remove) {
    HKEY key = nullptr;
    DWORD disp = 0;
    if (RegCreateKeyExW(hive, kUserEnvironment, 0, nullptr, 0, KEY_READ | KEY_WRITE, nullptr, &key, &disp) !=
        ERROR_SUCCESS) {
        return;
    }
    ApplyEnvKey(key, policy, remove);
    RegCloseKey(key);
}

void ApplyMachineEnvironment(const Policy& policy, bool remove) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kMachineEnvironment, 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) {
        return;
    }
    ApplyEnvKey(key, policy, remove);
    RegCloseKey(key);
}

void ApplyAllLoadedUsers(const Policy& policy, bool remove) {
    ApplyInternetSettings(HKEY_CURRENT_USER, policy, remove);
    ApplyUserEnvironment(HKEY_CURRENT_USER, policy, remove);
    DWORD i = 0;
    wchar_t name[256];
    DWORD nlen = 256;
    while (RegEnumKeyExW(HKEY_USERS, i++, name, &nlen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        nlen = 256;
        if (!IsUserSidKey(name)) {
            continue;
        }
        HKEY user = nullptr;
        if (RegOpenKeyExW(HKEY_USERS, name, 0, KEY_READ | KEY_WRITE, &user) != ERROR_SUCCESS) {
            continue;
        }
        ApplyInternetSettings(user, policy, remove);
        ApplyUserEnvironment(user, policy, remove);
        RegCloseKey(user);
    }
}

std::wstring QueryWinInetBypass() {
    INTERNET_PER_CONN_OPTIONW opt{};
    opt.dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.dwOptionCount = 1;
    list.pOptions = &opt;
    DWORD size = sizeof(list);
    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) {
        return {};
    }
    std::wstring out;
    if (opt.Value.pszValue) {
        out = opt.Value.pszValue;
        GlobalFree(opt.Value.pszValue);
    }
    return out;
}

void SetWinInetBypass(const std::wstring& bypass) {
    INTERNET_PER_CONN_OPTIONW opt{};
    opt.dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    opt.Value.pszValue = const_cast<LPWSTR>(bypass.c_str());
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.dwOptionCount = 1;
    list.pOptions = &opt;
    InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list));
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}

void ApplyImpersonatedSessions(const Policy& policy, bool remove) {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        return;
    }
    for (DWORD i = 0; i < count; ++i) {
        if (sessions[i].State != WTSActive && sessions[i].State != WTSConnected) {
            continue;
        }
        HANDLE token = nullptr;
        if (!WTSQueryUserToken(sessions[i].SessionId, &token)) {
            continue;
        }
        if (ImpersonateLoggedOnUser(token)) {
            const auto current = WideToUtf8(QueryWinInetBypass());
            const auto next = remove ? StripProxyBypass(current, policy.domains)
                                     : MergeProxyBypass(current, policy.domains);
            if (current != next) {
                SetWinInetBypass(Utf8ToWide(next));
            }
            RevertToSelf();
        }
        CloseHandle(token);
    }
    WTSFreeMemory(sessions);
}

#endif

}  // namespace

std::string MergeProxyBypass(const std::string& existing, const std::vector<std::string>& domains) {
    std::vector<std::string> out;
    std::vector<std::string> seen;
    for (const auto& part : SplitList(existing)) {
        if (!IsOwnedBypass(part, domains)) {
            PushUnique(out, seen, part);
        }
    }
    for (const auto& domain : domains) {
        PushUnique(out, seen, domain);
        PushUnique(out, seen, "*." + domain);
    }
    PushUnique(out, seen, "100.82.*");
    return JoinList(out, ';');
}

std::string StripProxyBypass(const std::string& existing, const std::vector<std::string>& domains) {
    std::vector<std::string> out;
    for (const auto& part : SplitList(existing)) {
        if (!IsOwnedBypass(part, domains)) {
            out.push_back(part);
        }
    }
    return JoinList(out, ';');
}

std::string MergeNoProxy(const std::string& existing, const std::vector<std::string>& domains) {
    std::vector<std::string> out;
    std::vector<std::string> seen;
    for (const auto& part : SplitList(existing)) {
        if (!IsOwnedBypass(part, domains)) {
            PushUnique(out, seen, part);
        }
    }
    for (const auto& domain : domains) {
        PushUnique(out, seen, domain);
        PushUnique(out, seen, "." + domain);
    }
    return JoinList(out, ',');
}

std::string StripNoProxy(const std::string& existing, const std::vector<std::string>& domains) {
    std::vector<std::string> out;
    for (const auto& part : SplitList(existing)) {
        if (!IsOwnedBypass(part, domains)) {
            out.push_back(part);
        }
    }
    return JoinList(out, ',');
}

void ApplyProxyBypass(const Policy& policy) {
#ifdef _WIN32
    ApplyAllLoadedUsers(policy, false);
    ApplyMachineEnvironment(policy, false);
    ApplyImpersonatedSessions(policy, false);
    ApplyWinHttpProxyBypass(policy, false);
#else
    (void)policy;
#endif
}

void RemoveProxyBypass(const Policy& policy) {
#ifdef _WIN32
    ApplyAllLoadedUsers(policy, true);
    ApplyMachineEnvironment(policy, true);
    ApplyImpersonatedSessions(policy, true);
    ApplyWinHttpProxyBypass(policy, true);
#else
    (void)policy;
#endif
}

}  // namespace st
