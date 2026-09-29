#include "control.h"

#include "json_io.h"
#include "paths.h"
#include "profile.h"
#include "utf.h"
#include "util.h"

#include <cstdlib>
#include <regex>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace st {
namespace {

Result<std::string> RunCurl(const std::vector<std::string>& extra) {
#ifdef _WIN32
    std::wstring cmd = L"\"" + Utf8ToWide(std::getenv("SystemRoot") ? std::getenv("SystemRoot") : "C:\\Windows") +
                       L"\\System32\\curl.exe\" --silent --show-error --fail --max-time 12";
    for (const auto& arg : extra) {
        cmd += L" ";
        cmd += Utf8ToWide(arg);
    }
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE out_r = nullptr, out_w = nullptr;
    CreatePipe(&out_r, &out_w, &sa, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(out_r);
        CloseHandle(out_w);
        return Result<std::string>::fail("Tunnel probe failed: curl is unavailable.");
    }
    CloseHandle(out_w);
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    std::string out;
    char chunk[512];
    DWORD read = 0;
    while (ReadFile(out_r, chunk, sizeof(chunk), &read, nullptr) && read) {
        out.append(chunk, read);
    }
    CloseHandle(out_r);
    if (code != 0) {
        return Result<std::string>::fail("Tunnel probe failed: " + out);
    }
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ')) {
        out.pop_back();
    }
    return Result<std::string>::ok(std::move(out));
#else
    (void)extra;
    return Result<std::string>::fail("Verify is only implemented on Windows.");
#endif
}

bool LooksLikeIpv4(const std::string& text) {
    static const std::regex re(R"(^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$)");
    return std::regex_match(text, re);
}

}  // namespace

Error SetDesiredMode(const std::string& mode) {
    if (mode != "connected" && mode != "blocked") {
        return Fail("Invalid desired state.");
    }
    return WriteJsonAtomic(DesiredPath(), nlohmann::json{{"mode", mode}});
}

Result<std::string> ReadDesiredMode() {
    auto json = ReadJsonFile(DesiredPath());
    if (!json) {
        return Result<std::string>::fail(json.error.message);
    }
    try {
        const auto mode = json.value.at("mode").get<std::string>();
        if (mode != "connected" && mode != "blocked") {
            return Result<std::string>::fail("Invalid desired state.");
        }
        return Result<std::string>::ok(mode);
    } catch (...) {
        return Result<std::string>::fail("Invalid desired state.");
    }
}

Result<std::string> VerifyEgress() {
    auto profile = ReadConnection(ConnectionPath());
    if (!profile) {
        return Result<std::string>::fail(profile.error.message);
    }
    auto proxied = RunCurl({"--noproxy", "no-bypass.invalid", "--socks5-hostname", "127.0.0.1:17891",
                            "https://api.ipify.org"});
    if (!proxied) {
        return proxied;
    }
    if (!LooksLikeIpv4(proxied.value)) {
        return Result<std::string>::fail("Proxy probe returned an invalid IP.");
    }
    if (!profile.value.expected_exit_ip.empty() && proxied.value != profile.value.expected_exit_ip) {
        return Result<std::string>::fail("Unexpected proxy egress: " + proxied.value + "; expected " +
                                         profile.value.expected_exit_ip + ".");
    }
    auto direct = RunCurl({"--noproxy", "*", "https://api.ipify.org"});
    if (!direct) {
        return Result<std::string>::fail("Direct probe failed: " + direct.error.message);
    }
    return Result<std::string>::ok("Proxy egress: " + proxied.value + "\nOrdinary direct egress: " + direct.value);
}

}  // namespace st
