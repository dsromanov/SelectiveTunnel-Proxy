#include "app/commands.h"
#include "app/settings.h"

#include "core/constants.h"
#include "core/control.h"
#include "core/engine.h"
#include "core/engine_config.h"
#include "core/guards.h"
#include "core/ipc.h"
#include "core/json_io.h"
#include "core/paths.h"
#include "core/policy.h"
#include "core/profile.h"
#include "core/sha256.h"
#include "core/status.h"
#include "core/utf.h"
#include "core/util.h"
#include "core/win_service.h"

#include <fstream>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <objbase.h>
#include <objidl.h>
#include <shlguid.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")
#endif

namespace st {
namespace {

void LogLine(std::vector<std::string>& lines, const std::string& text) { lines.push_back(text); }

#ifdef _WIN32

std::filesystem::path KnownFolderPath() {
    wchar_t buffer[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_COMMON_PROGRAMS, nullptr, SHGFP_TYPE_CURRENT, buffer);
    return buffer;
}

Error RunHidden(const std::wstring& cmd, const std::filesystem::path& cwd = {}) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    const wchar_t* dir = cwd.empty() ? nullptr : cwd.c_str();
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, dir, &si, &pi)) {
        return Fail("Cannot run: " + WideToUtf8(cmd));
    }
    WaitForSingleObject(pi.hProcess, 180000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (code != 0) {
        return Fail("Command failed.");
    }
    return Ok();
}

bool PortBusy(const char* ip, int port, int type) {
    SOCKET s = socket(AF_INET, type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    InetPtonA(AF_INET, ip, &addr.sin_addr);
    const int rc = bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    closesocket(s);
    return rc != 0;
}

Error AssertPortsFree() {
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (PortBusy(kDnsListen, kDnsPort, SOCK_DGRAM) || PortBusy(kDnsListen, kDnsPort, SOCK_STREAM)) {
        return Fail("Port 53 on 127.0.0.53 is already in use. Local DNS software must be reconfigured first.");
    }
    if (PortBusy(kDiagListen, kDiagPort, SOCK_STREAM)) {
        return Fail("Diagnostic port 17891 is already in use.");
    }
    return Ok();
}

Error AssertNoConflictingRoutes() {
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR) {
        return Ok();
    }
    const char* prefixes[] = {kFakeV4, kFakeV4a, kFakeV4b, kTunV4Net};
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        auto& row = table->Table[i];
        char ip[64]{};
        InetNtopA(AF_INET, &row.DestinationPrefix.Prefix.Ipv4.sin_addr, ip, sizeof(ip));
        const std::string got = std::string(ip) + "/" + std::to_string(row.DestinationPrefix.PrefixLength);
        for (const char* prefix : prefixes) {
            if (got == prefix && row.Metric != kGuardMetric) {
                FreeMibTable(table);
                return Fail(std::string("Reserved address range already has a route: ") + prefix);
            }
        }
    }
    FreeMibTable(table);
    return Ok();
}

Error HttpDownload(const std::string& url, const std::filesystem::path& dest) {
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256]{}, path[2048]{};
    parts.lpszHostName = host;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 2048;
    auto wurl = Utf8ToWide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &parts)) {
        return Fail("Dependency download failed. File: " + PathUtf8(dest.filename()));
    }
    HINTERNET session = WinHttpOpen(L"SelectiveTunnel/2.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        return Fail("Dependency download failed. File: " + PathUtf8(dest.filename()));
    }
    WinHttpSetTimeouts(session, 20000, 20000, 20000, 120000);
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 |
                      WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    WinHttpSetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    INTERNET_PORT port = parts.nPort ? parts.nPort : (parts.nScheme == INTERNET_SCHEME_HTTPS ? 443 : 80);
    HINTERNET connect = WinHttpConnect(session, host, port, 0);
    HINTERNET request = connect ? WinHttpOpenRequest(connect, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                     parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0)
                                : nullptr;
    DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    if (request) {
        WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect));
    }
    if (!request || !WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        if (request) {
            WinHttpCloseHandle(request);
        }
        if (connect) {
            WinHttpCloseHandle(connect);
        }
        WinHttpCloseHandle(session);
        return Fail("Dependency download failed. File: " + PathUtf8(dest.filename()) +
                    ". Check network or copy the official zip into dependencies\\.");
    }
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                        &status, &status_size, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return Fail("Dependency download HTTP " + std::to_string(status) + ". File: " + PathUtf8(dest.filename()));
    }
    HANDLE file = CreateFileW(dest.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return Fail("Cannot write download: " + PathUtf8(dest));
    }
    std::vector<char> chunk(64 * 1024);
    DWORD read = 0;
    std::uint64_t total = 0;
    while (WinHttpReadData(request, chunk.data(), static_cast<DWORD>(chunk.size()), &read) && read > 0) {
        DWORD written = 0;
        if (!WriteFile(file, chunk.data(), read, &written, nullptr) || written != read) {
            CloseHandle(file);
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);
            return Fail("Cannot write download: " + PathUtf8(dest.filename()));
        }
        total += read;
        read = 0;
    }
    CloseHandle(file);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (total < 1024) {
        return Fail("Downloaded file is too small. File: " + PathUtf8(dest.filename()));
    }
    return Ok();
}

Error DownloadOrCopy(const std::filesystem::path& bundled, const std::vector<std::string>& urls, const std::string& hash,
                     const std::filesystem::path& target) {
    if (FileExists(target) && Sha256Equals(Sha256FileHex(target), hash)) {
        return Ok();
    }
    std::error_code ec;
    std::filesystem::remove(target, ec);
    std::filesystem::create_directories(target.parent_path(), ec);
    if (FileExists(bundled)) {
        if (!Sha256Equals(Sha256FileHex(bundled), hash)) {
            return Fail("Bundled dependency SHA256 mismatch. File: " + PathUtf8(bundled.filename()));
        }
        std::filesystem::copy_file(bundled, target, std::filesystem::copy_options::overwrite_existing, ec);
        return Ok();
    }
#ifdef _WIN32
    auto part = target;
    part += L".part";
    Error last = Fail("Dependency download failed. File: " + PathUtf8(target.filename()));
    for (const auto& url : urls) {
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::filesystem::remove(part, ec);
            last = HttpDownload(url, part);
            if (last) {
                continue;
            }
            if (Sha256Equals(Sha256FileHex(part), hash)) {
                std::filesystem::rename(part, target, ec);
                if (ec) {
                    std::filesystem::copy_file(part, target, std::filesystem::copy_options::overwrite_existing, ec);
                    std::filesystem::remove(part, ec);
                }
                return Ok();
            }
            last = Fail("Downloaded dependency SHA256 mismatch. File: " + PathUtf8(target.filename()) +
                        "; size=" + std::to_string(FileSize(part)) +
                        ". Copy the official zip into the installer dependencies folder.");
            std::filesystem::remove(part, ec);
        }
    }
    return last;
#else
    (void)urls;
    return Fail("Bundled dependency missing: " + PathUtf8(bundled));
#endif
}

std::filesystem::path FindFile(const std::filesystem::path& root, const std::string& name) {
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(root, ec);
         it != std::filesystem::recursive_directory_iterator(); ++it) {
        if (it->path().filename() == name) {
            return it->path();
        }
    }
    return {};
}

Error ExtractZip(const std::filesystem::path& zip, const std::filesystem::path& dest) {
    std::error_code ec;
    std::filesystem::create_directories(dest, ec);
    std::wstring cmd = L"tar.exe -xf \"" + zip.wstring() + L"\" -C \"" + dest.wstring() + L"\"";
    return RunHidden(cmd);
}

Error CreateRunasShortcut() {
    const auto link = std::filesystem::path(KnownFolderPath()) / L"SelectiveTunnel.lnk";
    IShellLinkW* sl = nullptr;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                reinterpret_cast<void**>(&sl)))) {
        return Fail("Cannot create Start Menu shortcut.");
    }
    const auto target = AppRoot() / "SelectiveTunnel.exe";
    sl->SetPath(target.c_str());
    sl->SetWorkingDirectory(AppRoot().c_str());
    sl->SetDescription(L"SelectiveTunnel");
    IPersistFile* pf = nullptr;
    sl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf));
    pf->Save(link.c_str(), TRUE);
    pf->Release();
    sl->Release();
    auto bytes = ReadBytes(link);
    if (bytes && bytes.value.size() > 0x15) {
        bytes.value[0x15] = static_cast<std::uint8_t>(bytes.value[0x15] | 0x20);
        WriteBytesAtomic(link, bytes.value.data(), bytes.value.size());
    }
    return Ok();
}

Error CopySelf() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    const auto src_dir = std::filesystem::path(path).parent_path();
    std::error_code ec;
    std::filesystem::create_directories(AppRoot(), ec);
    std::filesystem::create_directories(AppRoot() / "bin", ec);
    std::filesystem::copy_file(path, AppRoot() / "SelectiveTunnel.exe", std::filesystem::copy_options::overwrite_existing,
                               ec);
    const auto svc_src = FileExists(src_dir / "SelectiveTunnelSvc.exe") ? src_dir / "SelectiveTunnelSvc.exe"
                                                                       : src_dir / "SelectiveTunnelSvc.exe";
    if (FileExists(src_dir / "SelectiveTunnelSvc.exe")) {
        std::filesystem::copy_file(src_dir / "SelectiveTunnelSvc.exe", AppRoot() / "SelectiveTunnelSvc.exe",
                                   std::filesystem::copy_options::overwrite_existing, ec);
    }
    return Ok();
}

void OpenReport(const std::filesystem::path& path) {
    ShellExecuteW(nullptr, L"open", L"notepad.exe", path.c_str(), nullptr, SW_SHOWNORMAL);
}

#endif

}  // namespace

#ifdef _WIN32

int RunInstall(bool resume) {
    if (!IsAdministrator()) {
        ElevateAndRerun(resume ? L"--install --resume" : L"--install");
        return 0;
    }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    std::vector<std::string> lines;
    try {
        SYSTEM_INFO info{};
        GetNativeSystemInfo(&info);
        if (info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
            throw std::runtime_error("Use 64-bit Windows 10/11.");
        }
        if (auto err = ProtectDirectory(DataRoot())) {
            throw std::runtime_error(err.message);
        }
        if (auto err = ProtectDirectory(AppRoot())) {
            throw std::runtime_error(err.message);
        }
        if (PathHasReparsePoint(DataRoot()) || PathHasReparsePoint(AppRoot())) {
            throw std::runtime_error("Unexpected reparse point in partial installation.");
        }
        const bool configured = FileExists(ConnectionPath()) || FileExists(PolicyPath()) || ServiceExists();
        if (configured && !FileExists(AppRoot() / "SelectiveTunnel.exe")) {
            // 1.1.0 or interrupted 2.0 with profile: migrate, keep secrets.
        } else if (configured && FileExists(AppRoot() / "SelectiveTunnel.exe") && !resume) {
            throw std::runtime_error("A configured client already exists. Use Update.cmd.");
        }
        if (auto err = AssertPortsFree()) {
            throw std::runtime_error(err.message);
        }
        if (auto err = AssertNoConflictingRoutes()) {
            throw std::runtime_error(err.message);
        }
        const auto pkg = PackageRoot();
        const auto download = DataRoot() / "download";
        if (auto err = DownloadOrCopy(pkg / "dependencies" / kSingBoxZipName, {kSingBoxUrl}, kSingBoxSha256,
                                      download / "engine.zip")) {
            throw std::runtime_error(err.message);
        }
        if (auto err = DownloadOrCopy(pkg / "dependencies" / kWintunZipName, {kWintunUrl}, kWintunSha256,
                                      download / "wintun.zip")) {
            throw std::runtime_error(err.message);
        }
        Profile profile;
        bool have_profile = FileExists(ConnectionPath());
        if (have_profile) {
            auto existing = ReadConnection(ConnectionPath());
            if (existing) {
                profile = existing.value;
            } else {
                have_profile = false;
            }
        }
        if (!have_profile) {
            auto edited = ShowProxySettings(nullptr, &profile);
            if (!edited) {
                MessageBoxW(nullptr,
                            L"Setup cancelled. Cached downloads retained; use Resume-Install.cmd to continue.",
                            L"SelectiveTunnel", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            profile = edited.value;
        }
        if (auto err = ExtractZip(download / "engine.zip", download / "engine")) {
            throw std::runtime_error(err.message);
        }
        if (auto err = ExtractZip(download / "wintun.zip", download / "wintun")) {
            throw std::runtime_error(err.message);
        }
        const auto box = FindFile(download / "engine", "sing-box.exe");
        const auto wintun = FindFile(download / "wintun", "wintun.dll");
        if (box.empty() || wintun.empty()) {
            throw std::runtime_error("Extracted dependencies are incomplete.");
        }
        std::error_code ec;
        std::filesystem::create_directories(AppRoot() / "bin", ec);
        std::filesystem::copy_file(box, EnginePath(), std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::copy_file(wintun, WintunPath(), std::filesystem::copy_options::overwrite_existing, ec);
        CopySelf();
        auto policy_path = pkg / "policy" / "domains.json";
        auto policy = LoadBundledPolicy(policy_path);
        if (!policy) {
            throw std::runtime_error(policy.error.message);
        }
        if (auto err = SaveConnection(profile, ConnectionPath())) {
            throw std::runtime_error(err.message);
        }
        WriteJsonAtomic(PolicyPath(), policy.value.ToJson());
        SetDesiredMode("connected");
        WriteTextAtomic(Ipv4OnlyFlagPath(), "1");
        auto config = NewEngineConfig(profile, policy.value, DataRoot(), DetectBindInterface(), true);
        if (auto err = TestEngineConfig(config, EnginePath())) {
            throw std::runtime_error(err.message);
        }
        RemoveLegacyScheduledTask();
        RemoveLegacyFakeIpRoutes();
        if (auto err = SetGuards(policy.value)) {
            throw std::runtime_error(err.message);
        }
        ClearDnsCache();
        if (auto err = InstallWindowsService(AppRoot() / "SelectiveTunnelSvc.exe")) {
            throw std::runtime_error(err.message);
        }
        CreateRunasShortcut();
        StartWindowsService();
        MessageBoxW(nullptr,
                    L"Installed. Reboot before opening browsers and Figma/ChatGPT.\nThen open SelectiveTunnel from Start and run Verify IP.\nHapp can run in parallel (Proxy mode preferred).",
                    L"SelectiveTunnel 2.0", MB_OK | MB_ICONINFORMATION);
        return 0;
    } catch (const std::exception& ex) {
        MessageBoxW(nullptr, Utf8ToWide(std::string(ex.what()) + "\nInspect ProgramData\\SelectiveTunnel; run --uninstall to restore direct access.").c_str(),
                    L"SelectiveTunnel", MB_OK | MB_ICONERROR);
        return 1;
    }
}

int RunUninstall() {
    if (!IsAdministrator()) {
        ElevateAndRerun(L"--uninstall");
        return 0;
    }
    try {
        if (PathHasReparsePoint(DataRoot()) || PathHasReparsePoint(AppRoot())) {
            throw std::runtime_error("Refusing to remove a directory containing reparse points.");
        }
        SetDesiredMode("blocked");
        StopWindowsService();
        UninstallWindowsService();
        KillOwnEngine(EnginePath());
        RemoveGuards();
        RemoveLegacyScheduledTask();
        const auto link = KnownFolderPath() / L"SelectiveTunnel.lnk";
        std::error_code ec;
        std::filesystem::remove(link, ec);
        std::filesystem::remove_all(AppRoot(), ec);
        std::filesystem::remove_all(DataRoot(), ec);
        MessageBoxW(nullptr,
                    L"Uninstalled. Selected services now use direct access. Restart browsers to discard cached fake addresses.",
                    L"SelectiveTunnel", MB_OK | MB_ICONINFORMATION);
        return 0;
    } catch (const std::exception& ex) {
        MessageBoxW(nullptr, Utf8ToWide(ex.what()).c_str(), L"SelectiveTunnel", MB_OK | MB_ICONERROR);
        return 1;
    }
}

int RunUpdate() {
    if (!IsAdministrator()) {
        ElevateAndRerun(L"--update");
        return 0;
    }
    const auto report = DesktopFile("SelectiveTunnel-Update.txt");
    std::vector<std::string> lines;
    bool success = false;
    bool changed = false;
    std::filesystem::path backup;
    try {
        if (PathHasReparsePoint(DataRoot()) || PathHasReparsePoint(AppRoot())) {
            throw std::runtime_error("Unexpected reparse point. Update cancelled.");
        }
        auto profile = ReadConnection(ConnectionPath());
        auto policy = LoadBundledPolicy(PolicyPath());
        auto desired = ReadDesiredMode();
        if (!profile || !policy || !desired) {
            throw std::runtime_error("Cannot read the existing profile.");
        }
        backup = DataRoot() / "updates" / RandomHex(8);
        std::error_code ec;
        std::filesystem::create_directories(backup, ec);
        std::filesystem::copy_file(AppRoot() / "SelectiveTunnel.exe", backup / "SelectiveTunnel.exe",
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (FileExists(AppRoot() / "SelectiveTunnelSvc.exe")) {
            std::filesystem::copy_file(AppRoot() / "SelectiveTunnelSvc.exe", backup / "SelectiveTunnelSvc.exe",
                                       std::filesystem::copy_options::overwrite_existing, ec);
        }
        auto config = NewEngineConfig(profile.value, policy.value, DataRoot(), DetectBindInterface(), true);
        if (auto err = TestEngineConfig(config, EnginePath())) {
            throw std::runtime_error(err.message);
        }
        StopWindowsService();
        KillOwnEngine(EnginePath());
        changed = true;
        CopySelf();
        WriteTextAtomic(Ipv4OnlyFlagPath(), "1");
        RemoveLegacyFakeIpRoutes();
        RemoveLegacyScheduledTask();
        InstallWindowsService(AppRoot() / "SelectiveTunnelSvc.exe");
        ClearDnsCache();
        StartWindowsService();
        const auto started = NowUtcIso();
        for (int i = 0; i < 25; ++i) {
            SleepMs(1000);
            auto status = ReadStatus();
            const auto expected = desired.value == "blocked" ? "blocked" : "running";
            if (status && status.value.state == expected && status.value.updated_utc >= started) {
                success = true;
                break;
            }
        }
        if (!success) {
            throw std::runtime_error("Updated supervisor did not become ready.");
        }
        lines.emplace_back("SelectiveTunnel 2.0.0 updated successfully. Proxy credentials, domain rules and connection mode preserved.");
        lines.emplace_back("IPv4 tunnel mode enabled. Happ can keep running in parallel.");
        if (desired.value == "connected") {
            auto verify = VerifyEgress();
            lines.emplace_back(verify ? verify.value : "Client started, but IP verification failed. Run Diagnose.cmd.");
        } else {
            lines.emplace_back("Client remains blocked as before the update. Press Connect when ready.");
        }
    } catch (const std::exception& ex) {
        lines.emplace_back(std::string("Update failed: ") + ex.what());
        if (changed && !success && !backup.empty()) {
            try {
                StopWindowsService();
                KillOwnEngine(EnginePath());
                std::error_code ec;
                std::filesystem::copy_file(backup / "SelectiveTunnel.exe", AppRoot() / "SelectiveTunnel.exe",
                                           std::filesystem::copy_options::overwrite_existing, ec);
                if (FileExists(backup / "SelectiveTunnelSvc.exe")) {
                    std::filesystem::copy_file(backup / "SelectiveTunnelSvc.exe", AppRoot() / "SelectiveTunnelSvc.exe",
                                               std::filesystem::copy_options::overwrite_existing, ec);
                }
                lines.emplace_back("Previous program files restored.");
            } catch (...) {
                lines.emplace_back("Rollback incomplete. Backup retained in ProgramData/SelectiveTunnel/updates.");
            }
        }
        StartWindowsService();
    }
    std::string text;
    for (const auto& line : lines) {
        text += line + "\r\n";
    }
    WriteTextAtomic(report, text);
    OpenReport(report);
    return success ? 0 : 1;
}

#else

int RunInstall(bool) { return 1; }
int RunUninstall() { return 1; }
int RunUpdate() { return 1; }

#endif

int RunControl(const std::string& action) {
#ifdef _WIN32
    if (!IsAdministrator()) {
        ElevateAndRerun(Utf8ToWide("--control " + action));
        return 0;
    }
    nlohmann::json request = {{"cmd", ToLowerAscii(action)}};
    nlohmann::json response;
    StartWindowsService();
    if (auto err = SendIpc(request, response)) {
        MessageBoxW(nullptr, Utf8ToWide(err.message).c_str(), L"SelectiveTunnel", MB_OK | MB_ICONERROR);
        return 1;
    }
    if (!response.value("ok", false)) {
        MessageBoxW(nullptr, Utf8ToWide(response.value("error", "error")).c_str(), L"SelectiveTunnel", MB_OK | MB_ICONERROR);
        return 1;
    }
    if (response.contains("verify")) {
        MessageBoxW(nullptr, Utf8ToWide(response["verify"].get<std::string>()).c_str(), L"Egress verification", MB_OK);
    }
    return 0;
#else
    (void)action;
    return 1;
#endif
}

}  // namespace st
