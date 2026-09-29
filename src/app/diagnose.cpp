#include "app/commands.h"

#include "core/constants.h"
#include "core/engine.h"
#include "core/engine_config.h"
#include "core/guards.h"
#include "core/json_io.h"
#include "core/paths.h"
#include "core/policy.h"
#include "core/profile.h"
#include "core/sha256.h"
#include "core/status.h"
#include "core/utf.h"
#include "core/util.h"
#include "core/win_service.h"

#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace st {
namespace {

void Add(std::ostringstream& out, const std::string& text) { out << text << "\r\n"; }

#ifdef _WIN32
std::string FileLine(const std::filesystem::path& path, const std::string& label) {
    if (!FileExists(path)) {
        return label + " : MISSING";
    }
    return label + " : present; SHA256=" + Sha256FileHex(path);
}
#endif

}  // namespace

int RunDiagnose() {
#ifdef _WIN32
    if (!IsAdministrator()) {
        ElevateAndRerun(L"--diagnose");
        return 0;
    }
    const auto output = DesktopFile("SelectiveTunnel-Diagnostics.txt");
    std::ostringstream out;
    Add(out, "SelectiveTunnel diagnostics - read only; no passwords, profile contents or process command lines included.");
    Add(out, NowUtcIso());
    Add(out, std::string("Administrator: ") + (IsAdministrator() ? "true" : "false"));
    Add(out, "Version: " + std::string(kVersion));
    Add(out, "\r\n[Installed files]");
    Add(out, FileLine(AppRoot() / "SelectiveTunnel.exe", "SelectiveTunnel.exe"));
    Add(out, FileLine(AppRoot() / "SelectiveTunnelSvc.exe", "SelectiveTunnelSvc.exe"));
    Add(out, FileLine(EnginePath(), "bin\\sing-box.exe"));
    Add(out, FileLine(WintunPath(), "bin\\wintun.dll"));
    Add(out, "\r\n[Supervisor]");
    auto status = ReadStatus();
    if (status) {
        Add(out, "State=" + status.value.state + "; updated=" + status.value.updated_utc +
                     "; engine_pid=" + std::to_string(status.value.engine_pid) +
                     "; policy_version=" + std::to_string(status.value.policy_version));
    } else {
        Add(out, "status.json unavailable");
    }
    Add(out, std::string("Service installed: ") + (ServiceExists() ? "yes" : "no"));
    Add(out, "\r\n[Adapters / Happ]");
    const auto bind = DetectBindInterface();
    Add(out, "Physical bind interface: " + (bind.empty() ? "(none detected)" : bind));
    for (const auto& hint : DetectHappHints()) {
        Add(out, hint);
    }
    Add(out, "DNS listen: 127.0.0.53:53 (not 127.0.0.1, so Happ can keep localhost:53)");
    Add(out, std::string("FakeIP v4: ") + kFakeV4 + " (not 198.18.0.0/15)");
    Add(out, "\r\n[System proxy]");
#ifdef _WIN32
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0,
                          KEY_READ, &key) == ERROR_SUCCESS) {
            DWORD enable = 0, size = sizeof(enable), type = 0;
            if (RegQueryValueExW(key, L"ProxyEnable", nullptr, &type, reinterpret_cast<LPBYTE>(&enable), &size) ==
                ERROR_SUCCESS) {
                Add(out, std::string("ProxyEnable=") + (enable ? "1" : "0"));
            }
            wchar_t buf[1024]{};
            size = sizeof(buf);
            if (RegQueryValueExW(key, L"ProxyServer", nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
                ERROR_SUCCESS) {
                Add(out, "ProxyServer=" + WideToUtf8(buf));
            }
            buf[0] = 0;
            size = sizeof(buf);
            if (RegQueryValueExW(key, L"ProxyOverride", nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
                ERROR_SUCCESS) {
                Add(out, "ProxyOverride=" + WideToUtf8(buf));
            }
            buf[0] = 0;
            size = sizeof(buf);
            if (RegQueryValueExW(key, L"AutoConfigURL", nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
                ERROR_SUCCESS &&
                buf[0]) {
                Add(out, "AutoConfigURL is set; PAC can ignore ProxyOverride. Prefer Happ Proxy without PAC.");
            }
            RegCloseKey(key);
        } else {
            Add(out, "Internet Settings key unavailable");
        }
        HKEY env = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ, &env) == ERROR_SUCCESS) {
            wchar_t noproxy[1024]{};
            DWORD nsize = sizeof(noproxy);
            DWORD ntype = 0;
            if (RegQueryValueExW(env, L"NO_PROXY", nullptr, &ntype, reinterpret_cast<LPBYTE>(noproxy), &nsize) ==
                    ERROR_SUCCESS ||
                RegQueryValueExW(env, L"no_proxy", nullptr, &ntype, reinterpret_cast<LPBYTE>(noproxy), &nsize) ==
                    ERROR_SUCCESS) {
                Add(out, "NO_PROXY=" + WideToUtf8(noproxy));
            }
            RegCloseKey(env);
        }
    }
#endif
    Add(out, "\r\n[Encrypted profile and engine config]");
    auto profile = ReadConnection(ConnectionPath());
    if (!profile) {
        Add(out, "Profile decrypt/validation: FAILED. Enter proxy credentials in Settings on THIS PC; do not copy connection.dpapi between PCs.");
    } else {
        Add(out, "Profile decrypt/validation: OK");
        try {
            auto policy = LoadBundledPolicy(PolicyPath());
            if (!policy) {
                Add(out, "Engine config check: FAILED (raw error withheld to protect credentials).");
            } else {
                auto config = NewEngineConfig(profile.value, policy.value, DataRoot(), bind, FileExists(Ipv4OnlyFlagPath()));
                if (auto err = TestEngineConfig(config, EnginePath())) {
                    Add(out, "Engine config check: FAILED (raw error withheld to protect credentials).");
                } else {
                    Add(out, "Engine config check: OK");
                }
            }
        } catch (...) {
            Add(out, "Engine config check: FAILED (raw error withheld to protect credentials).");
        }
    }
    WriteTextAtomic(output, out.str());
    ShellExecuteW(nullptr, L"open", L"notepad.exe", output.c_str(), nullptr, SW_SHOWNORMAL);
    return 0;
#else
    return 1;
#endif
}

int RunStartupProbe() {
#ifdef _WIN32
    if (!IsAdministrator()) {
        ElevateAndRerun(L"--diagnose-startup");
        return 0;
    }
    const auto output = DesktopFile("SelectiveTunnel-Startup.txt");
    std::ostringstream out;
    Add(out, "SelectiveTunnel startup probe " + NowUtcIso());
    try {
        auto profile = ReadConnection(ConnectionPath());
        auto policy = LoadBundledPolicy(PolicyPath());
        if (!profile || !policy) {
            throw std::runtime_error("Cannot read profile/policy.");
        }
        auto config = NewEngineConfig(profile.value, policy.value, DataRoot(), DetectBindInterface(),
                                      FileExists(Ipv4OnlyFlagPath()));
        if (auto err = TestEngineConfig(config, EnginePath())) {
            throw std::runtime_error("Configuration check failed.");
        }
        Add(out, "Configuration check: OK");
        StopWindowsService();
        KillOwnEngine(EnginePath());
        SleepMs(2000);
        config["log"] = {{"level", "error"}, {"timestamp", false}};
        EngineHandle handle;
        StartEngineMemory(config, EnginePath(), handle);
        SleepMs(6000);
        if (!handle.running()) {
            Add(out, "Engine exited during startup. Credentials were not written to a file.");
        } else {
            Add(out, "Engine stayed running during the probe.");
            StopEngineMemory(handle);
        }
        StartWindowsService();
        Add(out, "Supervisor restarted.");
    } catch (const std::exception& ex) {
        Add(out, std::string("Probe failed: ") + ex.what());
        StartWindowsService();
    }
    WriteTextAtomic(output, out.str());
    ShellExecuteW(nullptr, L"open", L"notepad.exe", output.c_str(), nullptr, SW_SHOWNORMAL);
    return 0;
#else
    return 1;
#endif
}

}  // namespace st
