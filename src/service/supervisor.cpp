#include "service/service.h"

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
#include "core/proxy_bypass.h"
#include "core/status.h"
#include "core/util.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace st {
namespace {

std::atomic<bool> g_stop{false};
#ifdef _WIN32
HANDLE g_wake = nullptr;
HANDLE g_lock = INVALID_HANDLE_VALUE;
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_service_status{};
#endif
EngineHandle g_engine;
Policy g_policy;
std::string g_update_error;
std::string g_bind;
auto g_last_maintenance = std::chrono::steady_clock::now() - std::chrono::minutes(1);
auto g_next_update = std::chrono::system_clock::now();

void WriteState(const std::string& state, const std::string& detail) {
    Status status;
    status.state = state;
    status.detail = detail;
    status.updated_utc = NowUtcIso();
    status.policy_version = g_policy.version;
    status.update_error = g_update_error;
    status.engine_pid = g_engine.running() ? g_engine.pid : 0;
    WriteStatus(status);
}

bool Ipv4Only() { return FileExists(Ipv4OnlyFlagPath()); }

nlohmann::json OkJson(const nlohmann::json& extra = {}) {
    auto json = extra;
    json["ok"] = true;
    return json;
}

nlohmann::json ErrJson(const std::string& message) { return {{"ok", false}, {"error", message}}; }

nlohmann::json IpcDispatch(const nlohmann::json& request) {
    const auto cmd = request.value("cmd", "");
    try {
        if (cmd == "status") {
            auto status = ReadStatus();
            if (!status) {
                return ErrJson(status.error.message);
            }
            auto json = status.value.ToJson();
            json["ok"] = true;
            json["happ_hints"] = DetectHappHints();
            json["bind_interface"] = g_bind;
            return json;
        }
        if (cmd == "connect") {
            auto policy = LoadBundledPolicy(PolicyPath());
            if (!policy) {
                return ErrJson(policy.error.message);
            }
            if (auto err = SetGuards(policy.value)) {
                return ErrJson(err.message);
            }
            SetDesiredMode("connected");
#ifdef _WIN32
            if (g_wake) {
                SetEvent(g_wake);
            }
#endif
            return OkJson();
        }
        if (cmd == "block") {
            auto policy = LoadBundledPolicy(PolicyPath());
            if (policy) {
                SetGuards(policy.value);
            }
            SetDesiredMode("blocked");
            KillOwnEngine(EnginePath());
            StopEngineMemory(g_engine);
            ClearDnsCache();
#ifdef _WIN32
            if (g_wake) {
                SetEvent(g_wake);
            }
#endif
            return OkJson();
        }
        if (cmd == "refresh") {
            WriteTextAtomic(RefreshRequestPath(), "1");
#ifdef _WIN32
            if (g_wake) {
                SetEvent(g_wake);
            }
#endif
            return OkJson();
        }
        if (cmd == "verify") {
            auto result = VerifyEgress();
            if (!result) {
                return ErrJson(result.error.message);
            }
            return OkJson({{"verify", result.value}});
        }
        if (cmd == "save_profile") {
            auto incoming = Profile::FromJson(request.at("profile"));
            if (!incoming) {
                return ErrJson(incoming.error.message);
            }
            auto current = ReadConnection(ConnectionPath());
            if (incoming.value.password.empty() && current) {
                incoming.value.password = current.value.password;
            }
            auto policy = LoadBundledPolicy(PolicyPath());
            if (!policy) {
                return ErrJson(policy.error.message);
            }
            auto config = NewEngineConfig(incoming.value, policy.value, DataRoot(), DetectBindInterface(), Ipv4Only());
            if (auto err = TestEngineConfig(config, EnginePath())) {
                return ErrJson(err.message);
            }
            SetDesiredMode("blocked");
            KillOwnEngine(EnginePath());
            StopEngineMemory(g_engine);
            if (auto err = SaveConnection(incoming.value, ConnectionPath())) {
                return ErrJson(err.message);
            }
#ifdef _WIN32
            if (g_wake) {
                SetEvent(g_wake);
            }
#endif
            return OkJson({{"message", "Сохранено. Нажмите «Через прокси»."}});
        }
        if (cmd == "import_policy") {
            auto candidate = Policy::FromJson(request.at("policy"));
            if (!candidate) {
                return ErrJson(candidate.error.message);
            }
            auto current = LoadBundledPolicy(PolicyPath());
            if (!current) {
                return ErrJson(current.error.message);
            }
            if (candidate.value.version <= current.value.version) {
                return ErrJson("Increase the policy version before importing.");
            }
            auto merged = MergePolicies(current.value, candidate.value);
            auto profile = ReadConnection(ConnectionPath());
            if (!profile) {
                return ErrJson(profile.error.message);
            }
            auto config = NewEngineConfig(profile.value, merged, DataRoot(), DetectBindInterface(), Ipv4Only());
            if (auto err = TestEngineConfig(config, EnginePath())) {
                return ErrJson(err.message);
            }
            SetDesiredMode("blocked");
            KillOwnEngine(EnginePath());
            StopEngineMemory(g_engine);
            if (auto err = SetGuards(merged)) {
                return ErrJson(err.message);
            }
            WriteJsonAtomic(PolicyPath(), merged.ToJson());
            g_policy = merged;
#ifdef _WIN32
            if (g_wake) {
                SetEvent(g_wake);
            }
#endif
            return OkJson({{"message", "Список обновлён. Нажмите «Через прокси»."}});
        }
        return ErrJson("Unknown command.");
    } catch (const std::exception& ex) {
        return ErrJson(ex.what());
    }
}

void SupervisorLoop() {
#ifdef _WIN32
    g_wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_lock = CreateFileW(GuardLockPath().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_lock == INVALID_HANDLE_VALUE) {
        WriteTextAtomic(DataRoot() / "guard-error.txt",
                        "Supervisor startup failed. Check encrypted connection, installation and system network rules.");
        return;
    }
#endif
    auto profile = ReadConnection(ConnectionPath());
    auto policy = LoadBundledPolicy(PolicyPath());
    if (!profile || !policy) {
        WriteTextAtomic(DataRoot() / "guard-error.txt",
                        "Supervisor startup failed. Check encrypted connection, installation and system network rules.");
        return;
    }
    g_policy = policy.value;
    KillOwnEngine(EnginePath());
    SetGuards(g_policy);
    RemoveLegacyFakeIpRoutes();

#ifdef _WIN32
    std::thread pipe([&] { RunPipeServer(g_stop, IpcDispatch); });
#endif

    while (!g_stop) {
        try {
            auto desired = ReadDesiredMode();
            if (!desired) {
                throw std::runtime_error(desired.error.message);
            }
            if (desired.value == "blocked") {
                StopEngineMemory(g_engine);
                ApplyProxyBypass(g_policy);
                const auto now = std::chrono::steady_clock::now();
                if (now - g_last_maintenance > std::chrono::seconds(30)) {
                    SetGuards(g_policy, false);
                    g_last_maintenance = now;
                }
                WriteState("blocked", "Selected domains blocked. Other traffic stays direct.");
#ifdef _WIN32
                WaitForSingleObject(g_wake, 2000);
#endif
                continue;
            }
            const auto now = std::chrono::steady_clock::now();
            ApplyProxyBypass(g_policy);
            if (now - g_last_maintenance > std::chrono::seconds(30)) {
                SetGuards(g_policy, false);
                const auto bind = DetectBindInterface();
                if (!bind.empty() && bind != g_bind && g_engine.running()) {
                    StopEngineMemory(g_engine);
                }
                g_bind = bind;
                g_last_maintenance = now;
            }
            if (!g_engine.running()) {
                StopEngineMemory(g_engine);
                profile = ReadConnection(ConnectionPath());
                policy = LoadBundledPolicy(PolicyPath());
                if (!profile || !policy) {
                    throw std::runtime_error("Cannot read connection or policy.");
                }
                g_policy = policy.value;
                g_bind = DetectBindInterface();
                auto config = NewEngineConfig(profile.value, g_policy, DataRoot(), g_bind, Ipv4Only());
                if (auto err = TestEngineConfig(config, EnginePath())) {
                    throw std::runtime_error(err.message);
                }
                if (auto err = StartEngineMemory(config, EnginePath(), g_engine)) {
                    throw std::runtime_error(err.message);
                }
                SleepMs(2000);
                if (!g_engine.running()) {
                    throw std::runtime_error("Proxy engine could not start. Check local ports and network configuration.");
                }
                ClearDnsCache();
            }
            WriteState("running", "Engine running. Verify egress checks proxy access and the external IP.");

            const bool refresh = FileExists(RefreshRequestPath());
            if (refresh || std::chrono::system_clock::now() >= g_next_update) {
                if (refresh) {
                    std::error_code ec;
                    std::filesystem::remove(RefreshRequestPath(), ec);
                }
                g_next_update = std::chrono::system_clock::now() + std::chrono::hours(6);
                try {
                    if (profile.value.policy_url.empty()) {
                        g_update_error =
                            "No signed feed. DNS IPs refresh automatically; import domain rules locally.";
                    } else {
                        auto candidate = ReceivePolicy(profile.value, g_policy);
                        if (!candidate) {
                            throw std::runtime_error(candidate.error.message);
                        }
                        if (candidate.value.version > g_policy.version) {
                            auto config =
                                NewEngineConfig(profile.value, candidate.value, DataRoot(), g_bind, Ipv4Only());
                            TestEngineConfig(config, EnginePath());
                            StopEngineMemory(g_engine);
                            SetGuards(candidate.value);
                            WriteJsonAtomic(PolicyPath(), candidate.value.ToJson());
                            g_policy = candidate.value;
                        }
                        g_update_error.clear();
                    }
                } catch (...) {
                    g_update_error = "Rule update rejected or unavailable; previous policy retained.";
                    g_next_update = std::chrono::system_clock::now() + std::chrono::minutes(15);
                }
            }
        } catch (...) {
            StopEngineMemory(g_engine);
            WriteState("error", "Engine stopped safely. Check settings, local DNS port, Windows Firewall and routes.");
            SleepMs(5000);
        }
#ifdef _WIN32
        WaitForSingleObject(g_wake, 2000);
#else
        SleepMs(2000);
#endif
    }
    StopEngineMemory(g_engine);
#ifdef _WIN32
    if (pipe.joinable()) {
        // Unblock ConnectNamedPipe by opening the pipe once.
        HANDLE poke = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (poke != INVALID_HANDLE_VALUE) {
            CloseHandle(poke);
        }
        pipe.join();
    }
    if (g_lock != INVALID_HANDLE_VALUE) {
        CloseHandle(g_lock);
    }
    if (g_wake) {
        CloseHandle(g_wake);
    }
#endif
}

#ifdef _WIN32
void WINAPI ServiceCtrl(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        g_stop = true;
        if (g_wake) {
            SetEvent(g_wake);
        }
        g_service_status.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_status_handle, &g_service_status);
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerW(L"SelectiveTunnel", ServiceCtrl);
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_service_status.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_status_handle, &g_service_status);
    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_status_handle, &g_service_status);
    SupervisorLoop();
    g_service_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_status_handle, &g_service_status);
}
#endif

}  // namespace

int RunSupervisorConsole() {
    SupervisorLoop();
    return 0;
}

int RunService() {
#ifdef _WIN32
    SERVICE_TABLE_ENTRYW table[] = {{const_cast<LPWSTR>(L"SelectiveTunnel"), ServiceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return RunSupervisorConsole();
        }
        return 1;
    }
    return 0;
#else
    return RunSupervisorConsole();
#endif
}

}  // namespace st
