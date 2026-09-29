#include "engine.h"

#include "util.h"

#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace st {

bool EngineHandle::running() const {
#ifdef _WIN32
    if (!process) {
        return false;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(static_cast<HANDLE>(process), &code)) {
        return false;
    }
    return code == STILL_ACTIVE;
#else
    return false;
#endif
}

void StopEngineMemory(EngineHandle& handle) {
#ifdef _WIN32
    if (handle.process) {
        const auto proc = static_cast<HANDLE>(handle.process);
        if (handle.running()) {
            TerminateProcess(proc, 1);
            WaitForSingleObject(proc, 5000);
        }
        CloseHandle(proc);
        handle.process = nullptr;
    }
    if (handle.job) {
        CloseHandle(static_cast<HANDLE>(handle.job));
        handle.job = nullptr;
    }
    handle.pid = 0;
#else
    handle = {};
#endif
}

void KillOwnEngine(const std::filesystem::path& engine) {
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const auto want = engine.filename().wstring();
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, want.c_str()) != 0) {
                continue;
            }
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
            if (!proc) {
                continue;
            }
            wchar_t path[MAX_PATH]{};
            DWORD size = MAX_PATH;
            const bool match = QueryFullProcessImageNameW(proc, 0, path, &size) && _wcsicmp(path, engine.c_str()) == 0;
            if (match) {
                TerminateProcess(proc, 1);
            }
            CloseHandle(proc);
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
#else
    (void)engine;
#endif
}

Error StartEngineMemory(const nlohmann::json& config, const std::filesystem::path& engine, EngineHandle& handle,
                        const std::string& mode) {
    StopEngineMemory(handle);
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE in_r = nullptr, in_w = nullptr, out_r = nullptr, out_w = nullptr, err_r = nullptr, err_w = nullptr;
    if (!CreatePipe(&in_r, &in_w, &sa, 0) || !CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&err_r, &err_w, &sa, 0)) {
        return Fail("Could not start the proxy engine. No credentials were written to disk.");
    }
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = in_r;
    si.hStdOutput = out_w;
    si.hStdError = err_w;
    PROCESS_INFORMATION pi{};
    auto cmd = L"\"" + engine.wstring() + L"\" " + std::wstring(mode.begin(), mode.end()) + L" -c stdin";
    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(0);
    const auto dir = engine.parent_path().wstring();
    const BOOL started =
        CreateProcessW(engine.c_str(), cmd_buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                       nullptr, dir.c_str(), &si, &pi);
    CloseHandle(in_r);
    CloseHandle(out_w);
    CloseHandle(err_w);
    if (!started) {
        CloseHandle(in_w);
        CloseHandle(out_r);
        CloseHandle(err_r);
        return Fail("Could not start the proxy engine. No credentials were written to disk.");
    }

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    auto json = config.dump();
    DWORD written = 0;
    const BOOL wrote = WriteFile(in_w, json.data(), static_cast<DWORD>(json.size()), &written, nullptr);
    SecureClear(json);
    CloseHandle(in_w);
    CloseHandle(out_r);
    CloseHandle(err_r);
    if (!wrote) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(job);
        return Fail("Could not start the proxy engine. No credentials were written to disk.");
    }
    handle.process = pi.hProcess;
    handle.job = job;
    handle.pid = pi.dwProcessId;
    return Ok();
#else
    (void)config;
    (void)engine;
    (void)mode;
    return Fail("Engine launch is only implemented on Windows.");
#endif
}

Error TestEngineConfig(const nlohmann::json& config, const std::filesystem::path& engine) {
    EngineHandle handle;
    if (auto err = StartEngineMemory(config, engine, handle, "check")) {
        return err;
    }
#ifdef _WIN32
    const DWORD wait = WaitForSingleObject(static_cast<HANDLE>(handle.process), 15000);
    DWORD code = 1;
    GetExitCodeProcess(static_cast<HANDLE>(handle.process), &code);
    StopEngineMemory(handle);
    if (wait != WAIT_OBJECT_0) {
        return Fail("Engine configuration check timed out.");
    }
    if (code != 0) {
        return Fail("Engine rejected proxy settings. Check host, port, protocol and credentials format.");
    }
    return Ok();
#else
    StopEngineMemory(handle);
    return Fail("Engine check is only implemented on Windows.");
#endif
}

}  // namespace st
