#include "ipc.h"

#include "constants.h"
#include "utf.h"

#include <atomic>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#endif

#include <vector>

namespace st {

#ifdef _WIN32

namespace {

HANDLE CreateSecurePipe() {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd,
                                                              nullptr)) {
        return INVALID_HANDLE_VALUE;
    }
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    HANDLE pipe = CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                   1, 65536, 65536, 0, &sa);
    LocalFree(sd);
    return pipe;
}

bool ReadMessage(HANDLE pipe, std::string& out, unsigned timeout_ms) {
    DWORD available = 0;
    const DWORD start = GetTickCount();
    while (true) {
        if (GetTickCount() - start > timeout_ms) {
            return false;
        }
        DWORD read = 0;
        char buf[4096];
        if (!ReadFile(pipe, buf, sizeof(buf), &read, nullptr)) {
            const DWORD err = GetLastError();
            if (err == ERROR_MORE_DATA) {
                out.append(buf, read);
                continue;
            }
            return false;
        }
        out.append(buf, read);
        return true;
    }
}

}  // namespace

Error SendIpc(const nlohmann::json& request, nlohmann::json& response, unsigned timeout_ms) {
    const auto payload = request.dump();
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return Fail("Background service is not running.");
    }
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
    DWORD written = 0;
    if (!WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr)) {
        CloseHandle(pipe);
        return Fail("Cannot send command to the service.");
    }
    std::string raw;
    if (!ReadMessage(pipe, raw, timeout_ms)) {
        CloseHandle(pipe);
        return Fail("Service did not answer.");
    }
    CloseHandle(pipe);
    try {
        response = nlohmann::json::parse(raw);
        return Ok();
    } catch (...) {
        return Fail("Invalid service response.");
    }
}

void RunPipeServer(std::atomic<bool>& stop, IpcHandler handler) {
    while (!stop) {
        HANDLE pipe = CreateSecurePipe();
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(500);
            continue;
        }
        const BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : GetLastError() == ERROR_PIPE_CONNECTED;
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }
        std::string raw;
        if (ReadMessage(pipe, raw, 30000)) {
            nlohmann::json request = nlohmann::json::object();
            try {
                request = nlohmann::json::parse(raw);
            } catch (...) {
                request = {{"cmd", ""}};
            }
            auto response = handler(request);
            const auto text = response.dump();
            DWORD written = 0;
            WriteFile(pipe, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        }
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
}

#else

Error SendIpc(const nlohmann::json&, nlohmann::json&, unsigned) { return Fail("IPC is only implemented on Windows."); }
void RunPipeServer(std::atomic<bool>&, IpcHandler) {}

#endif

}  // namespace st
