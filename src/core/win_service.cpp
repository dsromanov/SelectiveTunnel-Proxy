#include "win_service.h"

#include "constants.h"
#include "utf.h"
#include "util.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <oleauto.h>
#include <taskschd.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#endif

namespace st {

#ifdef _WIN32

Error InstallWindowsService(const std::filesystem::path& svc_exe) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        return Fail("Cannot open the service manager.");
    }
    std::wstring cmd = L"\"" + svc_exe.wstring() + L"\"";
    SC_HANDLE svc = CreateServiceW(scm, Utf8ToWide(kServiceName).c_str(), Utf8ToWide(kServiceDisplay).c_str(),
                                   SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                   SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        const DWORD err = GetLastError();
        CloseServiceHandle(scm);
        if (err == ERROR_SERVICE_EXISTS) {
            return Ok();
        }
        return Fail("Cannot register the SelectiveTunnel service.");
    }
    SERVICE_DESCRIPTIONW desc{};
    wchar_t text[] = L"Selective authenticated proxy; persistent guards remain when stopped.";
    desc.lpDescription = text;
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return Ok();
}

Error UninstallWindowsService() {
    StopWindowsService();
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return Fail("Cannot open the service manager.");
    }
    SC_HANDLE svc = OpenServiceW(scm, Utf8ToWide(kServiceName).c_str(), DELETE);
    if (!svc) {
        CloseServiceHandle(scm);
        return Ok();
    }
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return Ok();
}

Error StartWindowsService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return Fail("Cannot open the service manager.");
    }
    SC_HANDLE svc = OpenServiceW(scm, Utf8ToWide(kServiceName).c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return Fail("SelectiveTunnel service is not installed.");
    }
    StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return Ok();
}

Error StopWindowsService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return Fail("Cannot open the service manager.");
    }
    SC_HANDLE svc = OpenServiceW(scm, Utf8ToWide(kServiceName).c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return Ok();
    }
    SERVICE_STATUS status{};
    ControlService(svc, SERVICE_CONTROL_STOP, &status);
    for (int i = 0; i < 40; ++i) {
        if (!QueryServiceStatus(svc, &status) || status.dwCurrentState == SERVICE_STOPPED) {
            break;
        }
        SleepMs(250);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return Ok();
}

bool ServiceExists() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }
    SC_HANDLE svc = OpenServiceW(scm, Utf8ToWide(kServiceName).c_str(), SERVICE_QUERY_STATUS);
    const bool exists = svc != nullptr;
    if (svc) {
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return exists;
}

Error RemoveLegacyScheduledTask() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(hr);
    ITaskService* service = nullptr;
    Error err;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService,
                                reinterpret_cast<void**>(&service)))) {
        err = Ok();
    } else {
        VARIANT empty;
        VariantInit(&empty);
        if (SUCCEEDED(service->Connect(empty, empty, empty, empty))) {
            ITaskFolder* folder = nullptr;
            BSTR root = SysAllocString(L"\\");
            if (SUCCEEDED(service->GetFolder(root, &folder))) {
                BSTR task = SysAllocString(L"SelectiveTunnel");
                folder->DeleteTask(task, 0);
                SysFreeString(task);
                folder->Release();
            }
            SysFreeString(root);
        }
        service->Release();
    }
    if (uninit) {
        CoUninitialize();
    }
    return err;
}

#else

Error InstallWindowsService(const std::filesystem::path&) { return Fail("Windows only."); }
Error UninstallWindowsService() { return Fail("Windows only."); }
Error StartWindowsService() { return Fail("Windows only."); }
Error StopWindowsService() { return Fail("Windows only."); }
Error RemoveLegacyScheduledTask() { return Ok(); }
bool ServiceExists() { return false; }

#endif

}  // namespace st
