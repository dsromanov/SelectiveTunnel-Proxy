#include "paths.h"

#include "constants.h"
#include "utf.h"
#include "util.h"

#include <cstdlib>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#endif

namespace st {
namespace {

std::filesystem::path KnownFolder(int csidl, const char* env_name, const char* fallback) {
#ifdef _WIN32
    wchar_t buffer[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, buffer))) {
        return std::filesystem::path(buffer);
    }
#endif
    if (const char* value = std::getenv(env_name)) {
        return std::filesystem::path(value);
    }
    return std::filesystem::temp_directory_path() / fallback;
}

}  // namespace

std::filesystem::path ExeDir() {
#ifdef _WIN32
    wchar_t buffer[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    return std::filesystem::path(buffer).parent_path();
#else
    return std::filesystem::current_path();
#endif
}

std::filesystem::path PackageRoot() {
    const auto exe = ExeDir();
    if (FileExists(exe / "policy" / "domains.json")) {
        return exe;
    }
    if (FileExists(exe.parent_path() / "policy" / "domains.json")) {
        return exe.parent_path();
    }
    if (FileExists(exe.parent_path().parent_path() / "policy" / "domains.json")) {
        return exe.parent_path().parent_path();
    }
    return exe;
}

std::filesystem::path DataRoot() {
#ifdef _WIN32
    return KnownFolder(CSIDL_COMMON_APPDATA, "PROGRAMDATA", "SelectiveTunnel-data") / kAppName;
#else
    return std::filesystem::temp_directory_path() / "SelectiveTunnel-data";
#endif
}

std::filesystem::path AppRoot() {
#ifdef _WIN32
    return KnownFolder(CSIDL_PROGRAM_FILES, "PROGRAMFILES", "SelectiveTunnel-app") / kAppName;
#else
    return ExeDir();
#endif
}

std::filesystem::path EnginePath() { return AppRoot() / "bin" / "sing-box.exe"; }
std::filesystem::path WintunPath() { return AppRoot() / "bin" / "wintun.dll"; }
std::filesystem::path ConnectionPath() { return DataRoot() / "connection.dpapi"; }
std::filesystem::path PolicyPath() { return DataRoot() / "policy.json"; }
std::filesystem::path DesiredPath() { return DataRoot() / "desired.json"; }
std::filesystem::path StatusPath() { return DataRoot() / "status.json"; }
std::filesystem::path GuardLockPath() { return DataRoot() / "guard.lock"; }
std::filesystem::path RefreshRequestPath() { return DataRoot() / "refresh.request"; }
std::filesystem::path Ipv4OnlyFlagPath() { return DataRoot() / "tun-ipv4-only.flag"; }

std::filesystem::path DesktopFile(const std::string& name) {
#ifdef _WIN32
    wchar_t buffer[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT, buffer))) {
        return std::filesystem::path(buffer) / Utf8ToWide(name);
    }
#endif
    return std::filesystem::current_path() / name;
}

bool PathHasReparsePoint(const std::filesystem::path& path) {
#ifdef _WIN32
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) {
        return true;
    }
    WIN32_FIND_DATAW data{};
    const auto query = path / L"*";
    HANDLE find = FindFirstFileW(query.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }
    bool found = false;
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            found = true;
            break;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (PathHasReparsePoint(path / data.cFileName)) {
                found = true;
                break;
            }
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return found;
#else
    (void)path;
    return false;
#endif
}

Error ProtectDirectory(const std::filesystem::path& path) {
#ifdef _WIN32
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1,
                                                              &sd, nullptr)) {
        return Fail("Failed to restrict directory permissions.");
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    const DWORD status = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
                                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
                                               nullptr, dacl, nullptr);
    LocalFree(sd);
    if (status != ERROR_SUCCESS) {
        return Fail("Failed to restrict directory permissions.");
    }
    return Ok();
#else
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    return Ok();
#endif
}

}  // namespace st
