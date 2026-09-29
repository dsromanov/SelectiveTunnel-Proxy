#include "util.h"

#include "utf.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>
#else
#include <unistd.h>
#endif

namespace st {
namespace {

#ifdef _WIN32
using DnsFlushFn = void(WINAPI*)();
#endif

}  // namespace

void SecureClear(std::string& value) {
    if (!value.empty()) {
        volatile char* p = value.data();
        for (std::size_t i = 0; i < value.size(); ++i) {
            p[i] = 0;
        }
        value.clear();
    }
}

void SecureClear(std::vector<std::uint8_t>& value) {
    if (!value.empty()) {
        volatile std::uint8_t* p = value.data();
        for (std::size_t i = 0; i < value.size(); ++i) {
            p[i] = 0;
        }
        value.clear();
    }
}

std::string NowUtcIso() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &time);
#else
    gmtime_r(&time, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

std::string RandomHex(std::size_t bytes) {
    std::random_device rd;
    std::independent_bits_engine<std::mt19937, 32, std::uint32_t> eng(rd());
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < bytes; ++i) {
        out << std::setw(2) << (eng() & 0xffu);
    }
    return out.str();
}

std::string ToLowerAscii(std::string_view value) {
    std::string out(value);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

bool EqualsIgnoreCase(std::string_view a, std::string_view b) {
    return ToLowerAscii(a) == ToLowerAscii(b);
}

bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle) {
    const auto h = ToLowerAscii(haystack);
    const auto n = ToLowerAscii(needle);
    return h.find(n) != std::string::npos;
}

std::string PathUtf8(const std::filesystem::path& path) {
    const auto u8 = path.u8string();
    return {u8.begin(), u8.end()};
}

Result<std::string> ReadTextFile(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return Result<std::string>::fail("Cannot read " + PathUtf8(path));
    }
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xef &&
        static_cast<unsigned char>(text[1]) == 0xbb && static_cast<unsigned char>(text[2]) == 0xbf) {
        text.erase(0, 3);
    }
    return Result<std::string>::ok(std::move(text));
}

Error WriteBytesAtomic(const std::filesystem::path& path, const std::uint8_t* data, std::size_t size) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    auto tmp = path;
    tmp += ".";
    tmp += RandomHex(8);
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            return Fail("Cannot write temporary file.");
        }
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!out) {
            return Fail("Cannot write temporary file.");
        }
    }
#ifdef _WIN32
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(tmp, ec);
        return Fail("Cannot replace " + PathUtf8(path));
    }
#else
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp);
        return Fail("Cannot replace " + PathUtf8(path));
    }
#endif
    return Ok();
}

Error WriteTextAtomic(const std::filesystem::path& path, std::string_view text) {
    return WriteBytesAtomic(path, reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

Result<std::vector<std::uint8_t>> ReadBytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return Result<std::vector<std::uint8_t>>::fail("Cannot read " + PathUtf8(path));
    }
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return Result<std::vector<std::uint8_t>>::ok(std::move(data));
}

bool FileExists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

std::uint64_t FileSize(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::file_size(path, ec);
}

bool IsAdministrator() {
#ifdef _WIN32
    BOOL admin = FALSE;
    PSID sid = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &sid)) {
        return false;
    }
    CheckTokenMembership(nullptr, sid, &admin);
    FreeSid(sid);
    return admin == TRUE;
#else
    return geteuid() == 0;
#endif
}

Error RequireAdministrator() {
    if (!IsAdministrator()) {
        return Fail("Run as administrator.");
    }
    return Ok();
}

void SleepMs(unsigned milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

void ClearDnsCache() {
#ifdef _WIN32
    HMODULE dns = LoadLibraryW(L"dnsapi.dll");
    if (!dns) {
        return;
    }
    auto fn = reinterpret_cast<DnsFlushFn>(GetProcAddress(dns, "DnsFlushResolverCache"));
    if (fn) {
        fn();
    }
    FreeLibrary(dns);
#endif
}

}  // namespace st
