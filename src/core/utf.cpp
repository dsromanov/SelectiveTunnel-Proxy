#include "utf.h"

#include <cstdint>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace st {

#ifdef _WIN32

std::wstring Utf8ToWide(std::string_view utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
                                           nullptr, 0);
    if (needed <= 0) {
        throw std::runtime_error("Invalid UTF-8 text.");
    }
    std::wstring wide(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), wide.data(), needed);
    return wide;
}

std::string WideToUtf8(std::wstring_view wide) {
    if (wide.empty()) {
        return {};
    }
    const int needed =
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        throw std::runtime_error("Invalid UTF-16 text.");
    }
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), needed, nullptr, nullptr);
    return utf8;
}

#else

std::wstring Utf8ToWide(std::string_view utf8) {
    std::wstring wide;
    wide.reserve(utf8.size());
    for (unsigned char c : utf8) {
        wide.push_back(static_cast<wchar_t>(c));
    }
    return wide;
}

std::string WideToUtf8(std::wstring_view wide) {
    std::string utf8;
    utf8.reserve(wide.size());
    for (wchar_t c : wide) {
        utf8.push_back(static_cast<char>(c));
    }
    return utf8;
}

#endif

}  // namespace st
