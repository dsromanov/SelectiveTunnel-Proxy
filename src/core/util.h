#pragma once

#include "error.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace st {

void SecureClear(std::string& value);
void SecureClear(std::vector<std::uint8_t>& value);

std::string NowUtcIso();
std::string RandomHex(std::size_t bytes = 16);
std::string ToLowerAscii(std::string_view value);
bool EqualsIgnoreCase(std::string_view a, std::string_view b);
bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle);
std::string PathUtf8(const std::filesystem::path& path);

Result<std::string> ReadTextFile(const std::filesystem::path& path);
Error WriteTextAtomic(const std::filesystem::path& path, std::string_view text);
Error WriteBytesAtomic(const std::filesystem::path& path, const std::uint8_t* data, std::size_t size);
Result<std::vector<std::uint8_t>> ReadBytes(const std::filesystem::path& path);

bool FileExists(const std::filesystem::path& path);
std::uint64_t FileSize(const std::filesystem::path& path);

bool IsAdministrator();
Error RequireAdministrator();

void SleepMs(unsigned milliseconds);
void ClearDnsCache();

}  // namespace st
