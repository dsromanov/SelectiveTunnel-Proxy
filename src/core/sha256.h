#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace st {

std::string Sha256Hex(const std::uint8_t* data, std::size_t size);
std::string Sha256Hex(const std::string& text);
std::string Sha256FileHex(const std::filesystem::path& path);
bool Sha256Equals(std::string_view actual, std::string_view expected);

}  // namespace st
