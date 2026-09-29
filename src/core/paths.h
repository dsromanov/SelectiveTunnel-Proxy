#pragma once

#include "error.h"

#include <filesystem>
#include <string>

namespace st {

std::filesystem::path ExeDir();
std::filesystem::path PackageRoot();
std::filesystem::path DataRoot();
std::filesystem::path AppRoot();
std::filesystem::path EnginePath();
std::filesystem::path WintunPath();
std::filesystem::path ConnectionPath();
std::filesystem::path PolicyPath();
std::filesystem::path DesiredPath();
std::filesystem::path StatusPath();
std::filesystem::path GuardLockPath();
std::filesystem::path RefreshRequestPath();
std::filesystem::path Ipv4OnlyFlagPath();
std::filesystem::path DesktopFile(const std::string& name);

Error ProtectDirectory(const std::filesystem::path& path);
bool PathHasReparsePoint(const std::filesystem::path& path);

}  // namespace st
