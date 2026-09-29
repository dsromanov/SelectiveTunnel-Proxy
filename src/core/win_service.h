#pragma once

#include "error.h"

#include <filesystem>

namespace st {

Error InstallWindowsService(const std::filesystem::path& svc_exe);
Error UninstallWindowsService();
Error StartWindowsService();
Error StopWindowsService();
Error RemoveLegacyScheduledTask();
bool ServiceExists();

}  // namespace st
