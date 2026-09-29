#pragma once

#include "error.h"

#include <nlohmann/json.hpp>

#include <filesystem>

namespace st {

Result<nlohmann::json> ReadJsonFile(const std::filesystem::path& path);
Error WriteJsonAtomic(const std::filesystem::path& path, const nlohmann::json& value);

}  // namespace st
