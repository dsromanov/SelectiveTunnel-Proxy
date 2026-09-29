#pragma once

#include "error.h"
#include "policy.h"
#include "profile.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>

namespace st {

nlohmann::json NewEngineConfig(const Profile& profile, const Policy& policy, const std::filesystem::path& data_root,
                               const std::string& bind_interface = {}, bool ipv4_only = true);

std::string EngineConfigJson(const nlohmann::json& config);

}  // namespace st
