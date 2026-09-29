#pragma once

#include "error.h"
#include "profile.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace st {

struct Policy {
    int version = 1;
    std::vector<std::string> domains;
    std::vector<std::string> cidrs;

    nlohmann::json ToJson() const;
    static Result<Policy> FromJson(const nlohmann::json& value);
};

Error AssertPolicy(const Policy& policy);
Error AssertProxyPolicy(const Policy& policy);

Policy MergePolicies(const Policy& current, Policy candidate);
Result<Policy> LoadBundledPolicy(const std::filesystem::path& path);

Result<Policy> ConvertFromSignedPolicy(const nlohmann::json& envelope, const Profile& profile,
                                       const Policy& current);
Result<Policy> ReceivePolicy(const Profile& profile, const Policy& current);

}  // namespace st
