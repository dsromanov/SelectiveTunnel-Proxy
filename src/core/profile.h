#pragma once

#include "error.h"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>

namespace st {

struct Profile {
    int schema = 2;
    std::string protocol = "socks5";
    std::string server_ip = "176.119.140.14";
    int server_port = 14073;
    std::string username;
    std::string password;
    std::string expected_exit_ip = "176.119.140.14";
    std::string tls_server_name;
    std::string policy_url;
    std::string policy_public_key;

    nlohmann::json ToJson() const;
    static Result<Profile> FromJson(const nlohmann::json& value);
};

Error AssertProfile(const Profile& profile);
Result<Profile> DefaultProfile();

Error SaveConnection(const Profile& profile, const std::filesystem::path& path);
Result<Profile> ReadConnection(const std::filesystem::path& path);

}  // namespace st
