#include "profile.h"

#include "util.h"

#include <regex>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif

namespace st {
namespace {

bool IsIpv4(const std::string& text) {
    const std::regex re(R"(^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$)");
    return std::regex_match(text, re);
}

bool ValidUtf8Length(const std::string& value, std::size_t min_bytes, std::size_t max_bytes) {
    return value.size() >= min_bytes && value.size() <= max_bytes;
}

bool HasControlChars(const std::string& value) {
    for (unsigned char c : value) {
        if (c <= 0x1f || c == 0x7f) {
            return true;
        }
    }
    return false;
}

}  // namespace

nlohmann::json Profile::ToJson() const {
    return nlohmann::json{{"schema", schema},
                          {"protocol", protocol},
                          {"server_ip", server_ip},
                          {"server_port", server_port},
                          {"username", username},
                          {"password", password},
                          {"expected_exit_ip", expected_exit_ip},
                          {"tls_server_name", tls_server_name},
                          {"policy_url", policy_url},
                          {"policy_public_key", policy_public_key}};
}

Result<Profile> Profile::FromJson(const nlohmann::json& value) {
    try {
        Profile profile;
        profile.schema = value.at("schema").get<int>();
        profile.protocol = value.at("protocol").get<std::string>();
        profile.server_ip = value.at("server_ip").get<std::string>();
        profile.server_port = value.at("server_port").get<int>();
        profile.username = value.value("username", "");
        profile.password = value.value("password", "");
        profile.expected_exit_ip = value.value("expected_exit_ip", "");
        profile.tls_server_name = value.value("tls_server_name", "");
        profile.policy_url = value.value("policy_url", "");
        profile.policy_public_key = value.value("policy_public_key", "");
        if (auto err = AssertProfile(profile)) {
            return Result<Profile>::fail(err.message);
        }
        return Result<Profile>::ok(std::move(profile));
    } catch (const std::exception& ex) {
        return Result<Profile>::fail(std::string("Invalid connection profile: ") + ex.what());
    }
}

Result<Profile> DefaultProfile() {
    Profile profile;
    return Result<Profile>::ok(std::move(profile));
}

Error AssertProfile(const Profile& profile) {
    if (profile.schema != 2) {
        return Fail("A proxy connection (schema 2) is required.");
    }
    if (profile.protocol != "socks5" && profile.protocol != "http" && profile.protocol != "https") {
        return Fail("Unsupported proxy protocol.");
    }
    if (!IsIpv4(profile.server_ip)) {
        return Fail("Enter the numeric IPv4 address of the proxy.");
    }
    if (profile.server_port < 1 || profile.server_port > 65535) {
        return Fail("Invalid server port.");
    }
    for (const auto* name : {&profile.username, &profile.password}) {
        if (name->empty() || HasControlChars(*name) || !ValidUtf8Length(*name, 1, 255)) {
            return Fail("Invalid proxy username/password (1..255 UTF-8 bytes; no control characters).");
        }
    }
    if (profile.protocol != "socks5" && profile.username.find(':') != std::string::npos) {
        return Fail("HTTP proxy username cannot contain a colon.");
    }
    if (!profile.expected_exit_ip.empty() && !IsIpv4(profile.expected_exit_ip)) {
        return Fail("Invalid expected exit IP.");
    }
    if (profile.protocol == "https") {
        static const std::regex host(R"(^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$)");
        if (!std::regex_match(profile.tls_server_name, host)) {
            return Fail(
                "HTTPS proxy requires the hostname on its TLS certificate. HTTP(S) marketing alone does not imply TLS "
                "to the proxy.");
        }
    }
    if (profile.policy_url.empty() != profile.policy_public_key.empty()) {
        return Fail("Policy URL and public signing key must be configured together.");
    }
    if (!profile.policy_url.empty()) {
        static const std::regex url(R"(^https://[^/@:?#]+/[^?#]*$)");
        if (!std::regex_match(profile.policy_url, url) || profile.policy_url.find('@') != std::string::npos) {
            return Fail("Policy URL must be HTTPS on port 443, without credentials or query.");
        }
        if (profile.policy_url.find(":443/") == std::string::npos &&
            profile.policy_url.rfind("https://", 0) == 0) {
            const auto rest = profile.policy_url.substr(8);
            const auto slash = rest.find('/');
            const auto hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
            if (hostport.find(':') != std::string::npos && hostport.find(":443") == std::string::npos) {
                return Fail("Policy URL must be HTTPS on port 443, without credentials or query.");
            }
        }
    }
    return Ok();
}

Error SaveConnection(const Profile& profile, const std::filesystem::path& path) {
    if (auto err = AssertProfile(profile)) {
        return err;
    }
    auto json = profile.ToJson().dump();
#ifdef _WIN32
    DATA_BLOB plain{};
    plain.pbData = reinterpret_cast<BYTE*>(json.data());
    plain.cbData = static_cast<DWORD>(json.size());
    DATA_BLOB sealed{};
    if (!CryptProtectData(&plain, L"SelectiveTunnel", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &sealed)) {
        SecureClear(json);
        return Fail("Cannot encrypt the connection on this Windows machine.");
    }
    SecureClear(json);
    const auto err = WriteBytesAtomic(path, sealed.pbData, sealed.cbData);
    SecureZeroMemory(sealed.pbData, sealed.cbData);
    LocalFree(sealed.pbData);
    return err;
#else
    const auto err = WriteTextAtomic(path, json);
    SecureClear(json);
    return err;
#endif
}

Result<Profile> ReadConnection(const std::filesystem::path& path) {
    auto bytes = ReadBytes(path);
    if (!bytes) {
        return Result<Profile>::fail("Cannot decrypt the connection on this Windows machine. Re-enter proxy settings.");
    }
#ifdef _WIN32
    DATA_BLOB sealed{};
    sealed.pbData = bytes.value.data();
    sealed.cbData = static_cast<DWORD>(bytes.value.size());
    DATA_BLOB plain{};
    if (!CryptUnprotectData(&sealed, nullptr, nullptr, nullptr, nullptr, 0, &plain)) {
        return Result<Profile>::fail("Cannot decrypt the connection on this Windows machine. Re-enter proxy settings.");
    }
    std::string json(reinterpret_cast<char*>(plain.pbData), reinterpret_cast<char*>(plain.pbData) + plain.cbData);
    SecureZeroMemory(plain.pbData, plain.cbData);
    LocalFree(plain.pbData);
    SecureClear(bytes.value);
    try {
        auto parsed = Profile::FromJson(nlohmann::json::parse(json));
        SecureClear(json);
        return parsed;
    } catch (const std::exception&) {
        SecureClear(json);
        return Result<Profile>::fail("Cannot decrypt the connection on this Windows machine. Re-enter proxy settings.");
    }
#else
    try {
        auto parsed = Profile::FromJson(nlohmann::json::parse(bytes.value.begin(), bytes.value.end()));
        SecureClear(bytes.value);
        return parsed;
    } catch (const std::exception&) {
        return Result<Profile>::fail("Cannot read connection profile.");
    }
#endif
}

}  // namespace st
