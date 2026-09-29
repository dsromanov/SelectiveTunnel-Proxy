#include "policy.h"

#include "crypto.h"
#include "json_io.h"
#include "util.h"

#include <algorithm>
#include <cstdio>
#include <regex>
#include <set>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace st {
namespace {

const std::vector<std::string> kBroad = {"com",        "net",           "org",         "co.uk",
                                         "com.au",     "cloudflare.com", "cloudfront.net", "amazonaws.com",
                                         "azureedge.net", "google.com", "jsdelivr.net"};

bool ValidDomain(const std::string& domain) {
    if (domain.size() > 253 || domain != ToLowerAscii(domain)) {
        return false;
    }
    static const std::regex re(R"(^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$)");
    return std::regex_match(domain, re);
}

bool ParseIpv4(const std::string& text, std::uint32_t& ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    char extra = 0;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4) {
        return false;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return false;
    }
    ip = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

Error AssertCidr(const std::string& cidr) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        return Fail("Only explicit IPv4 CIDRs are supported.");
    }
    std::uint32_t ip = 0;
    if (!ParseIpv4(cidr.substr(0, slash), ip)) {
        return Fail("Only explicit IPv4 CIDRs are supported.");
    }
    int prefix = 0;
    try {
        prefix = std::stoi(cidr.substr(slash + 1));
    } catch (...) {
        return Fail("Only explicit IPv4 CIDRs are supported.");
    }
    if (prefix < 24 || prefix > 32) {
        return Fail("CIDRs must be IPv4 /24 through /32; do not route whole CDN networks.");
    }
    const unsigned a = ip >> 24;
    const unsigned b = (ip >> 16) & 0xff;
    if (a == 0 || a == 10 || a == 127 || a >= 224 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
        (a == 169 && b == 254) || (a == 198 && (b == 18 || b == 19))) {
        return Fail("Non-public CIDR is forbidden.");
    }
    const std::uint32_t host_mask = prefix == 32 ? 0 : ((1u << (32 - prefix)) - 1);
    if ((ip & host_mask) != 0) {
        return Fail("CIDR must be a network address.");
    }
    return Ok();
}

#ifdef _WIN32
Result<std::string> HttpGetNoRedirect(const std::string& url) {
    if (url.rfind("https://", 0) != 0) {
        return Result<std::string>::fail("Policy URL must be HTTPS on port 443, without credentials or query.");
    }
    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256]{};
    wchar_t path[2048]{};
    parts.lpszHostName = host;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 2048;
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &parts)) {
        return Result<std::string>::fail("Policy URL must be HTTPS on port 443, without credentials or query.");
    }
    if (parts.nPort != INTERNET_DEFAULT_HTTPS_PORT) {
        return Result<std::string>::fail("Policy URL must be HTTPS on port 443, without credentials or query.");
    }
    HINTERNET session = WinHttpOpen(L"SelectiveTunnel/2.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        return Result<std::string>::fail("Rule update rejected or unavailable; previous policy retained.");
    }
    DWORD timeout = 20000;
    WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(session, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(session, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    DWORD disable = WINHTTP_DISABLE_REDIRECTS;
    HINTERNET connect = WinHttpConnect(session, host, parts.nPort, 0);
    HINTERNET request = nullptr;
    std::string body;
    Error err;
    if (!connect) {
        err = Fail("Rule update rejected or unavailable; previous policy retained.");
    } else {
        request = WinHttpOpenRequest(connect, L"GET", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     WINHTTP_FLAG_SECURE);
        if (!request || !WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)) ||
            !WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request, nullptr)) {
            err = Fail("Rule update rejected or unavailable; previous policy retained.");
        } else {
            DWORD status = 0, status_size = sizeof(status);
            WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, &status,
                                &status_size, WINHTTP_NO_HEADER_INDEX);
            if (status != 200) {
                err = Fail("Rule update rejected or unavailable; previous policy retained.");
            } else {
                while (true) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(request, &avail) || avail == 0) {
                        break;
                    }
                    if (body.size() + avail > 131072) {
                        err = Fail("Policy response is too large.");
                        break;
                    }
                    std::string chunk(avail, 0);
                    DWORD read = 0;
                    if (!WinHttpReadData(request, chunk.data(), avail, &read)) {
                        err = Fail("Rule update rejected or unavailable; previous policy retained.");
                        break;
                    }
                    body.append(chunk.data(), read);
                }
            }
        }
    }
    if (request) {
        WinHttpCloseHandle(request);
    }
    if (connect) {
        WinHttpCloseHandle(connect);
    }
    WinHttpCloseHandle(session);
    if (err) {
        return Result<std::string>::fail(err.message);
    }
    return Result<std::string>::ok(std::move(body));
}
#endif

}  // namespace

nlohmann::json Policy::ToJson() const {
    return nlohmann::json{{"version", version}, {"domains", domains}, {"cidrs", cidrs}};
}

Result<Policy> Policy::FromJson(const nlohmann::json& value) {
    try {
        Policy policy;
        policy.version = value.at("version").get<int>();
        policy.domains = value.at("domains").get<std::vector<std::string>>();
        policy.cidrs = value.value("cidrs", std::vector<std::string>{});
        if (auto err = AssertPolicy(policy)) {
            return Result<Policy>::fail(err.message);
        }
        return Result<Policy>::ok(std::move(policy));
    } catch (const std::exception& ex) {
        return Result<Policy>::fail(std::string("Invalid policy: ") + ex.what());
    }
}

Error AssertPolicy(const Policy& policy) {
    if (policy.version < 1 || policy.version > 2147483647) {
        return Fail("Invalid policy version.");
    }
    if (policy.domains.size() < 1 || policy.domains.size() > 200) {
        return Fail("Expected 1..200 domain suffixes.");
    }
    std::set<std::string> unique;
    for (const auto& domain : policy.domains) {
        if (!ValidDomain(domain)) {
            return Fail("Invalid domain suffix: " + domain);
        }
        if (std::find(kBroad.begin(), kBroad.end(), domain) != kBroad.end()) {
            return Fail("Shared infrastructure suffix is too broad: " + domain);
        }
        if (!unique.insert(domain).second) {
            return Fail("Duplicate domains.");
        }
    }
    if (policy.cidrs.size() > 100) {
        return Fail("Too many IP ranges.");
    }
    for (const auto& cidr : policy.cidrs) {
        if (auto err = AssertCidr(cidr)) {
            return err;
        }
    }
    return Ok();
}

Error AssertProxyPolicy(const Policy& policy) {
    if (auto err = AssertPolicy(policy)) {
        return err;
    }
    if (!policy.cidrs.empty()) {
        return Fail("The proxy edition uses domain rules only. Leave cidrs empty to avoid shared-CDN and adapter-change leaks.");
    }
    return Ok();
}

Policy MergePolicies(const Policy& current, Policy candidate) {
    std::set<std::string> domains(current.domains.begin(), current.domains.end());
    domains.insert(candidate.domains.begin(), candidate.domains.end());
    candidate.domains.assign(domains.begin(), domains.end());
    std::set<std::string> cidrs(current.cidrs.begin(), current.cidrs.end());
    cidrs.insert(candidate.cidrs.begin(), candidate.cidrs.end());
    candidate.cidrs.assign(cidrs.begin(), cidrs.end());
    return candidate;
}

Result<Policy> LoadBundledPolicy(const std::filesystem::path& path) {
    auto json = ReadJsonFile(path);
    if (!json) {
        return Result<Policy>::fail(json.error.message);
    }
    return Policy::FromJson(json.value);
}

Result<Policy> ConvertFromSignedPolicy(const nlohmann::json& envelope, const Profile& profile, const Policy& current) {
    if (auto err = AssertProfile(profile)) {
        return Result<Policy>::fail(err.message);
    }
    if (profile.policy_public_key.empty()) {
        return Result<Policy>::fail("No trusted policy signing key configured.");
    }
    try {
        auto payload = Base64Decode(envelope.at("payload").get<std::string>());
        auto signature = Base64Decode(envelope.at("signature").get<std::string>());
        if (!payload || !signature) {
            return Result<Policy>::fail("Invalid policy signature.");
        }
        if (payload.value.size() > 65536) {
            return Result<Policy>::fail("Decoded policy is too large.");
        }
        if (auto err = VerifyRsaSha256(profile.policy_public_key, payload.value.data(), payload.value.size(),
                                       signature.value.data(), signature.value.size())) {
            return Result<Policy>::fail(err.message);
        }
        auto candidate = Policy::FromJson(nlohmann::json::parse(payload.value.begin(), payload.value.end()));
        if (!candidate) {
            return candidate;
        }
        if (candidate.value.version <= current.version) {
            Policy none;
            none.version = 0;
            none.domains.clear();
            return Result<Policy>::ok(std::move(none));
        }
        auto merged = MergePolicies(current, candidate.value);
        if (auto err = AssertPolicy(merged)) {
            return Result<Policy>::fail(err.message);
        }
        return Result<Policy>::ok(std::move(merged));
    } catch (const std::exception&) {
        return Result<Policy>::fail("Invalid policy signature.");
    }
}

Result<Policy> ReceivePolicy(const Profile& profile, const Policy& current) {
    if (auto err = AssertProfile(profile)) {
        return Result<Policy>::fail(err.message);
    }
    if (profile.policy_url.empty()) {
        Policy none;
        none.version = 0;
        none.domains.clear();
        return Result<Policy>::ok(std::move(none));
    }
#ifdef _WIN32
    auto body = HttpGetNoRedirect(profile.policy_url);
    if (!body) {
        return Result<Policy>::fail(body.error.message);
    }
    try {
        return ConvertFromSignedPolicy(nlohmann::json::parse(body.value), profile, current);
    } catch (const std::exception&) {
        return Result<Policy>::fail("Rule update rejected or unavailable; previous policy retained.");
    }
#else
    (void)current;
    return Result<Policy>::fail("Policy download is only implemented on Windows.");
#endif
}

}  // namespace st
