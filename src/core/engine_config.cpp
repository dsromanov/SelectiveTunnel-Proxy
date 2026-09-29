#include "engine_config.h"

#include "constants.h"
#include "paths.h"
#include "util.h"

#include <stdexcept>

namespace st {

nlohmann::json NewEngineConfig(const Profile& profile, const Policy& policy, const std::filesystem::path& data_root,
                               const std::string& bind_interface, bool ipv4_only) {
    if (auto err = AssertProfile(profile)) {
        throw std::runtime_error(err.message);
    }
    if (auto err = AssertProxyPolicy(policy)) {
        throw std::runtime_error(err.message);
    }

    nlohmann::json proxy;
    if (profile.protocol == "socks5") {
        proxy = {{"type", "socks"},
                 {"tag", "proxy"},
                 {"server", profile.server_ip},
                 {"server_port", profile.server_port},
                 {"version", "5"},
                 {"username", profile.username},
                 {"password", profile.password},
                 {"network", "tcp"}};
    } else {
        proxy = {{"type", "http"},
                 {"tag", "proxy"},
                 {"server", profile.server_ip},
                 {"server_port", profile.server_port},
                 {"username", profile.username},
                 {"password", profile.password}};
        if (profile.protocol == "https") {
            proxy["tls"] = {{"enabled", true}, {"server_name", profile.tls_server_name}};
        }
    }

    nlohmann::json fakeip = {{"type", "fakeip"}, {"tag", "fake"}, {"inet4_range", kFakeV4}};
    if (!ipv4_only) {
        fakeip["inet6_range"] = kFakeV6;
    }

    nlohmann::json dns_rules = nlohmann::json::array();
    if (ipv4_only) {
        dns_rules.push_back({{"domain_suffix", policy.domains},
                             {"query_type", nlohmann::json::array({"A"})},
                             {"action", "route"},
                             {"server", "fake"},
                             {"rewrite_ttl", 60}});
        dns_rules.push_back({{"domain_suffix", policy.domains},
                             {"query_type", nlohmann::json::array({"AAAA", "HTTPS", "SVCB"})},
                             {"action", "predefined"},
                             {"rcode", "NOERROR"}});
    } else {
        dns_rules.push_back({{"domain_suffix", policy.domains},
                             {"query_type", nlohmann::json::array({"A", "AAAA"})},
                             {"action", "route"},
                             {"server", "fake"},
                             {"rewrite_ttl", 60}});
        dns_rules.push_back({{"domain_suffix", policy.domains},
                             {"query_type", nlohmann::json::array({"HTTPS", "SVCB"})},
                             {"action", "predefined"},
                             {"rcode", "NOERROR"}});
    }
    dns_rules.push_back({{"domain_suffix", policy.domains}, {"action", "route"}, {"server", "remote"}});
    dns_rules.push_back({{"action", "reject"}});

    nlohmann::json tun = {{"type", "tun"},
                          {"tag", "tun"},
                          {"interface_name", kTunName},
                          {"mtu", 1380},
                          {"auto_route", true},
                          {"strict_route", false},
                          {"dns_mode", "disabled"},
                          {"stack", "gvisor"}};
    if (ipv4_only) {
        tun["address"] = nlohmann::json::array({kTunV4});
        tun["route_address"] = nlohmann::json::array({kFakeV4a, kFakeV4b});
    } else {
        tun["address"] = nlohmann::json::array({kTunV4, kTunV6});
        tun["route_address"] = nlohmann::json::array({kFakeV4a, kFakeV4b, kFakeV6a, kFakeV6b});
    }

    nlohmann::json fake_cidrs = nlohmann::json::array({kFakeV4});
    if (!ipv4_only) {
        fake_cidrs.push_back(kFakeV6);
    }

    nlohmann::json rules = nlohmann::json::array();
    rules.push_back({{"inbound", nlohmann::json::array({"dns-in"})}, {"action", "hijack-dns"}});
    rules.push_back({{"inbound", nlohmann::json::array({"diagnostic"})}, {"network", "udp"}, {"action", "reject"}});
    rules.push_back({{"domain_suffix", policy.domains}, {"network", "udp"}, {"action", "reject"}});
    rules.push_back({{"inbound", nlohmann::json::array({"diagnostic"})}, {"action", "route"}, {"outbound", "proxy"}});
    rules.push_back({{"domain_suffix", policy.domains}, {"action", "route"}, {"outbound", "proxy"}});
    rules.push_back({{"ip_cidr", fake_cidrs}, {"action", "reject"}});

    nlohmann::json route = {{"default_domain_resolver", {{"server", "remote"}, {"strategy", "ipv4_only"}}},
                            {"rules", rules},
                            {"final", "direct"}};
    if (!bind_interface.empty()) {
        route["auto_detect_interface"] = false;
        route["default_interface"] = bind_interface;
    } else {
        route["auto_detect_interface"] = true;
    }

    const auto cache = data_root / (ipv4_only ? "cache-ipv4.db" : "cache.db");
    nlohmann::json config = {
        {"log", {{"disabled", true}}},
        {"dns",
         {{"servers",
           nlohmann::json::array(
               {fakeip,
                {{"type", "https"},
                 {"tag", "remote"},
                 {"server", "1.1.1.1"},
                 {"server_port", 443},
                 {"path", "/dns-query"},
                 {"tls", {{"enabled", true}, {"server_name", "cloudflare-dns.com"}}},
                 {"detour", "proxy"}}})},
          {"rules", dns_rules},
          {"final", "remote"}}},
        {"inbounds", nlohmann::json::array({{{ "type", "direct"},
                                             {"tag", "dns-in"},
                                             {"listen", kDnsListen},
                                             {"listen_port", kDnsPort}},
                                            {{"type", "mixed"},
                                             {"tag", "diagnostic"},
                                             {"listen", kDiagListen},
                                             {"listen_port", kDiagPort}},
                                            tun})},
        {"outbounds", nlohmann::json::array({proxy, {{"type", "direct"}, {"tag", "direct"}}})},
        {"route", route},
        {"experimental", {{"cache_file", {{"enabled", true}, {"path", PathUtf8(cache)}, {"store_fakeip", true}}}}}};
    return config;
}

std::string EngineConfigJson(const nlohmann::json& config) { return config.dump(); }

}  // namespace st
