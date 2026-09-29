#include "app/commands.h"

#include "core/constants.h"
#include "core/crypto.h"
#include "core/engine.h"
#include "core/engine_config.h"
#include "core/json_io.h"
#include "core/paths.h"
#include "core/policy.h"
#include "core/profile.h"
#include "core/proxy_bypass.h"
#include "core/sha256.h"
#include "core/util.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <filesystem>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

namespace st {
namespace {

int g_passed = 0;

void Check(const std::string& name, const std::function<void()>& fn) {
    fn();
    ++g_passed;
    std::cout << "PASS " << name << "\n";
}

template <typename T>
void Require(const T& value, const std::string& message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

Profile FixtureProfile() {
    Profile p;
    p.server_ip = "127.0.0.1";
    p.server_port = 1080;
    p.username = "fixture-user";
    p.password = "fixture-password";
    p.expected_exit_ip.clear();
    return p;
}

int FreePort() {
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int len = sizeof(addr);
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    const int port = ntohs(addr.sin_port);
    closesocket(s);
    return port;
#else
    return 18000 + g_passed;
#endif
}

#ifdef _WIN32
bool QueryDns(int port, int type, std::vector<std::uint8_t>& answer) {
    std::vector<std::uint8_t> packet{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    const char* name = "chatgpt.com";
    std::string label;
    for (int i = 0;; ++i) {
        if (name[i] == '.' || name[i] == 0) {
            packet.push_back(static_cast<std::uint8_t>(label.size()));
            packet.insert(packet.end(), label.begin(), label.end());
            label.clear();
            if (name[i] == 0) {
                break;
            }
        } else {
            label.push_back(name[i]);
        }
    }
    packet.push_back(0);
    packet.push_back(0);
    packet.push_back(static_cast<std::uint8_t>(type));
    packet.push_back(0);
    packet.push_back(1);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    DWORD timeout = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sendto(s, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
           reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    answer.resize(512);
    int alen = sizeof(addr);
    const int n = recvfrom(s, reinterpret_cast<char*>(answer.data()), static_cast<int>(answer.size()), 0,
                           reinterpret_cast<sockaddr*>(&addr), &alen);
    closesocket(s);
    if (n <= 0) {
        return false;
    }
    answer.resize(n);
    return true;
}
#endif

}  // namespace

int RunSelfTest(int argc, char** argv) {
    std::filesystem::path engine;
    std::string python = "python";
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--engine" && i + 1 < argc) {
            engine = argv[++i];
        } else if (arg == "--python" && i + 1 < argc) {
            python = argv[++i];
        }
    }
    if (engine.empty()) {
        const auto candidate = PackageRoot() / "bin" / "sing-box.exe";
        if (FileExists(candidate)) {
            engine = candidate;
        } else if (FileExists(EnginePath())) {
            engine = EnginePath();
        }
    }
    auto policy = LoadBundledPolicy(PackageRoot() / "policy" / "domains.json");
    if (!policy) {
        std::cerr << policy.error.message << "\n";
        return 1;
    }
    const auto scratch = std::filesystem::temp_directory_path() / ("SelectiveProxy-" + RandomHex(8));
    std::error_code ec;
    std::filesystem::create_directories(scratch, ec);
    try {
        Check("SOCKS5 HTTP and TLS proxy configurations accepted via stdin", [&] {
            if (engine.empty()) {
                auto p = FixtureProfile();
                for (const char* proto : {"socks5", "http", "https"}) {
                    p.protocol = proto;
                    if (p.protocol == "https") {
                        p.tls_server_name = "proxy.example.org";
                    }
                    auto c = NewEngineConfig(p, policy.value, scratch, {}, false);
                    Require(c["outbounds"][0]["tag"] == "proxy", "proxy outbound");
                }
                return;
            }
#ifdef _WIN32
            auto p = FixtureProfile();
            for (const char* proto : {"socks5", "http", "https"}) {
                p.protocol = proto;
                if (p.protocol == "https") {
                    p.tls_server_name = "proxy.example.org";
                }
                auto err = TestEngineConfig(NewEngineConfig(p, policy.value, scratch, {}, false), engine);
                Require(!err, err.message);
            }
#endif
        });
        Check("Other services remain direct and selected UDP is rejected", [&] {
            auto c = NewEngineConfig(FixtureProfile(), policy.value, scratch, {}, false);
            Require(c["route"]["final"] == "direct", "Direct default required");
            Require(c["inbounds"][2]["route_address"].size() == 4, "Unexpected TUN ranges");
            Require(!c["inbounds"][2]["route_address"].empty(), "TUN ranges");
            bool full = false;
            for (const auto& item : c["inbounds"][2]["route_address"]) {
                if (item == "0.0.0.0/0" || item == "::/0") {
                    full = true;
                }
            }
            Require(!full, "Full tunnel not permitted");
            Require(c["inbounds"][2]["dns_mode"] == "disabled", "Other adapter DNS must remain unchanged");
            Require(c["route"]["rules"][2]["network"] == "udp" && c["route"]["rules"][2]["action"] == "reject",
                    "Selected UDP must not fall through");
            Require(c["outbounds"][0]["network"] == "tcp", "Unsupported upstream UDP enabled");
            Require(c["dns"]["servers"][1]["type"] == "https" && c["dns"]["servers"][1]["detour"] == "proxy",
                    "DNS must use TCP through proxy");
            Require(c["route"]["rules"].back()["action"] == "reject", "Stale FakeIPs must fail closed");
            Require(c["inbounds"][0]["listen"] == kDnsListen, "DNS must listen on 127.0.0.53");
            Require(c["dns"]["servers"][0]["inet4_range"] == kFakeV4, "FakeIP must not use 198.18.0.0/15");
        });
        Check("System proxy bypass keeps selected domains off Happ", [&] {
            const std::vector<std::string> domains{"figma.com", "chatgpt.com"};
            const auto merged = MergeProxyBypass("<local>;telegram.org", domains);
            Require(merged.find("figma.com") != std::string::npos, "figma bypass");
            Require(merged.find("*.figma.com") != std::string::npos, "figma wildcard");
            Require(merged.find("chatgpt.com") != std::string::npos, "chatgpt bypass");
            Require(merged.find("100.82.*") != std::string::npos, "fakeip bypass");
            Require(merged.find("<local>") != std::string::npos, "keep local");
            Require(merged.find("telegram.org") != std::string::npos, "keep foreign");
            const auto again = MergeProxyBypass(merged, domains);
            Require(std::count(again.begin(), again.end(), ';') ==
                        static_cast<std::ptrdiff_t>(std::count(merged.begin(), merged.end(), ';')),
                    "merge must be idempotent");
            const auto stripped = StripProxyBypass(merged, domains);
            Require(stripped.find("figma.com") == std::string::npos, "strip figma");
            Require(stripped.find("100.82.*") == std::string::npos, "strip fakeip");
            Require(stripped.find("telegram.org") != std::string::npos, "keep telegram");
            const auto no_proxy = MergeNoProxy("localhost,telegram.org", domains);
            Require(no_proxy.find(".figma.com") != std::string::npos, "figma suffix for Codex/Electron");
            Require(no_proxy.find("chatgpt.com") != std::string::npos, "chatgpt no_proxy");
            Require(no_proxy.find("localhost") != std::string::npos, "keep localhost");
            Require(StripNoProxy(no_proxy, domains).find("telegram.org") != std::string::npos, "keep telegram env");
        });
        Check("Empty credentials invalid ports and broad CIDRs rejected", [&] {
            auto p = FixtureProfile();
            p.password.clear();
            Require(static_cast<bool>(AssertProfile(p)), "empty password");
            p = FixtureProfile();
            p.username = "a\nb";
            Require(static_cast<bool>(AssertProfile(p)), "control char");
            p = FixtureProfile();
            p.server_port = 65536;
            Require(static_cast<bool>(AssertProfile(p)), "port");
            p = FixtureProfile();
            p.protocol = "https";
            Require(static_cast<bool>(AssertProfile(p)), "https host");
            auto rules = policy.value;
            rules.cidrs = {"1.1.1.0/24"};
            bool failed = false;
            try {
                NewEngineConfig(FixtureProfile(), rules, scratch);
            } catch (...) {
                failed = true;
            }
            Require(failed, "Expected rejection");
        });
        Check("DPAPI roundtrip stores no cleartext username or password", [&] {
            auto path = scratch / "connection.dpapi";
            auto p = FixtureProfile();
            auto err = SaveConnection(p, path);
            Require(!err, err.message);
            auto read = ReadConnection(path);
            Require(read && read.value.password == p.password && read.value.username == p.username,
                    "Credential roundtrip failed");
            auto bytes = ReadBytes(path);
            Require(bytes, "read blob");
#ifdef _WIN32
            const std::string raw(bytes.value.begin(), bytes.value.end());
            Require(raw.find(p.password) == std::string::npos, "Cleartext password persisted");
            Require(raw.find(p.username) == std::string::npos, "Cleartext login persisted");
#endif
            p.password = "new-fixture-password";
            Require(!SaveConnection(p, path), "save");
            Require(ReadConnection(path).value.password == p.password, "Encrypted atomic replacement failed");
            bytes.value[20] ^= 1;
            WriteBytesAtomic(path, bytes.value.data(), bytes.value.size());
#ifdef _WIN32
            Require(!ReadConnection(path), "tamper");
#endif
        });
        Check("No domain feed required for standalone proxy mode", [&] {
            auto received = ReceivePolicy(FixtureProfile(), policy.value);
            Require(received && received.value.version == 0, "Missing feed should not make an HTTP call");
        });
        Check("Signed updates reject tampering replay and preserve existing domains", [&] {
            const char* mod =
                "5ezTeV8CO8ACdhx6pWO3JWDswTkQzM8FSdJVZT8jOBVu0TQ4bEwSsbWIhQbemWY8k9LImxZl13dkytuuCcdh6BLNNsrsHlWSUcdvySMB1c6APB6xt2"
                "cN7g65NLSHmJkNELYcO9+9WxY/ot22G5GkWG1jVmJda3/et6+MvoZhhpcjAFLcP5aRm+2kuEIxLOQV5lGjIsWeXv5aVPhGpDfQbsT0Kc3XbCA52STwQ"
                "b9BrCz3xbgaO5APOn9OhvAoXWsnZnOd3o5rPGPIjQrNWxZNWPF0B6hio16quohebnyH7LJF5Uyn+kMMIx1NwxN/AgJqMSiiTG0O1J6iAsNRS/1dsxp2"
                "+wvKRdShd/tA008OvGL1g+iYvZTuIQkBx0nhlWbRwul8F6WTaJUW0UJbBRHozC/Fni03FIKh5SC2LkkNfIqiZvcenj25yl1ySG6+YptHjzJ7EFEu1q8h"
                "gWIHAFHvRrr496QuZjvb3UF71gD4SzU60cEB8CZhMdJ/6YUdk9/5";
            const char* d =
                "Glhnd17l8T18Mrcq7PhG6Ckp266LoKIggZ/QkeI5CYA4M0+73tndIwBxYQfDWhmjO49xlcasWvLm6VEgaSWvz+EWo05/XW7x7f2vjwEcQNjRbAIa3DBa"
                "YeKNQW8lodw4qWdqhwhJKM6c8k8cAp7usUSwdxmciXishwjeFEcu1daLx8nWy5D3xIGHiCbqflGwujQ0wINbFRipNlb/9ilgkE6wSPl5c33iTwGq52ew"
                "MVeyONUyaUyFmC716yOJxoGEWa+Nu1T8hnfxP/WJI1lf1wpp5IPdQafFRYyqMDS9BGDQ25dq6/v/qXSvQu/AFsV+piMNVgdYs4MEnCjhT6AH6a110EIK"
                "vcFECPsE4RfAfaaaA+AMiRGd+e4/bRkzJoLUEI+hEmzpoKPm0gJgptYjoNP09YTgYkRqaeRbY3PgClxqz0QQpdUns5MPsBXq+kzht8vYNU7BkgKaGloT"
                "PCdzvfmie25yPzDle8G/gw6tudBWQpNjHKqLDEIfPdjIPPgR";
            Profile p = FixtureProfile();
            p.policy_url = "https://policy.example.org/policy.json";
            p.policy_public_key = std::string("<RSAKeyValue><Modulus>") + mod + "</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            Policy next = policy.value;
            next.version = 2;
            next.domains = {"test.figma.com"};
            const auto payload = next.ToJson().dump();
            auto sig = SignRsaSha256(mod, d, reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size());
            Require(static_cast<bool>(sig), sig.error.message);
            nlohmann::json env = {{"payload", Base64Encode(reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size())},
                                  {"signature", Base64Encode(sig.value.data(), sig.value.size())}};
            auto merged = ConvertFromSignedPolicy(env, p, policy.value);
            Require(merged && std::find(merged.value.domains.begin(), merged.value.domains.end(), "chatgpt.com") !=
                                  merged.value.domains.end() &&
                        std::find(merged.value.domains.begin(), merged.value.domains.end(), "test.figma.com") !=
                            merged.value.domains.end(),
                    "Unsafe policy removal");
            auto replay = ConvertFromSignedPolicy(env, p, merged.value);
            Require(replay && replay.value.version == 0, "Replay accepted");
            auto tampered = payload;
            tampered[1] = static_cast<char>(tampered[1] ^ 1);
            env["payload"] = Base64Encode(reinterpret_cast<const std::uint8_t*>(tampered.data()), tampered.size());
            auto bad = ConvertFromSignedPolicy(env, p, policy.value);
            Require(!bad, "tamper accepted");
        });
        Check("IPv4-only TUN compatibility config", [&] {
            WriteTextAtomic(scratch / "tun-ipv4-only.flag", "1");
            auto c = NewEngineConfig(FixtureProfile(), policy.value, scratch, {}, true);
            Require(c["inbounds"][2]["address"].size() == 1, "IPv6 TUN address remains");
            for (const auto& item : c["inbounds"][2]["route_address"]) {
                Require(item.get<std::string>().find(':') == std::string::npos, "IPv6 route remains");
            }
            Require(c["route"]["final"] == "direct", "Default route changed");
        });
#ifdef _WIN32
        if (!engine.empty()) {
            Check("Real DNS mode ipv4Only=true uses 100.82 FakeIP", [&] {
                WriteTextAtomic(scratch / "tun-ipv4-only.flag", "1");
                auto c = NewEngineConfig(FixtureProfile(), policy.value, scratch, {}, true);
                Require(!TestEngineConfig(c, engine), "config");
                const int dns = FreePort();
                c["inbounds"] = nlohmann::json::array(
                    {{{"type", "direct"}, {"tag", "dns-in"}, {"listen", "127.0.0.1"}, {"listen_port", dns}}});
                EngineHandle handle;
                Require(!StartEngineMemory(c, engine, handle), "start");
                SleepMs(800);
                std::vector<std::uint8_t> answer;
                Require(QueryDns(dns, 1, answer), "dns A");
                Require((answer[3] & 15) == 0, "DNS error");
                Require(answer.size() >= 4 && answer[answer.size() - 4] == 100 && answer[answer.size() - 3] == 82,
                        "Wrong fake IPv4");
                Require(QueryDns(dns, 28, answer), "dns AAAA");
                Require(answer[7] == 0, "AAAA leaked");
                StopEngineMemory(handle);
            });
        }
#endif
        std::cout << g_passed << " checks passed. No system network settings changed; no real proxy credentials used.\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "FAIL: " << ex.what() << "\n";
        return 1;
    }
}

}  // namespace st
