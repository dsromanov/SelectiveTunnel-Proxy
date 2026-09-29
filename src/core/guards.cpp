#include "guards.h"

#include "constants.h"
#include "paths.h"
#include "proxy_bypass.h"
#include "utf.h"
#include "util.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_DCOM
#define _WIN32_DCOM
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <netfw.h>
#include <objbase.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace st {
namespace {

const wchar_t* kNrptRoot = L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";

bool IsTunnelAdapter(const IP_ADAPTER_ADDRESSES* adapter) {
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK || adapter->IfType == IF_TYPE_TUNNEL) {
        return true;
    }
    const auto name = WideToUtf8(adapter->FriendlyName ? adapter->FriendlyName : L"");
    const auto desc = WideToUtf8(adapter->Description ? adapter->Description : L"");
    const auto combined = name + " " + desc;
    static const char* keys[] = {"wintun",        "wireguard", "happ",          "sing-box", "selectivetunnel",
                                 "tap-windows",   "tap0901",   "nordlynx",      "openvpn",  "clash",
                                 "meta",          "tun2socks", "tun2proxy",     "wg ",      "vpn"};
    for (const char* key : keys) {
        if (ContainsIgnoreCase(combined, key)) {
            return true;
        }
    }
    return EqualsIgnoreCase(name, kTunName);
}

ULONG LoopbackIndex() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &size);
    std::vector<unsigned char> buf(size);
    auto addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, addrs, &size) != NO_ERROR) {
        return 1;
    }
    for (auto* a = addrs; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            return a->IfIndex;
        }
    }
    return 1;
}

Error EnsureRoute(const char* cidr, int family) {
    const std::string text = cidr;
    const auto slash = text.find('/');
    SOCKADDR_INET dest{};
    SOCKADDR_INET next{};
    UINT8 prefix = static_cast<UINT8>(std::stoi(text.substr(slash + 1)));
    if (family == AF_INET) {
        dest.si_family = AF_INET;
        next.si_family = AF_INET;
        InetPtonA(AF_INET, text.substr(0, slash).c_str(), &dest.Ipv4.sin_addr);
        next.Ipv4.sin_addr.s_addr = INADDR_ANY;
    } else {
        dest.si_family = AF_INET6;
        next.si_family = AF_INET6;
        InetPtonA(AF_INET6, text.substr(0, slash).c_str(), &dest.Ipv6.sin6_addr);
    }
    MIB_IPFORWARD_ROW2 row{};
    InitializeIpForwardEntry(&row);
    row.DestinationPrefix.Prefix = dest;
    row.DestinationPrefix.PrefixLength = prefix;
    row.NextHop = next;
    row.InterfaceIndex = LoopbackIndex();
    row.Metric = kGuardMetric;
    row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(3);
    const DWORD status = CreateIpForwardEntry2(&row);
    if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS) {
        return Fail(std::string("Persistent guard route ") + cidr + " failed.");
    }
    return Ok();
}

void DeleteRoutePrefix(const char* cidr, int family) {
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(family, &table) != NO_ERROR) {
        return;
    }
    const std::string text = cidr;
    const auto slash = text.find('/');
    const UINT8 prefix = static_cast<UINT8>(std::stoi(text.substr(slash + 1)));
    SOCKADDR_INET want{};
    if (family == AF_INET) {
        want.si_family = AF_INET;
        InetPtonA(AF_INET, text.substr(0, slash).c_str(), &want.Ipv4.sin_addr);
    } else {
        want.si_family = AF_INET6;
        InetPtonA(AF_INET6, text.substr(0, slash).c_str(), &want.Ipv6.sin6_addr);
    }
    const ULONG loop = LoopbackIndex();
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        auto& row = table->Table[i];
        if (row.InterfaceIndex != loop || row.Metric != kGuardMetric || row.DestinationPrefix.PrefixLength != prefix) {
            continue;
        }
        if (family == AF_INET) {
            if (row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr != want.Ipv4.sin_addr.s_addr) {
                continue;
            }
        } else if (std::memcmp(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr, &want.Ipv6.sin6_addr,
                               sizeof(IN6_ADDR)) != 0) {
            continue;
        }
        DeleteIpForwardEntry2(&row);
    }
    FreeMibTable(table);
}

Error AssertFirewallEnabled() {
    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                  reinterpret_cast<void**>(&policy));
    if (FAILED(hr)) {
        return Fail("Windows Firewall must be enabled for every profile.");
    }
    const NET_FW_PROFILE_TYPE2 profiles[] = {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
    Error err;
    for (auto profile : profiles) {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        if (FAILED(policy->get_FirewallEnabled(profile, &enabled)) || enabled != VARIANT_TRUE) {
            err = Fail("Windows Firewall must be enabled for every profile.");
            break;
        }
    }
    policy->Release();
    return err;
}

std::wstring RemoteAddresses() {
    std::wstring value = Utf8ToWide(kFakeV4);
    value += L",";
    value += Utf8ToWide(kFakeV6);
    return value;
}

BSTR MakeBstr(const std::wstring& text) { return SysAllocString(text.c_str()); }

VARIANT InterfaceList(const std::wstring& alias) {
    VARIANT value{};
    SAFEARRAY* wrapped = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    VARIANT item{};
    item.vt = VT_BSTR;
    item.bstrVal = MakeBstr(alias);
    LONG idx = 0;
    SafeArrayPutElement(wrapped, &idx, &item);
    VariantClear(&item);
    value.vt = VT_ARRAY | VT_VARIANT;
    value.parray = wrapped;
    return value;
}

void ApplyInterfaceAndRemote(INetFwRule* rule, const std::wstring& alias) {
    VARIANT ifs = InterfaceList(alias);
    rule->put_Interfaces(ifs);
    VariantClear(&ifs); 
    BSTR remote = MakeBstr(RemoteAddresses());
    rule->put_RemoteAddresses(remote);
    SysFreeString(remote);
    rule->put_Enabled(VARIANT_TRUE);
}

Error ApplyFirewall(const std::vector<std::pair<std::wstring, std::wstring>>& adapters) {
    INetFwPolicy2* policy = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                  reinterpret_cast<void**>(&policy));
    if (FAILED(hr)) {
        return Fail("Firewall guard could not be applied.");
    }
    INetFwRules* rules = nullptr;
    policy->get_Rules(&rules);
    for (const auto& adapter : adapters) {
        const std::wstring name = L"SelectiveTunnel-" + adapter.first;
        BSTR item_name = MakeBstr(name);
        INetFwRule* rule = nullptr;
        if (SUCCEEDED(rules->Item(item_name, &rule)) && rule) {
            ApplyInterfaceAndRemote(rule, adapter.second);
            rule->Release();
            SysFreeString(item_name);
            continue;
        }
        SysFreeString(item_name);
        INetFwRule* created = nullptr;
        CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule),
                         reinterpret_cast<void**>(&created));
        BSTR bname = MakeBstr(name);
        BSTR grouping = MakeBstr(Utf8ToWide(kAppName));
        created->put_Name(bname);
        created->put_Grouping(grouping);
        created->put_Direction(NET_FW_RULE_DIR_OUT);
        created->put_Action(NET_FW_ACTION_BLOCK);
        created->put_Profiles(NET_FW_PROFILE2_ALL);
        created->put_Protocol(256);
        ApplyInterfaceAndRemote(created, adapter.second);
        rules->Add(created);
        created->Release();
        SysFreeString(bname);
        SysFreeString(grouping);
    }
    rules->Release();
    policy->Release();
    return Ok();
}

void RemoveFirewallGroup() {
    INetFwPolicy2* policy = nullptr;
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2),
                                reinterpret_cast<void**>(&policy)))) {
        return;
    }
    INetFwRules* rules = nullptr;
    policy->get_Rules(&rules);
    IUnknown* unk = nullptr;
    rules->get__NewEnum(&unk);
    IEnumVARIANT* ev = nullptr;
    unk->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(&ev));
    unk->Release();
    VARIANT item;
    VariantInit(&item);
    std::vector<std::wstring> names;
    while (ev->Next(1, &item, nullptr) == S_OK) {
        INetFwRule* rule = nullptr;
        if (item.vt == VT_DISPATCH && item.pdispVal &&
            SUCCEEDED(item.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rule)))) {
            BSTR grouping = nullptr;
            rule->get_Grouping(&grouping);
            if (grouping && wcscmp(grouping, Utf8ToWide(kAppName).c_str()) == 0) {
                BSTR name = nullptr;
                rule->get_Name(&name);
                if (name) {
                    names.emplace_back(name);
                    SysFreeString(name);
                }
            }
            if (grouping) {
                SysFreeString(grouping);
            }
            rule->Release();
        }
        VariantClear(&item);
    }
    ev->Release();
    for (const auto& name : names) {
        BSTR drop = SysAllocString(name.c_str());
        rules->Remove(drop);
        SysFreeString(drop);
    }
    rules->Release();
    policy->Release();
}

bool NrptExists(const std::wstring& ns) {
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNrptRoot, 0, KEY_READ, &root) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t name[256];
    DWORD i = 0, nlen = 256;
    bool found = false;
    while (RegEnumKeyExW(root, i++, name, &nlen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        nlen = 256;
        HKEY child = nullptr;
        if (RegOpenKeyExW(root, name, 0, KEY_READ, &child) != ERROR_SUCCESS) {
            continue;
        }
        wchar_t comment[64]{};
        DWORD csize = sizeof(comment);
        DWORD type = 0;
        if (RegQueryValueExW(child, L"Comment", nullptr, &type, reinterpret_cast<LPBYTE>(comment), &csize) ==
                ERROR_SUCCESS &&
            wcscmp(comment, L"SelectiveTunnel") == 0) {
            wchar_t namespaces[512]{};
            DWORD nsize = sizeof(namespaces);
            if (RegQueryValueExW(child, L"Name", nullptr, &type, reinterpret_cast<LPBYTE>(namespaces), &nsize) ==
                    ERROR_SUCCESS &&
                wcscmp(namespaces, ns.c_str()) == 0) {
                found = true;
            }
        }
        RegCloseKey(child);
        if (found) {
            break;
        }
    }
    RegCloseKey(root);
    return found;
}

Error AddNrpt(const std::wstring& ns) {
    if (NrptExists(ns)) {
        return Ok();
    }
    GUID guid{};
    CoCreateGuid(&guid);
    wchar_t guid_text[64]{};
    StringFromGUID2(guid, guid_text, 64);
    HKEY root = nullptr;
    DWORD disp = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kNrptRoot, 0, nullptr, 0, KEY_WRITE, nullptr, &root, &disp) !=
        ERROR_SUCCESS) {
        return Fail("Cannot create NRPT policy.");
    }
    HKEY child = nullptr;
    if (RegCreateKeyExW(root, guid_text, 0, nullptr, 0, KEY_WRITE, nullptr, &child, &disp) != ERROR_SUCCESS) {
        RegCloseKey(root);
        return Fail("Cannot create NRPT policy.");
    }
    const wchar_t* servers = L"127.0.0.53";
    DWORD options = 0x8;
    DWORD version = 2;
    const wchar_t comment[] = L"SelectiveTunnel";
    std::wstring multi = ns;
    multi.push_back(L'\0');
    multi.push_back(L'\0');
    RegSetValueExW(child, L"Name", 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(multi.c_str()),
                   static_cast<DWORD>((ns.size() + 2) * sizeof(wchar_t)));
    RegSetValueExW(child, L"GenericDNSServers", 0, REG_SZ, reinterpret_cast<const BYTE*>(servers),
                   static_cast<DWORD>((wcslen(servers) + 1) * sizeof(wchar_t)));
    RegSetValueExW(child, L"ConfigOptions", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&options), sizeof(options));
    RegSetValueExW(child, L"Version", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&version), sizeof(version));
    RegSetValueExW(child, L"Comment", 0, REG_SZ, reinterpret_cast<const BYTE*>(comment), sizeof(comment));
    RegCloseKey(child);
    RegCloseKey(root);
    return Ok();
}

void RemoveOwnedNrpt() {
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNrptRoot, 0, KEY_READ | KEY_WRITE, &root) != ERROR_SUCCESS) {
        return;
    }
    wchar_t name[256];
    DWORD nlen = 256;
    std::vector<std::wstring> drop;
    DWORD i = 0;
    while (RegEnumKeyExW(root, i++, name, &nlen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        nlen = 256;
        HKEY child = nullptr;
        if (RegOpenKeyExW(root, name, 0, KEY_READ, &child) != ERROR_SUCCESS) {
            continue;
        }
        wchar_t comment[64]{};
        DWORD csize = sizeof(comment), type = 0;
        if (RegQueryValueExW(child, L"Comment", nullptr, &type, reinterpret_cast<LPBYTE>(comment), &csize) ==
                ERROR_SUCCESS &&
            wcscmp(comment, L"SelectiveTunnel") == 0) {
            drop.emplace_back(name);
        }
        RegCloseKey(child);
    }
    for (const auto& key : drop) {
        RegDeleteKeyW(root, key.c_str());
    }
    RegCloseKey(root);
}

std::vector<std::pair<std::wstring, std::wstring>> UpAdapters() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, nullptr, &size);
    std::vector<unsigned char> buf(size);
    auto addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    std::vector<std::pair<std::wstring, std::wstring>> out;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, addrs, &size) != NO_ERROR) {
        return out;
    }
    for (auto* a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) {
            continue;
        }
        const auto friendly = a->FriendlyName ? std::wstring(a->FriendlyName) : L"";
        if (EqualsIgnoreCase(WideToUtf8(friendly), kTunName)) {
            continue;
        }
        std::wstring guid = a->AdapterName ? Utf8ToWide(a->AdapterName) : L"";
        if (!guid.empty() && guid.front() == L'{') {
            guid = guid.substr(1, guid.size() - 2);
        }
        out.emplace_back(guid, friendly);
    }
    return out;
}

}  // namespace

std::string DetectBindInterface() {
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, nullptr, &size);
    std::vector<unsigned char> buf(size);
    auto addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, addrs, &size) != NO_ERROR) {
        return {};
    }
    std::string fallback;
    for (auto* a = addrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || IsTunnelAdapter(a)) {
            continue;
        }
        const auto name = WideToUtf8(a->FriendlyName ? a->FriendlyName : L"");
        if (name.empty()) {
            continue;
        }
        if (fallback.empty()) {
            fallback = name;
        }
        if (a->FirstGatewayAddress && (a->IfType == IF_TYPE_ETHERNET_CSMACD || a->IfType == IF_TYPE_IEEE80211)) {
            return name;
        }
        if (a->FirstGatewayAddress && fallback == name) {
            fallback = name;
        }
    }
    return fallback;
}

std::vector<std::string> DetectHappHints() {
    std::vector<std::string> hints;
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &size);
    std::vector<unsigned char> buf(size);
    auto addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &size) != NO_ERROR) {
        return hints;
    }
    bool happ = false;
    bool other_tun = false;
    for (auto* a = addrs; a; a = a->Next) {
        const auto name = WideToUtf8(a->FriendlyName ? a->FriendlyName : L"");
        const auto desc = WideToUtf8(a->Description ? a->Description : L"");
        if (ContainsIgnoreCase(name, "happ") || ContainsIgnoreCase(desc, "happ")) {
            happ = true;
        } else if (!EqualsIgnoreCase(name, kTunName) &&
                   (a->IfType == IF_TYPE_TUNNEL || ContainsIgnoreCase(desc, "wintun") ||
                    ContainsIgnoreCase(desc, "wireguard"))) {
            other_tun = true;
        }
    }
    if (happ) {
        hints.emplace_back("Happ TUN adapter detected. Keep Figma/ChatGPT bypassed in Happ if it hijacks DNS.");
    } else if (other_tun) {
        hints.emplace_back("Another TUN/VPN adapter is present. Split routing may be required.");
    }
    return hints;
}

Error SetGuards(const Policy& policy, bool flush_dns) {
    if (auto err = RequireAdministrator()) {
        return err;
    }
    if (auto err = AssertPolicy(policy)) {
        return err;
    }
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(hr);
    if (auto err = AssertFirewallEnabled()) {
        if (uninit) {
            CoUninitialize();
        }
        return err;
    }
    if (auto err = EnsureRoute(kFakeV4, AF_INET)) {
        if (uninit) {
            CoUninitialize();
        }
        return err;
    }
    EnsureRoute(kFakeV6, AF_INET6);
    auto adapters = UpAdapters();
    if (auto err = ApplyFirewall(adapters)) {
        if (uninit) {
            CoUninitialize();
        }
        return err;
    }
    for (const auto& domain : policy.domains) {
        const auto w = Utf8ToWide(domain);
        if (auto err = AddNrpt(w)) {
            if (uninit) {
                CoUninitialize();
            }
            return err;
        }
        if (auto err = AddNrpt(L"." + w)) {
            if (uninit) {
                CoUninitialize();
            }
            return err;
        }
    }
    ApplyProxyBypass(policy);
    if (flush_dns) {
        ClearDnsCache();
    }
    if (uninit) {
        CoUninitialize();
    }
    return Ok();
}

Error RemoveGuards() {
    if (auto err = RequireAdministrator()) {
        return err;
    }
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninit = SUCCEEDED(hr);
    RemoveOwnedNrpt();
    auto policy = LoadBundledPolicy(PolicyPath());
    if (policy) {
        RemoveProxyBypass(policy.value);
    }
    RemoveFirewallGroup();
    DeleteRoutePrefix(kFakeV4, AF_INET);
    DeleteRoutePrefix(kFakeV6, AF_INET6);
    DeleteRoutePrefix(kLegacyFakeV4, AF_INET);
    DeleteRoutePrefix(kLegacyFakeV4a, AF_INET);
    DeleteRoutePrefix(kLegacyFakeV4b, AF_INET);
    ClearDnsCache();
    if (uninit) {
        CoUninitialize();
    }
    return Ok();
}

Error RemoveLegacyFakeIpRoutes() {
    DeleteRoutePrefix(kLegacyFakeV4, AF_INET);
    DeleteRoutePrefix(kLegacyFakeV4a, AF_INET);
    DeleteRoutePrefix(kLegacyFakeV4b, AF_INET);
    return Ok();
}

}  // namespace st

#else

namespace st {

Error SetGuards(const Policy&, bool) { return Fail("Guards are only implemented on Windows."); }
Error RemoveGuards() { return Fail("Guards are only implemented on Windows."); }
Error RemoveLegacyFakeIpRoutes() { return Ok(); }
std::string DetectBindInterface() { return {}; }
std::vector<std::string> DetectHappHints() { return {}; }

}  // namespace st

#endif
