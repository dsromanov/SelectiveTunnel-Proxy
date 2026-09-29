#pragma once

namespace st {

inline constexpr const char* kAppName = "SelectiveTunnel";
inline constexpr const char* kVersion = "2.0.0";
inline constexpr const char* kTunName = "SelectiveTunnel-TUN";
inline constexpr const char* kServiceName = "SelectiveTunnel";
inline constexpr const char* kServiceDisplay = "SelectiveTunnel";
inline constexpr const char* kNrptComment = "SelectiveTunnel";
inline constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\SelectiveTunnel";

inline constexpr const char* kFakeV4 = "100.82.0.0/16";
inline constexpr const char* kFakeV4a = "100.82.0.0/17";
inline constexpr const char* kFakeV4b = "100.82.128.0/17";
inline constexpr const char* kFakeV6 = "fd71:5e1e:c710::/48";
inline constexpr const char* kFakeV6a = "fd71:5e1e:c710::/49";
inline constexpr const char* kFakeV6b = "fd71:5e1e:c710:8000::/49";
inline constexpr const char* kDnsListen = "127.0.0.53";
inline constexpr int kDnsPort = 53;
inline constexpr const char* kDiagListen = "127.0.0.1";
inline constexpr int kDiagPort = 17891;
inline constexpr const char* kTunV4 = "172.31.255.1/30";
inline constexpr const char* kTunV6 = "fd71:5e1e:c711::1/126";
inline constexpr const char* kTunV4Net = "172.31.255.0/30";
inline constexpr const char* kTunV6Net = "fd71:5e1e:c711::/126";

inline constexpr const char* kLegacyFakeV4 = "198.18.0.0/15";
inline constexpr const char* kLegacyFakeV4a = "198.18.0.0/16";
inline constexpr const char* kLegacyFakeV4b = "198.19.0.0/16";

inline constexpr int kGuardMetric = 9999;
inline constexpr int kStatusStaleSeconds = 60;

inline constexpr const char* kSingBoxZipName = "sing-box-1.14.0-windows-amd64.zip";
inline constexpr const char* kWintunZipName = "wintun-0.14.1.zip";
inline constexpr const char* kSingBoxUrl =
    "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-windows-amd64.zip";
inline constexpr const char* kWintunUrl = "https://www.wintun.net/builds/wintun-0.14.1.zip";
inline constexpr const char* kSingBoxSha256 = "3FFB56267DA14E287BE48BD10CF7E6505260125BAD940B75101FBB4D5D58E5D6";
inline constexpr const char* kWintunSha256 = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51";

inline constexpr const char* kDefaultProxyIp = "176.119.140.14";
inline constexpr int kDefaultSocksPort = 14073;

}  // namespace st
