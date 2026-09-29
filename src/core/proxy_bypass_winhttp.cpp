#include "proxy_bypass.h"

#include "utf.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>
#endif

namespace st {

void ApplyWinHttpProxyBypass(const Policy& policy, bool remove) {
#ifdef _WIN32
    WINHTTP_PROXY_INFO info{};
    if (!WinHttpGetDefaultProxyConfiguration(&info)) {
        return;
    }
    if (info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY) {
        const std::string current = info.lpszProxyBypass ? WideToUtf8(info.lpszProxyBypass) : "";
        const auto next =
            remove ? StripProxyBypass(current, policy.domains) : MergeProxyBypass(current, policy.domains);
        auto wide = Utf8ToWide(next);
        WINHTTP_PROXY_INFO set{};
        set.dwAccessType = info.dwAccessType;
        set.lpszProxy = info.lpszProxy;
        set.lpszProxyBypass = wide.empty() ? nullptr : wide.data();
        WinHttpSetDefaultProxyConfiguration(&set);
    }
    if (info.lpszProxy) {
        GlobalFree(info.lpszProxy);
    }
    if (info.lpszProxyBypass) {
        GlobalFree(info.lpszProxyBypass);
    }
#else
    (void)policy;
    (void)remove;
#endif
}

}  // namespace st
