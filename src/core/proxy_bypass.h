#pragma once

#include "error.h"
#include "policy.h"

#include <string>
#include <vector>

namespace st {

std::string MergeProxyBypass(const std::string& existing, const std::vector<std::string>& domains);
std::string StripProxyBypass(const std::string& existing, const std::vector<std::string>& domains);
std::string MergeNoProxy(const std::string& existing, const std::vector<std::string>& domains);
std::string StripNoProxy(const std::string& existing, const std::vector<std::string>& domains);

void ApplyProxyBypass(const Policy& policy);
void RemoveProxyBypass(const Policy& policy);
void ApplyWinHttpProxyBypass(const Policy& policy, bool remove);

}  // namespace st
